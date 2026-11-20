"""Run-scoped, read-only tools for the reviewer — PLAN §9 (``chat <run-id>``).

Every tool reads one run through a ``mode=ro`` :class:`~partex.storage.RunReader`; there is no write
tool. Findings and evidence carry bytes captured from the target (headers, bodies, banners echoed into
finding descriptions), so every return is framed as untrusted data with :mod:`pydantic_ai.framing`,
which escapes any copy of the tag inside the body. Evidence is secret-redacted before it is framed.
IDs that are unknown, or that belong to another run, fail the call with ``ToolFailed`` so the model
adapts instead of retrying.
"""

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, cast

from pydantic_ai import RunContext, ToolFailed
from pydantic_ai.framing import register_tag, wrap

from ..ids import canonical_json
from ..models import ArtifactEvidence, ConfigEvidence, Evidence, Finding, HttpEvidence, redact
from ..storage import RunReader, RunRecord, RunStore

UNTRUSTED_TAG = register_tag('partex_untrusted_data')
# The opening briefing is model output written from untrusted data, so it is framed (and escaped) too.
BRIEFING_TAG = register_tag('partex_briefing')


type RunReads = RunReader | RunStore
"""Read access to the store: a ``mode=ro`` reader for ``chat``; the session's engine store for ``agent``."""

type RunChoice = str
"""``current``, ``previous`` (the ``--from`` run), or the ID (``run_…``) of an earlier run against the same target."""

type AuditHook = Callable[[str, dict[str, Any], dict[str, Any]], Awaitable[None]]
"""Records one read-tool call (``tool, args, compact result``). ``agent`` sets it; ``chat`` leaves it None,
so the reviewer stays fully read-only."""


@dataclass(frozen=True, slots=True)
class ReviewDeps:
    """What the read tools may touch: the current run, and optionally one earlier run, read-only."""

    run_id: str
    reader: RunReads
    previous_run_id: str | None = None
    """The run an ``agent`` session continues from (``--from``); ``None`` for ``chat``."""
    audit: AuditHook | None = None
    """Set by ``agent`` to log read-tool calls to the session run; ``None`` for the read-only ``chat``."""


def _target_key(run: RunRecord) -> tuple[frozenset[str], frozenset[int]] | None:
    """A run's target identity: the hosts and ports of its scope snapshot (``None`` if it has none)."""
    scope = run.scope_snapshot
    return None if scope is None else (frozenset(scope.hosts), frozenset(scope.ports))


async def _same_target_runs(deps: ReviewDeps) -> list[RunRecord]:
    """Runs in the store against the same target (hosts and ports) as the current run, oldest first.

    Runs of other targets or engagements in the same database are never exposed to the model.
    """
    key = _target_key(await deps.reader.get_run(deps.run_id))
    if key is None:
        return []
    return [run for run in await deps.reader.list_runs() if _target_key(run) == key]


async def _run_id(deps: ReviewDeps, run: RunChoice) -> str:
    if run == 'current':
        return deps.run_id
    if run == 'previous':
        if deps.previous_run_id is None:
            raise ToolFailed("there is no previous run in this session; use run='current' or call list_runs")
        return deps.previous_run_id
    if run == deps.previous_run_id or any(candidate.id == run for candidate in await _same_target_runs(deps)):
        return run
    raise ToolFailed(f'run {run!r} is not a run against this target; call list_runs for valid run IDs')


def frame_untrusted(kind: str, payload: Any) -> str:
    """Serialize *payload* and frame it as untrusted target-derived data."""
    return wrap(UNTRUSTED_TAG, json.dumps(payload, indent=2, sort_keys=True), kind=kind)


async def _audit_read(deps: ReviewDeps, tool: str, args: dict[str, Any], result: dict[str, Any]) -> None:
    if deps.audit is not None:
        await deps.audit(tool, args, result)


def _finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        'id': finding.id,
        'check_id': finding.check_id,
        'severity': finding.severity,
        'subject': finding.subject,
        'title': finding.title,
        'status': finding.status,
        'evidence_ids': finding.evidence_ids,
    }


async def list_runs(ctx: RunContext[ReviewDeps]) -> str:
    """List earlier sessions/runs against this same target (oldest first), including the current run.

    Use a returned ``id`` as the ``run`` argument of the other read tools to look at that run's
    findings and evidence. Runs against other targets are not listed.
    """
    runs = await _same_target_runs(ctx.deps)
    await _audit_read(ctx.deps, 'list_runs', {}, {'count': len(runs)})
    return frame_untrusted(
        'runs',
        [
            {
                'id': run.id,
                'created_at': run.created_at,
                'state': run.state,
                'kind': run.input_kind,
                'checks': list(run.selected_checks),
                'findings': run.findings_count,
                'requests_spent': run.requests_spent,
                'current': run.id == ctx.deps.run_id,
            }
            for run in runs
        ],
    )


async def list_findings(ctx: RunContext[ReviewDeps], run: RunChoice = 'current') -> str:
    """List a run's findings: id, check, severity, subject, title, status, and evidence IDs.

    Args:
        run: ``current`` (default), ``previous`` (the run an agent session continues from), or a run ID from
            ``list_runs``.
    """
    findings = await ctx.deps.reader.findings(await _run_id(ctx.deps, run))
    await _audit_read(ctx.deps, 'list_findings', {'run': run}, {'count': len(findings)})
    return frame_untrusted('findings', [_finding_summary(finding) for finding in findings])


def _evidence_summary(item: Evidence) -> dict[str, Any]:
    if isinstance(item, ConfigEvidence):
        return {'id': item.id, 'kind': item.kind, 'path': item.config.path, 'format': item.config.format}
    if isinstance(item, ArtifactEvidence):
        redacted_artifact = cast(ArtifactEvidence, redact(item))
        return {
            'id': item.id,
            'kind': item.kind,
            'url': redacted_artifact.artifact.url,
            'status': redacted_artifact.artifact.status_code,
            'content_type': redacted_artifact.artifact.content_type,
            'size_bytes': redacted_artifact.artifact.size_bytes,
            'sha256': redacted_artifact.artifact.sha256,
        }
    redacted = cast(HttpEvidence, redact(item))  # redaction keeps the evidence kind
    request, response = redacted.http.request, redacted.http.response
    return {
        'id': item.id,
        'kind': item.kind,
        'request': f'{request.method} {request.url}',
        'status': response.status_code,
        'response_headers': response.headers,
        'body_bytes': None if response.body is None else len(response.body.encode()),
    }


async def list_evidence(ctx: RunContext[ReviewDeps], run: RunChoice = 'current') -> str:
    """List everything a run captured, in capture order: request, status, response headers, body size.

    Use it to see what a run actually saw, including runs with no findings. Bodies are omitted; use
    lookup_evidence for one exchange in full.

    Args:
        run: ``current`` (default), ``previous`` (the run an agent session continues from), or a run ID from
            ``list_runs``.
    """
    evidence = await ctx.deps.reader.evidence(await _run_id(ctx.deps, run))
    await _audit_read(ctx.deps, 'list_evidence', {'run': run}, {'count': len(evidence)})
    return frame_untrusted('evidence_list', [_evidence_summary(item) for item in evidence])


async def get_finding(ctx: RunContext[ReviewDeps], finding_id: str, run: RunChoice = 'current') -> str:
    """Return one finding of a run in full (description, remediation, verification ID).

    Args:
        finding_id: A finding ID from ``list_findings`` (``fn_…``).
        run: ``current`` (default), ``previous`` (the run an agent session continues from), or a run ID from
            ``list_runs``.
    """
    finding = await ctx.deps.reader.get_finding(await _run_id(ctx.deps, run), finding_id)
    await _audit_read(ctx.deps, 'get_finding', {'finding_id': finding_id, 'run': run}, {'found': finding is not None})
    if finding is None:
        raise ToolFailed(f'no finding {finding_id!r} in this run; call list_findings for valid IDs')
    return frame_untrusted('finding', finding.model_dump(mode='json'))


async def lookup_evidence(ctx: RunContext[ReviewDeps], evidence_id: str, run: RunChoice = 'current') -> str:
    """Return one captured exchange or config excerpt of a run, with secrets redacted.

    Args:
        evidence_id: An evidence ID from ``list_evidence`` or a finding (``ev_…``).
        run: ``current`` (default), ``previous`` (the run an agent session continues from), or a run ID from
            ``list_runs``.
    """
    evidence = await ctx.deps.reader.get_evidence(await _run_id(ctx.deps, run), evidence_id)
    await _audit_read(
        ctx.deps, 'lookup_evidence', {'evidence_id': evidence_id, 'run': run}, {'found': evidence is not None}
    )
    if evidence is None:
        raise ToolFailed(f'no evidence {evidence_id!r} in this run; use evidence_ids from list_findings')
    return frame_untrusted('evidence', json.loads(canonical_json(redact(evidence).model_dump(mode='json'))))


REVIEWER_TOOLS = (list_runs, list_findings, get_finding, list_evidence, lookup_evidence)
