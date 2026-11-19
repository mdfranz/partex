"""Run-scoped, read-only tools for the reviewer — PLAN §9 (``chat <run-id>``).

Every tool reads one run through a ``mode=ro`` :class:`~partex.storage.RunReader`; there is no write
tool. Findings and evidence carry bytes captured from the target (headers, bodies, banners echoed into
finding descriptions), so every return is framed as untrusted data with :mod:`pydantic_ai.framing`,
which escapes any copy of the tag inside the body. Evidence is secret-redacted before it is framed.
IDs that are unknown, or that belong to another run, fail the call with ``ToolFailed`` so the model
adapts instead of retrying.
"""

import json
from dataclasses import dataclass
from typing import Any, Literal, cast

from pydantic_ai import RunContext, ToolFailed
from pydantic_ai.framing import register_tag, wrap

from ..ids import canonical_json
from ..models import ConfigEvidence, Evidence, Finding, HttpEvidence, redact
from ..storage import RunReader, RunStore

UNTRUSTED_TAG = register_tag('partex_untrusted_data')
# The opening briefing is model output written from untrusted data, so it is framed (and escaped) too.
BRIEFING_TAG = register_tag('partex_briefing')


type RunReads = RunReader | RunStore
"""Read access to the store: a ``mode=ro`` reader for ``chat``; the session's engine store for ``agent``."""

type RunChoice = Literal['current', 'previous']


@dataclass(frozen=True, slots=True)
class ReviewDeps:
    """What the read tools may touch: the current run, and optionally one earlier run, read-only."""

    run_id: str
    reader: RunReads
    previous_run_id: str | None = None
    """The run an ``agent`` session continues from (``--from``); ``None`` for ``chat``."""


def _run_id(deps: ReviewDeps, run: RunChoice) -> str:
    if run == 'current':
        return deps.run_id
    if deps.previous_run_id is None:
        raise ToolFailed("there is no previous run in this session; use run='current'")
    return deps.previous_run_id


def frame_untrusted(kind: str, payload: Any) -> str:
    """Serialize *payload* and frame it as untrusted target-derived data."""
    return wrap(UNTRUSTED_TAG, json.dumps(payload, indent=2, sort_keys=True), kind=kind)


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


async def list_findings(ctx: RunContext[ReviewDeps], run: RunChoice = 'current') -> str:
    """List a run's findings: id, check, severity, subject, title, status, and evidence IDs.

    Args:
        run: ``current`` (default), or ``previous`` for the run an agent session continues from.
    """
    findings = await ctx.deps.reader.findings(_run_id(ctx.deps, run))
    return frame_untrusted('findings', [_finding_summary(finding) for finding in findings])


def _evidence_summary(item: Evidence) -> dict[str, Any]:
    if isinstance(item, ConfigEvidence):
        return {'id': item.id, 'kind': item.kind, 'path': item.config.path, 'format': item.config.format}
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
        run: ``current`` (default), or ``previous`` for the run an agent session continues from.
    """
    evidence = await ctx.deps.reader.evidence(_run_id(ctx.deps, run))
    return frame_untrusted('evidence_list', [_evidence_summary(item) for item in evidence])


async def get_finding(ctx: RunContext[ReviewDeps], finding_id: str, run: RunChoice = 'current') -> str:
    """Return one finding of a run in full (description, remediation, verification ID).

    Args:
        finding_id: A finding ID from ``list_findings`` (``fn_…``).
        run: ``current`` (default), or ``previous`` for the run an agent session continues from.
    """
    finding = await ctx.deps.reader.get_finding(_run_id(ctx.deps, run), finding_id)
    if finding is None:
        raise ToolFailed(f'no finding {finding_id!r} in this run; call list_findings for valid IDs')
    return frame_untrusted('finding', finding.model_dump(mode='json'))


async def lookup_evidence(ctx: RunContext[ReviewDeps], evidence_id: str, run: RunChoice = 'current') -> str:
    """Return one captured exchange or config excerpt of a run, with secrets redacted.

    Args:
        evidence_id: An evidence ID from ``list_evidence`` or a finding (``ev_…``).
        run: ``current`` (default), or ``previous`` for the run an agent session continues from.
    """
    evidence = await ctx.deps.reader.get_evidence(_run_id(ctx.deps, run), evidence_id)
    if evidence is None:
        raise ToolFailed(f'no evidence {evidence_id!r} in this run; use evidence_ids from list_findings')
    return frame_untrusted('evidence', json.loads(canonical_json(redact(evidence).model_dump(mode='json'))))


REVIEWER_TOOLS = (list_findings, get_finding, list_evidence, lookup_evidence)
