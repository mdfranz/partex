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
from typing import Any

from pydantic_ai import RunContext, ToolFailed
from pydantic_ai.framing import register_tag, wrap

from ..ids import canonical_json
from ..models import Finding, redact
from ..storage import RunReader

UNTRUSTED_TAG = register_tag('partex_untrusted_data')
# The opening briefing is model output written from untrusted data, so it is framed (and escaped) too.
BRIEFING_TAG = register_tag('partex_briefing')


@dataclass(frozen=True, slots=True)
class ReviewDeps:
    """What reviewer tools may touch: one run, read-only."""

    run_id: str
    reader: RunReader


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


async def list_findings(ctx: RunContext[ReviewDeps]) -> str:
    """List this run's findings: id, check, severity, subject, title, status, and evidence IDs."""
    findings = await ctx.deps.reader.findings(ctx.deps.run_id)
    return frame_untrusted('findings', [_finding_summary(finding) for finding in findings])


async def get_finding(ctx: RunContext[ReviewDeps], finding_id: str) -> str:
    """Return one finding of this run in full (description, remediation, verification ID).

    Args:
        finding_id: A finding ID from ``list_findings`` (``fn_…``).
    """
    finding = await ctx.deps.reader.get_finding(ctx.deps.run_id, finding_id)
    if finding is None:
        raise ToolFailed(f'no finding {finding_id!r} in this run; call list_findings for valid IDs')
    return frame_untrusted('finding', finding.model_dump(mode='json'))


async def lookup_evidence(ctx: RunContext[ReviewDeps], evidence_id: str) -> str:
    """Return one captured exchange or config excerpt of this run, with secrets redacted.

    Args:
        evidence_id: An evidence ID cited by a finding (``ev_…``).
    """
    evidence = await ctx.deps.reader.get_evidence(ctx.deps.run_id, evidence_id)
    if evidence is None:
        raise ToolFailed(f'no evidence {evidence_id!r} in this run; use evidence_ids from list_findings')
    return frame_untrusted('evidence', json.loads(canonical_json(redact(evidence).model_dump(mode='json'))))


REVIEWER_TOOLS = (list_findings, get_finding, lookup_evidence)
