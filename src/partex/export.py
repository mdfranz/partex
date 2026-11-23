"""Canonical JSON run export with default secret redaction — PLAN §7, §12."""

import warnings
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .ids import canonical_json
from .models import CoverageEntry, Evidence, Finding, Severity, Verification, redact
from .storage import RunReader, RunRecord, RunStore, ToolCallRecord, WebResearchRecord

__all__ = [
    'SEVERITY_RANK',
    'ExportStore',
    'IncludeSecretsWarning',
    'build_export_payload',
    'export_run_data',
    'export_run_json',
    'write_run_export',
]


class IncludeSecretsWarning(UserWarning):
    """Emitted when exporting a run with ``include_secrets=True``."""


SEVERITY_RANK: dict[Severity, int] = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
}

type ExportStore = RunReader | RunStore


def _serialize_run(run: RunRecord) -> dict[str, Any]:
    """Serialize *run* without non-deterministic ``id``, ``created_at``, or ``ended_at`` fields."""
    return {
        'authorized': run.authorized,
        'engagement_id': run.engagement_id,
        'engine_version': run.engine_version,
        'error': run.error,
        'findings_count': run.findings_count,
        'input_kind': run.input_kind,
        'input_ref': run.input_ref,
        'input_sha256': run.input_sha256,
        'input_tokens': run.input_tokens,
        'model': run.model,
        'model_calls': run.model_calls,
        'output_tokens': run.output_tokens,
        'requests_spent': run.requests_spent,
        'scope_snapshot': None if run.scope_snapshot is None else run.scope_snapshot.model_dump(mode='json'),
        'selected_checks': list(run.selected_checks),
        'state': run.state,
        'write_requests_spent': run.write_requests_spent,
    }


def _serialize_tool_call(call: ToolCallRecord) -> dict[str, Any]:
    """Serialize *call* without non-deterministic ``call_id`` or ``created_at`` fields."""
    return {
        'args': call.args,
        'result': call.result,
        'tool': call.tool,
    }


def _serialize_web_research(entry: WebResearchRecord) -> dict[str, Any]:
    """Serialize one saved web search (#113) without its random ``id``/``call_id`` or ``created_at``."""
    return {
        'answer': entry.answer,
        'auth_mode': entry.auth_mode,
        'model': entry.model,
        'provider': entry.provider,
        'query': entry.query,
        'sources': list(entry.sources),
        'truncated': entry.truncated,
    }


def _finding_sort_key(finding: Finding) -> tuple[int, str, str]:
    """Sort findings by (severity rank desc, check_id asc, finding_id asc)."""
    return (-SEVERITY_RANK[finding.severity], finding.check_id, finding.id)


def build_export_payload(
    run: RunRecord,
    *,
    evidence: Sequence[Evidence] = (),
    findings: Sequence[Finding] = (),
    verifications: Sequence[Verification] = (),
    coverage: Sequence[CoverageEntry] = (),
    tool_calls: Sequence[ToolCallRecord] = (),
    web_research: Sequence[WebResearchRecord] = (),
    include_secrets: bool = False,
) -> dict[str, Any]:
    """Assemble the canonical JSON-serializable payload for a run export."""
    if include_secrets:
        warnings.warn(
            'Exporting run with include_secrets=True; output may contain unredacted secrets.',
            IncludeSecretsWarning,
            stacklevel=2,
        )
        serialized_evidence = [item.model_dump(mode='json') for item in evidence]
    else:
        serialized_evidence = [redact(item).model_dump(mode='json') for item in evidence]

    sorted_findings = sorted(findings, key=_finding_sort_key)
    sorted_verifications = sorted(verifications, key=lambda v: (v.finding_id, v.id))
    sorted_coverage = sorted(coverage, key=lambda c: (c.surface, c.risk_area))

    return {
        'coverage': [entry.model_dump(mode='json') for entry in sorted_coverage],
        'evidence': serialized_evidence,
        'findings': [finding.model_dump(mode='json') for finding in sorted_findings],
        'run': _serialize_run(run),
        'tool_calls': [_serialize_tool_call(call) for call in tool_calls],
        'verifications': [verification.model_dump(mode='json') for verification in sorted_verifications],
        'web_research': [_serialize_web_research(entry) for entry in web_research],
    }


async def export_run_data(
    store: ExportStore,
    run_id: str,
    *,
    include_secrets: bool = False,
) -> dict[str, Any]:
    """Load *run_id* and its artifacts from *store* and build the export payload."""
    run = await store.get_run(run_id)
    evidence = await store.evidence(run_id)
    findings = await store.findings(run_id)
    verifications = await store.verifications(run_id)
    coverage = await store.coverage(run_id)
    tool_calls = await store.tool_calls(run_id)
    web_research = await store.web_research(run_id)
    return build_export_payload(
        run,
        evidence=evidence,
        findings=findings,
        verifications=verifications,
        coverage=coverage,
        tool_calls=tool_calls,
        web_research=web_research,
        include_secrets=include_secrets,
    )


async def export_run_json(
    store: ExportStore,
    run_id: str,
    *,
    include_secrets: bool = False,
) -> bytes:
    """Export *run_id* from *store* as canonical JSON bytes (no trailing newline)."""
    payload = await export_run_data(store, run_id, include_secrets=include_secrets)
    return canonical_json(payload)


async def write_run_export(
    store: ExportStore,
    run_id: str,
    out_path: str | Path,
    *,
    include_secrets: bool = False,
) -> bytes:
    """Write canonical JSON export for *run_id* to *out_path* with a trailing newline."""
    payload_bytes = await export_run_json(store, run_id, include_secrets=include_secrets) + b'\n'
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload_bytes)
    return payload_bytes
