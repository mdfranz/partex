"""Cross-run reporting rollup over the store — PLAN §7/§8 (``partex report``).

A read-only aggregation of what runs already recorded: findings by severity and check, model spend
from ``llm_usage``, and the agent tool-call audit from ``tool_calls``. No engine or schema change —
the store stays the only writer, and this never touches the network or a model.
"""

from collections.abc import Sequence
from typing import Any

from .export import SEVERITY_RANK
from .models import Finding, Severity
from .storage import LlmUsageRecord, RunReader, RunRecord, RunStore, ToolCallRecord

type ReportStore = RunReader | RunStore

_SEVERITIES: tuple[Severity, ...] = tuple(sorted(SEVERITY_RANK, key=lambda s: -SEVERITY_RANK[s]))


def _count(pairs: dict[str, int]) -> list[dict[str, Any]]:
    """A ``{key: count}`` map as a list sorted by count desc then key asc (deterministic)."""
    return [{'name': k, 'count': v} for k, v in sorted(pairs.items(), key=lambda kv: (-kv[1], kv[0]))]


def _refused(result: Any) -> bool:
    return isinstance(result, dict) and 'refused' in result


def _errored(result: Any) -> bool:
    return isinstance(result, dict) and 'error' in result


def _severity_breakdown(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    """Counts per severity, highest rank first, only severities that occur."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return [{'severity': s, 'count': counts[s]} for s in _SEVERITIES if s in counts]


def build_report_payload(
    runs: Sequence[RunRecord],
    findings: Sequence[Finding],
    tool_calls: Sequence[ToolCallRecord],
    llm_usage: Sequence[LlmUsageRecord],
) -> dict[str, Any]:
    """Aggregate the already-read run data into a deterministic, JSON-serializable report payload."""
    states: dict[str, int] = {}
    for run in runs:
        states[run.state] = states.get(run.state, 0) + 1
    created = sorted(run.created_at for run in runs)

    by_check: dict[str, list[Finding]] = {}
    for finding in findings:
        by_check.setdefault(finding.check_id, []).append(finding)
    checks = [
        {
            'check_id': check_id,
            'total': len(group),
            'by_severity': _severity_breakdown(group),
        }
        for check_id, group in sorted(by_check.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]

    spend: dict[tuple[str, str], dict[str, int]] = {}
    for u in llm_usage:
        agg = spend.setdefault(
            (u.role, u.model),
            {'turns': 0, 'input_tokens': 0, 'output_tokens': 0, 'cache_read_tokens': 0, 'latency_ms': 0, 'errors': 0},
        )
        agg['turns'] += 1
        agg['input_tokens'] += u.input_tokens
        agg['output_tokens'] += u.output_tokens
        agg['cache_read_tokens'] += u.cache_read_tokens
        agg['latency_ms'] += u.latency_ms
        agg['errors'] += 0 if u.status == 'ok' else 1
    model_usage = [
        {
            'role': role,
            'model': model,
            'turns': agg['turns'],
            'input_tokens': agg['input_tokens'],
            'output_tokens': agg['output_tokens'],
            'cache_read_tokens': agg['cache_read_tokens'],
            'total_latency_ms': agg['latency_ms'],
            'avg_latency_ms': round(agg['latency_ms'] / agg['turns']) if agg['turns'] else 0,
            'errors': agg['errors'],
        }
        for (role, model), agg in sorted(spend.items(), key=lambda kv: (-kv[1]['turns'], kv[0]))
    ]

    tools: dict[str, dict[str, int]] = {}
    for call in tool_calls:
        agg = tools.setdefault(call.tool, {'calls': 0, 'refused': 0, 'errored': 0})
        agg['calls'] += 1
        agg['refused'] += 1 if _refused(call.result) else 0
        agg['errored'] += 1 if _errored(call.result) else 0
    by_tool = [
        {'tool': tool, 'calls': agg['calls'], 'refused': agg['refused'], 'errored': agg['errored']}
        for tool, agg in sorted(tools.items(), key=lambda kv: (-kv[1]['calls'], kv[0]))
    ]

    return {
        'runs': {
            'total': len(runs),
            'by_state': _count(states),
            'requests_spent': sum(run.requests_spent for run in runs),
            'first': created[0] if created else None,
            'last': created[-1] if created else None,
        },
        'findings': {
            'total': len(findings),
            'by_severity': _severity_breakdown(findings),
            'by_check': checks,
        },
        'model_usage': model_usage,
        'tool_calls': {'total': len(tool_calls), 'by_tool': by_tool},
    }


async def gather_report_payload(store: ReportStore) -> dict[str, Any]:
    """Read every run's findings, tool calls, and model usage from *store* and build the report."""
    runs = await store.list_runs()
    findings: list[Finding] = []
    tool_calls: list[ToolCallRecord] = []
    llm_usage: list[LlmUsageRecord] = []
    for run in runs:
        findings.extend(await store.findings(run.id))
        tool_calls.extend(await store.tool_calls(run.id))
        llm_usage.extend(await store.llm_usage(run.id))
    return build_report_payload(runs, findings, tool_calls, llm_usage)


def render_report_text(payload: dict[str, Any]) -> str:
    """A compact human report. The JSON payload (``--json``) carries the full detail."""
    runs = payload['runs']
    lines = [f'runs: {runs["total"]}  requests spent: {runs["requests_spent"]}']
    if runs['first'] is not None:
        lines.append(f'window: {runs["first"]} .. {runs["last"]}')
    if runs['by_state']:
        lines.append('  states: ' + ', '.join(f'{row["name"]}={row["count"]}' for row in runs['by_state']))

    findings = payload['findings']
    lines.append(f'findings: {findings["total"]}')
    if findings['by_severity']:
        lines.append('  severity: ' + ', '.join(f'{row["severity"]}={row["count"]}' for row in findings['by_severity']))
    for check in findings['by_check']:
        sev = ', '.join(f'{row["severity"]} {row["count"]}' for row in check['by_severity'])
        lines.append(f'  {check["check_id"]:<24} {check["total"]:>4}  ({sev})')

    usage = payload['model_usage']
    lines.append(f'model usage: {sum(row["turns"] for row in usage)} turns')
    for row in usage:
        lines.append(
            f'  {row["role"]}/{row["model"]}: {row["turns"]} turns, '
            f'{row["input_tokens"]}/{row["output_tokens"]} tok in/out, '
            f'{row["cache_read_tokens"]} cache-rd, avg {row["avg_latency_ms"]}ms, {row["errors"]} errors'
        )

    tool_calls = payload['tool_calls']
    lines.append(f'tool calls: {tool_calls["total"]}')
    for row in tool_calls['by_tool']:
        lines.append(f'  {row["tool"]:<18} {row["calls"]:>4}  refused {row["refused"]}  errored {row["errored"]}')
    return '\n'.join(lines) + '\n'
