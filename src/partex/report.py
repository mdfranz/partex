"""Cross-run reporting rollup over the store — PLAN §7/§8 (``partex report``).

A read-only aggregation of what runs already recorded: findings by severity and check, run-level model
spend from ``runs`` (``model``, ``model_calls``, ``input_tokens``, ``output_tokens``), and the action
tool-call audit from ``tool_calls``. The store stays the only writer, and this never touches the
network or a model.
"""

from collections.abc import Sequence
from typing import Any

from .export import SEVERITY_RANK
from .models import Finding, Severity
from .storage import RunReader, RunRecord, RunStore, ToolCallRecord

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

    spend: dict[str, dict[str, int]] = {}
    for run in runs:
        if run.model_calls <= 0 and run.input_tokens <= 0 and run.output_tokens <= 0:
            continue
        model_label = run.model or 'unknown'
        agg = spend.setdefault(
            model_label,
            {'runs': 0, 'model_calls': 0, 'input_tokens': 0, 'output_tokens': 0},
        )
        agg['runs'] += 1
        agg['model_calls'] += run.model_calls
        agg['input_tokens'] += run.input_tokens
        agg['output_tokens'] += run.output_tokens
    model_usage = [
        {
            'model': model,
            'runs': agg['runs'],
            'model_calls': agg['model_calls'],
            'input_tokens': agg['input_tokens'],
            'output_tokens': agg['output_tokens'],
        }
        for model, agg in sorted(spend.items(), key=lambda kv: (-kv[1]['model_calls'], kv[0]))
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
    """Read every run's findings and tool calls from *store* and build the report."""
    runs = await store.list_runs()
    findings: list[Finding] = []
    tool_calls: list[ToolCallRecord] = []
    for run in runs:
        findings.extend(await store.findings(run.id))
        tool_calls.extend(await store.tool_calls(run.id))
    return build_report_payload(runs, findings, tool_calls)


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
    lines.append(f'model usage: {sum(row["model_calls"] for row in usage)} calls')
    for row in usage:
        lines.append(
            f'  {row["model"]}: {row["model_calls"]} calls ({row["runs"]} runs), '
            f'{row["input_tokens"]}/{row["output_tokens"]} tok in/out'
        )

    tool_calls = payload['tool_calls']
    lines.append(f'tool calls: {tool_calls["total"]}')
    for row in tool_calls['by_tool']:
        lines.append(f'  {row["tool"]:<18} {row["calls"]:>4}  refused {row["refused"]}  errored {row["errored"]}')
    return '\n'.join(lines) + '\n'
