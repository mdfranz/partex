"""``partex report`` — cross-run rollup over the store (#61). No network, models, or credentials."""

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from partex.export import export_run_data
from partex.models import Finding
from partex.report import build_report_payload, gather_report_payload, render_report_text
from partex.storage import LlmUsageRecord, RunRecord, RunStore, ToolCallRecord


def _run(run_id: str, *, state: str = 'checks_complete', created_at: str, requests_spent: int = 0) -> RunRecord:
    return RunRecord(
        id=run_id,
        created_at=created_at,
        state=state,  # pyright: ignore[reportArgumentType]
        input_kind='engagement',
        input_ref='eng',
        input_sha256='sha',
        engine_version='0.1.0',
        selected_checks=('header-security',),
        authorized=True,
        model='m',
        requests_spent=requests_spent,
        scope_snapshot=None,
        error=None,
        summary_error=None,
        findings_count=0,
    )


def _finding(fid: str, check_id: str, severity: str) -> Finding:
    return Finding(
        id=fid,
        check_id=check_id,
        check_version='1.0',
        severity=severity,  # pyright: ignore[reportArgumentType]
        subject=f'test:{fid}',
        title=fid,
        description='d',
        evidence_ids=['ev_1'],
        remediation='fix',
        status='reported',
    )


def _usage(role: str, model: str, *, inp: int, out: int, latency: int, status: str = 'ok') -> LlmUsageRecord:
    return LlmUsageRecord(
        role=role,
        model=model,
        input_tokens=inp,
        output_tokens=out,
        cache_read_tokens=0,
        cache_write_tokens=0,
        latency_ms=latency,
        status=status,
        created_at='2026-01-01T00:00:00+00:00',
    )


def _call(tool: str, result: object) -> ToolCallRecord:
    return ToolCallRecord(call_id='tc', tool=tool, args={}, result=result, created_at='2026-01-01T00:00:00+00:00')


def test_build_report_aggregates_everything() -> None:
    runs = [
        _run('run_a', created_at='2026-11-19T02:00:00+00:00', requests_spent=3),
        _run('run_b', state='checks_failed', created_at='2026-11-19T05:00:00+00:00', requests_spent=7),
    ]
    findings = [
        _finding('f1', 'header-security', 'medium'),
        _finding('f2', 'header-security', 'low'),
        _finding('f3', 'version-disclosure', 'low'),
    ]
    tool_calls = [
        _call('http_request', {'evidence_id': 'ev_1', 'status': 200}),
        _call('http_request', {'refused': 'scope'}),
        _call('run_check', {'error': 'boom'}),
    ]
    usage = [
        _usage('tester', 'glm', inp=100, out=10, latency=1000),
        _usage('tester', 'glm', inp=200, out=20, latency=3000, status='error'),
        _usage('summarizer', 'sonnet', inp=50, out=5, latency=500),
    ]
    payload = build_report_payload(runs, findings, tool_calls, usage)

    assert payload['runs'] == {
        'total': 2,
        'by_state': [{'name': 'checks_complete', 'count': 1}, {'name': 'checks_failed', 'count': 1}],
        'requests_spent': 10,
        'first': '2026-11-19T02:00:00+00:00',
        'last': '2026-11-19T05:00:00+00:00',
    }
    assert payload['findings']['total'] == 3
    assert payload['findings']['by_severity'] == [{'severity': 'medium', 'count': 1}, {'severity': 'low', 'count': 2}]
    # Most findings first; header-security's breakdown is severity-ranked.
    assert payload['findings']['by_check'][0]['check_id'] == 'header-security'
    assert payload['findings']['by_check'][0]['by_severity'] == [
        {'severity': 'medium', 'count': 1},
        {'severity': 'low', 'count': 1},
    ]

    tester = next(m for m in payload['model_usage'] if m['role'] == 'tester')
    assert tester['turns'] == 2
    assert tester['input_tokens'] == 300
    assert tester['output_tokens'] == 30
    assert tester['total_latency_ms'] == 4000
    assert tester['avg_latency_ms'] == 2000
    assert tester['errors'] == 1
    # Busiest role first.
    assert payload['model_usage'][0]['role'] == 'tester'

    assert payload['tool_calls']['total'] == 3
    http = next(t for t in payload['tool_calls']['by_tool'] if t['tool'] == 'http_request')
    assert (http['calls'], http['refused'], http['errored']) == (2, 1, 0)
    rc = next(t for t in payload['tool_calls']['by_tool'] if t['tool'] == 'run_check')
    assert (rc['calls'], rc['refused'], rc['errored']) == (1, 0, 1)


def test_build_report_empty() -> None:
    payload = build_report_payload([], [], [], [])
    assert payload['runs'] == {'total': 0, 'by_state': [], 'requests_spent': 0, 'first': None, 'last': None}
    assert payload['findings'] == {'total': 0, 'by_severity': [], 'by_check': []}
    assert payload['model_usage'] == []
    assert payload['tool_calls'] == {'total': 0, 'by_tool': []}
    # Renders without raising on an empty report.
    assert 'runs: 0' in render_report_text(payload)


def test_render_text_has_sections() -> None:
    payload = build_report_payload(
        [_run('run_a', created_at='2026-11-19T02:00:00+00:00', requests_spent=3)],
        [_finding('f1', 'header-security', 'medium')],
        [_call('http_request', {'status': 200})],
        [_usage('tester', 'glm', inp=100, out=10, latency=1000)],
    )
    text = render_report_text(payload)
    assert 'findings: 1' in text
    assert 'header-security' in text
    assert 'tester/glm' in text
    assert 'http_request' in text


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[RunStore]:
    async with await RunStore.open(tmp_path / 'partex.db') as s:
        yield s


async def test_gather_reads_usage_and_tool_calls_across_runs(store: RunStore) -> None:
    for _ in range(2):
        run_id = await store.create_run(
            input_kind='engagement',
            input_ref='eng',
            input_sha256='sha',
            engine_version='0.1.0',
            selected_checks=['header-security'],
            authorized=True,
        )
        await store.record_llm_usage(run_id, role='tester', model='glm', status='ok', input_tokens=100, output_tokens=5)
        await store.record_tool_call(run_id, 'http_request', {'url': 'x'}, {'status': 200})
        await store.record_tool_call(run_id, 'http_request', {'url': 'y'}, {'refused': 'scope'})

    payload = await gather_report_payload(store)
    assert payload['runs']['total'] == 2
    assert payload['model_usage'][0]['turns'] == 2
    assert payload['model_usage'][0]['input_tokens'] == 200
    http = payload['tool_calls']['by_tool'][0]
    assert (http['tool'], http['calls'], http['refused']) == ('http_request', 4, 2)


async def test_export_includes_llm_usage(store: RunStore) -> None:
    run_id = await store.create_run(
        input_kind='engagement',
        input_ref='eng',
        input_sha256='sha',
        engine_version='0.1.0',
        selected_checks=['header-security'],
        authorized=True,
    )
    await store.record_llm_usage(
        run_id, role='tester', model='glm', status='ok', input_tokens=42, output_tokens=7, latency_ms=99
    )
    payload = await export_run_data(store, run_id)
    assert payload['llm_usage'] == [
        {
            'cache_read_tokens': 0,
            'cache_write_tokens': 0,
            'input_tokens': 42,
            'latency_ms': 99,
            'model': 'glm',
            'output_tokens': 7,
            'role': 'tester',
            'status': 'ok',
        }
    ]
    # created_at is non-deterministic and must not leak into the export.
    assert 'created_at' not in payload['llm_usage'][0]
