"""``partex report`` — cross-run rollup over the store (#61, #245). No network, models, or credentials."""

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from partex.export import export_run_data
from partex.models import Finding
from partex.report import build_report_payload, gather_report_payload, render_report_text
from partex.storage import RunRecord, RunStore, ToolCallRecord


def _run(
    run_id: str,
    *,
    state: str = 'checks_complete',
    created_at: str,
    requests_spent: int = 0,
    model: str | None = 'm',
    model_calls: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> RunRecord:
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
        model=model,
        model_calls=model_calls,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        requests_spent=requests_spent,
        scope_snapshot=None,
        error=None,
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


def _call(tool: str, result: object) -> ToolCallRecord:
    return ToolCallRecord(call_id='tc', tool=tool, args={}, result=result, created_at='2026-01-01T00:00:00+00:00')


def test_build_report_aggregates_everything() -> None:
    runs = [
        _run(
            'run_a',
            created_at='2026-11-19T02:00:00+00:00',
            requests_spent=3,
            model='glm',
            model_calls=2,
            input_tokens=300,
            output_tokens=30,
        ),
        _run(
            'run_b',
            state='checks_failed',
            created_at='2026-11-19T05:00:00+00:00',
            requests_spent=7,
            model='sonnet',
            model_calls=1,
            input_tokens=50,
            output_tokens=5,
        ),
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
    payload = build_report_payload(runs, findings, tool_calls)

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

    glm = next(m for m in payload['model_usage'] if m['model'] == 'glm')
    assert glm['runs'] == 1
    assert glm['model_calls'] == 2
    assert glm['input_tokens'] == 300
    assert glm['output_tokens'] == 30
    # Busiest model first.
    assert payload['model_usage'][0]['model'] == 'glm'

    assert payload['tool_calls']['total'] == 3
    http = next(t for t in payload['tool_calls']['by_tool'] if t['tool'] == 'http_request')
    assert (http['calls'], http['refused'], http['errored']) == (2, 1, 0)
    rc = next(t for t in payload['tool_calls']['by_tool'] if t['tool'] == 'run_check')
    assert (rc['calls'], rc['refused'], rc['errored']) == (1, 0, 1)


def test_build_report_empty() -> None:
    payload = build_report_payload([], [], [])
    assert payload['runs'] == {'total': 0, 'by_state': [], 'requests_spent': 0, 'first': None, 'last': None}
    assert payload['findings'] == {'total': 0, 'by_severity': [], 'by_check': []}
    assert payload['model_usage'] == []
    assert payload['tool_calls'] == {'total': 0, 'by_tool': []}
    # Renders without raising on an empty report.
    assert 'runs: 0' in render_report_text(payload)


def test_render_text_has_sections() -> None:
    payload = build_report_payload(
        [
            _run(
                'run_a',
                created_at='2026-11-19T02:00:00+00:00',
                requests_spent=3,
                model='glm',
                model_calls=1,
                input_tokens=100,
                output_tokens=10,
            )
        ],
        [_finding('f1', 'header-security', 'medium')],
        [_call('http_request', {'status': 200})],
    )
    text = render_report_text(payload)
    assert 'findings: 1' in text
    assert 'header-security' in text
    assert 'glm: 1 calls' in text
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
        await store.record_model_usage(run_id, model='glm', input_tokens=100, output_tokens=5)
        await store.record_tool_call(run_id, 'http_request', {'url': 'x'}, {'status': 200})
        await store.record_tool_call(run_id, 'http_request', {'url': 'y'}, {'refused': 'scope'})

    payload = await gather_report_payload(store)
    assert payload['runs']['total'] == 2
    assert payload['model_usage'][0]['model_calls'] == 2
    assert payload['model_usage'][0]['input_tokens'] == 200
    http = payload['tool_calls']['by_tool'][0]
    assert (http['tool'], http['calls'], http['refused']) == ('http_request', 4, 2)


async def test_export_includes_run_model_usage_totals(store: RunStore) -> None:
    run_id = await store.create_run(
        input_kind='engagement',
        input_ref='eng',
        input_sha256='sha',
        engine_version='0.1.0',
        selected_checks=['header-security'],
        authorized=True,
    )
    await store.record_model_usage(run_id, model='glm', input_tokens=42, output_tokens=7)
    payload = await export_run_data(store, run_id)
    assert payload['run']['model'] == 'glm'
    assert payload['run']['model_calls'] == 1
    assert payload['run']['input_tokens'] == 42
    assert payload['run']['output_tokens'] == 7
    assert 'llm_usage' not in payload
    assert 'summary' not in payload
