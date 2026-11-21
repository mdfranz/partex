"""Tests for canonical JSON run export with default redaction — PLAN §7, §12."""

import json
import warnings
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import anyio
import pytest
from inline_snapshot import snapshot

from partex.export import IncludeSecretsWarning, export_run_data, export_run_json, write_run_export
from partex.ids import evidence_id, finding_id, verification_id
from partex.models import (
    ConfigEvidence,
    ConfigExcerpt,
    CoverageEntry,
    Evidence,
    Finding,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
    ReviewSummary,
    Scope,
    Severity,
    Verification,
)
from partex.storage import RunReader, RunStore, StoreError

SECRET_AUTH = 'Bearer top-secret-jwt-token'
SECRET_COOKIE = 'session=super-secret-cookie-val'
SECRET_SET_COOKIE = 'sid=fresh-secret-cookie; HttpOnly; Secure'
SECRET_CONFIG = 'db_password=hunter2\napi_key=sk-test-12345'


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[RunStore]:
    async with await RunStore.open(tmp_path / 'partex.db') as s:
        yield s


def _make_http_evidence(
    path: str,
    *,
    headers: list[tuple[str, str]] | None = None,
    response_headers: list[tuple[str, str]] | None = None,
    secret_fields: list[str] | None = None,
    source: str = 'capture:0',
) -> HttpEvidence:
    item = HttpEvidence(
        id='',
        source=source,
        http=HttpExchange(
            request=HttpRequest(
                method='GET',
                url=f'https://app.example.test{path}',
                headers=headers or [],
            ),
            response=HttpResponse(
                status_code=200,
                headers=response_headers or [('Content-Type', 'text/html')],
                body=f'<p>{path}</p>',
            ),
        ),
        secret_fields=secret_fields or [],
    )
    return item.model_copy(update={'id': evidence_id(item)})


def _make_config_evidence(
    path: str = 'secrets.ini',
    *,
    content: str = SECRET_CONFIG,
    secret_fields: list[str] | None = None,
    revision: str | None = 'rev1',
) -> ConfigEvidence:
    item = ConfigEvidence(
        id='',
        source=f'bundle/{path}',
        config=ConfigExcerpt(path=path, format='config', content=content, revision=revision),
        secret_fields=secret_fields or [],
    )
    return item.model_copy(update={'id': evidence_id(item)})


def _make_finding(
    check_id: str,
    severity: Severity,
    title: str,
    evidence: list[Evidence],
    *,
    status: str = 'reported',
    verification_id_val: str | None = None,
) -> Finding:
    ev_ids = [item.id for item in evidence]
    return Finding.model_validate(
        {
            'id': finding_id(check_id, f'test:{title}', title, ev_ids),
            'check_id': check_id,
            'check_version': '1.0.0',
            'severity': severity,
            'subject': f'test:{title}',
            'title': title,
            'description': f'Detail for {title}',
            'evidence_ids': ev_ids,
            'remediation': f'Fix {title}',
            'status': status,
            'verification_id': verification_id_val,
        }
    )


def _make_verification(finding: Finding, requests: list[Evidence], *, verdict: str = 'confirmed') -> Verification:
    req_ids = [item.id for item in requests]
    return Verification.model_validate(
        {
            'id': verification_id(finding.id, req_ids),
            'finding_id': finding.id,
            'check_id': finding.check_id,
            'requests': req_ids,
            'verdict': verdict,
            'replayable': True,
            'detail': 'Reproduced deterministically',
            'counterevidence': 'None observed',
        }
    )


async def _seed_full_run(store: RunStore) -> tuple[str, str]:
    """Create a complete run containing evidence with secrets, findings, verification, coverage, tool call, summary."""
    ev_http = _make_http_evidence(
        '/admin',
        headers=[('Authorization', SECRET_AUTH), ('Cookie', SECRET_COOKIE)],
        response_headers=[('Content-Type', 'text/html'), ('Set-Cookie', SECRET_SET_COOKIE)],
        secret_fields=[
            '$.http.request.headers[0][1]',
            '$.http.request.headers[1][1]',
            '$.http.response.headers[1][1]',
        ],
        source='bundle/evidence/0001.json',
    )
    ev_cfg = _make_config_evidence(
        'config.ini',
        content=SECRET_CONFIG,
        secret_fields=['$.config.content'],
    )
    f_low = _make_finding('version-disclosure', 'low', 'Banner disclosed', [ev_cfg])
    f_high = _make_finding('header-security', 'high', 'Missing HSTS', [ev_http])
    verif = _make_verification(f_high, [ev_http])

    run_id = await store.create_run(
        input_kind='bundle',
        input_ref='fixtures/bundles/valid',
        input_sha256='abc123def456',
        engine_version='0.1.0',
        selected_checks=['header-security', 'version-disclosure'],
        authorized=False,
        model=None,
    )
    await store.commit_passive(run_id, [ev_http, ev_cfg], [f_low, f_high])
    await store.record_verification(run_id, verif)
    await store.upsert_coverage(
        run_id,
        [
            CoverageEntry(
                surface='GET /admin',
                risk_area='transport-security',
                outcome='reported',
                source='check_observed',
                evidence_ids=[ev_http.id],
                reason='HSTS missing',
                goal_attempts=1,
            ),
        ],
    )
    call_id = await store.record_tool_call(
        run_id,
        'lookup_evidence',
        {'evidence_id': ev_http.id},
        {'status': 'ok'},
    )
    await store.save_summary(
        run_id,
        ReviewSummary(
            narrative='Confirmed missing HSTS (high) and reported banner disclosure (low).',
            finding_ids=[f_high.id, f_low.id],
        ),
        model='test-model',
    )
    return run_id, call_id


async def test_export_redacted_snapshot(store: RunStore) -> None:
    run_id, call_id = await _seed_full_run(store)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        raw = await export_run_json(store, run_id)

    assert caught == []
    exported = raw.decode('utf-8')
    assert '<redacted>' in exported
    for secret_fragment in (SECRET_AUTH, SECRET_COOKIE, SECRET_SET_COOKIE, 'hunter2', 'sk-test-12345'):
        assert secret_fragment not in exported
    assert run_id not in exported
    assert call_id not in exported
    assert 'created_at' not in exported
    assert exported == snapshot(
        '{"coverage":[{"evidence_ids":["ev_55250b92b421f7c8"],"goal_attempts":1,"outcome":"reported","reason":"HSTS missing","risk_area":"transport-security","source":"check_observed","surface":"GET /admin"}],"evidence":[{"http":{"request":{"body":null,"headers":[["Authorization","<redacted>"],["Cookie","session=<redacted>"]],"method":"GET","url":"https://app.example.test/admin"},"response":{"body":"<p>/admin</p>","headers":[["Content-Type","text/html"],["Set-Cookie","sid=<redacted>; HttpOnly; Secure"]],"status_code":200}},"id":"ev_55250b92b421f7c8","kind":"http_exchange","secret_fields":["$.http.request.headers[0][1]","$.http.request.headers[1][1]","$.http.response.headers[1][1]"],"source":"bundle/evidence/0001.json"},{"config":{"content":"<redacted>","format":"config","path":"config.ini","revision":"rev1"},"id":"ev_7d9d00d79ffc0227","kind":"config_excerpt","secret_fields":["$.config.content"],"source":"bundle/config.ini"}],"findings":[{"check_id":"header-security","check_version":"1.0.0","description":"Detail for Missing HSTS","evidence_ids":["ev_55250b92b421f7c8"],"id":"fn_dfdbda97e91b6119","remediation":"Fix Missing HSTS","severity":"high","status":"verified","subject":"test:Missing HSTS","title":"Missing HSTS","verification_id":"vf_fa50835f7bdd12a0"},{"check_id":"version-disclosure","check_version":"1.0.0","description":"Detail for Banner disclosed","evidence_ids":["ev_7d9d00d79ffc0227"],"id":"fn_21efcc7c32c90e9d","remediation":"Fix Banner disclosed","severity":"low","status":"reported","subject":"test:Banner disclosed","title":"Banner disclosed","verification_id":null}],"llm_usage":[],"run":{"authorized":false,"engine_version":"0.1.0","error":null,"findings_count":2,"input_kind":"bundle","input_ref":"fixtures/bundles/valid","input_sha256":"abc123def456","model":null,"requests_spent":0,"scope_snapshot":null,"selected_checks":["header-security","version-disclosure"],"state":"complete","summary_error":null},"summary":{"finding_ids":["fn_dfdbda97e91b6119","fn_21efcc7c32c90e9d"],"narrative":"Confirmed missing HSTS (high) and reported banner disclosure (low)."},"tool_calls":[{"args":{"evidence_id":"ev_55250b92b421f7c8"},"result":{"status":"ok"},"tool":"lookup_evidence"}],"verifications":[{"check_id":"header-security","counterevidence":"None observed","detail":"Reproduced deterministically","finding_id":"fn_dfdbda97e91b6119","id":"vf_fa50835f7bdd12a0","replayable":true,"requests":["ev_55250b92b421f7c8"],"verdict":"confirmed"}],"web_research":[]}'
    )


async def test_export_include_secrets_snapshot(store: RunStore) -> None:
    run_id, call_id = await _seed_full_run(store)

    with pytest.warns(IncludeSecretsWarning, match='include_secrets=True') as caught:
        raw = await export_run_json(store, run_id, include_secrets=True)

    assert len(caught) == 1
    exported = raw.decode('utf-8')
    assert '<redacted>' not in exported
    for secret_fragment in (SECRET_AUTH, SECRET_COOKIE, SECRET_SET_COOKIE, 'hunter2', 'sk-test-12345'):
        assert secret_fragment in exported
    assert json.loads(exported)['evidence'][1]['config']['content'] == SECRET_CONFIG
    assert run_id not in exported
    assert call_id not in exported
    assert 'created_at' not in exported
    assert exported == snapshot(
        '{"coverage":[{"evidence_ids":["ev_55250b92b421f7c8"],"goal_attempts":1,"outcome":"reported","reason":"HSTS missing","risk_area":"transport-security","source":"check_observed","surface":"GET /admin"}],"evidence":[{"http":{"request":{"body":null,"headers":[["Authorization","Bearer top-secret-jwt-token"],["Cookie","session=super-secret-cookie-val"]],"method":"GET","url":"https://app.example.test/admin"},"response":{"body":"<p>/admin</p>","headers":[["Content-Type","text/html"],["Set-Cookie","sid=fresh-secret-cookie; HttpOnly; Secure"]],"status_code":200}},"id":"ev_55250b92b421f7c8","kind":"http_exchange","secret_fields":["$.http.request.headers[0][1]","$.http.request.headers[1][1]","$.http.response.headers[1][1]"],"source":"bundle/evidence/0001.json"},{"config":{"content":"db_password=hunter2\\napi_key=sk-test-12345","format":"config","path":"config.ini","revision":"rev1"},"id":"ev_7d9d00d79ffc0227","kind":"config_excerpt","secret_fields":["$.config.content"],"source":"bundle/config.ini"}],"findings":[{"check_id":"header-security","check_version":"1.0.0","description":"Detail for Missing HSTS","evidence_ids":["ev_55250b92b421f7c8"],"id":"fn_dfdbda97e91b6119","remediation":"Fix Missing HSTS","severity":"high","status":"verified","subject":"test:Missing HSTS","title":"Missing HSTS","verification_id":"vf_fa50835f7bdd12a0"},{"check_id":"version-disclosure","check_version":"1.0.0","description":"Detail for Banner disclosed","evidence_ids":["ev_7d9d00d79ffc0227"],"id":"fn_21efcc7c32c90e9d","remediation":"Fix Banner disclosed","severity":"low","status":"reported","subject":"test:Banner disclosed","title":"Banner disclosed","verification_id":null}],"llm_usage":[],"run":{"authorized":false,"engine_version":"0.1.0","error":null,"findings_count":2,"input_kind":"bundle","input_ref":"fixtures/bundles/valid","input_sha256":"abc123def456","model":null,"requests_spent":0,"scope_snapshot":null,"selected_checks":["header-security","version-disclosure"],"state":"complete","summary_error":null},"summary":{"finding_ids":["fn_dfdbda97e91b6119","fn_21efcc7c32c90e9d"],"narrative":"Confirmed missing HSTS (high) and reported banner disclosure (low)."},"tool_calls":[{"args":{"evidence_id":"ev_55250b92b421f7c8"},"result":{"status":"ok"},"tool":"lookup_evidence"}],"verifications":[{"check_id":"header-security","counterevidence":"None observed","detail":"Reproduced deterministically","finding_id":"fn_dfdbda97e91b6119","id":"vf_fa50835f7bdd12a0","replayable":true,"requests":["ev_55250b92b421f7c8"],"verdict":"confirmed"}],"web_research":[]}'
    )


async def test_export_summary_is_null_when_absent(store: RunStore) -> None:
    ev = _make_http_evidence('/health')
    f = _make_finding('header-security', 'medium', 'Missing CSP', [ev])
    run_id = await store.create_run(
        input_kind='bundle',
        input_ref='bundle',
        input_sha256='00' * 32,
        engine_version='0.1.0',
        selected_checks=['header-security'],
    )
    await store.commit_passive(run_id, [ev], [f])

    raw = await export_run_json(store, run_id)
    assert b'"summary":null' in raw
    parsed = json.loads(raw)
    assert parsed['summary'] is None


async def test_passive_exports_byte_identical_across_fresh_stores(tmp_path: Path) -> None:
    ev1 = _make_http_evidence(
        '/one', headers=[('Authorization', 'Bearer s1')], secret_fields=['$.http.request.headers[0][1]']
    )
    ev2 = _make_http_evidence('/two')
    f_high = _make_finding('header-security', 'high', 'Missing HSTS', [ev1])
    f_low = _make_finding('header-security', 'low', 'Weak cookie', [ev2])

    db_a = tmp_path / 'a.db'
    db_b = tmp_path / 'b.db'

    async with await RunStore.open(db_a) as store_a:
        run_a = await store_a.create_run(
            input_kind='bundle',
            input_ref='bundle',
            input_sha256='sha_same',
            engine_version='0.1.0',
            selected_checks=['header-security'],
        )
        await store_a.commit_passive(run_a, [ev1, ev2], [f_high, f_low])
        call_a = await store_a.record_tool_call(run_a, 'list_findings', {}, {'count': 2})
        bytes_a = await export_run_json(store_a, run_a)

    # Slight delay guarantees a distinct created_at timestamp alongside distinct UUID run_id / call_id.
    await anyio.sleep(0.01)

    async with await RunStore.open(db_b) as store_b:
        run_b = await store_b.create_run(
            input_kind='bundle',
            input_ref='bundle',
            input_sha256='sha_same',
            engine_version='0.1.0',
            selected_checks=['header-security'],
        )
        # Commit findings in reverse order to verify export sorting normalizes order.
        await store_b.commit_passive(run_b, [ev1, ev2], [f_low, f_high])
        call_b = await store_b.record_tool_call(run_b, 'list_findings', {}, {'count': 2})

    assert run_a != run_b
    assert call_a != call_b

    async with await RunReader.open(db_b) as reader_b:
        bytes_b = await export_run_json(reader_b, run_b)

    assert bytes_a == bytes_b
    text = bytes_a.decode('utf-8')
    for excluded in (run_a, run_b, call_a, call_b, 'created_at'):
        assert excluded not in text


async def test_findings_ordered_by_severity_desc_check_id_finding_id(store: RunStore) -> None:
    ev = _make_http_evidence('/order')
    run_id = await store.create_run(
        input_kind='bundle',
        input_ref='bundle',
        input_sha256='sha',
        engine_version='0.1.0',
        selected_checks=['alpha-check', 'beta-check'],
    )

    f_info = _make_finding('alpha-check', 'info', 'Info note', [ev])
    f_low = _make_finding('alpha-check', 'low', 'Low note', [ev])
    f_med_beta = _make_finding('beta-check', 'medium', 'Medium beta', [ev])
    f_med_alpha_a = _make_finding('alpha-check', 'medium', 'Medium alpha 1', [ev])
    f_med_alpha_b = _make_finding('alpha-check', 'medium', 'Medium alpha 2', [ev])
    f_high = _make_finding('beta-check', 'high', 'High alert', [ev])
    f_crit = _make_finding('beta-check', 'critical', 'Critical issue', [ev])

    # Tie-break within same (severity, check_id) must sort by finding_id ascending.
    pair_sorted = sorted([f_med_alpha_a, f_med_alpha_b], key=lambda f: f.id)

    # Insert deliberately scrambled relative to the expected export order.
    scrambled = [f_info, f_med_beta, pair_sorted[1], f_low, f_crit, pair_sorted[0], f_high]
    await store.commit_passive(run_id, [ev], scrambled)

    payload = await export_run_data(store, run_id)
    got_ids = [item['id'] for item in payload['findings']]
    expected_ids = [
        f_crit.id,
        f_high.id,
        pair_sorted[0].id,
        pair_sorted[1].id,
        f_med_beta.id,
        f_low.id,
        f_info.id,
    ]
    assert got_ids == expected_ids


async def test_evidence_preserves_registration_order(store: RunStore) -> None:
    candidates = [_make_http_evidence(f'/ep-{i}') for i in range(6)]
    by_id = sorted(candidates, key=lambda item: item.id)
    # Construct a registration order guaranteed to differ from alphabetical ID order.
    registered = [by_id[-1], by_id[0], by_id[2]]
    reg_ids = [item.id for item in registered]
    assert reg_ids != sorted(reg_ids)

    run_id = await store.create_run(
        input_kind='bundle',
        input_ref='bundle',
        input_sha256='sha',
        engine_version='0.1.0',
        selected_checks=['header-security'],
    )
    await store.commit_passive(run_id, registered, [])

    payload = await export_run_data(store, run_id)
    assert [item['id'] for item in payload['evidence']] == reg_ids


async def test_export_with_scope_snapshot_and_verifications_ordering(store: RunStore) -> None:
    ev_a = _make_http_evidence('/a')
    ev_b = _make_http_evidence('/b')
    f1 = _make_finding('header-security', 'high', 'Finding One', [ev_a])
    f2 = _make_finding('header-security', 'medium', 'Finding Two', [ev_b])
    v1 = _make_verification(f1, [ev_a], verdict='confirmed')
    v2 = _make_verification(f2, [ev_b], verdict='not_reproduced')

    scope = Scope(
        hosts=['app.example.test'],
        path_prefixes=['/'],
        exclusions=['/logout'],
        ports=[443],
        max_rps=5,
        max_requests=100,
    )
    run_id = await store.create_run(
        input_kind='engagement',
        input_ref='engagements/app',
        input_sha256='engsha',
        engine_version='0.1.0',
        selected_checks=['header-security'],
        authorized=True,
        model='openai:test',
        scope_snapshot=scope,
    )
    await store.commit_passive(run_id, [ev_a, ev_b], [f1, f2])
    expected_v_order = sorted([v1, v2], key=lambda v: (v.finding_id, v.id))
    # Record verifications in reverse of expected export order.
    await store.record_verification(run_id, expected_v_order[1])
    await store.record_verification(run_id, expected_v_order[0])

    payload: dict[str, Any] = await export_run_data(store, run_id)
    assert payload['run']['authorized'] is True
    assert payload['run']['model'] == 'openai:test'
    assert payload['run']['scope_snapshot'] == scope.model_dump(mode='json')
    assert [v['id'] for v in payload['verifications']] == [v.id for v in expected_v_order]


async def test_write_run_export_appends_single_newline(store: RunStore, tmp_path: Path) -> None:
    ev = _make_http_evidence('/caf\u00e9')
    f = _make_finding('header-security', 'low', 'Caf\u00e9 header gap', [ev])
    run_id = await store.create_run(
        input_kind='bundle',
        input_ref='bundle',
        input_sha256='sha',
        engine_version='0.1.0',
        selected_checks=['header-security'],
    )
    await store.commit_passive(run_id, [ev], [f])

    out_file = tmp_path / 'nested' / 'dir' / 'export.json'
    written = await write_run_export(store, run_id, out_file)
    canonical = await export_run_json(store, run_id)

    assert out_file.read_bytes() == written
    assert written == canonical + b'\n'
    assert not canonical.endswith(b'\n')
    assert not canonical.endswith(b' ')
    assert b'\\u00e9' in canonical  # ensure_ascii=True


async def test_export_unknown_run_raises_store_error(store: RunStore) -> None:
    with pytest.raises(StoreError) as exc_info:
        await export_run_json(store, 'run_does_not_exist')
    assert exc_info.value.rule_code == 'run-not-found'


async def test_redacted_export_does_not_mutate_stored_secrets(store: RunStore) -> None:
    ev = _make_http_evidence(
        '/secret',
        headers=[('Authorization', SECRET_AUTH)],
        secret_fields=['$.http.request.headers[0][1]'],
    )
    run_id = await store.create_run(
        input_kind='bundle',
        input_ref='bundle',
        input_sha256='sha',
        engine_version='0.1.0',
        selected_checks=['header-security'],
    )
    await store.commit_passive(run_id, [ev], [])

    redacted_payload = await export_run_data(store, run_id, include_secrets=False)
    assert redacted_payload['evidence'][0]['http']['request']['headers'] == [['Authorization', '<redacted>']]

    with pytest.warns(IncludeSecretsWarning):
        unredacted_payload = await export_run_data(store, run_id, include_secrets=True)
    assert unredacted_payload['evidence'][0]['http']['request']['headers'] == [['Authorization', SECRET_AUTH]]
