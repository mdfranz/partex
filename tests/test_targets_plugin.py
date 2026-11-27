"""Tests for deterministic target discovery rollup and ``TargetsPlugin`` (``/targets``)."""

import hashlib
import inspect
import json
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import pytest
from pydantic import BaseModel

from partex.agent_adapter.scope_plugin import ScopeControl
from partex.agent_adapter.targets_plugin import (
    TARGETS_PLUGIN_FACTORY,
    TARGETS_PLUGIN_ID,
    TargetsControl,
    TargetsPlugin,
    TargetsPluginSettings,
    current_targets,
)
from partex.engine import live_session, probe_url_entries, run_test
from partex.errors import BudgetExhausted, PartexError
from partex.ids import evidence_id, finding_id
from partex.models import (
    ArtifactAsset,
    ArtifactEvidence,
    ConfigEvidence,
    ConfigExcerpt,
    CoverageEntry,
    Evidence,
    Finding,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
    Scope,
)
from partex.storage import RunReader, RunRecord, RunStore, ToolCallRecord
from partex.targets import (
    RunTargetInput,
    build_targets_rollup,
    canonical_origin,
    format_origin,
    format_status_badge,
    gather_all_targets,
    gather_run_targets,
    render_target_detail,
    render_targets_overview,
)


def _http_ev(
    url: str,
    *,
    method: str = 'GET',
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
    body: str | None = 'ok',
    secret_fields: list[str] | None = None,
    tls_verified: bool = True,
) -> HttpEvidence:
    ev = HttpEvidence(
        id='',
        source='capture:test',
        http=HttpExchange(
            request=HttpRequest(method=method, url=url, headers=[]),
            response=HttpResponse(status_code=status, headers=headers or [], body=body),
        ),
        secret_fields=secret_fields or [],
        tls_verified=tls_verified,
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


def _artifact_ev(
    url: str, *, content_type: str = 'application/javascript', tls_verified: bool = True
) -> ArtifactEvidence:
    payload = b'console.log(1);'
    ev = ArtifactEvidence(
        id='',
        source='capture:test',
        artifact=ArtifactAsset(
            url=url,
            status_code=200,
            headers=[('Content-Type', content_type)],
            content_type=content_type,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        ),
        tls_verified=tls_verified,
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


def _config_ev(path: str, *, fmt: str = 'openapi', source: str = 'capture:test') -> ConfigEvidence:
    ev = ConfigEvidence(
        id='',
        source=source,
        config=ConfigExcerpt(path=path, format=fmt, content='{"openapi":"3.0.0"}'),
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


def _finding(
    evidence: Evidence,
    *,
    check_id: str = 'version-disclosure',
    severity: Any = 'medium',
    subject: str = 'header:server',
    title: str = 'Server version disclosed',
    status: Any = 'reported',
) -> Finding:
    return Finding(
        id=finding_id(check_id, subject, title, [evidence.id]),
        check_id=check_id,
        check_version='0.1',
        severity=severity,
        subject=subject,
        title=title,
        description='detail',
        evidence_ids=[evidence.id],
        remediation='fix',
        status=status,
    )


def _run_record(
    run_id: str, *, scope: Scope | None = None, state: Any = 'checks_complete', spent: int = 1
) -> RunRecord:
    return RunRecord(
        id=run_id,
        created_at='2026-11-22T00:00:00+00:00',
        state=state,
        input_kind='engagement',
        input_ref='engagement.json',
        input_sha256='0' * 64,
        engine_version='0.1.0',
        selected_checks=('version-disclosure',),
        authorized=True,
        model=None,
        requests_spent=spent,
        scope_snapshot=scope,
        error=None,
        findings_count=0,
    )


def _text(value: object) -> str:
    """Plain text of a status segment: Pax may return a ``StatusLink`` (``.text`` + ``.url``) instead of a string."""
    return value if isinstance(value, str) else str(getattr(value, 'text', value))


def _engagement(tmp_path: Path, server: Any, *, urls: list[str] | None = None, **scope_extra: Any) -> Path:
    scope_data: dict[str, Any] = {
        'hosts': ['127.0.0.1'],
        'path_prefixes': ['/'],
        'exclusions': ['/admin/shutdown'],
        'ports': sorted({server.port, 9}),
        'max_rps': 64,
        'max_requests': 100,
    }
    if urls is not None:
        scope_data['urls'] = urls
    scope_data.update(scope_extra)
    directory = tmp_path / 'engagement'
    directory.mkdir(exist_ok=True)
    (directory / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'fixture-app', 'base_url': server.base_url + '/'},
                'scope': scope_data,
                'authorization': {'attestation': 'local loopback fixture', 'operator': 'test'},
            }
        ),
        encoding='utf-8',
    )
    return directory


# ── pure rollup & rendering ───────────────────────────────────────────────────


def test_rollup_collapses_origins_groups_states_and_sorts_deterministically() -> None:
    urls = [
        'http://192.168.12.1:80/*',
        'https://192.168.12.2:443/*',
        'http://192.168.12.3:8080/*',
        'http://192.168.12.4:8080/*',
        'http://[::1]:8080/*',
        'https://192.168.12.5:8443/*',
    ]
    scope = Scope(
        hosts=['192.168.12.1', '192.168.12.2', '192.168.12.3', '192.168.12.4', '::1', '192.168.12.5'],
        ports=[80, 443, 8080, 8443],
        urls=urls,
    )

    ev_router_root = _http_ev(
        'http://192.168.12.1/?token=should-hide',
        headers=[('Server', 'lighttpd/1.4.67'), ('Content-Type', 'text/html')],
        body='<html><head><title>Router\n Admin</title></head></html>',
    )
    ev_router_api = _http_ev(
        'http://192.168.12.1:80/api/status?secret=123',
        method='POST',
        status=401,
        headers=[('X-Powered-By', 'PHP/8.2')],
        body='{}',
    )
    ev_router_js = _artifact_ev('http://192.168.12.1/app.js?v=1')
    ev_router_spec = _config_ev('http://192.168.12.1/openapi.json')

    ev_redir = _http_ev(
        'https://192.168.12.2/',
        status=302,
        headers=[('Server', 'nginx/1.24.0'), ('Location', 'https://192.168.12.2:443/login?next=secret_tok#frag')],
        body='',
        tls_verified=False,
    )
    ev_ipv6 = _http_ev('http://[::1]:8080/health', status=200, body='ok')

    f_high = _finding(
        ev_router_api, severity='high', subject='auth', title='Unauthenticated admin endpoint', status='verified'
    )
    f_med = _finding(ev_router_root, severity='medium', subject='header:csp', title='Missing CSP')
    f_redir_low = _finding(ev_redir, severity='low', subject='header:server', title='Server banner exposed')

    gaps = [
        CoverageEntry(
            surface='https://192.168.12.2',
            risk_area='error-page-disclosure',
            outcome='not_applicable',
            source='check_observed',
            reason='redirect-only response',
        )
    ]
    calls = [
        ToolCallRecord(
            call_id='tc_1',
            tool='initial_probe',
            args={'total': 4},
            result={
                'outcomes': {
                    'https://192.168.12.2/': 'ok',
                    'http://192.168.12.3:8080/': 'unreachable',
                    'http://192.168.12.4:8080/': 'unprobed',
                    'http://[::1]:8080/': 'ok',
                }
            },
            created_at='2026-11-22T00:00:01+00:00',
        )
    ]

    rollup = build_targets_rollup(
        [
            RunTargetInput(
                run=_run_record('run_1', scope=scope, spent=5),
                evidence=[ev_router_root, ev_router_api, ev_router_js, ev_router_spec, ev_redir, ev_ipv6],
                findings=[f_med, f_high, f_redir_low],
                coverage=gaps,
                tool_calls=calls,
                is_current=True,
            )
        ],
        scope_label='this run',
    )

    assert [t.origin for t in rollup.targets] == [
        'http://192.168.12.1',
        'https://192.168.12.2',
        'http://[::1]:8080',
        'http://192.168.12.3:8080',
        'http://192.168.12.4:8080',
        'https://192.168.12.5:8443',
    ]
    assert (rollup.up_count, rollup.unreachable_count, rollup.unprobed_count, rollup.total_findings) == (3, 1, 2, 3)

    router = rollup.targets[0]
    assert router.title == 'Router Admin'
    assert router.banners == ('lighttpd/1.4.67', 'PHP/8.2')
    assert [p.path for p in router.paths] == ['/', '/api/status']
    assert router.js_count == 1 and router.openapi_count == 1

    redir = rollup.targets[1]
    assert redir.redirects == ('/login',)
    assert redir.tls_unverified is True
    assert len(redir.coverage_gaps) == 1

    budget_unprobed = rollup.targets[4]
    added_unprobed = rollup.targets[5]
    assert budget_unprobed.state == 'unprobed' and budget_unprobed.state_note == 'request budget'
    assert added_unprobed.state == 'unprobed' and added_unprobed.state_note is None

    overview = render_targets_overview(rollup)
    assert 'Targets in this run (6 total: 3 up, 1 unreachable, 2 unprobed · 3 findings):' in overview
    assert '"Router Admin" · lighttpd/1.4.67, PHP/8.2 · 2 paths · 1 JS · 1 OpenAPI' in overview
    assert '1 high, 1 medium (1 verified) — Unauthenticated admin endpoint, Missing CSP' in overview
    assert '302 → /login' in overview
    assert '(TLS unverified)' in overview
    assert 'http://192.168.12.3:8080  unreachable' in overview
    assert 'http://192.168.12.4:8080  unprobed (request budget)' in overview
    assert 'should-hide' not in overview and 'secret_tok' not in overview and 'frag' not in overview

    filtered = render_targets_overview(rollup, findings_only=True)
    assert '192.168.12.1' in filtered and '192.168.12.2' in filtered
    assert '192.168.12.3' not in filtered and '[::1]' not in filtered


def test_secret_redaction_and_terminal_escape_neutralization() -> None:
    secret_val = 'Bearer top-secret-token-value'
    ev = _http_ev(
        'https://app.example.test/api?key=secret-qs',
        headers=[('Server', 'Evil\x1b[31mServer\x07'), ('Authorization', secret_val), ('Content-Type', 'text/html')],
        body='<title>Bad\x1b]0;pwned\x07Title</title>',
        secret_fields=['$.http.response.headers[1][1]'],
    )
    finding = _finding(ev, subject='hdr:\x1b[2J', title='Leak\x1b[31mTitle')
    rollup = build_targets_rollup(
        [
            RunTargetInput(
                run=_run_record('run_1'),
                evidence=[ev],
                findings=[finding],
                coverage=[],
                tool_calls=[],
            )
        ],
        scope_label='this run',
    )

    overview = render_targets_overview(rollup)
    detail = render_target_detail(rollup, 'app.example.test')
    for text in (overview, detail):
        assert secret_val not in text
        assert 'secret-qs' not in text
        assert '\x1b' not in text and '\x07' not in text
        assert '\\x1b' in text


def test_cross_run_dedup_invalid_filtering_and_detail_matching() -> None:
    ev_a_old = _http_ev('http://multi.test/a', headers=[('Date', 'Sun, 22 Nov 2026 00:00:00 GMT')])
    ev_a_new = _http_ev('http://multi.test/a', headers=[('Date', 'Sun, 22 Nov 2026 01:00:00 GMT')])
    ev_a_8080 = _http_ev('http://multi.test:8080/b')
    ev_b = _http_ev('https://clean.test/')
    ev_old_only = _http_ev('https://legacy.test/')

    # Distinct ev_ IDs produce distinct fn_ IDs across runs for the same (check_id, subject, title).
    f_reported = _finding(ev_a_old, status='reported')
    f_verified = _finding(ev_a_new, status='verified')
    assert f_reported.id != f_verified.id

    rollup = build_targets_rollup(
        [
            RunTargetInput(
                run=_run_record('run_old'),
                evidence=[ev_a_old, ev_old_only],
                findings=[f_reported],
                coverage=[],
                tool_calls=[],
                is_current=False,
            ),
            RunTargetInput(
                run=_run_record('run_cur'),
                evidence=[ev_a_new, ev_a_8080, ev_b],
                findings=[f_verified],
                coverage=[],
                tool_calls=[],
                is_current=True,
            ),
        ],
        scope_label='all runs (2 runs)',
        multi_run=True,
    )

    target_80 = next(t for t in rollup.targets if t.origin == 'http://multi.test')
    assert len(target_80.findings) == 1 and target_80.findings[0].status == 'verified'
    assert target_80.run_ids == ('run_old', 'run_cur')

    overview = render_targets_overview(rollup, show_all_hint=False)
    assert 'http://multi.test  200  1 path [current]' in overview
    assert 'https://legacy.test  200  1 path\n' in overview
    assert '/targets --all' not in overview

    # When every target in a multi-run rollup is current, omit redundant [current] tags.
    all_current = build_targets_rollup(
        [
            RunTargetInput(
                run=_run_record('run_1'),
                evidence=[ev_b],
                findings=[],
                coverage=[],
                tool_calls=[],
                is_current=False,
            ),
            RunTargetInput(
                run=_run_record('run_2'),
                evidence=[ev_b],
                findings=[],
                coverage=[],
                tool_calls=[],
                is_current=True,
            ),
        ],
        scope_label='all runs (2 runs)',
        multi_run=True,
    )
    assert '[current]' not in render_targets_overview(all_current, show_all_hint=False)

    # Bare hostname matches both ports on multi.test; host:port pins one; unknown names known targets.
    both = render_target_detail(rollup, 'multi.test')
    assert 'http://multi.test  [up]' in both and 'http://multi.test:8080  [up]' in both
    pinned = render_target_detail(rollup, 'multi.test:8080')
    assert 'http://multi.test:8080  [up]' in pinned and 'http://multi.test  [up]' not in pinned
    missing = render_target_detail(rollup, 'nope.test')
    assert "No target matching 'nope.test'" in missing and 'https://clean.test' in missing


def test_tls_error_states_boilerplate_titles_and_subpath_redirects() -> None:
    scope = Scope(
        hosts=['ok.test', 'subredir.test', 'rootredir.test', 'bad400.test', 'tls1.test', 'tls2.test', 'slow.test'],
        ports=[80, 443, 8080],
        urls=[
            'http://ok.test/*',
            'http://subredir.test/*',
            'http://rootredir.test/*',
            'http://bad400.test:8080/*',
            'https://tls1.test/*',
            'https://tls2.test/*',
            'http://slow.test/*',
        ],
    )
    ev_ok_200 = _http_ev('http://ok.test/', status=200, headers=[('Content-Type', 'text/html')], body='<html>ok</html>')
    ev_ok_404 = _http_ev(
        'http://ok.test/missing',
        status=404,
        headers=[('Content-Type', 'text/html')],
        body='<html><title>Custom Missing Page</title></html>',
    )
    ev_sub_200 = _http_ev(
        'http://subredir.test/',
        status=200,
        headers=[('Content-Type', 'text/html')],
        body='<html><title>404 Not Found</title></html>',
    )
    ev_sub_301 = _http_ev(
        'http://subredir.test/sub',
        status=301,
        headers=[('Location', 'https://subredir.test/sub')],
        body='<html><title>Not Found</title></html>',
    )
    ev_root_301 = _http_ev(
        'http://rootredir.test/',
        status=301,
        headers=[('Location', 'https://rootredir.test/')],
        body='<html><title>301 Moved Permanently</title></html>',
    )
    ev_bad_400 = _http_ev(
        'http://bad400.test:8080/',
        status=400,
        headers=[('Content-Type', 'text/html')],
        body='<html><title>HTTP Status 400 \u2013 Bad Request</title></html>',
    )
    calls = [
        ToolCallRecord(
            call_id='tc_1',
            tool='initial_probe',
            args={'total': 3},
            result={
                'outcomes': {
                    'https://tls1.test/': 'tls_verify_failed',
                    'https://tls2.test/': 'tls_error',
                    'http://slow.test/': 'timeout',
                }
            },
            created_at='2026-11-22T00:00:01+00:00',
        )
    ]

    rollup = build_targets_rollup(
        [
            RunTargetInput(
                run=_run_record('run_1', scope=scope, spent=4),
                evidence=[ev_ok_200, ev_ok_404, ev_sub_200, ev_sub_301, ev_root_301, ev_bad_400],
                findings=[],
                coverage=[],
                tool_calls=calls,
            )
        ],
        scope_label='this run',
    )

    assert [t.origin for t in rollup.targets] == [
        'http://ok.test',
        'http://subredir.test',
        'http://rootredir.test',
        'http://bad400.test:8080',
        'https://tls1.test',
        'https://tls2.test',
        'http://slow.test',
    ]
    assert rollup.tls_error_count == 2
    assert rollup.unreachable_count == 1

    ok_target, sub_target, root_target, bad_target, tls1, tls2, slow = rollup.targets
    assert ok_target.title is None  # 404 custom title never overrides a 200 target with no title
    assert (
        sub_target.title is None
        and sub_target.root_redirect is None
        and sub_target.redirects == ('https://subredir.test/sub',)
    )
    assert root_target.title is None and root_target.root_redirect == 'https://rootredir.test'
    assert bad_target.title is None
    assert tls1.state == 'tls_error' and tls1.state_note == 'cert verify failed — try -k'
    assert tls2.state == 'tls_error' and tls2.state_note == 'handshake failed'
    assert slow.state == 'unreachable' and slow.state_note == 'timeout'

    overview = render_targets_overview(rollup)
    assert '4 up, 2 tls error, 1 unreachable' in overview
    assert 'Custom Missing Page' not in overview
    assert 'Not Found' not in overview
    assert 'Moved Permanently' not in overview
    assert 'Bad Request' not in overview
    assert 'http://subredir.test  200,301  2 paths' in overview
    assert 'http://rootredir.test  301 → https://rootredir.test  1 path' in overview
    assert 'https://tls1.test  tls error (cert verify failed — try -k)' in overview
    assert 'https://tls2.test  tls error (handshake failed)' in overview
    assert 'http://slow.test  unreachable (timeout)' in overview
    assert 'https://subredir.test/sub' in render_target_detail(rollup, 'subredir.test')
    assert 'https://tls1.test  [tls error — cert verify failed — try -k]' in render_target_detail(rollup, 'tls1.test')


def test_helpers_edge_cases() -> None:
    assert canonical_origin('not-a-url') is None
    assert canonical_origin('http://[::1]:badport/') is None
    assert format_origin('http', '::1', 80) == 'http://[::1]'
    assert format_origin('https', 'example.test', 443) == 'https://example.test'
    assert format_origin('http', 'example.test', 8080) == 'http://example.test:8080'
    assert format_status_badge(0, 0, 0) == ''
    assert format_status_badge(3, 2, 0) == 'targets: 2/3 up'
    assert format_status_badge(3, 2, 1) == 'targets: 2/3 up, 1 finding'
    assert format_status_badge(3, 2, 4) == 'targets: 2/3 up, 4 findings'


# ── engine initial_probe persistence ──────────────────────────────────────────


async def test_probe_url_entries_populates_outcomes() -> None:
    async def request(url: str) -> object:
        if url == 'http://dead.test:9':
            raise PartexError('connection refused')
        if url == 'http://stop.test/':
            raise BudgetExhausted('budget spent')
        return object()

    outcomes: dict[str, str] = {}
    probed, failed, unprobed = await probe_url_entries(
        request,
        entries=[
            'http://base.test/',
            'http://ok.test/',
            'http://dead.test:9/*',
            'http://stop.test/',
            'http://skip.test/',
        ],
        base_url='http://base.test/',
        verbose=False,
        outcomes=outcomes,
    )
    assert (probed, failed, unprobed) == (1, 1, 2)
    assert outcomes == {
        'http://ok.test/': 'ok',
        'http://dead.test:9': 'unreachable',
        'http://stop.test/': 'unprobed',
        'http://skip.test/': 'unprobed',
    }


async def test_probe_url_entries_skips_normalized_baseline_and_classifies_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen_urls: list[str] = []

    async def request(url: str) -> object:
        seen_urls.append(url)
        if url == 'https://cert.test:443':
            try:
                raise ssl.SSLCertVerificationError(1, 'certificate verify failed: self-signed certificate')
            except ssl.SSLCertVerificationError as inner:
                raise PartexError(f'request to {url} failed: {inner}') from inner
        if url == 'https://legacy.test:443':
            try:
                raise ssl.SSLError('[SSL: UNSAFE_LEGACY_RENEGOTIATION_DISABLED] unsafe legacy renegotiation disabled')
            except ssl.SSLError as inner:
                raise PartexError(f'request to {url} failed: {inner}') from inner
        if url == 'http://slow.test:80':
            try:
                raise httpx2.ConnectTimeout('timed out')
            except httpx2.ConnectTimeout as inner:
                raise PartexError(f'request to {url} failed: {inner}') from inner
        if url == 'http://dead.test:9':
            raise PartexError('connection refused')
        return object()

    outcomes: dict[str, str] = {}
    probed, failed, unprobed = await probe_url_entries(
        request,
        entries=[
            'http://base.test:80/*',
            'http://dup.test:80/*',
            'http://dup.test/',
            'https://cert.test:443/*',
            'https://legacy.test:443/*',
            'http://slow.test:80/*',
            'http://dead.test:9/*',
        ],
        base_url='http://base.test/',
        verbose=True,
        outcomes=outcomes,
    )
    assert seen_urls == [
        'http://dup.test:80',
        'https://cert.test:443',
        'https://legacy.test:443',
        'http://slow.test:80',
        'http://dead.test:9',
    ]
    assert (probed, failed, unprobed) == (1, 4, 0)
    assert outcomes == {
        'http://dup.test:80': 'ok',
        'https://cert.test:443': 'tls_verify_failed',
        'https://legacy.test:443': 'tls_error',
        'http://slow.test:80': 'timeout',
        'http://dead.test:9': 'unreachable',
    }
    err = capsys.readouterr().err
    assert 'tls error (cert verify failed — try -k)' in err
    assert 'tls error (handshake failed)' in err
    assert 'unreachable (timeout)' in err
    assert '(2 TLS — try -k)' in err


async def test_run_test_records_initial_probe_and_rollup_skips_invalid_runs(
    tmp_path: Path, target_app: Any, tmp_store: RunStore
) -> None:
    base, port = target_app.base_url, target_app.port
    urls_file = tmp_path / 'urls.txt'
    urls_file.write_text(f'{base}/*\n{base}/alt/*\nhttp://127.0.0.1:9/dead/*\n', encoding='utf-8')
    eng_dir = _engagement(tmp_path, target_app)

    result = await run_test(eng_dir, tmp_store, ['version-disclosure'], authorized=True, urls_file=urls_file)
    assert result.state == 'checks_complete'
    calls = [c for c in await tmp_store.tool_calls(result.run_id) if c.tool == 'initial_probe']
    assert len(calls) == 1
    assert calls[0].result == {'outcomes': {f'{base}/alt': 'ok', 'http://127.0.0.1:9/dead': 'unreachable'}}
    assert base not in calls[0].result['outcomes'] and f'{base}/' not in calls[0].result['outcomes']

    # An invalid run is ignored by gather_all_targets.
    bad_id = await tmp_store.create_run(
        input_kind='engagement',
        input_ref='bad',
        input_sha256='0' * 64,
        engine_version='0.1.0',
        selected_checks=(),
        scope_snapshot=Scope(hosts=['ignored.test'], ports=[80], urls=['http://ignored.test/*']),
    )
    await tmp_store.set_state(bad_id, 'invalid', error='unauthorized')

    rollup = await gather_all_targets(tmp_store, current_run_id=result.run_id)
    origins = {t.origin: t for t in rollup.targets}
    assert f'http://127.0.0.1:{port}' in origins and origins[f'http://127.0.0.1:{port}'].state == 'up'
    assert 'http://127.0.0.1:9' in origins and origins['http://127.0.0.1:9'].state == 'unreachable'
    assert 'http://ignored.test' not in origins


def test_rollup_keeps_distinct_artifact_findings_and_suppresses_query_only_root_redirect() -> None:
    scope = Scope(hosts=['192.168.12.1'], ports=[80], urls=['http://192.168.12.1/*'])
    ev_root_ok = _http_ev('http://192.168.12.1/', status=200)
    ev_root_qs_redir = _http_ev('http://192.168.12.1/?v=0', status=301, headers=[('Location', '/')])
    ev_rest_v1 = _artifact_ev('http://192.168.12.1/rest.js?v=1')
    ev_ui = _artifact_ev('http://192.168.12.1/ui.min.js?v=1')
    ev_rest_v2 = _artifact_ev('http://192.168.12.1/rest.js?v=2')

    f_rest_v1 = _finding(
        ev_rest_v1,
        check_id='js:endpoints',
        subject='http://192.168.12.1',
        title='JavaScript endpoints discovered',
        status='reported',
    )
    f_ui = _finding(
        ev_ui,
        check_id='js:endpoints',
        subject='http://192.168.12.1',
        title='JavaScript endpoints discovered',
        status='reported',
    )
    f_rest_v2 = _finding(
        ev_rest_v2,
        check_id='js:endpoints',
        subject='http://192.168.12.1',
        title='JavaScript endpoints discovered',
        status='verified',
    )

    single = build_targets_rollup(
        [
            RunTargetInput(
                run=_run_record('run_1', scope=scope),
                evidence=[ev_root_ok, ev_root_qs_redir, ev_rest_v1, ev_ui],
                findings=[f_rest_v1, f_ui],
                coverage=[],
                tool_calls=[],
                is_current=True,
            )
        ],
        scope_label='this run',
    )
    assert single.total_findings == 2
    target = single.targets[0]
    assert target.root_redirect is None
    assert target.redirects == ('/',)
    assert '→ /' not in render_targets_overview(single)
    assert '/' in render_target_detail(single, '192.168.12.1')

    multi = build_targets_rollup(
        [
            RunTargetInput(
                run=_run_record('run_1', scope=scope),
                evidence=[ev_root_ok, ev_rest_v1, ev_ui],
                findings=[f_rest_v1, f_ui],
                coverage=[],
                tool_calls=[],
            ),
            RunTargetInput(
                run=_run_record('run_2', scope=scope),
                evidence=[ev_root_ok, ev_rest_v2],
                findings=[f_rest_v2],
                coverage=[],
                tool_calls=[],
            ),
        ],
        scope_label='all runs (2 runs)',
        multi_run=True,
    )
    assert multi.total_findings == 2
    assert sorted(f.status for f in multi.targets[0].findings) == ['reported', 'verified']


async def test_gather_all_targets_skips_empty_checks_failed_runs(tmp_store: RunStore) -> None:
    scope = Scope(hosts=['192.168.12.1'], ports=[80], urls=['http://192.168.12.1/*'])
    ok_id = await tmp_store.create_run(
        input_kind='engagement',
        input_ref='ok',
        input_sha256='0' * 64,
        engine_version='0.1.0',
        selected_checks=('version-disclosure',),
        scope_snapshot=scope,
    )
    await tmp_store.set_state(ok_id, 'checks_complete')

    failed_id = await tmp_store.create_run(
        input_kind='engagement',
        input_ref='failed',
        input_sha256='1' * 64,
        engine_version='0.1.0',
        selected_checks=('version-disclosure',),
        scope_snapshot=scope,
    )
    await tmp_store.set_state(failed_id, 'checks_failed', error='boom')

    rollup = await gather_all_targets(tmp_store)
    assert rollup.scope_label == 'all runs (1 run)'
    assert rollup.targets[0].run_ids == (ok_id,)


# ── TargetsPlugin & TargetsControl modes ──────────────────────────────────────


async def _invoke(command: Any, args: list[str]) -> str:
    result = command.handler(args)
    if inspect.isawaitable(result):
        return str(await result)
    return str(result)


@dataclass
class _FakeHost:
    console: Any = None

    def settings(self, model: type[BaseModel], **kwargs: Any) -> BaseModel:
        return model()


async def test_live_session_targets_control_updates_on_probe_check_and_scope_import(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    base, port = target_app.base_url, target_app.port
    eng = _engagement(tmp_path, target_app, urls=[f'{base}/*', 'http://127.0.0.1:9/dead/*'])

    async with live_session(eng, tmp_store, authorized=True, checks=()) as session:
        control = TargetsControl.for_session(session)
        token = current_targets.set(control)
        try:
            plugin = TargetsPlugin.from_host(_FakeHost())  # pyright: ignore[reportArgumentType]
            assert plugin.get_capabilities() == ()
            (cmd,) = plugin.get_commands()
            (seg,) = plugin.get_status_segments()
            assert cmd.name == 'targets'
            assert _text(seg()) == 'targets: 1/2 up'

            initial = await _invoke(cmd, [])
            assert f'http://127.0.0.1:{port}' in initial
            assert 'http://127.0.0.1:9  unreachable' in initial
            assert '127.0.0.1' in cmd.complete(['']) and '--findings' in cmd.complete([''])

            # Perform a check and stage/confirm an nmap scan mid-session.
            await session.run_check('version-disclosure')
            assert 'finding' in _text(seg())

            scan = tmp_path / 'scan.xml'
            scan.write_text(
                '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
                '<address addr="10.0.0.99" addrtype="ipv4"/>'
                '<ports><port protocol="tcp" portid="8080"><state state="open"/>'
                '<service name="http"/></port></ports></host></nmaprun>',
                encoding='utf-8',
            )
            scope_ctrl = ScopeControl(session)
            await scope_ctrl.handle(['nmap', str(scan)])
            await scope_ctrl.handle(['confirm'])
            assert _text(seg()).startswith('targets: 1/3 up')

            updated = await control.handle([])
            assert 'http://10.0.0.99:8080  unprobed' in updated
            detail = await control.handle([f'127.0.0.1:{port}'])
            assert f'http://127.0.0.1:{port}  [up]' in detail and 'findings (' in detail
            assert 'Usage: /targets' in await control.handle(['--help'])
            assert 'Usage: /targets' in await control.handle(['--bogus'])
            assert 'Usage: /targets' in await control.handle(['a', 'b'])
        finally:
            current_targets.reset(token)


async def test_chat_reader_targets_control_is_read_only(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    base, port = target_app.base_url, target_app.port
    async with live_session(
        _engagement(tmp_path, target_app, urls=[f'{base}/*']),
        tmp_store,
        authorized=True,
        checks=('version-disclosure',),
    ) as session:
        run_id = session.run_id
    before_calls = await tmp_store.tool_calls(run_id)
    await tmp_store.aclose()

    async with await RunReader.open(tmp_store.path) as reader:
        control = await TargetsControl.for_reader(reader, run_id)
        token = current_targets.set(control)
        try:
            plugin = TargetsPlugin.from_host(_FakeHost())  # pyright: ignore[reportArgumentType]
            assert plugin.get_capabilities() == ()
            (seg,) = plugin.get_status_segments()
            assert _text(seg()).startswith('targets: 1/1 up, ')
            overview = await _invoke(plugin.get_commands()[0], [])
            all_runs = await _invoke(plugin.get_commands()[0], ['--all'])
            assert f'http://127.0.0.1:{port}' in overview and f'http://127.0.0.1:{port}' in all_runs
            assert await gather_run_targets(reader, run_id)
        finally:
            current_targets.reset(token)

    async with await RunReader.open(tmp_store.path) as reader:
        assert await reader.tool_calls(run_id) == before_calls


async def test_standalone_targets_plugin_reads_configured_or_env_db(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with live_session(
        _engagement(tmp_path, target_app), tmp_store, authorized=True, checks=('version-disclosure',)
    ):
        pass
    db_path = tmp_store.path
    await tmp_store.aclose()

    assert current_targets.get() is None
    plugin = TargetsPlugin(_FakeHost(), TargetsPluginSettings(db=str(db_path)))  # pyright: ignore[reportArgumentType]
    assert plugin.get_capabilities() == ()
    assert plugin.get_status_segments() == ()
    (cmd,) = plugin.get_commands()
    output = await _invoke(cmd, [])
    assert f'http://127.0.0.1:{target_app.port}' in output
    assert '/targets --all' not in output  # standalone already aggregates all runs

    # PARTEX_DB fallback and missing DB handling.
    monkeypatch.setenv('PARTEX_DB', str(db_path))
    env_plugin = TargetsPlugin.from_host(_FakeHost())  # pyright: ignore[reportArgumentType]
    assert f'http://127.0.0.1:{target_app.port}' in await _invoke(env_plugin.get_commands()[0], [])

    missing_plugin = TargetsPlugin(
        _FakeHost(),  # pyright: ignore[reportArgumentType]
        TargetsPluginSettings(db=str(tmp_path / 'missing.db')),
    )
    assert 'Could not read' in await _invoke(missing_plugin.get_commands()[0], [])


def test_plugin_constants_match_class() -> None:
    assert TARGETS_PLUGIN_ID == 'partex_targets'
    assert TARGETS_PLUGIN_FACTORY == 'partex.agent_adapter.targets_plugin:TargetsPlugin'
