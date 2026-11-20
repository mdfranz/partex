"""Tests for full-body JS download, discovery, and tree-sitter js-analysis check/skill (issue #69)."""

import hashlib
import json
import stat
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, DeltaToolCall, DeltaToolCalls, FunctionModel

from partex.agent_adapter import TesterDeps, build_tester_agent
from partex.checks.js_analysis import (
    analyze_js_bytes,
    discover_js_urls,
    extract_js_surface,
    js_analysis_check,
)
from partex.engagement import Engagement
from partex.engine import live_session
from partex.errors import PartexError, ScopeViolation
from partex.export import export_run_data
from partex.ids import evidence_id, finding_id
from partex.models import (
    ArtifactAsset,
    ArtifactEvidence,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
    redact,
)
from partex.registry import build_registry
from partex.storage import RunStore, artifact_dir
from partex.target import MAX_BODY_BYTES, ScopedHttpClient

pytest_plugins = ['plugins.target_server']

FIXTURE_JS = Path(__file__).parent.parent / 'fixtures' / 'js' / 'sample.js'


def _engagement(port: int, *, max_requests: int = 50) -> Engagement:
    return Engagement.model_validate(
        {
            'schema_version': 1,
            'target': {'name': 'js-app', 'base_url': f'http://127.0.0.1:{port}'},
            'scope': {
                'hosts': ['127.0.0.1'],
                'path_prefixes': ['/'],
                'exclusions': ['/admin/shutdown'],
                'ports': [port],
                'max_rps': 64,
                'max_requests': max_requests,
            },
            'authorization': {'attestation': 'fixture', 'operator': 'test'},
        }
    )


def _stub_client(
    target_server: Any,
    handler: Any,
    *,
    max_requests: int = 50,
    on_artifact: Any = None,
) -> ScopedHttpClient:
    return ScopedHttpClient(
        _engagement(target_server.port, max_requests=max_requests),
        transport=httpx2.MockTransport(handler),
        on_artifact=on_artifact,
    )


# ── Full-body download (target.py) ────────────────────────────────────────────


async def test_download_asset_stores_over_256kb_with_0600_and_deterministic_id(
    target_server: Any, tmp_path: Path
) -> None:
    payload = b'const x = "/api/v1/items";\n' * 15_000  # > 375 KB (> MAX_BODY_BYTES 256 KB)
    assert len(payload) > MAX_BODY_BYTES
    captured: list[ArtifactEvidence] = []

    async def on_artifact(ev: ArtifactEvidence) -> None:
        captured.append(ev)

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            content=payload,
            headers=[
                ('Content-Type', 'application/javascript'),
                ('Set-Cookie', 'sid=secret-cookie-val; HttpOnly'),
            ],
        )

    dest = tmp_path / 'artifacts'
    async with _stub_client(target_server, handler, on_artifact=on_artifact) as client:
        ev = await client.download_asset(f'http://127.0.0.1:{target_server.port}/static/main.js', dest_dir=dest)

    assert captured == [ev]
    assert client.requests_spent == 1
    assert ev.id.startswith('ev_')
    assert ev.artifact.size_bytes == len(payload)
    assert ev.file_path is not None
    stored = Path(ev.file_path)
    assert stored.is_file() and stored.read_bytes() == payload
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600

    # Evidence ID is machine-independent (ignores file_path and source).
    other = ev.model_copy(update={'file_path': '/elsewhere/other', 'source': 'other'})
    assert evidence_id(other) == ev.id

    # Set-Cookie on artifact is redacted value-only.
    redacted = redact(ev)
    assert isinstance(redacted, ArtifactEvidence)
    assert 'secret-cookie-val' not in redacted.model_dump_json()


async def test_download_asset_refuses_out_of_scope_excluded_and_over_ceiling(
    target_server: Any, tmp_path: Path
) -> None:
    dest = tmp_path / 'artifacts'
    port = target_server.port

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == '/huge.js':
            return httpx2.Response(200, content=b'a' * 2048)
        if request.url.path == '/missing.js':
            return httpx2.Response(404, text='not found')
        return httpx2.Response(200, content=b'ok')

    async with _stub_client(target_server, handler) as client:
        with pytest.raises(ScopeViolation):
            await client.download_asset(f'http://evil.example.test:{port}/app.js', dest_dir=dest)
        with pytest.raises(ScopeViolation):
            await client.download_asset(f'http://127.0.0.1:{port}/admin/shutdown', dest_dir=dest)
        with pytest.raises(PartexError, match='exceeds max_bytes'):
            await client.download_asset(f'http://127.0.0.1:{port}/huge.js', dest_dir=dest, max_bytes=1024)
        with pytest.raises(PartexError, match='HTTP 404'):
            await client.download_asset(f'http://127.0.0.1:{port}/missing.js', dest_dir=dest)

    # No artifact files (not even temp files) remain on disk.
    leftover = [p for p in dest.rglob('*') if p.is_file()] if dest.exists() else []
    assert leftover == []


# ── Tree-sitter js-analysis check ─────────────────────────────────────────────


def _stored_artifact(
    tmp_path: Path, data: bytes, url: str = 'https://app.example.test/static/sample.js'
) -> ArtifactEvidence:
    """An artifact stored the way ``download_asset`` stores it: ``<db>.artifacts/<sha256>``."""
    digest = hashlib.sha256(data).hexdigest()
    directory = tmp_path / 'run.db.artifacts'
    directory.mkdir(exist_ok=True)
    (directory / digest).write_bytes(data)
    artifact = ArtifactEvidence(
        id='',
        source='capture:test',
        artifact=ArtifactAsset(
            url=url,
            status_code=200,
            headers=[('Content-Type', 'application/javascript')],
            content_type='application/javascript',
            sha256=digest,
            size_bytes=len(data),
        ),
        file_path=str(directory / digest),
    )
    return artifact.model_copy(update={'id': evidence_id(artifact)})


def test_js_analysis_fixture_deterministic_and_redacted(tmp_path: Path) -> None:
    artifact = _stored_artifact(tmp_path, FIXTURE_JS.read_bytes())

    assert js_analysis_check.applies_to([artifact]) is True
    drafts = list(js_analysis_check.review([artifact]))
    subjects = {d.subject for d in drafts}
    assert 'js:endpoints' in subjects
    assert 'js:secret:apiKey' in subjects
    assert 'js:version-disclosure' in subjects
    assert 'js:sourcemap' in subjects
    assert 'js:sink:innerHTML' in subjects
    # Placeholder secret must not trigger a finding.
    assert 'js:secret:placeholderKey' not in subjects

    # Secret value must never appear in any finding draft.
    for d in drafts:
        assert 'sk-fixture-secret-value-9876543210' not in d.title
        assert 'sk-fixture-secret-value-9876543210' not in d.description
        assert 'sk-fixture-secret-value-9876543210' not in d.remediation

    # ID-stable across repeated runs.
    drafts_again = list(js_analysis_check.review([artifact]))
    ids_1 = [finding_id(d.check_id, d.subject, d.title, d.evidence_ids) for d in drafts]
    ids_2 = [finding_id(d.check_id, d.subject, d.title, d.evidence_ids) for d in drafts_again]
    assert ids_1 == ids_2

    # Surface rows extracted deterministically.
    surface = extract_js_surface([artifact])
    assert surface == [{'kind': 'endpoint', 'key': '/api/v1/users', 'evidence_ids': [artifact.id]}]


def test_js_analysis_truncated_and_unparseable_and_missing_file(tmp_path: Path) -> None:
    truncated_http = HttpEvidence(
        id='ev_trunc',
        source='capture:1',
        http=HttpExchange(
            request=HttpRequest(method='GET', url='https://app.example.test/app.js', headers=[]),
            response=HttpResponse(
                status_code=200,
                headers=[('Content-Type', 'application/javascript')],
                body='const a = fetch("/api/v1/ping"); const broken = ',
                body_note='truncated',
            ),
        ),
    )
    missing_artifact = ArtifactEvidence(
        id='ev_missing',
        source='capture:2',
        artifact=ArtifactAsset(
            url='https://app.example.test/gone.js',
            status_code=200,
            headers=[],
            content_type='application/javascript',
            sha256='0' * 64,
            size_bytes=10,
        ),
        file_path=str(tmp_path / 'does-not-exist.js'),
    )

    drafts = list(js_analysis_check.review([truncated_http, missing_artifact]))
    parse_drafts = [d for d in drafts if d.subject == 'js:parse-status']
    assert len(parse_drafts) == 2
    assert any('partial' in d.title.lower() for d in parse_drafts)
    assert any('unreadable' in d.title.lower() for d in parse_drafts)
    # Error-tolerant tree-sitter still extracts the endpoint before the syntax error!
    assert any(d.subject == 'js:endpoints' for d in drafts)


def test_js_analysis_does_not_execute_js(tmp_path: Path) -> None:
    marker = tmp_path / 'pwned'
    js = f'require("fs").writeFileSync({str(marker)!r}, "1"); eval("1+1");'.encode()
    res = analyze_js_bytes(js)
    assert not marker.exists()
    assert ('eval', 1) in res.sinks


def test_discover_js_urls_partitions_by_scope_without_fetching() -> None:
    html_ev = HttpEvidence(
        id='ev_html',
        source='capture:1',
        http=HttpExchange(
            request=HttpRequest(method='GET', url='http://127.0.0.1:8000/', headers=[]),
            response=HttpResponse(
                status_code=200,
                headers=[('Content-Type', 'text/html')],
                body=(
                    '<html><script src="/static/app.js"></script>'
                    '<script src="https://cdn.evil.test/lib.js"></script></html>'
                ),
            ),
        ),
    )
    js_ev = HttpEvidence(
        id='ev_js',
        source='capture:2',
        http=HttpExchange(
            request=HttpRequest(method='GET', url='http://127.0.0.1:8000/static/app.js', headers=[]),
            response=HttpResponse(
                status_code=200,
                headers=[('Content-Type', 'application/javascript')],
                body='import "./chunk-1.js";\n//# sourceMappingURL=app.js.map\n',
            ),
        ),
    )
    scope = _engagement(8000).scope
    disc = discover_js_urls([html_ev, js_ev], scope=scope)
    assert disc.in_scope == (
        'http://127.0.0.1:8000/static/app.js',
        'http://127.0.0.1:8000/static/chunk-1.js',
        'http://127.0.0.1:8000/static/app.js.map',
    )
    assert disc.out_of_scope == ('https://cdn.evil.test/lib.js',)


# ── Skill lint & registry join ────────────────────────────────────────────────


def test_js_analysis_skill_and_check_registered() -> None:
    reg = build_registry()
    assert reg.errors == ()
    assert 'js-analysis' in reg.checks
    assert reg.skills_for('js-analysis') == ['js-analysis']


# ── Live agent download_asset + discover_js_assets + run_check ────────────────


def _scripted(calls: list[tuple[str, dict[str, Any]]]) -> FunctionModel:
    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        index = sum(isinstance(part, ToolReturnPart) for m in messages for part in m.parts)
        if index < len(calls):
            name, args = calls[index]
            return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=f'call_{index}')])
        return ModelResponse(parts=[TextPart('done')])

    async def stream(messages: list[ModelMessage], info: AgentInfo) -> AsyncIterator[str | DeltaToolCalls]:
        # Code Mode (#83) makes the tester agent stream its model requests.
        for part in respond(messages, info).parts:
            if isinstance(part, TextPart):
                yield part.content
            elif isinstance(part, ToolCallPart):
                yield {
                    0: DeltaToolCall(
                        name=part.tool_name, json_args=part.args_as_json_str(), tool_call_id=part.tool_call_id
                    )
                }

    return FunctionModel(respond, stream_function=stream)


def _tool_returns(messages: list[ModelMessage]) -> list[ToolReturnPart]:
    return [p for m in messages if isinstance(m, ModelRequest) for p in m.parts if isinstance(p, ToolReturnPart)]


async def test_agent_download_asset_and_js_analysis_e2e(tmp_store: RunStore, tmp_path: Path) -> None:
    import http.server
    import threading

    js_payload = FIXTURE_JS.read_bytes() + b'\n' + (b'// pad\n' * 40_000)  # > 256 KB
    html_payload = b'<html><script src="/bundle.js"></script><script src="https://cdn.other.test/x.js"></script></html>'

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body, ctype = (
                (js_payload, 'application/javascript') if self.path == '/bundle.js' else (html_payload, 'text/html')
            )
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    eng_dir = tmp_path / 'engagement'
    eng_dir.mkdir()
    (eng_dir / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'js-app', 'base_url': f'http://127.0.0.1:{port}/'},
                'scope': {
                    'hosts': ['127.0.0.1'],
                    'path_prefixes': ['/'],
                    'ports': [port],
                    'max_rps': 64,
                    'max_requests': 50,
                },
                'authorization': {'attestation': 'local loopback fixture', 'operator': 'test'},
            }
        )
    )

    try:
        async with live_session(eng_dir, tmp_store, authorized=True, checks=()) as session:
            agent: Agent[TesterDeps, str] = build_tester_agent('test')
            deps = TesterDeps(run_id=session.run_id, reader=tmp_store, session=session, store=tmp_store)
            result = await agent.run(
                'analyze js',
                deps=deps,
                model=_scripted(
                    [
                        ('discover_js_assets', {}),
                        ('download_asset', {'path': '/bundle.js'}),
                        ('run_check', {'check_id': 'js-analysis'}),
                        ('list_evidence', {}),
                    ]
                ),
            )
            returns = _tool_returns(result.all_messages())
            assert 'http://127.0.0.1' in str(returns[0].content)
            assert 'https://cdn.other.test/x.js' in str(returns[0].content)
            # download_asset returns metadata, never the raw JS body or secret.
            dl_text = str(returns[1].content)
            assert 'ev_' in dl_text and str(len(js_payload)) in dl_text
            assert 'sk-fixture-secret-value-9876543210' not in dl_text
            assert 'app.js.map' not in dl_text

            # run_check produced findings, none containing the secret.
            check_text = str(returns[2].content)
            assert 'fn_' in check_text
            assert 'sk-fixture-secret-value-9876543210' not in check_text

            # Stored artifact file exists beside the DB with mode 0600.
            artifacts = list(artifact_dir(tmp_store.path).iterdir())
            assert len(artifacts) == 1
            assert stat.S_IMODE(artifacts[0].stat().st_mode) == 0o600

            # Export payload also never leaks the secret.
            exported = await export_run_data(tmp_store, session.run_id)
            assert 'sk-fixture-secret-value-9876543210' not in json.dumps(exported)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# ── review fixes (PR #75) ─────────────────────────────────────────────────────


def test_repeated_sinks_and_secrets_are_aggregated_not_duplicated(tmp_path: Path) -> None:
    js = (
        'el.innerHTML = a;\n' + 'x.postMessage(1);\n' * 1500 + 'el.innerHTML = b;\n'
        'const a = {apiKey: "sk-live-abcdef123456"}; const b = {apiKey: "sk-live-zzzzzz654321"};\n'
    ).encode()
    drafts = list(js_analysis_check.review([_stored_artifact(tmp_path, js)]))
    ids = [finding_id(d.check_id, d.subject, d.title, d.evidence_ids) for d in drafts]
    assert len(ids) == len(set(ids)) and len(drafts) < 20  # no duplicate IDs, nowhere near the draft cap
    inner = next(d for d in drafts if d.subject == 'js:sink:innerHTML')
    assert '2 time(s)' in inner.description and 'line 1' in inner.description
    post = next(d for d in drafts if d.subject == 'js:sink:postMessage')
    assert '1500 time(s)' in post.description and 'more' in post.description
    assert sum(d.subject == 'js:secret:apiKey' for d in drafts) == 1


def test_endpoints_never_carry_query_strings_or_userinfo() -> None:
    js = (
        b"fetch('/api/v1/export?api_key=sk_live_SECRETVALUE123'); axios.get('https://user:pw@api.test/v1/x#frag');"
        b"var x = new XMLHttpRequest(); x.open('GET', '/api/v1/y?token=abc12345');"
    )
    endpoints = analyze_js_bytes(js).endpoints
    assert endpoints == ('/api/v1/export', '/api/v1/y', 'https://api.test/v1/x')
    assert not any(ch in e for e in endpoints for ch in '?#@')


def test_window_open_is_not_an_endpoint() -> None:
    assert analyze_js_bytes(b"window.open('/help', '_blank');").endpoints == ()  # neither arg is an endpoint


def test_artifact_must_be_the_content_addressed_file(tmp_path: Path) -> None:
    good = _stored_artifact(tmp_path, b"fetch('/api/v1/ok');")
    assert any(d.subject == 'js:endpoints' for d in js_analysis_check.review([good]))

    secret_file = tmp_path / 'credentials.js'  # an unrelated local file named like JS
    secret_file.write_text("fetch('/api/v1/leak');")
    forged = good.model_copy(update={'file_path': str(secret_file)})
    drafts = list(js_analysis_check.review([forged]))
    assert [d.subject for d in drafts] == ['js:parse-status'] and 'unreadable' in drafts[0].title

    tampered_dir = tmp_path / 'other.db.artifacts'
    tampered_dir.mkdir()
    (tampered_dir / good.artifact.sha256).write_text("fetch('/api/v1/tampered');")  # right name, wrong content
    tampered = good.model_copy(update={'file_path': str(tampered_dir / good.artifact.sha256)})
    assert [d.subject for d in js_analysis_check.review([tampered])] == ['js:parse-status']


def test_ui_strings_and_loose_version_matches_are_not_findings(tmp_path: Path) -> None:
    js = (
        b"const t = {passwordLabel: 'Enter your password', tokenType: 'Bearer', secretHint: 'Pick a strong one',"
        b" releaseTag: 'preview1', version: 'beta-channel', appVersion: '2.4.1', apiKey: 'sk-real-0123456789abcdef'};"
    )
    result = analyze_js_bytes(js)
    assert {key for key, _ in result.secrets} == {'apiKey', 'token-literal'}  # the sk- literal also matches by shape
    assert [(key, value) for key, value, _ in result.versions] == [('appVersion', '2.4.1')]


def test_html_error_page_with_a_js_url_is_not_analyzed() -> None:
    page = HttpEvidence(
        id='ev_404',
        source='capture:1',
        http=HttpExchange(
            request=HttpRequest(method='GET', url='https://app.example.test/missing.js', headers=[]),
            response=HttpResponse(
                status_code=404, headers=[('Content-Type', 'text/html')], body='<html>Not found</html>'
            ),
        ),
    )
    ok_but_html = page.model_copy(
        update={
            'http': page.http.model_copy(
                update={'response': page.http.response.model_copy(update={'status_code': 200})}
            )
        }
    )
    assert js_analysis_check.applies_to([page]) is False and js_analysis_check.applies_to([ok_but_html]) is False


async def test_failed_download_still_spends_a_persisted_request(target_server: Any, tmp_path: Path) -> None:
    spent: list[int] = []

    async def failed_send() -> None:
        spent.append(1)

    def handler(request: httpx2.Request) -> httpx2.Response:
        return (
            httpx2.Response(404, text='nope')
            if request.url.path == '/m.js'
            else httpx2.Response(200, content=b'a' * 4096)
        )

    client = ScopedHttpClient(
        _engagement(target_server.port), transport=httpx2.MockTransport(handler), on_failed_send=failed_send
    )
    async with client:
        port = target_server.port
        with pytest.raises(PartexError, match='HTTP 404'):
            await client.download_asset(f'http://127.0.0.1:{port}/m.js', dest_dir=tmp_path / 'a')
        with pytest.raises(PartexError, match='exceeds max_bytes'):
            await client.download_asset(f'http://127.0.0.1:{port}/big.js', dest_dir=tmp_path / 'a', max_bytes=1024)
        with pytest.raises(ScopeViolation):  # refused before any send: nothing spent
            await client.download_asset(f'http://evil.example.test:{port}/x.js', dest_dir=tmp_path / 'a')
    assert spent == [1, 1] and client.requests_spent == 2
