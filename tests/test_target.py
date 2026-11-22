"""Scoped target client — PLAN §4.2 send-time gate (issue #20).

Scope refusals are asserted to put no bytes on the wire via the fixture
server's request log (nothing was received ⇒ nothing was sent).  All tests
run against the localhost fixture server; the suite's non-loopback socket
block stays armed.
"""

import json
from pathlib import Path
from urllib.parse import quote

import httpx2
import logfire
import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from partex.engagement import Engagement
from partex.errors import BudgetExhausted, PartexError, ScopeViolation
from partex.models import HttpEvidence, get_all, get_header, redact
from partex.target import DEFAULT_SOURCE, ScopedHttpClient, TokenBucket
from partex.telemetry import configure_telemetry, resolve_log_path

pytest_plugins = ['plugins.target_server']


def engagement_for(
    target_server: object,
    *,
    hosts: list[str] | None = None,
    ports: list[int] | None = None,
    max_requests: int = 100,
    max_rps: int = 64,
    writes: int = 0,
) -> Engagement:
    server: object = target_server
    port = server.port  # pyright: ignore[reportAttributeAccessIssue]
    base_host = '127.0.0.1'
    return Engagement.model_validate(
        {
            'schema_version': 1,
            'target': {'name': 'fixture-app', 'base_url': f'http://{base_host}:{port}'},
            'scope': {
                'hosts': hosts if hosts is not None else [base_host],
                'path_prefixes': ['/'],
                'exclusions': ['/admin/shutdown'],
                'ports': ports if ports is not None else [port],
                'max_rps': max_rps,
                'max_requests': max_requests,
                **(
                    {'allowed_methods': ['GET', 'HEAD', 'OPTIONS', 'POST'], 'max_write_requests': writes}
                    if writes
                    else {}
                ),
            },
            'authorization': {'attestation': 'fixture authorization', 'operator': 'test'},
        }
    )


# ── Capture: every in-scope request returns and commits evidence ───────────────


async def test_in_scope_request_is_captured(target_server: object) -> None:
    captured: list[HttpEvidence] = []

    async def on_capture(evidence: HttpEvidence) -> None:
        captured.append(evidence)

    engagement = engagement_for(target_server)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement, on_capture=on_capture) as client:
        evidence = await client.request('GET', f'{base_url}/api/users')
    assert evidence.id.startswith('ev_')
    assert evidence.source == DEFAULT_SOURCE
    assert evidence.http.response.status_code == 200
    assert evidence.http.request.method == 'GET'
    assert evidence.http.request.url == f'{base_url}/api/users'
    assert evidence.http.request.url.endswith('/api/users')
    assert captured == [evidence]
    assert client.requests_spent == 1


async def test_post_body_and_headers_sent(target_server: object) -> None:
    engagement = engagement_for(target_server, writes=5)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        evidence = await client.request(
            'POST', f'{base_url}/api/orders', headers={'X-Test': '1'}, body='{"sku": "A-1"}'
        )
    sent = target_server.requests[-1]  # pyright: ignore[reportAttributeAccessIssue]
    assert sent['method'] == 'POST'
    assert sent['body'] == '{"sku": "A-1"}'
    assert evidence.http.request.body == '{"sku": "A-1"}'
    assert get_header(evidence.http.request.headers, 'X-Test') == '1'


async def test_binary_body_refused_not_stored(target_server: object) -> None:
    engagement = engagement_for(target_server)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        evidence = await client.request('GET', f'{base_url}/binary')
    assert evidence.http.response.body is None
    assert get_header(evidence.http.response.headers, 'Content-Type') == 'application/octet-stream'


# ── Scope gate: refused before any bytes hit the wire ─────────────────────────


async def test_out_of_scope_host_refused_before_send(target_server: object) -> None:
    engagement = engagement_for(target_server)
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    before = len(target_server.requests)  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        with pytest.raises(ScopeViolation, match='not in scope hosts'):
            await client.request('GET', f'http://evil-example.test:{port}/api/users')
    assert len(target_server.requests) == before  # pyright: ignore[reportAttributeAccessIssue]
    assert client.requests_spent == 0


async def test_excluded_path_refused_before_send(target_server: object) -> None:
    engagement = engagement_for(target_server)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    before = len(target_server.requests)  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        with pytest.raises(ScopeViolation, match='exclusion'):
            await client.request('GET', f'{base_url}/admin/shutdown')
    assert len(target_server.requests) == before  # pyright: ignore[reportAttributeAccessIssue]


async def test_out_of_scope_port_refused_before_send(target_server: object) -> None:
    engagement = engagement_for(target_server)
    bad_port = target_server.port + 1  # pyright: ignore[reportAttributeAccessIssue]
    before = len(target_server.requests)  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        with pytest.raises(ScopeViolation, match='not in scope ports'):
            await client.request('GET', f'http://127.0.0.1:{bad_port}/api/users')
    assert len(target_server.requests) == before  # pyright: ignore[reportAttributeAccessIssue]


async def test_dot_segment_escape_refused_before_send(target_server: object) -> None:
    engagement = engagement_for(target_server)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    before = len(target_server.requests)  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        with pytest.raises(ScopeViolation):
            await client.request('GET', f'{base_url}/api/../../admin/shutdown')
    assert len(target_server.requests) == before  # pyright: ignore[reportAttributeAccessIssue]


def test_no_bypass_api() -> None:
    """The only send paths are request/follow_redirect — no escape hatch (set_scope only ever extends, #64)."""
    public = {
        name
        for name in dir(ScopedHttpClient)
        if not name.startswith('_') and callable(getattr(ScopedHttpClient, name, None))
    }
    assert public == {'aclose', 'download_asset', 'follow_redirect', 'request', 'set_scope'}


# ── Redirects: captured, never auto-followed, re-validated before follow ───────


async def test_redirect_captured_not_followed_automatically(target_server: object) -> None:
    engagement = engagement_for(target_server)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        evidence = await client.request('GET', f'{base_url}/redirect?to=/api/next')
    assert evidence.http.response.status_code == 302
    assert get_header(evidence.http.response.headers, 'Location') == '/api/next'
    assert len(target_server.requests) == 1  # pyright: ignore[reportAttributeAccessIssue]


async def test_follow_redirect_in_scope(target_server: object) -> None:
    engagement = engagement_for(target_server)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        redirect = await client.request('GET', f'{base_url}/redirect?to=/api/next')
        followed = await client.follow_redirect(redirect)
    assert followed.http.response.status_code == 200
    assert followed.http.request.url == f'{base_url}/api/next'
    assert client.requests_spent == 2


async def test_follow_redirect_out_of_scope_refused(target_server: object) -> None:
    engagement = engagement_for(target_server)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    before = len(target_server.requests)  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        redirect = await client.request('GET', f'{base_url}/redirect?to=http://evil.test/api')
        with pytest.raises(ScopeViolation, match='not in scope hosts'):
            await client.follow_redirect(redirect)
    assert len(target_server.requests) == before + 1  # only the first request was sent


async def test_follow_redirect_to_excluded_path_refused(target_server: object) -> None:
    engagement = engagement_for(target_server)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        redirect = await client.request('GET', f'{base_url}/redirect?to=/admin/shutdown')
        with pytest.raises(ScopeViolation, match='exclusion'):
            await client.follow_redirect(redirect)


async def test_303_converts_to_get(target_server: object) -> None:
    engagement = engagement_for(target_server, writes=5)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        redirect = await client.request('POST', f'{base_url}/redirect?to=/api/next&code=303', body='{"a": 1}')
        followed = await client.follow_redirect(redirect)
    sent = target_server.requests[-1]  # pyright: ignore[reportAttributeAccessIssue]
    assert sent['method'] == 'GET'
    assert sent['body'] == ''
    assert followed.http.request.method == 'GET'
    assert followed.http.request.body is None


# ── Budgets (rule 5) ──────────────────────────────────────────────────────────


async def test_max_requests_budget_exhausted_cleanly(target_server: object) -> None:
    engagement = engagement_for(target_server, max_requests=2)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement) as client:
        await client.request('GET', f'{base_url}/api/one')
        await client.request('GET', f'{base_url}/api/two')
        with pytest.raises(BudgetExhausted, match='max_requests'):
            await client.request('GET', f'{base_url}/api/three')
    assert client.requests_spent == 2
    assert len(target_server.requests) == 2  # pyright: ignore[reportAttributeAccessIssue]


def test_token_bucket_waits_between_requests() -> None:
    """Deterministic bucket math with an injected clock and sleep."""
    now = 0.0
    waits: list[float] = []

    def clock() -> float:
        return now

    async def fake_sleep(seconds: float) -> None:
        nonlocal now
        waits.append(seconds)
        now += seconds  # time advances only when the bucket's sleep is awaited

    bucket = TokenBucket(2.0, clock=clock, sleep=fake_sleep)

    async def scenario() -> None:
        await bucket.acquire()  # immediate (full token)
        await bucket.acquire()  # must wait 0.5s for the refill
        await bucket.acquire()  # and again

    import anyio

    anyio.run(scenario)
    assert waits == [0.5, 0.5]


# ── DNS pinning (rule 2): resolve once, keep Host + SNI + cert identity ───────


async def test_pin_resolves_once_and_preserves_host_header(target_server: object) -> None:
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    engagement = engagement_for(target_server, hosts=['fixture.test'], ports=[port])
    resolutions: list[str] = []

    def resolver(host: str) -> str:
        resolutions.append(host)
        return '127.0.0.1'

    async with ScopedHttpClient(engagement, resolver=resolver) as client:
        first = await client.request('GET', f'http://fixture.test:{port}/api/one')
        second = await client.request('GET', f'http://fixture.test:{port}/api/two')
    assert first.http.response.status_code == 200
    assert second.http.response.status_code == 200
    assert resolutions == ['fixture.test']  # one resolution per run, reused
    for sent in target_server.requests:  # pyright: ignore[reportAttributeAccessIssue]
        assert sent['host_header'] == f'fixture.test:{port}'


async def test_pin_sets_sni_and_connects_to_pinned_address(target_server: object) -> None:
    """The transport rewrites the URL to the pin and marks SNI with the original host."""
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    engagement = engagement_for(target_server, hosts=['fixture.test'], ports=[port])
    seen: list[httpx2.Request] = []

    class RecordingTransport(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
            seen.append(request)
            return httpx2.Response(200, text='stubbed')

    def resolver(host: str) -> str:
        return '127.0.0.1'

    async with ScopedHttpClient(engagement, resolver=resolver, transport=RecordingTransport()) as client:
        await client.request('GET', f'http://fixture.test:{port}/api/x')
    assert client.requests_spent == 1
    request = seen[0]
    assert request.url.host == '127.0.0.1'  # connected to the pin
    assert request.headers['host'] == f'fixture.test:{port}'  # Host preserved
    assert request.extensions['sni_hostname'] == 'fixture.test'  # SNI + cert identity


async def test_pinned_capture_records_hostname_and_follows_relative_redirect(target_server: object) -> None:
    """Evidence keeps the requested hostname, not the pinned IP, so a relative redirect stays in scope."""
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    engagement = engagement_for(target_server, hosts=['fixture.test'], ports=[port])
    async with ScopedHttpClient(engagement, resolver=lambda host: '127.0.0.1') as client:
        redirect = await client.request('GET', f'http://fixture.test:{port}/redirect?to=/api/next')
        followed = await client.follow_redirect(redirect)
    assert redirect.http.request.url == f'http://fixture.test:{port}/redirect?to=/api/next'
    assert followed.http.request.url == f'http://fixture.test:{port}/api/next'
    assert followed.http.response.status_code == 200


async def test_repeated_response_headers_are_preserved(target_server: object) -> None:
    """Each Set-Cookie stays its own pair with its wire casing; nothing is comma-joined."""
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    engagement = engagement_for(target_server, hosts=['fixture.test'], ports=[port])

    class CookieTransport(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, headers=[('Set-Cookie', 'a=1; Secure'), ('Set-Cookie', 'sid=2')], text='ok')

    async with ScopedHttpClient(engagement, resolver=lambda host: '127.0.0.1', transport=CookieTransport()) as client:
        evidence = await client.request('GET', f'http://fixture.test:{port}/api/x')
    assert get_all(evidence.http.response.headers, 'set-cookie') == ['a=1; Secure', 'sid=2']
    assert ('Set-Cookie', 'sid=2') in evidence.http.response.headers


async def test_ip_literal_scope_host_needs_no_resolution(target_server: object) -> None:
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    engagement = engagement_for(target_server, hosts=['127.0.0.1'], ports=[port])

    def resolver(host: str) -> str:
        raise AssertionError('resolver must not be called for IP literals')

    async with ScopedHttpClient(engagement, resolver=resolver) as client:
        evidence = await client.request('GET', f'http://127.0.0.1:{port}/api/x')
    assert evidence.http.response.status_code == 200


# ── Secrets: credential-matched fields are marked and redactable ─────────────


async def test_secret_fields_marked_and_redacted(target_server: object) -> None:
    engagement = engagement_for(target_server, writes=5)
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    async with ScopedHttpClient(engagement, secrets=('sekrit-token',)) as client:
        evidence = await client.request(
            'POST',
            f'{base_url}/api/login',
            headers={'Authorization': 'Bearer sekrit-token'},
            body='password=sekrit-token',
        )
    # Header secrets are addressed by index, so casing on the wire cannot defeat redaction (#39).
    names = [name.lower() for name, _ in evidence.http.request.headers]
    index = names.index('authorization')
    assert evidence.secret_fields == [f'$.http.request.headers[{index}][1]', '$.http.request.body']
    redacted = redact(evidence)
    assert isinstance(redacted, HttpEvidence)
    assert get_header(redacted.http.request.headers, 'authorization') == '<redacted>'
    assert redacted.http.request.body == '<redacted>'
    assert len(redacted.http.request.headers) == len(evidence.http.request.headers)
    # The canonical id excludes secret_fields, so redaction does not change identity.
    assert get_header(evidence.http.request.headers, 'Authorization') == 'Bearer sekrit-token'


# ── #37: capped capture, body notes, target-issued secrets ────────────────────


def _stub_client(
    target_server: object,
    handler: object,
    *,
    source: str = DEFAULT_SOURCE,
    secrets: tuple[str, ...] = (),
    writes: int = 0,
) -> ScopedHttpClient:
    """A client on the fixture engagement whose transport is *handler* (no bytes leave the process)."""
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    engagement = engagement_for(target_server, hosts=['fixture.test'], ports=[port], writes=writes)
    return ScopedHttpClient(
        engagement,
        source=source,
        secrets=secrets,
        resolver=lambda host: '127.0.0.1',
        transport=httpx2.MockTransport(handler),  # pyright: ignore[reportArgumentType]
    )


def _url(target_server: object, path: str = '/api/x') -> str:
    return f'http://fixture.test:{target_server.port}{path}'  # pyright: ignore[reportAttributeAccessIssue]


async def test_target_spans_use_default_local_log_without_sensitive_request_data(
    target_server: object, tmp_path: Path
) -> None:
    run_id = 'run_' + 'a' * 32
    path_secret = 'private@path-marker'
    encoded_secret = quote(path_secret, safe='')
    log_path = resolve_log_path('test', None, {'PARTEX_STATE_DIR': str(tmp_path)})
    assert log_path is not None and log_path.parent == tmp_path / 'logs'
    configure_telemetry(log_path=log_path, remote=False, service_version='test')

    def reply(request: httpx2.Request) -> httpx2.Response:
        assert request.url.host == '127.0.0.1'
        return httpx2.Response(200, headers={'Set-Cookie': 'session=fixture-response-cookie'}, text='fixture-response')

    try:
        client = _stub_client(target_server, reply, source=f'capture:{run_id}:verify', secrets=(path_secret,), writes=5)
        async with client:
            with logfire.span('test caller'):
                evidence = await client.request(
                    'POST',
                    _url(target_server, '/api/orders?key=fixture-query'),
                    headers={'Authorization': 'Bearer fixture-auth'},
                    body='fixture-body',
                )
                artifact = await client.download_asset(
                    _url(target_server, f'/api/{encoded_secret}?other=fixture-download-query'),
                    dest_dir=tmp_path / 'downloads',
                )
        raw_log = log_path.read_text()
    finally:
        logfire.configure(send_to_logfire=False, console=False)

    records = [json.loads(line) for line in raw_log.splitlines()]
    caller = next(record for record in records if record['name'] == 'test caller')
    spans = [record for record in records if record['name'] == 'target request {method} {host}{path}']
    assert len(spans) == 2
    for span, (method, path, evidence_id) in zip(
        spans, [('POST', '/api/orders', evidence.id), ('GET', '[redacted]', artifact.id)], strict=True
    ):
        assert span['parent_span_id'] == caller['span_id']
        attrs = span['attributes']
        assert (attrs['run_id'], attrs['method'], attrs['host'], attrs['path']) == (
            run_id,
            method,
            'fixture.test',
            path,
        )
        assert (attrs['status_code'], attrs['evidence_id']) == (200, evidence_id)

    for secret in (
        path_secret,
        encoded_secret,
        'fixture-query',
        'fixture-download-query',
        'fixture-auth',
        'fixture-body',
        'fixture-response',
    ):
        assert secret not in raw_log


async def test_target_span_omits_exception_details_and_refused_requests(
    target_server: object, in_memory_span_exporter: InMemorySpanExporter
) -> None:
    def fail(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError('fixture-private-error', request=request)

    async with _stub_client(target_server, fail) as client:
        with pytest.raises(ScopeViolation):
            await client.request('GET', _url(target_server, '/admin/shutdown'))
        with pytest.raises(PartexError, match='fixture-private-error'):
            await client.request('GET', _url(target_server, '/api/x?value=fixture-private-query'))

    (span,) = in_memory_span_exporter.get_finished_spans()
    assert span.attributes is not None and span.attributes['request_failed'] is True
    assert span.attributes['path'] == '/api/x'
    assert not span.events
    assert span.status.description is None


async def test_large_body_is_truncated_at_the_cap(target_server: object) -> None:
    from partex.target import MAX_BODY_BYTES

    big = b'a' * (MAX_BODY_BYTES * 4)
    async with _stub_client(target_server, lambda request: httpx2.Response(200, content=big)) as client:
        evidence = await client.request('GET', _url(target_server))
    response = evidence.http.response
    assert response.body is not None and len(response.body) == MAX_BODY_BYTES
    assert response.body_note == 'truncated'


async def test_body_exactly_at_the_cap_is_complete(target_server: object) -> None:
    from partex.target import MAX_BODY_BYTES

    exact = b'b' * MAX_BODY_BYTES
    async with _stub_client(target_server, lambda request: httpx2.Response(200, content=exact)) as client:
        evidence = await client.request('GET', _url(target_server))
    assert evidence.http.response.body_note is None
    assert len(evidence.http.response.body or '') == MAX_BODY_BYTES


async def test_truncation_inside_a_multibyte_character_keeps_the_text(target_server: object) -> None:
    from partex.target import MAX_BODY_BYTES

    body = ('é' * MAX_BODY_BYTES).encode()  # 2 bytes each: the cap lands mid-character half the time
    async with _stub_client(target_server, lambda request: httpx2.Response(200, content=body + b'x')) as client:
        evidence = await client.request('GET', _url(target_server))
    response = evidence.http.response
    assert response.body_note == 'truncated'
    assert response.body is not None and set(response.body) == {'é'}
    assert len(response.body.encode()) <= MAX_BODY_BYTES


async def test_binary_body_is_refused_with_a_note(target_server: object) -> None:
    payload = b'\x00\xff\xfe\x00\x01not-text\x00\xff'
    async with _stub_client(target_server, lambda request: httpx2.Response(200, content=payload)) as client:
        evidence = await client.request('GET', _url(target_server))
    assert (evidence.http.response.body, evidence.http.response.body_note) == (None, 'refused')


async def test_gzip_bomb_is_bounded(target_server: object) -> None:
    import gzip

    from partex.target import MAX_BODY_BYTES

    bomb = gzip.compress(b'0' * (64 * 1024 * 1024))  # 64 MiB of zeros, ~64 KiB on the wire
    handler = lambda request: httpx2.Response(200, content=bomb, headers=[('Content-Encoding', 'gzip')])
    async with _stub_client(target_server, handler) as client:
        evidence = await client.request('GET', _url(target_server))
    assert evidence.http.response.body_note == 'truncated'
    assert len(evidence.http.response.body or '') == MAX_BODY_BYTES


async def test_response_stream_is_closed(target_server: object) -> None:
    closed: list[bool] = []

    class Tracked(httpx2.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[override]
            yield b'x' * 10

        async def aclose(self) -> None:
            closed.append(True)

    async with _stub_client(target_server, lambda request: httpx2.Response(200, stream=Tracked())) as client:
        await client.request('GET', _url(target_server))
    assert closed == [True]


async def test_target_issued_cookies_and_credential_headers_are_secret(target_server: object) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            headers=[
                ('Set-Cookie', 'sid=server-issued-token; Path=/; Secure; HttpOnly'),
                ('Set-Cookie', 'theme=dark'),
                ('Content-Type', 'text/plain'),
            ],
            text='ok',
        )

    async with _stub_client(target_server, handler) as client:  # no engagement secrets configured
        evidence = await client.request(
            'GET',
            _url(target_server),
            headers=[('Authorization', 'Bearer model-typed-token'), ('Cookie', 'sid=old'), ('Accept', '*/*')],
        )
    redacted = redact(evidence)
    assert isinstance(redacted, HttpEvidence)
    dumped = redacted.model_dump_json()
    for secret in ('server-issued-token', 'model-typed-token', 'sid=old'):
        assert secret not in dumped
    # Value-only: cookie names and attributes stay visible to checks and reviewers.
    assert get_all(redacted.http.response.headers, 'set-cookie') == [
        'sid=<redacted>; Path=/; Secure; HttpOnly',
        'theme=<redacted>',
    ]
    assert get_header(redacted.http.request.headers, 'cookie') == 'sid=<redacted>'
    assert get_header(redacted.http.request.headers, 'accept') == '*/*'
    # Storage keeps cleartext for replay (§5): only the export/model boundary redacts.
    assert (
        get_header(evidence.http.response.headers, 'set-cookie') == 'sid=server-issued-token; Path=/; Secure; HttpOnly'
    )


async def test_control_character_text_is_refused(target_server: object) -> None:
    """Valid UTF-8 that is mostly control characters is binary in disguise: refused, not stored."""
    payload = ('\x01\x02\x03\x04' * 50 + 'hi').encode()
    async with _stub_client(target_server, lambda request: httpx2.Response(200, content=payload)) as client:
        evidence = await client.request('GET', _url(target_server))
    assert (evidence.http.response.body, evidence.http.response.body_note) == (None, 'refused')
