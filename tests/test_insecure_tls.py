"""Opt-in acceptance of invalid TLS certificates (issue #71): strict by default, per-host, recorded, never the model's."""

import http.server
import json
import shutil
import ssl
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from partex import engine
from partex.agent_adapter import build_tester_agent
from partex.engagement import validate_engagement
from partex.errors import PartexError, ValidationFailed
from partex.ids import evidence_id
from partex.models import Engagement, HttpEvidence, Scope
from partex.storage import RunStore
from partex.target import ScopedHttpClient
from partex.verify import _engagement_from_snapshot  # pyright: ignore[reportPrivateUsage]

pytest_plugins = ['plugins.target_server']

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='openssl is needed to mint a test certificate')


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'TlsFixture/1.0'
    sys_version = ''

    def do_GET(self) -> None:
        self.server.requests.append(self.path)  # pyright: ignore[reportAttributeAccessIssue]
        body = b'ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


class _TlsServer(http.server.ThreadingHTTPServer):
    requests: list[str]


@pytest.fixture
def self_signed_server(tmp_path: Path) -> Iterator[_TlsServer]:
    """A loopback HTTPS server whose certificate is self-signed and names another host (so it never verifies)."""
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert)]
        + ['-days', '2', '-subj', '/CN=not-this-host.invalid'],
        check=True,
        capture_output=True,
    )
    server = _TlsServer(('127.0.0.1', 0), _Handler)
    server.requests = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _engagement(port: int, *, hosts: list[str] | None = None, **tls: Any) -> Engagement:
    data: dict[str, Any] = {
        'schema_version': 1,
        'target': {'name': 'tls-app', 'base_url': f'https://127.0.0.1:{port}/'},
        'scope': {
            'hosts': hosts or ['127.0.0.1'],
            'path_prefixes': ['/'],
            'exclusions': [],
            'ports': [port],
            'max_rps': 64,
            'max_requests': 50,
        },
        'authorization': {'attestation': 'loopback fixture', 'operator': 'test'},
    }
    if tls:
        data['tls'] = tls
    return validate_engagement(data)


def _write(tmp_path: Path, engagement: Engagement) -> Path:
    directory = tmp_path / 'engagement'
    directory.mkdir()
    (directory / 'engagement.json').write_text(json.dumps(engagement.model_dump(mode='json')))
    return directory


# ── the client ────────────────────────────────────────────────────────────────


async def test_invalid_certificates_are_refused_by_default(self_signed_server: _TlsServer) -> None:
    async with ScopedHttpClient(_engagement(self_signed_server.server_port)) as client:
        with pytest.raises(PartexError, match='failed'):
            await client.request('GET', f'https://127.0.0.1:{self_signed_server.server_port}/')
    assert self_signed_server.requests == []  # the handshake failed before any HTTP request


async def test_verify_false_accepts_the_certificate_and_flags_the_evidence(self_signed_server: _TlsServer) -> None:
    port = self_signed_server.server_port
    async with ScopedHttpClient(_engagement(port, verify=False)) as client:
        evidence = await client.request('GET', f'https://127.0.0.1:{port}/')
    assert evidence.http.response.status_code == 200 and evidence.tls_verified is False
    assert self_signed_server.requests == ['/']
    # The flag is not part of the evidence ID: the same exchange hashes the same either way.
    assert evidence_id(evidence.model_copy(update={'tls_verified': True})) == evidence.id
    # Exports show the flag only when it is False, so strict runs and old bundles are unchanged.
    assert evidence.model_dump(mode='json')['tls_verified'] is False
    assert 'tls_verified' not in evidence.model_copy(update={'tls_verified': True}).model_dump(mode='json')


async def test_insecure_hosts_relax_only_the_listed_host(self_signed_server: _TlsServer) -> None:
    port = self_signed_server.server_port
    engagement = _engagement(port, hosts=['127.0.0.1', 'localhost'], verify=False, insecure_hosts=['localhost'])
    async with ScopedHttpClient(engagement, resolver=lambda host: '127.0.0.1') as client:
        evidence = await client.request('GET', f'https://localhost:{port}/')
        assert evidence.tls_verified is False
        with pytest.raises(PartexError, match='failed'):  # 127.0.0.1 is in scope but not listed: still strict
            await client.request('GET', f'https://127.0.0.1:{port}/')


async def test_plain_http_is_never_marked_unverified(target_server: Any) -> None:
    engagement = _engagement(target_server.port, verify=False).model_copy(
        update={
            'target': _engagement(target_server.port).target.model_copy(update={'base_url': target_server.base_url})
        }
    )
    async with ScopedHttpClient(engagement) as client:
        evidence = await client.request('GET', f'{target_server.base_url}/')
    assert evidence.tls_verified is True


# ── engagement validation ─────────────────────────────────────────────────────


def test_insecure_hosts_need_verify_false_and_must_be_in_scope() -> None:
    with pytest.raises(ValidationFailed, match='verify'):
        _engagement(8443, insecure_hosts=['127.0.0.1'])
    with pytest.raises(ValidationFailed, match='scope.hosts') as excinfo:
        _engagement(8443, verify=False, insecure_hosts=['elsewhere.test'])
    assert excinfo.value.rule_code == 'tls-invalid'
    assert _engagement(8443).tls.verify is True  # the default stays strict


# ── runs: --insecure, audit and warning ───────────────────────────────────────


async def test_run_test_insecure_is_recorded_warned_and_strict_otherwise(
    self_signed_server: _TlsServer,
    tmp_path: Path,
    tmp_store: RunStore,
    capsys: pytest.CaptureFixture[str],
) -> None:
    port = self_signed_server.server_port
    path = _write(tmp_path, _engagement(port))  # engagement file says nothing about TLS

    with pytest.raises(PartexError, match='not trusted'):  # strict: the baseline capture cannot complete the handshake
        await engine.run_test(path, tmp_store, ['version-disclosure'], authorized=True)
    (strict_run,) = await tmp_store.list_runs()
    assert not [c for c in await tmp_store.tool_calls(strict_run.id) if c.tool == 'tls_verify_disabled']

    capsys.readouterr()
    relaxed = await engine.run_test(path, tmp_store, ['version-disclosure'], authorized=True, insecure=True)
    assert relaxed.state == 'checks_complete'
    assert 'TLS certificate verification is DISABLED for 127.0.0.1' in capsys.readouterr().err
    (audit,) = [c for c in await tmp_store.tool_calls(relaxed.run_id) if c.tool == 'tls_verify_disabled']
    assert audit.args == {'hosts': ['127.0.0.1'], 'all_in_scope_hosts': True}
    captured = await tmp_store.evidence(relaxed.run_id)
    assert captured and all(isinstance(e, HttpEvidence) and not e.tls_verified for e in captured)


def test_verification_replays_reuse_the_original_exchange_setting() -> None:
    scope = Scope(hosts=['127.0.0.1'], ports=[8443])
    relaxed = _engagement_from_snapshot(scope, 'https://127.0.0.1:8443', tls_unverified=True)
    strict = _engagement_from_snapshot(scope, 'https://127.0.0.1:8443')
    assert relaxed.tls.verify is False and relaxed.tls.insecure_hosts == ['127.0.0.1']
    assert strict.tls.verify is True


# ── never the model's choice ──────────────────────────────────────────────────


def test_the_model_has_no_tls_tool() -> None:
    names = set(build_tester_agent('test')._function_toolset.tools)  # pyright: ignore[reportPrivateUsage]
    assert not {name for name in names if 'tls' in name or 'insecure' in name or 'verify' in name}
