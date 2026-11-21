"""Engagement-level User-Agent (#135): validation, the client-level default on every send path, overrides, replay.

Hermetic: the fixture servers are loopback-only and the stub transport never leaves the process. What went on
the wire is asserted both from captured evidence (request headers as sent) and from what the transport saw.
"""

import importlib.metadata
import importlib.util
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest

from partex import cli
from partex.engagement import load_engagement, validate_engagement
from partex.engine import LiveSessionRefused, live_session, run_test
from partex.errors import ValidationFailed
from partex.models import USER_AGENT_MAX_CHARS, Engagement, HttpEvidence, get_header, redact
from partex.storage import RunStore
from partex.target import ScopedHttpClient, default_user_agent
from partex.verify import run_verification

FIXTURES = Path(__file__).parent.parent / 'fixtures'
_TARGET_APP = FIXTURES / 'target_app' / 'app.py'
PARTEX_UA = f'partex/{importlib.metadata.version("partex")}'


@pytest.fixture
def target_app() -> Iterator[Any]:
    spec = importlib.util.spec_from_file_location('partex_fixture_target_app_user_agent', _TARGET_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.make_server()
    thread = module.serve_thread(server)
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _manifest(port: int, *, user_agent: str | None = None, host: str = '127.0.0.1') -> dict[str, Any]:
    data: dict[str, Any] = {
        'schema_version': 1,
        'target': {'name': 'fixture-app', 'base_url': f'http://{host}:{port}'},
        'scope': {
            'hosts': [host],
            'path_prefixes': ['/'],
            'exclusions': ['/admin/shutdown'],
            'ports': [port],
            'max_rps': 64,
            'max_requests': 100,
        },
        'authorization': {'attestation': 'local fixture app on loopback', 'operator': 'test'},
    }
    if user_agent is not None:
        data['http'] = {'user_agent': user_agent}
    return data


def _engagement_dir(tmp_path: Path, port: int, *, user_agent: str | None = None) -> Path:
    directory = tmp_path / 'engagement'
    directory.mkdir(exist_ok=True)
    (directory / 'engagement.json').write_text(json.dumps(_manifest(port, user_agent=user_agent)))
    return directory


def _ua(evidence: HttpEvidence) -> str | None:
    return get_header(evidence.http.request.headers, 'user-agent')


# ── Validation: before any socket, with a named rule ──────────────────────────


def test_default_is_partex_and_version_not_the_http_library() -> None:
    assert default_user_agent() == PARTEX_UA
    assert 'httpx' not in default_user_agent()


def test_fixture_with_a_user_agent_loads() -> None:
    engagement = load_engagement(FIXTURES / 'engagements' / 'user-agent')
    assert engagement.http.user_agent == 'Mozilla/5.0 (X11; Linux x86_64) ExampleCorp-Pentest/1.0'
    assert load_engagement(FIXTURES / 'engagements' / 'valid').http.user_agent is None


@pytest.mark.parametrize(
    'user_agent',
    [
        '',
        '   ',
        'Agent/1.0\r\nX-Injected: 1',
        'Agent/1.0\n',
        'Agent\t1.0',
        'Agent\x00/1.0',
        'Agent\u200b/1.0',  # zero-width space (format character)
        'Agent\u202e/1.0',  # right-to-left override (format character)
        'Agént/1.0',  # not ASCII: an HTTP/1.1 header value cannot carry it portably
        'A' * (USER_AGENT_MAX_CHARS + 1),
    ],
)
def test_invalid_user_agent_fails_engagement_load_with_http_invalid(user_agent: str) -> None:
    with pytest.raises(ValidationFailed) as caught:
        validate_engagement(_manifest(8080, user_agent=user_agent))
    assert caught.value.rule_code == 'http-invalid'


def test_unknown_http_key_is_rejected() -> None:
    data = _manifest(8080)
    data['http'] = {'user_agent': 'Agent/1.0', 'rotate': True}
    with pytest.raises(ValidationFailed) as caught:
        validate_engagement(data)
    assert caught.value.rule_code == 'http-invalid'


def test_longest_allowed_user_agent_loads() -> None:
    value = 'A' * USER_AGENT_MAX_CHARS
    assert validate_engagement(_manifest(8080, user_agent=value)).http.user_agent == value


# ── The client default reaches every send path ────────────────────────────────


def _stub(seen: list[httpx2.Request], *, user_agent: str | None = None) -> ScopedHttpClient:
    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, headers={'content-type': 'text/plain'}, content=b'ok')

    manifest = _manifest(443, user_agent=user_agent, host='fixture.test')
    manifest['scope']['ports'] = [80, 443]
    return ScopedHttpClient(
        Engagement.model_validate(manifest),
        resolver=lambda host: '127.0.0.1',
        transport=httpx2.MockTransport(handler),  # pyright: ignore[reportArgumentType]
    )


@pytest.mark.parametrize('scheme', ['http', 'https'])
async def test_unset_sends_partex_default_on_request_and_download(scheme: str, tmp_path: Path) -> None:
    seen: list[httpx2.Request] = []
    async with _stub(seen) as client:
        evidence = await client.request('GET', f'{scheme}://fixture.test/a')
        artifact = await client.download_asset(f'{scheme}://fixture.test/app.js', dest_dir=tmp_path)
    assert _ua(evidence) == PARTEX_UA
    assert artifact.artifact.status_code == 200
    assert [request.headers['user-agent'] for request in seen] == [PARTEX_UA, PARTEX_UA]
    assert not any('httpx' in request.headers['user-agent'] for request in seen)


async def test_engagement_user_agent_is_sent_and_a_request_header_overrides_it(tmp_path: Path) -> None:
    seen: list[httpx2.Request] = []
    async with _stub(seen, user_agent='ExampleCorp-Pentest/1.0') as client:
        default = await client.request('GET', 'https://fixture.test/a')
        override = await client.request('GET', 'https://fixture.test/b', headers={'user-agent': 'Explicit/2.0'})
        await client.download_asset('https://fixture.test/c.js', dest_dir=tmp_path, headers={'User-Agent': 'Dl/3'})
    assert _ua(default) == 'ExampleCorp-Pentest/1.0'
    assert _ua(override) == 'Explicit/2.0'
    assert [request.headers.get_list('user-agent') for request in seen] == [
        ['ExampleCorp-Pentest/1.0'],
        ['Explicit/2.0'],  # replaced, not sent twice
        ['Dl/3'],
    ]


async def test_user_agent_is_never_secret_and_survives_redaction() -> None:
    seen: list[httpx2.Request] = []
    async with _stub(seen, user_agent='ExampleCorp-Pentest/1.0') as client:
        evidence = await client.request('GET', 'https://fixture.test/a')
    assert not any('user-agent' in field.lower() for field in evidence.secret_fields)
    redacted = redact(evidence)
    assert isinstance(redacted, HttpEvidence)
    assert _ua(redacted) == 'ExampleCorp-Pentest/1.0'


# ── Live paths: test, the agent's session client, and --user-agent ─────────────


async def test_run_test_captures_the_engagement_user_agent(
    target_app: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    directory = _engagement_dir(tmp_path, target_app.port, user_agent='ExampleCorp-Pentest/1.0')
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True)
    assert result.state == 'checks_complete'
    evidence = [item for item in await tmp_store.evidence(result.run_id) if isinstance(item, HttpEvidence)]
    assert evidence and {_ua(item) for item in evidence} == {'ExampleCorp-Pentest/1.0'}


async def test_user_agent_flag_overrides_the_engagement(target_app: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    directory = _engagement_dir(tmp_path, target_app.port, user_agent='FromFile/1.0')
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True, user_agent='FromFlag/2.0')
    evidence = [item for item in await tmp_store.evidence(result.run_id) if isinstance(item, HttpEvidence)]
    assert evidence and {_ua(item) for item in evidence} == {'FromFlag/2.0'}


async def test_bad_user_agent_flag_is_refused_before_any_socket(
    target_app: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    directory = _engagement_dir(tmp_path, target_app.port)
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True, user_agent='a\r\nb: c')
    assert (result.state, result.rule_code) == ('invalid', 'http-invalid')
    assert target_app.requests == []  # nothing reached the target
    with pytest.raises(LiveSessionRefused) as caught:
        async with live_session(directory, tmp_store, authorized=True, user_agent=''):
            pass
    assert caught.value.rule_code == 'http-invalid'
    assert target_app.requests == []


async def test_agent_session_client_uses_the_flag(target_app: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    """The agent tools (http_request, download_asset) and seeded probes all send through ``session.client``."""
    directory = _engagement_dir(tmp_path, target_app.port)
    async with live_session(directory, tmp_store, authorized=True, user_agent='Agent/9.0') as session:
        probe = await session.client.request('GET', f'{target_app.base_url}/robots.txt')
        artifact = await session.client.download_asset(
            f'{target_app.base_url}/robots.txt', dest_dir=tmp_path, headers=None
        )
        run_id = session.run_id
    assert _ua(probe) == 'Agent/9.0'
    assert artifact.artifact.status_code == 200
    evidence = [item for item in await tmp_store.evidence(run_id) if isinstance(item, HttpEvidence)]
    assert {_ua(item) for item in evidence} == {'Agent/9.0'}  # baseline capture included


# ── verify: the replay presents as the original request did ───────────────────


async def test_verify_replays_the_original_user_agent_unless_overridden(
    target_app: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    directory = _engagement_dir(tmp_path, target_app.port, user_agent='Original/1.0')
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True)
    finding = next(item for item in result.findings if item.subject.startswith('header:'))

    # The engagement file changes afterwards; the replay still presents as the original request did.
    _engagement_dir(tmp_path, target_app.port, user_agent='Changed/2.0')
    replay = await run_verification(result.run_id, finding.id, tmp_store, authorized=True)
    (evidence,) = [await tmp_store.get_evidence(result.run_id, item) for item in replay.replay_evidence_ids]
    assert isinstance(evidence, HttpEvidence) and _ua(evidence) == 'Original/1.0'

    replay = await run_verification(result.run_id, finding.id, tmp_store, authorized=True, user_agent='Override/3')
    (evidence,) = [await tmp_store.get_evidence(result.run_id, item) for item in replay.replay_evidence_ids]
    assert isinstance(evidence, HttpEvidence) and _ua(evidence) == 'Override/3'

    before = len(target_app.requests)
    with pytest.raises(ValidationFailed) as caught:
        await run_verification(result.run_id, finding.id, tmp_store, authorized=True, user_agent='bad\nua')
    assert caught.value.rule_code == 'http-invalid'
    assert len(target_app.requests) == before


# ── CLI ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    'argv',
    [
        ['test', 'eng', '--authorized', '--user-agent', 'Cli/1.0'],
        ['agent', 'eng', '--authorized', '--model', 'test', '--user-agent', 'Cli/1.0'],
        ['verify', 'run_x', 'fn_x', '--authorized', '--user-agent', 'Cli/1.0'],
    ],
)
def test_user_agent_flag_exists_on_test_agent_and_verify(argv: list[str]) -> None:
    assert cli.build_parser().parse_args(argv).user_agent == 'Cli/1.0'
