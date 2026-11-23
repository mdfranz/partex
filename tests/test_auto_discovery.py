"""Passive discovery checks re-run by themselves in a live session when assets or specs arrive (issue #185)."""

import http.server
import json
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic_ai import Agent
from test_js_analysis import _scripted, _tool_returns  # pyright: ignore[reportPrivateUsage]

from partex.agent_adapter import TesterDeps, build_tester_agent
from partex.engine import DEFAULT_AGENT_CHECKS, DISCOVERY_CHECKS, live_session
from partex.storage import RunStore

FIXTURE_JS = Path(__file__).parent.parent / 'fixtures' / 'js' / 'sample.js'
HTML = b'<html><script src="/bundle.js"></script></html>'


class _Server(http.server.ThreadingHTTPServer):
    hits: list[str]


@pytest.fixture
def server() -> Iterator[_Server]:
    js = FIXTURE_JS.read_bytes()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert isinstance(self.server, _Server)
            self.server.hits.append(self.path)
            body, ctype = (js, 'application/javascript') if self.path == '/bundle.js' else (HTML, 'text/html')
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    httpd = _Server(('127.0.0.1', 0), Handler)
    httpd.hits = []
    thread = threading.Thread(target=httpd.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _engagement_dir(tmp_path: Path, port: int) -> Path:
    directory = tmp_path / 'engagement'
    directory.mkdir()
    (directory / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'app', 'base_url': f'http://127.0.0.1:{port}/'},
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
    return directory


def test_agent_default_checks_include_the_passive_discovery_checks() -> None:
    assert DEFAULT_AGENT_CHECKS[0] == 'version-disclosure'
    assert set(DISCOVERY_CHECKS) <= set(DEFAULT_AGENT_CHECKS)


async def test_nothing_new_to_analyze_is_a_cheap_no_op(server: _Server, tmp_path: Path, tmp_store: RunStore) -> None:
    async with live_session(
        _engagement_dir(tmp_path, server.server_port), tmp_store, authorized=True, checks=()
    ) as session:
        assert await session.refresh_discovery() is None  # only the baseline HTML so far


async def test_downloaded_asset_is_analyzed_without_any_model_call_or_traffic(
    server: _Server, tmp_path: Path, tmp_store: RunStore
) -> None:
    async with live_session(
        _engagement_dir(tmp_path, server.server_port), tmp_store, authorized=True, checks=()
    ) as session:
        await session.download_asset(f'http://127.0.0.1:{server.server_port}/bundle.js')
        spent, hits = session.requests_spent, list(server.hits)

        update = await session.refresh_discovery()

        assert update is not None
        assert 'js-analysis' in update.checks
        assert update.failed == ()
        assert update.new_findings > 0
        assert session.requests_spent == spent and server.hits == hits  # passive: no budget, no traffic
        # Nothing arrived since, so the next call does nothing; a forced re-run does not duplicate findings.
        assert await session.refresh_discovery() is None
        findings_count = len(await tmp_store.findings(session.run_id))
        await session.run_check('js-analysis')
        assert len(await tmp_store.findings(session.run_id)) == findings_count


async def test_agent_is_told_about_discovery_on_its_next_result(
    server: _Server, tmp_path: Path, tmp_store: RunStore
) -> None:
    async with live_session(
        _engagement_dir(tmp_path, server.server_port), tmp_store, authorized=True, checks=()
    ) as session:
        agent: Agent[TesterDeps, str] = build_tester_agent('test')
        deps = TesterDeps(run_id=session.run_id, reader=tmp_store, session=session, store=tmp_store)
        result = await agent.run(
            'look around',
            deps=deps,
            model=_scripted(
                [
                    ('download_asset', {'path': '/bundle.js'}),
                    ('http_request', {'method': 'GET', 'path': '/'}),
                    ('http_request', {'method': 'GET', 'path': '/'}),
                ]
            ),
        )
        returns = [str(part.content) for part in _tool_returns(result.all_messages())]
        assert 'Discovery update' not in returns[0]  # the download itself stays quick
        assert 'Discovery update' in returns[1] and 'js-analysis' in returns[1]
        assert 'Discovery update' not in returns[2]  # announced once
        calls = [c for c in await tmp_store.tool_calls(session.run_id) if c.tool == 'discovery_refresh']
        assert len(calls) == 1 and 'js-analysis' in calls[0].result['checks']
