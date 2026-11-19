"""Live engine path — PLAN §6.1 live policy, §4.2 gates (issue #21).

All tests run against the local fixture target app; the suite's non-loopback
socket block stays armed.  Refusals and aborts are asserted to leave the app's
request log untouched — no bytes on the wire.
"""

import importlib.util
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from partex.engine import CheckSelectionError, run_test, select_active_checks
from partex.storage import RunStore

# tmp_store comes from the root conftest's pytest_plugins (registered there by #8).

_TARGET_APP = Path(__file__).parent.parent / 'fixtures' / 'target_app' / 'app.py'


def _load_target_app() -> object:
    spec = importlib.util.spec_from_file_location('partex_fixture_target_app', _TARGET_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def target_app() -> Iterator[object]:
    """The deliberately vulnerable fixture app on an ephemeral localhost port."""
    app = _load_target_app()
    server = app.make_server()  # pyright: ignore[reportAttributeAccessIssue]
    thread = app.serve_thread(server)  # pyright: ignore[reportAttributeAccessIssue]
    try:
        yield server
    finally:
        server.shutdown()  # pyright: ignore[reportAttributeAccessIssue]
        server.server_close()  # pyright: ignore[reportAttributeAccessIssue]
        thread.join(timeout=5)


def engagement_dir(tmp_path: Path, server: object, **scope: object) -> Path:
    """Write a dynamic fixture engagement pointing at *server*'s ephemeral port."""
    port = server.port  # pyright: ignore[reportAttributeAccessIssue]
    base_url = server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    scope_data: dict[str, object] = {
        'hosts': ['127.0.0.1'],
        'path_prefixes': ['/'],
        'exclusions': ['/admin/shutdown'],
        'ports': [port],
        'max_rps': 64,
        'max_requests': 100,
    }
    scope_data.update(scope)
    directory = tmp_path / 'engagement'
    directory.mkdir()
    (directory / 'engagement.json').write_text(
        __import__('json').dumps(
            {
                'schema_version': 1,
                'target': {'name': 'fixture-app', 'base_url': base_url},
                'scope': scope_data,
                'authorization': {
                    'attestation': 'local fixture app on loopback',
                    'operator': 'test',
                },
                'suggested_checks': ['version-disclosure'],
            }
        )
    )
    return directory


# ── Selection ────────────────────────────────────────────────────────────────


def test_select_active_rejects_passive_and_unknown() -> None:
    registry = {'header-security': object(), 'version-disclosure': object()}
    with pytest.raises(CheckSelectionError) as excinfo:
        select_active_checks(registry, ['header-security'])
    assert excinfo.value.rule_code == 'not-active'
    with pytest.raises(CheckSelectionError) as excinfo:
        select_active_checks(registry, ['nope'])
    assert excinfo.value.rule_code == 'unknown-check'
    with pytest.raises(CheckSelectionError) as excinfo:
        select_active_checks(registry, [])
    assert excinfo.value.rule_code == 'empty-selection'


async def test_selection_is_ordered_and_deduplicated(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    order: list[str] = []

    class ProbeCounter:
        check_id = 'counter'
        version = '1.0'
        title = 'count'
        description = 'count'

        def applies_to(self, evidence: Sequence[object]) -> bool:
            return True

        async def probe(self, evidence: Sequence[object], client: object) -> list[object]:
            order.append(self.check_id)
            return []

        def verify_recipe(self, finding: object) -> None:
            return None

    first = ProbeCounter()
    first.check_id = 'counter-a'
    second = ProbeCounter()
    second.check_id = 'counter-b'
    directory = engagement_dir(tmp_path, target_app)
    result = await run_test(
        directory,
        tmp_store,
        ['counter-b', 'counter-a', 'counter-b'],
        authorized=True,
        registry={'counter-a': first, 'counter-b': second},
    )
    assert result.state == 'checks_complete'
    assert order == ['counter-b', 'counter-a']
    assert result.selected_checks == ('counter-b', 'counter-a')


# ── Gates: all before any socket ──────────────────────────────────────────────


async def test_missing_authorized_flag_fails_before_any_socket(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    directory = engagement_dir(tmp_path, target_app)
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=False)
    assert result.state == 'invalid'
    assert result.rule_code == 'unauthorized'
    assert target_app.requests == []  # pyright: ignore[reportAttributeAccessIssue]


async def test_out_of_scope_base_url_is_invalid_before_any_socket(tmp_path: Path, tmp_store: RunStore) -> None:
    # The shipped fixture engagement fails E5 at load time: base_url host is
    # not in scope.hosts.
    fixture = Path(__file__).parent.parent / 'fixtures' / 'engagements' / 'target-app-out-of-scope'
    result = await run_test(fixture, tmp_store, ['version-disclosure'], authorized=True)
    assert result.state == 'invalid'
    assert result.rule_code == 'scope-invalid'


async def test_missing_credential_aborts_before_any_socket(
    target_app: object, tmp_path: Path, tmp_store: RunStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv('PARTEX_CRED_SESSION', raising=False)
    directory = engagement_dir(tmp_path, target_app)
    manifest = directory / 'engagement.json'
    data = __import__('json').loads(manifest.read_text())
    data['credentials'] = {'session': 'PARTEX_CRED_SESSION'}
    manifest.write_text(__import__('json').dumps(data))
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True)
    assert result.state == 'invalid'
    assert result.rule_code == 'credential-missing'
    assert target_app.requests == []  # pyright: ignore[reportAttributeAccessIssue]


# ── The live path itself ──────────────────────────────────────────────────────


async def test_run_test_finds_banner_and_stack_trace(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    directory = engagement_dir(tmp_path, target_app)
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True)
    assert result.state == 'checks_complete'
    assert result.authorized is True
    assert result.requests_spent == 3  # baseline + robots + unknown path
    assert result.evidence_count == 3
    titles = {finding.title for finding in result.findings}
    assert any('server' in title.lower() and 'banner' in title.lower() for title in titles)
    assert any('stack trace' in title.lower() for title in titles)
    # Every finding cites evidence that is stored and resolvable.
    for finding in result.findings:
        for evidence_id in finding.evidence_ids:
            stored = await tmp_store.get_evidence(result.run_id, evidence_id)
            assert stored is not None
    # The run row records authorization and the scope snapshot.
    record = await tmp_store.get_run(result.run_id)
    assert record.authorized is True
    assert record.requests_spent == 3
    assert record.scope_snapshot is not None


async def test_baseline_is_captured_once_and_reused_by_the_check(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    directory = engagement_dir(tmp_path, target_app)
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True)
    assert result.requests_spent == 3
    paths = [entry['path'] for entry in target_app.requests]  # pyright: ignore[reportAttributeAccessIssue]
    assert paths == ['/', '/robots.txt', '/partex-nonexistent-probe-0']


async def test_budget_exhaustion_ends_checks_complete(target_app: object, tmp_path: Path, tmp_store: RunStore) -> None:
    # max_requests=2: baseline + robots fit; the unknown-path probe exhausts.
    directory = engagement_dir(tmp_path, target_app, max_requests=2)
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True)
    assert result.state == 'checks_complete'  # clean end, not failure
    assert result.budget_exhausted is True
    assert result.requests_spent == 2
    assert result.findings == ()
    assert result.skipped_checks == ('version-disclosure',)
    # Evidence already paid for is readable.
    stored = await tmp_store.evidence(result.run_id)
    assert len(stored) == 2


async def test_crashing_check_keeps_committed_evidence_and_earlier_findings(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    class Boom:
        check_id = 'boom'
        version = '1.0'
        title = 'boom'
        description = 'boom'

        def applies_to(self, evidence: Sequence[object]) -> bool:
            return True

        async def probe(self, evidence: Sequence[object], client: object) -> list[object]:
            base_url = target_app.base_url  # pyright: ignore[reportAttributeAccessIssue]
            await client.request('GET', f'{base_url}/boom-request')  # pyright: ignore[reportAttributeAccessIssue]
            raise RuntimeError('check exploded')

        def verify_recipe(self, finding: object) -> None:
            return None

    directory = engagement_dir(tmp_path, target_app)
    result = await run_test(
        directory,
        tmp_store,
        ['version-disclosure', 'boom'],
        authorized=True,
        registry={
            'version-disclosure': __import__(
                'partex.checks.version_disclosure', fromlist=['x']
            ).version_disclosure_check,
            'boom': Boom(),
        },
    )
    assert result.state == 'checks_failed'
    assert result.failed_check == 'boom'
    assert result.requests_spent == 4  # 3 probes + boom's own request
    # Earlier check's findings stay readable...
    earlier = await tmp_store.findings(result.run_id)
    assert any(finding.check_id == 'version-disclosure' for finding in earlier)
    # ...and so does the evidence the crashing check had already captured.
    stored = await tmp_store.evidence(result.run_id)
    assert any(item.http.request.url.endswith('/boom-request') for item in stored)


async def test_scope_violating_probe_is_a_check_failure(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    class OutOfScope:
        check_id = 'out-of-scope'
        version = '1.0'
        title = 'out'
        description = 'out'

        def applies_to(self, evidence: Sequence[object]) -> bool:
            return True

        async def probe(self, evidence: Sequence[object], client: object) -> list[object]:
            await client.request('GET', 'http://evil.test/x')  # pyright: ignore[reportAttributeAccessIssue]
            return []

        def verify_recipe(self, finding: object) -> None:
            return None

    directory = engagement_dir(tmp_path, target_app)
    result = await run_test(
        directory, tmp_store, ['out-of-scope'], authorized=True, registry={'out-of-scope': OutOfScope()}
    )
    assert result.state == 'checks_failed'
    assert result.failed_check == 'out-of-scope'
    assert 'scope' in (result.error or '')
