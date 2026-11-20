"""Live engine path — PLAN §6.1 live policy, §4.2 gates (issue #21).

All tests run against the local fixture target app; the suite's non-loopback
socket block stays armed.  Refusals and aborts are asserted to leave the app's
request log untouched — no bytes on the wire.
"""

import importlib.util
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from partex.engine import (
    CheckFailed,
    CheckSelectionError,
    default_live_checks,
    installed_checks,
    order_for_live_run,
    run_test,
    select_live_checks,
)
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


def test_select_live_accepts_passive_and_active_and_rejects_unknown() -> None:
    class Passive:
        check_id = 'p'

        def review(self, evidence: object) -> list[object]:
            return []

    class Active:
        check_id = 'a'

        async def probe(self, evidence: object, client: object) -> list[object]:
            return []

    registry = {'p': Passive(), 'a': Active(), 'neither': object()}
    selected = select_live_checks(registry, ['p', 'a', 'p'])
    assert [c.check_id for c in selected] == ['p', 'a']  # ordered, de-duplicated
    active, passive = order_for_live_run(selected)
    assert [c.check_id for c in active] == ['a'] and [c.check_id for c in passive] == ['p']
    with pytest.raises(CheckSelectionError) as excinfo:
        select_live_checks(registry, ['nope'])
    assert excinfo.value.rule_code == 'unknown-check' and 'available' in str(excinfo.value)
    with pytest.raises(CheckSelectionError) as excinfo:
        select_live_checks(registry, [])
    assert excinfo.value.rule_code == 'empty-selection'
    with pytest.raises(CheckSelectionError) as excinfo:
        select_live_checks(registry, ['neither'])
    assert excinfo.value.rule_code == 'not-runnable'


def test_default_live_checks_are_every_passive_check_plus_version_disclosure() -> None:
    defaults = default_live_checks(installed_checks())
    assert 'header-security' in defaults and defaults[-1] == 'version-disclosure'
    assert 'js-analysis' in defaults


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


# ── Passive checks in the live pipeline (issue #51) ───────────────────────────


async def test_live_run_runs_active_then_passive_and_passive_sees_probe_traffic(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    registry = installed_checks()
    seen: dict[str, int] = {}

    class Spy:
        """A passive check that records how many exchanges it was shown, and when it ran."""

        check_id = 'spy'
        version = '1'
        title = 'spy'
        description = 'spy'

        def applies_to(self, evidence: Sequence[object]) -> bool:
            return True

        def review(self, evidence: Sequence[object]) -> list[object]:
            seen['exchanges'] = len(evidence)
            return []

    result = await run_test(
        engagement_dir(tmp_path, target_app),
        tmp_store,
        ['spy', 'header-security', 'version-disclosure'],  # passive first in the selection
        authorized=True,
        registry={**registry, 'spy': Spy()},
    )
    assert result.state == 'checks_complete'
    kinds = {finding.check_id for finding in result.findings}
    assert {'header-security', 'version-disclosure'} <= kinds  # both kinds of findings from one live run
    assert seen['exchanges'] == result.evidence_count > 1  # passive saw the baseline *and* the probes
    captured_ids = {item.id for item in await tmp_store.evidence(result.run_id)}
    for finding in result.findings:
        assert set(finding.evidence_ids) <= captured_ids  # cites only this run's evidence
    assert result.selected_checks == ('spy', 'header-security', 'version-disclosure')


async def test_passive_check_that_does_not_apply_is_reported_skipped(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    class Never:
        check_id = 'never'
        version = '1'
        title = 'never'
        description = 'never'

        def applies_to(self, evidence: Sequence[object]) -> bool:
            return False

        def review(self, evidence: Sequence[object]) -> list[object]:
            raise AssertionError('must not run')

    result = await run_test(
        engagement_dir(tmp_path, target_app), tmp_store, ['never'], authorized=True, registry={'never': Never()}
    )
    assert result.state == 'checks_complete' and result.skipped_checks == ('never',)


async def test_raising_passive_check_fails_the_run_but_keeps_earlier_findings_and_evidence(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    registry = installed_checks()

    class Boom:
        check_id = 'boom'
        version = '1'
        title = 'boom'
        description = 'boom'

        def applies_to(self, evidence: Sequence[object]) -> bool:
            return True

        def review(self, evidence: Sequence[object]) -> list[object]:
            raise RuntimeError('kaput')

    result = await run_test(
        engagement_dir(tmp_path, target_app),
        tmp_store,
        ['version-disclosure', 'header-security', 'boom'],
        authorized=True,
        registry={**registry, 'boom': Boom()},
    )
    assert result.state == 'checks_failed' and result.failed_check == 'boom' and 'kaput' in (result.error or '')
    stored = await tmp_store.findings(result.run_id)
    assert {f.check_id for f in stored} >= {'version-disclosure', 'header-security'}  # committed before the failure
    assert len(await tmp_store.evidence(result.run_id)) == result.evidence_count > 0
    assert CheckFailed  # the failure surfaced as CheckFailed rather than a crash


async def test_passive_checks_still_run_after_the_budget_ends_active_work(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    result = await run_test(
        engagement_dir(tmp_path, target_app, max_requests=1),
        tmp_store,
        ['version-disclosure', 'header-security'],
        authorized=True,
    )
    assert result.state == 'checks_complete' and result.budget_exhausted
    assert 'header-security' in {f.check_id for f in result.findings}  # baseline alone is enough for passive review


# ── Catch-all routes and the coverage ledger (issue #53) ──────────────────────


async def test_catch_all_target_records_error_handler_not_reached(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    target_app.catch_all = True  # pyright: ignore[reportAttributeAccessIssue]
    result = await run_test(engagement_dir(tmp_path, target_app), tmp_store, ['version-disclosure'], authorized=True)
    assert result.state == 'checks_complete'
    assert not [f for f in result.findings if f.subject == 'error-page']  # nothing to report, and not "clean" either
    (entry,) = result.coverage
    assert (entry.risk_area, entry.outcome, entry.source) == (
        'error-page-disclosure',
        'not_applicable',
        'check_observed',
    )
    assert 'catch-all' in entry.reason and len(entry.evidence_ids) == 2  # the probe and the baseline
    stored = await tmp_store.coverage(result.run_id)
    assert [(c.risk_area, c.outcome) for c in stored] == [('error-page-disclosure', 'not_applicable')]


async def test_real_error_handler_is_reported_in_coverage(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    result = await run_test(engagement_dir(tmp_path, target_app), tmp_store, ['version-disclosure'], authorized=True)
    assert any(f.subject == 'error-page' for f in result.findings)  # existing behavior unchanged
    (entry,) = result.coverage
    assert entry.outcome == 'reported' and 'stack traces' in entry.reason

    target_app.hardened = True  # pyright: ignore[reportAttributeAccessIssue]
    clean_dir = tmp_path / 'again'
    clean_dir.mkdir()
    clean = await run_test(engagement_dir(clean_dir, target_app), tmp_store, ['version-disclosure'], authorized=True)
    (clean_entry,) = clean.coverage
    assert clean_entry.outcome == 'no_issue_found'


async def test_probe_refused_by_scope_is_recorded_as_not_exercised(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    # Exclude the unknown-path probe (and robots.txt): the check cannot reach the error handler at all.
    result = await run_test(
        engagement_dir(tmp_path, target_app, exclusions=['/partex-nonexistent-probe-0', '/robots.txt']),
        tmp_store,
        ['version-disclosure'],
        authorized=True,
    )
    assert result.state == 'checks_complete'
    (entry,) = result.coverage
    assert entry.outcome == 'not_applicable' and 'refused by the engagement scope' in entry.reason


async def test_a_bad_coverage_hook_fails_the_run_like_a_bad_draft(
    target_app: object, tmp_path: Path, tmp_store: RunStore
) -> None:
    class BadCoverage:
        check_id = 'bad-coverage'
        version = '1'
        title = 'bad'
        description = 'bad'

        def applies_to(self, evidence: Sequence[object]) -> bool:
            return True

        async def probe(self, evidence: Sequence[object], client: object) -> list[object]:
            return []

        def coverage(self, evidence: Sequence[object]) -> list[object]:
            return [
                {'surface': 's', 'risk_area': 'r', 'outcome': 'no_issue_found', 'source': 'agent_reported'},
            ]

    result = await run_test(
        engagement_dir(tmp_path, target_app),
        tmp_store,
        ['bad-coverage'],
        authorized=True,
        registry={'bad-coverage': BadCoverage()},
    )
    assert result.state == 'checks_failed' and 'check_observed' in (result.error or '')
