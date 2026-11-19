"""Tests for the SQLite RunStore — PLAN §7, §7.1."""

import sqlite3
from contextlib import closing
from pathlib import Path

import anyio
import pytest

from partex.ids import evidence_id, finding_id, verification_id
from partex.models import (
    Authorization,
    ConfigEvidence,
    ConfigExcerpt,
    CoverageEntry,
    Engagement,
    EngagementTarget,
    Evidence,
    Finding,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
    ReviewSummary,
    Scope,
    Verification,
    get_header,
)
from partex.storage import SCHEMA_VERSION, RunReader, RunStore, StoreError, surface_node_id

# ── builders ──────────────────────────────────────────────────────────────────


def _http(path: str = '/', *, secret: bool = False) -> HttpEvidence:
    item = HttpEvidence(
        id='',
        source=f'capture:{path}',
        http=HttpExchange(
            request=HttpRequest(
                method='GET', url=f'https://app.example.test{path}', headers=[('Cookie', 'session=abc')]
            ),
            response=HttpResponse(status_code=200, headers=[('Content-Type', 'text/html')], body=f'<p>{path}</p>'),
        ),
        secret_fields=['$.http.request.headers[0][1]'] if secret else [],
    )
    return item.model_copy(update={'id': evidence_id(item)})


def _config() -> ConfigEvidence:
    item = ConfigEvidence(
        id='',
        source='openapi.json',
        config=ConfigExcerpt(path='openapi.yaml', format='openapi', content='x', revision='1'),
    )
    return item.model_copy(update={'id': evidence_id(item)})


def _finding(*evidence: Evidence, title: str = 'Missing HSTS') -> Finding:
    ids = [e.id for e in evidence]
    return Finding(
        id=finding_id('header-security', 'header:strict-transport-security', title, ids),
        check_id='header-security',
        check_version='1',
        severity='medium',
        subject='header:strict-transport-security',
        title=title,
        description='d',
        evidence_ids=ids,
        remediation='r',
        status='reported',
    )


def _verification(finding: Finding, verdict: str, *requests: Evidence) -> Verification:
    ids = [e.id for e in requests]
    return Verification.model_validate(
        {
            'id': verification_id(finding.id, ids),
            'finding_id': finding.id,
            'check_id': finding.check_id,
            'requests': ids,
            'verdict': verdict,
            'replayable': True,
            'detail': 'banner matched',
            'counterevidence': 'control request lacked banner',
        }
    )


async def _run(store: RunStore, **overrides: object) -> str:
    kwargs: dict[str, object] = {
        'input_kind': 'bundle',
        'input_ref': 'fixtures/bundles/valid',
        'input_sha256': 'a' * 64,
        'engine_version': '0.1.0',
        'selected_checks': ['header-security'],
    } | overrides
    return await store.create_run(**kwargs)  # pyright: ignore[reportArgumentType]


def _execute(path: Path, sql: str) -> None:
    """Run one statement on a short-lived raw connection (simulates another process / tampering)."""
    with closing(sqlite3.connect(path, isolation_level=None)) as conn:
        conn.execute(sql)


# ── open, pragmas, versioning ─────────────────────────────────────────────────


async def test_open_creates_versioned_wal_database(tmp_store: RunStore, tmp_store_path: Path):
    assert tmp_store_path.is_file()
    with closing(sqlite3.connect(tmp_store_path)) as conn:
        assert conn.execute('PRAGMA user_version').fetchone() == (SCHEMA_VERSION,)
        assert conn.execute('PRAGMA journal_mode').fetchone() == ('wal',)
        tables = {name for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {
        'engagements',
        'runs',
        'evidence',
        'findings',
        'verifications',
        'tool_calls',
        'summaries',
        'surface_nodes',
        'surface_edges',
        'coverage_entries',
        'llm_usage',
    } <= tables


async def test_connection_pragmas(tmp_store: RunStore):
    pragmas = await tmp_store._db.run(  # pyright: ignore[reportPrivateUsage]
        lambda c: [c.execute(f'PRAGMA {p}').fetchone()[0] for p in ('foreign_keys', 'synchronous', 'busy_timeout')]
    )
    assert pragmas == [1, 1, 5000]  # synchronous=NORMAL is 1


async def test_open_creates_parent_directories(tmp_path: Path):
    async with await RunStore.open(tmp_path / 'deep' / 'er' / 'partex.db') as store:
        assert store.path.is_file()


async def test_reopen_keeps_data(tmp_store_path: Path):
    async with await RunStore.open(tmp_store_path) as store:
        run_id = await _run(store)
    async with await RunStore.open(tmp_store_path) as store:
        assert (await store.get_run(run_id)).id == run_id


@pytest.mark.parametrize('opener', [RunStore.open, RunReader.open])
async def test_unknown_schema_version_refused(tmp_store_path: Path, opener: object):
    async with await RunStore.open(tmp_store_path):
        pass
    _execute(tmp_store_path, 'PRAGMA user_version = 99')
    with pytest.raises(StoreError) as exc:
        await opener(tmp_store_path)  # pyright: ignore[reportUnknownVariableType, reportCallIssue]
    assert exc.value.rule_code == 'store-version'


async def test_foreign_database_refused(tmp_store_path: Path):
    _execute(tmp_store_path, 'CREATE TABLE something_else (x)')
    with pytest.raises(StoreError) as exc:
        await RunStore.open(tmp_store_path)
    assert exc.value.rule_code == 'store-version'


async def test_reader_requires_existing_database(tmp_path: Path):
    with pytest.raises(StoreError) as exc:
        await RunReader.open(tmp_path / 'nope.db')
    assert exc.value.rule_code == 'store-missing'
    assert not (tmp_path / 'nope.db').exists()


# ── single writer, read-only readers ──────────────────────────────────────────


async def test_reader_is_read_only(tmp_store: RunStore, tmp_store_path: Path):
    await _run(tmp_store)
    async with await RunReader.open(tmp_store_path) as reader:
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            await reader._db.run(lambda c: c.execute("UPDATE runs SET state = 'complete'"))  # pyright: ignore[reportPrivateUsage]
    assert not any(hasattr(RunReader, name) for name in ('create_run', 'commit_passive', 'add_evidence', 'set_state'))


async def test_reader_sees_commits_made_after_it_opened(tmp_store: RunStore, tmp_store_path: Path):
    async with await RunReader.open(tmp_store_path) as reader:
        assert await reader.list_runs() == []
        run_id = await _run(tmp_store)
        assert [r.id for r in await reader.list_runs()] == [run_id]


async def test_second_writer_lock_timeout_is_a_clear_error(tmp_store_path: Path):
    async with await RunStore.open(tmp_store_path, busy_timeout_ms=50) as store:
        holder = sqlite3.connect(tmp_store_path, isolation_level=None)
        holder.execute('BEGIN IMMEDIATE')
        try:
            with pytest.raises(StoreError, match='locked') as exc:
                await _run(store)
            assert exc.value.rule_code == 'store-locked'
        finally:
            holder.execute('ROLLBACK')
            holder.close()
        await _run(store)  # lock released: the writer works again


async def test_other_sqlite_errors_propagate(tmp_store: RunStore):
    with pytest.raises(sqlite3.OperationalError, match='syntax'):
        await tmp_store._db.run(lambda c: c.execute('SELEC 1'))  # pyright: ignore[reportPrivateUsage]


async def test_concurrent_calls_serialize_on_one_connection(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    items = [_http(f'/p{i}') for i in range(20)]
    async with anyio.create_task_group() as tg:
        for item in items:
            tg.start_soon(tmp_store.add_evidence, run_id, item)
    stored = await tmp_store.evidence(run_id)
    assert sorted(e.id for e in stored) == sorted(e.id for e in items)
    seqs = await tmp_store._db.run(  # pyright: ignore[reportPrivateUsage]
        lambda c: [s for (s,) in c.execute('SELECT seq FROM evidence WHERE run_id = ? ORDER BY seq', (run_id,))]
    )
    assert seqs == list(range(20))


# ── runs and state ────────────────────────────────────────────────────────────


async def test_create_and_list_runs(tmp_store: RunStore):
    scope = Scope(hosts=['app.example.test'], ports=[443])
    first = await _run(tmp_store)
    second = await _run(
        tmp_store, input_kind='engagement', input_ref='eng_x', authorized=True, model='m', scope_snapshot=scope
    )

    runs = await tmp_store.list_runs()
    assert [r.id for r in runs] == [first, second]
    run = runs[1]
    assert run.id.startswith('run_')
    assert (run.state, run.input_kind, run.authorized, run.model) == ('created', 'engagement', True, 'm')
    assert run.selected_checks == ('header-security',)
    assert run.scope_snapshot == scope
    assert (run.requests_spent, run.findings_count, run.error, run.summary_error) == (0, 0, None, None)
    assert runs[0].scope_snapshot is None


@pytest.mark.parametrize(
    ('path', 'allowed'),
    [
        (['invalid'], True),
        (['checks_failed'], True),
        (['checks_complete', 'complete'], True),
        (['checks_complete', 'checks_failed'], False),
        (['invalid', 'checks_complete'], False),
        (['checks_failed', 'complete'], False),
        (['checks_complete', 'complete', 'checks_complete'], False),
        (['created'], False),
    ],
)
async def test_state_transitions_are_monotonic(tmp_store: RunStore, path: list[str], allowed: bool):
    run_id = await _run(tmp_store)
    *setup, last = path
    for state in setup:
        await tmp_store.set_state(run_id, state)  # pyright: ignore[reportArgumentType]
    if allowed:
        await tmp_store.set_state(run_id, last)  # pyright: ignore[reportArgumentType]
        assert (await tmp_store.get_run(run_id)).state == last
    else:
        with pytest.raises(StoreError) as exc:
            await tmp_store.set_state(run_id, last)  # pyright: ignore[reportArgumentType]
        assert exc.value.rule_code == 'run-state'


async def test_failure_state_records_error(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    await tmp_store.set_state(run_id, 'checks_failed', error='header-security raised KeyError')
    assert (await tmp_store.get_run(run_id)).error == 'header-security raised KeyError'


async def test_requests_spent(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    await tmp_store.add_requests_spent(run_id)
    await tmp_store.add_requests_spent(run_id, 4)
    assert (await tmp_store.get_run(run_id)).requests_spent == 5


@pytest.mark.parametrize(
    'call',
    [
        lambda s: s.get_run('run_nope'),
        lambda s: s.evidence('run_nope'),
        lambda s: s.findings('run_nope'),
        lambda s: s.verifications('run_nope'),
        lambda s: s.summary('run_nope'),
        lambda s: s.coverage('run_nope'),
        lambda s: s.tool_calls('run_nope'),
        lambda s: s.surface('run_nope'),
        lambda s: s.set_state('run_nope', 'invalid'),
        lambda s: s.add_requests_spent('run_nope'),
        lambda s: s.add_evidence('run_nope', _http()),
        lambda s: s.commit_findings('run_nope', []),
        lambda s: s.set_summary_error('run_nope', 'x'),
        lambda s: s.record_tool_call('run_nope', 't', {}, {}),
        lambda s: s.record_llm_usage('run_nope', role='tester', model='m', status='ok'),
        lambda s: s.upsert_coverage('run_nope', []),
        lambda s: s.upsert_surface_node('run_nope', 'host', 'h'),
        lambda s: s.add_surface_edge('run_nope', 'a', 'b', 'redirects_to'),
    ],
)
async def test_unknown_run_id(tmp_store: RunStore, call: object):
    with pytest.raises(StoreError) as exc:
        await call(tmp_store)  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
    assert exc.value.rule_code == 'run-not-found'


# ── passive commit: all or nothing ────────────────────────────────────────────


async def test_commit_passive_is_atomic_and_ordered(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    evidence: list[Evidence] = [_http('/b'), _config(), _http('/a')]
    findings = [_finding(evidence[0]), _finding(evidence[2], title='Missing CSP')]

    await tmp_store.commit_passive(run_id, evidence, findings)

    assert await tmp_store.evidence(run_id) == evidence
    assert await tmp_store.findings(run_id) == findings
    run = await tmp_store.get_run(run_id)
    assert (run.state, run.findings_count) == ('checks_complete', 2)


async def test_commit_passive_rolls_back_everything_on_bad_finding(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    good, orphan = _http('/ok'), _http('/never-registered')

    with pytest.raises(StoreError) as exc:
        await tmp_store.commit_passive(run_id, [good], [_finding(good), _finding(orphan, title='x')])

    assert exc.value.rule_code == 'dangling-evidence'
    assert await tmp_store.evidence(run_id) == []
    assert await tmp_store.findings(run_id) == []
    assert (await tmp_store.get_run(run_id)).state == 'created'


async def test_commit_passive_requires_created_run(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    await tmp_store.set_state(run_id, 'invalid', error='bundle-version')
    with pytest.raises(StoreError) as exc:
        await tmp_store.commit_passive(run_id, [], [])
    assert exc.value.rule_code == 'run-state'


# ── live: per-capture evidence, per-check findings ────────────────────────────


async def test_add_evidence_is_per_capture_and_idempotent(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    first, second = _http('/1', secret=True), _http('/2')

    assert await tmp_store.add_evidence(run_id, first) is True
    assert await tmp_store.add_evidence(run_id, second) is True
    assert await tmp_store.add_evidence(run_id, first) is False

    stored = await tmp_store.evidence(run_id)
    assert stored == [first, second]
    assert stored[0].secret_fields == ['$.http.request.headers[0][1]']  # cleartext + markers kept for replay
    assert isinstance(stored[0], HttpEvidence) and get_header(stored[0].http.request.headers, 'Cookie') == 'session=abc'


async def test_evidence_is_scoped_to_its_run(tmp_store: RunStore):
    run_a, run_b = await _run(tmp_store), await _run(tmp_store)
    item = _http()
    await tmp_store.add_evidence(run_a, item)
    assert await tmp_store.get_evidence(run_a, item.id) == item
    assert await tmp_store.get_evidence(run_b, item.id) is None
    with pytest.raises(StoreError) as exc:
        await tmp_store.commit_findings(run_b, [_finding(item)])
    assert exc.value.rule_code == 'dangling-evidence'


async def test_commit_findings_per_check_is_atomic(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    item = _http()
    await tmp_store.add_evidence(run_id, item)

    await tmp_store.commit_findings(run_id, [_finding(item)])
    with pytest.raises(StoreError):
        await tmp_store.commit_findings(run_id, [_finding(item, title='second'), _finding(_http('/x'), title='bad')])

    assert [f.title for f in await tmp_store.findings(run_id)] == ['Missing HSTS']
    assert await tmp_store.get_finding(run_id, _finding(item).id) == _finding(item)
    assert await tmp_store.get_finding(run_id, 'fn_nope') is None


# ── verification ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ('verdict', 'status'),
    [('confirmed', 'verified'), ('not_reproduced', 'verification_failed'), ('inconclusive', 'verification_failed')],
)
async def test_record_verification_transitions_status(tmp_store: RunStore, verdict: str, status: str):
    run_id = await _run(tmp_store)
    item, poc = _http('/'), _http('/poc')
    finding = _finding(item)
    await tmp_store.add_evidence(run_id, item)
    await tmp_store.commit_findings(run_id, [finding])
    await tmp_store.set_state(run_id, 'checks_complete')

    verification = _verification(finding, verdict, poc)
    await tmp_store.record_verification(run_id, verification, [poc])

    stored = await tmp_store.get_finding(run_id, finding.id)
    assert stored is not None
    assert (stored.status, stored.verification_id) == (status, verification.id)
    assert await tmp_store.verifications(run_id) == [verification]
    assert await tmp_store.get_evidence(run_id, poc.id) == poc


async def test_reverification_replaces_status(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    item = _http()
    finding = _finding(item)
    await tmp_store.commit_passive(run_id, [item], [finding])
    await tmp_store.record_verification(run_id, _verification(finding, 'confirmed', item))
    later = _verification(finding, 'not_reproduced', item).model_copy(update={'id': 'vf_later'})
    await tmp_store.record_verification(run_id, later)

    stored = await tmp_store.get_finding(run_id, finding.id)
    assert stored is not None and (stored.status, stored.verification_id) == ('verification_failed', 'vf_later')
    assert len(await tmp_store.verifications(run_id)) == 2


async def test_verification_failures_leave_finding_untouched(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    item = _http()
    finding = _finding(item)
    await tmp_store.commit_passive(run_id, [item], [finding])

    with pytest.raises(StoreError) as exc:
        await tmp_store.record_verification(run_id, _verification(finding, 'confirmed', _http('/missing')))
    assert exc.value.rule_code == 'dangling-evidence'

    ghost = _verification(finding, 'confirmed', item).model_copy(update={'finding_id': 'fn_ghost'})
    with pytest.raises(StoreError) as exc:
        await tmp_store.record_verification(run_id, ghost)
    assert exc.value.rule_code == 'finding-not-found'

    stored = await tmp_store.get_finding(run_id, finding.id)
    assert stored is not None and stored.status == 'reported'
    assert await tmp_store.verifications(run_id) == []


async def test_no_verification_on_invalid_run(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    await tmp_store.set_state(run_id, 'invalid')
    with pytest.raises(StoreError) as exc:
        await tmp_store.record_verification(run_id, _verification(_finding(_http()), 'confirmed'))
    assert exc.value.rule_code == 'run-state'


# ── summaries ─────────────────────────────────────────────────────────────────


async def test_summary_lifecycle(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    item = _http()
    finding = _finding(item)
    with pytest.raises(StoreError):
        await tmp_store.save_summary(run_id, ReviewSummary(narrative='early', finding_ids=[]), 'm')

    await tmp_store.commit_passive(run_id, [item], [finding])
    assert await tmp_store.summary(run_id) is None

    await tmp_store.set_summary_error(run_id, 'timed out after 60s')
    assert (await tmp_store.get_run(run_id)).summary_error == 'timed out after 60s'

    first = ReviewSummary(narrative='one finding', finding_ids=[finding.id])
    await tmp_store.save_summary(run_id, first, 'test-model')
    run = await tmp_store.get_run(run_id)
    assert (run.state, run.summary_error) == ('complete', None)
    assert await tmp_store.summary(run_id) == first

    second = ReviewSummary(narrative='regenerated', finding_ids=[finding.id])
    await tmp_store.save_summary(run_id, second, 'test-model')
    assert await tmp_store.summary(run_id) == second


# ── engagements, audit, coverage, surface ─────────────────────────────────────


async def test_record_engagement_is_idempotent(tmp_store: RunStore):
    engagement = Engagement(
        target=EngagementTarget(name='app', base_url='https://app.example.test'),
        scope=Scope(hosts=['app.example.test']),
        authorization=Authorization(attestation='SOW-1', operator='op'),
    )
    first = await tmp_store.record_engagement(engagement)
    assert first == await tmp_store.record_engagement(engagement)
    assert first.startswith('eng_')
    rows = await tmp_store._db.run(lambda c: c.execute('SELECT id, operator FROM engagements').fetchall())  # pyright: ignore[reportPrivateUsage]
    assert rows == [(first, 'op')]


async def test_tool_calls_and_llm_usage(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    call_id = await tmp_store.record_tool_call(
        run_id, 'http_request', {'path': '/', 'headers': {'Cookie': '<redacted>'}}, {'ok': True}
    )
    (call,) = await tmp_store.tool_calls(run_id)
    assert call.call_id == call_id and call_id.startswith('tc_')
    assert (call.tool, call.args, call.result) == (
        'http_request',
        {'headers': {'Cookie': '<redacted>'}, 'path': '/'},
        {'ok': True},
    )

    assert await tmp_store.llm_usage_totals(run_id) == {'calls': 0, 'input_tokens': 0, 'output_tokens': 0}
    await tmp_store.record_llm_usage(run_id, role='tester', model='m', status='ok', input_tokens=10, output_tokens=3)
    await tmp_store.record_llm_usage(run_id, role='judge', model='m', status='error', input_tokens=5, latency_ms=12)
    assert await tmp_store.llm_usage_totals(run_id) == {'calls': 2, 'input_tokens': 15, 'output_tokens': 3}


async def test_coverage_upsert(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    item = _http()
    await tmp_store.add_evidence(run_id, item)
    surface = 'GET /users/{id}'
    await tmp_store.upsert_coverage(
        run_id,
        [
            CoverageEntry(
                surface=surface,
                risk_area='authz',
                outcome='needs_follow_up',
                source='agent_reported',
                reason='no 2nd role',
            )
        ],
    )
    settled = CoverageEntry(
        surface=surface,
        risk_area='authz',
        outcome='no_issue_found',
        source='check_observed',
        evidence_ids=[item.id],
        goal_attempts=2,
    )
    await tmp_store.upsert_coverage(run_id, [settled])
    assert await tmp_store.coverage(run_id) == [settled]

    with pytest.raises(StoreError) as exc:
        await tmp_store.upsert_coverage(
            run_id,
            [
                CoverageEntry(
                    surface='x', risk_area='y', outcome='reported', source='check_observed', evidence_ids=['ev_missing']
                )
            ],
        )
    assert exc.value.rule_code == 'dangling-evidence'


async def test_surface_graph(tmp_store: RunStore):
    run_id = await _run(tmp_store)
    a, b = _http('/a'), _http('/b')
    await tmp_store.add_evidence(run_id, a)
    await tmp_store.add_evidence(run_id, b)

    host = await tmp_store.upsert_surface_node(run_id, 'host', 'app.example.test', metadata={'scheme': 'https'})
    ep = await tmp_store.upsert_surface_node(run_id, 'endpoint', 'GET /a', evidence_ids=[a.id])
    assert ep == await tmp_store.upsert_surface_node(
        run_id, 'endpoint', 'GET /a', metadata={'seen': 2}, evidence_ids=[b.id]
    )
    assert ep == surface_node_id('endpoint', 'GET /a') != surface_node_id('host', 'GET /a')
    await tmp_store.add_surface_edge(run_id, host, ep, 'exposes_endpoint', a.id)
    await tmp_store.add_surface_edge(run_id, host, ep, 'exposes_endpoint', a.id)

    nodes, edges = await tmp_store.surface(run_id)
    by_kind = {n.kind: n for n in nodes}
    assert by_kind['endpoint'].metadata == {'seen': 2}
    assert by_kind['endpoint'].evidence_ids == tuple(sorted([a.id, b.id]))
    assert by_kind['host'].metadata == {'scheme': 'https'} and by_kind['host'].evidence_ids == ()
    assert [(e.src_id, e.dst_id, e.rel, e.evidence_id) for e in edges] == [(host, ep, 'exposes_endpoint', a.id)]

    for call in (
        tmp_store.upsert_surface_node(run_id, 'endpoint', 'GET /z', evidence_ids=['ev_missing']),
        tmp_store.add_surface_edge(run_id, host, ep, 'redirects_to', 'ev_missing'),
    ):
        with pytest.raises(StoreError) as exc:
            await call
        assert exc.value.rule_code == 'dangling-evidence'
    await tmp_store.add_surface_edge(run_id, ep, host, 'redirects_to')


# ── re-validation on read ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ('sql', 'read'),
    [
        ('UPDATE evidence SET content = \'{"kind": "http_exchange"}\'', lambda s, r: s.evidence(r)),
        ("UPDATE findings SET severity = 'catastrophic'", lambda s, r: s.findings(r)),
        ('UPDATE runs SET scope_snapshot = \'{"hosts": []}\'', lambda s, r: s.get_run(r)),
        ("UPDATE runs SET selected_checks = '[1]'", lambda s, r: s.list_runs()),
    ],
)
async def test_schema_drift_is_a_load_error(tmp_store: RunStore, tmp_store_path: Path, sql: str, read: object):
    run_id = await _run(tmp_store, scope_snapshot=Scope(hosts=['h']))
    item = _http()
    await tmp_store.commit_passive(run_id, [item], [_finding(item)])
    _execute(tmp_store_path, sql)

    async with await RunReader.open(tmp_store_path) as reader:
        with pytest.raises(StoreError) as exc:
            await read(reader, run_id)  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
    assert exc.value.rule_code == 'store-load'


async def test_reader_exposes_the_same_reads(tmp_store: RunStore, tmp_store_path: Path):
    run_id = await _run(tmp_store)
    item = _http()
    finding = _finding(item)
    await tmp_store.commit_passive(run_id, [item], [finding])
    async with await RunReader.open(tmp_store_path) as reader:
        assert reader.path == tmp_store_path
        assert await reader.evidence(run_id) == [item]
        assert await reader.findings(run_id) == [finding]
        assert (await reader.get_run(run_id)).findings_count == 1
