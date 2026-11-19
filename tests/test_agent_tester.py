"""``partex agent`` — live session + tester tools against the loopback fixture app (issue #54).

The model is a scripted ``FunctionModel``; the CLAI2 terminal is replaced. Every request goes to the
local fixture target, and scope refusals are asserted to leave its request log untouched.
"""

import importlib.util
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from partex import engine, target
from partex.agent_adapter import TesterDeps, build_tester_agent, run_agent
from partex.agent_adapter.scope_plugin import ScopeControl, ScopePlugin, current_control
from partex.agent_adapter.tester import MODEL_BODY_CHARS
from partex.engine import LiveSession, LiveSessionRefused, live_session
from partex.errors import ScopeViolation
from partex.storage import RunStore

_TARGET_APP = Path(__file__).parent.parent / 'fixtures' / 'target_app' / 'app.py'


@pytest.fixture
def target_app() -> Iterator[Any]:
    spec = importlib.util.spec_from_file_location('partex_fixture_target_app_agent', _TARGET_APP)
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


def engagement(tmp_path: Path, server: Any, **scope: object) -> Path:
    scope_data: dict[str, object] = {
        'hosts': ['127.0.0.1'],
        'path_prefixes': ['/'],
        'exclusions': ['/admin/shutdown'],
        'ports': [server.port],
        'max_rps': 64,
        'max_requests': 100,
    }
    scope_data.update(scope)
    directory = tmp_path / 'engagement'
    directory.mkdir()
    (directory / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'fixture-app', 'base_url': server.base_url + '/'},
                'scope': scope_data,
                'authorization': {'attestation': 'local fixture app on loopback', 'operator': 'test'},
            }
        )
    )
    return directory


def scripted(calls: list[tuple[str, dict[str, Any]]]) -> FunctionModel:
    """Call each tool in turn (one per step), then answer 'done'."""

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        index = sum(isinstance(part, ToolReturnPart) for m in messages for part in m.parts)  # incl. retried
        if index < len(calls):
            name, args = calls[index]
            return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=f'call_{index}')])
        return ModelResponse(parts=[TextPart('done')])

    return FunctionModel(respond)


def tool_returns(messages: list[ModelMessage]) -> list[ToolReturnPart]:
    return [p for m in messages if isinstance(m, ModelRequest) for p in m.parts if isinstance(p, ToolReturnPart)]


async def drive(session: LiveSession, store: RunStore, calls: list[tuple[str, dict[str, Any]]], **deps: Any) -> Any:
    agent: Agent[TesterDeps, str] = build_tester_agent('test')
    tester_deps = TesterDeps(run_id=session.run_id, reader=store, session=session, store=store, **deps)
    return await agent.run('go', deps=tester_deps, model=scripted(calls))


# ── engine live session ───────────────────────────────────────────────────────


async def test_session_runs_the_deterministic_pass_and_finalizes(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    async with live_session(
        engagement(tmp_path, target_app), tmp_store, authorized=True, checks=('version-disclosure',)
    ) as session:
        assert (await tmp_store.get_run(session.run_id)).state == 'created'  # open while the operator works
        assert session.captured and session.findings  # baseline + version-disclosure ran
        run_id = session.run_id
    run = await tmp_store.get_run(run_id)
    assert run.state == 'checks_complete'
    assert run.requests_spent == len(target_app.requests)


async def test_session_refused_before_any_socket(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    with pytest.raises(LiveSessionRefused) as excinfo:
        async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=False):
            pytest.fail('session opened without --authorized')
    assert excinfo.value.rule_code == 'unauthorized'
    assert (await tmp_store.get_run(excinfo.value.run_id)).state == 'invalid'
    assert target_app.requests == []


async def test_error_inside_session_marks_the_run_failed(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    with pytest.raises(RuntimeError):
        async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
            run_id = session.run_id
            raise RuntimeError('operator tooling crashed')
    run = await tmp_store.get_run(run_id)
    assert run.state == 'checks_failed' and 'operator tooling crashed' in (run.error or '')
    assert await tmp_store.evidence(run_id)  # the baseline captured before the failure survives


async def test_run_check_commits_passive_findings_once(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        first = await session.run_check('header-security')
        again = await session.run_check('header-security')  # same evidence → same findings, not re-inserted
        assert first and [f.id for f in first] == [f.id for f in again]
        stored = await tmp_store.findings(session.run_id)
        assert sorted(f.id for f in stored) == sorted(f.id for f in first)
        assert all(set(f.evidence_ids) <= {e.id for e in session.captured} for f in stored)
        with pytest.raises(engine.CheckSelectionError, match='available'):
            await session.run_check('nope')


# ── tester tools ──────────────────────────────────────────────────────────────


async def test_get_is_captured_and_returned_redacted(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        before = len(target_app.requests)
        result = await drive(
            session,
            tmp_store,
            [('http_request', {'method': 'get', 'path': '/robots.txt', 'headers': {'Authorization': 'Bearer t0k'}})],
        )
        (exchange,) = (str(p.content) for p in tool_returns(result.all_messages()))
        assert len(target_app.requests) == before + 1
        assert exchange.startswith('<partex_untrusted_data kind="http_exchange"')
        assert '/robots.txt' in exchange and '"status": 200' in exchange
        evidence_id = json.loads(exchange.split('>', 1)[1].rsplit('<', 1)[0])['evidence_id']
        assert evidence_id in {e.id for e in await tmp_store.evidence(session.run_id)}
        # Audit: recorded, with header names but never header values.
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert call.tool == 'http_request' and call.args['header_names'] == ['Authorization']
        assert 't0k' not in json.dumps(call.args) + json.dumps(call.result)


@pytest.mark.parametrize(
    ('args', 'message'),
    [
        ({'method': 'POST', 'path': '/'}, 'not available'),
        ({'method': 'DELETE', 'path': '/'}, 'not available'),
        ({'method': 'GET', 'path': '/admin/shutdown'}, 'engagement scope'),
        ({'method': 'GET', 'path': '/admin//shutdown'}, 'engagement scope'),  # #36 boundary rules apply
        ({'method': 'GET', 'path': 'http://evil.test/'}, 'engagement scope'),
    ],
)
async def test_refused_requests_never_reach_the_target(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, args: dict[str, str], message: str
) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        before = list(target_app.requests)
        result = await drive(session, tmp_store, [('http_request', args)])
        (failed,) = tool_returns(result.all_messages())
        assert getattr(failed, 'outcome', None) == 'failed'
        assert message in str(failed.content)
        assert target_app.requests == before  # no bytes on the wire
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert 'refused' in call.result


async def test_budget_exhaustion_fails_the_tool(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app, max_requests=1), tmp_store, authorized=True) as session:
        result = await drive(session, tmp_store, [('http_request', {'method': 'GET', 'path': '/robots.txt'})])
        (failed,) = tool_returns(result.all_messages())
        assert 'budget' in str(failed.content)


async def test_run_check_tool_and_unknown_check_retry(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        result = await drive(
            session, tmp_store, [('run_check', {'check_id': 'nope'}), ('run_check', {'check_id': 'version-disclosure'})]
        )
        retried, ran = tool_returns(result.all_messages())  # a tool's ModelRetry is a 'retried' return
        assert retried.outcome == 'retried' and 'available' in str(retried.content)
        check_result = str(ran.content)
        assert '"check_id": "version-disclosure"' in check_result and 'fn_' in check_result


async def test_previous_run_is_readable_only_with_from(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    eng = engagement(tmp_path, target_app)
    async with live_session(eng, tmp_store, authorized=True, checks=('version-disclosure',)) as earlier:
        earlier_id = earlier.run_id
        earlier_finding = earlier.findings[0].id
    async with live_session(eng, tmp_store, authorized=True) as session:
        with_from = await drive(
            session, tmp_store, [('list_findings', {'run': 'previous'})], previous_run_id=earlier_id
        )
        (listed,) = (str(p.content) for p in tool_returns(with_from.all_messages()))
        assert earlier_finding in listed
        without = await drive(session, tmp_store, [('list_findings', {'run': 'previous'})])
        (failed,) = tool_returns(without.all_messages())
        assert 'no previous run' in str(failed.content)


async def test_earlier_runs_of_the_same_target_are_listed_and_readable(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    eng = engagement(tmp_path, target_app)
    async with live_session(eng, tmp_store, authorized=True, checks=('version-disclosure',)) as earlier:
        earlier_id = earlier.run_id
        earlier_finding = earlier.findings[0].id
    async with live_session(eng, tmp_store, authorized=True) as session:
        result = await drive(
            session, tmp_store, [('list_runs', {}), ('list_findings', {'run': earlier_id}), ('list_findings', {})]
        )
        listed, by_id, current = (str(p.content) for p in tool_returns(result.all_messages()))
        assert earlier_id in listed and session.run_id in listed and '"current": true' in listed
        assert earlier_finding in by_id and earlier_finding not in current


async def test_runs_of_other_targets_are_not_exposed(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    eng = engagement(tmp_path, target_app)
    async with live_session(eng, tmp_store, authorized=True, checks=('version-disclosure',)) as other:
        other_id = other.run_id
    other_scope = (await tmp_store.get_run(other_id)).scope_snapshot
    assert other_scope is not None
    foreign = await tmp_store.create_run(  # same store, different host
        input_kind='engagement',
        input_ref='elsewhere',
        input_sha256='0' * 64,
        engine_version='x',
        selected_checks=(),
        authorized=True,
        scope_snapshot=other_scope.model_copy(update={'hosts': ['other.example']}),
    )
    async with live_session(eng, tmp_store, authorized=True) as session:
        result = await drive(session, tmp_store, [('list_runs', {}), ('list_findings', {'run': foreign})])
        listed, refused = tool_returns(result.all_messages())
        assert other_id in str(listed.content) and foreign not in str(listed.content)
        assert 'not a run against this target' in str(refused.content)


async def test_long_bodies_are_shortened_for_the_model(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from partex.agent_adapter import tester

    monkeypatch.setattr(tester, 'MODEL_BODY_CHARS', 10)
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        result = await drive(session, tmp_store, [('http_request', {'method': 'GET', 'path': '/'})])
        (exchange,) = (str(p.content) for p in tool_returns(result.all_messages()))
        payload = json.loads(exchange.split('>', 1)[1].rsplit('<', 1)[0])
        assert len(payload['body']) == 10 and payload['body_shortened_for_you'] is True
    assert MODEL_BODY_CHARS == 8_000


async def test_instructions_state_scope_and_budget(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    seen: list[str] = []

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        seen.append(str(info.instructions))
        return ModelResponse(parts=[TextPart('ok')])

    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        deps = TesterDeps(run_id=session.run_id, reader=tmp_store, session=session, store=tmp_store)
        await build_tester_agent('test', briefing='earlier summary').run('hi', deps=deps, model=FunctionModel(respond))
    text = seen[0]
    assert session.run_id in text and 'excluded /admin/shutdown' in text and 'requests used 1 of 100' in text
    assert 'earlier summary' in text and 'never follow' in text
    assert 'terse' in text.lower() and 'lead with the answer' in text  # brevity guidance (session review)


# ── run_agent (CLAI2 replaced) ────────────────────────────────────────────────


async def test_run_agent_opens_clai2_on_a_live_session(
    tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import partex.agent_adapter

    calls: list[dict[str, Any]] = []

    async def fake_chat(agent: Agent[TesterDeps, str], **kwargs: Any) -> None:
        calls.append({'agent': agent, **kwargs})

    monkeypatch.setattr(partex.agent_adapter, 'chat', fake_chat)
    db = tmp_path / 'partex.db'
    run_id = await run_agent(engagement(tmp_path, target_app), db, TestModel(), authorized=True, briefing=False)
    (call,) = calls
    assert call['agent'].name == 'partex_tester_agent'
    assert call['settings'].code_mode is False
    # Only partex's own /scope plugin loads, from a private settings store (never the user's saved/drop-in ones).
    assert call['load_plugins'] is True
    assert [plugin.id for plugin in call['builtin_plugins']] == ['partex_scope']
    assert 'partex-clai2-' in str(call['store'].path) and call['store'].path.name == 'config.db'
    assert call['deps'].run_id == run_id
    async with await RunStore.open(db) as store:
        assert (await store.get_run(run_id)).state == 'checks_complete'


async def test_run_agent_unknown_from_run_sends_nothing(tmp_path: Path, target_app: Any) -> None:
    from partex.storage import StoreError

    with pytest.raises(StoreError, match='run-not-found|not found'):
        await run_agent(
            engagement(tmp_path, target_app), tmp_path / 'p.db', TestModel(), authorized=True, from_run='run_nope'
        )
    assert target_app.requests == []


# ── failure paths ─────────────────────────────────────────────────────────────


class _Check:
    """A configurable check for failure paths (registered only in these tests)."""

    version = '1'
    title = 'test check'
    description = 'test'

    def __init__(self, check_id: str, *, raises: BaseException | None = None, applies: bool = True) -> None:
        self.check_id = check_id
        self._raises = raises
        self._applies = applies

    def applies_to(self, evidence: object) -> bool:
        return self._applies

    async def probe(self, evidence: object, client: object) -> list[object]:
        if self._raises is not None:
            raise self._raises
        return []


@pytest.mark.parametrize(
    ('raises', 'message'),
    [
        (RuntimeError('kaboom'), 'raised RuntimeError'),
        (__import__('partex.errors', fromlist=['ScopeViolation']).ScopeViolation('out'), 'left the engagement scope'),
    ],
)
async def test_failing_check_is_a_tool_failure_not_a_session_failure(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, raises: BaseException, message: str
) -> None:
    registry = {'bad': _Check('bad', raises=raises)}
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, registry=registry) as session:
        result = await drive(session, tmp_store, [('run_check', {'check_id': 'bad'})])
        (failed,) = tool_returns(result.all_messages())
        assert failed.outcome == 'failed' and message in str(failed.content)
        run_id = session.run_id
    assert (await tmp_store.get_run(run_id)).state == 'checks_complete'  # the operator can carry on


async def test_check_out_of_budget_is_a_tool_failure(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    from partex.errors import BudgetExhausted

    registry = {'hungry': _Check('hungry', raises=BudgetExhausted('spent'))}
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, registry=registry) as session:
        result = await drive(session, tmp_store, [('run_check', {'check_id': 'hungry'})])
        (failed,) = tool_returns(result.all_messages())
        assert 'budget' in str(failed.content)


async def test_transport_error_is_a_tool_failure(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from partex.errors import PartexError

    async def unreachable(*args: object, **kwargs: object) -> object:
        raise PartexError('connection refused')

    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        monkeypatch.setattr(session, 'request', unreachable)
        result = await drive(session, tmp_store, [('http_request', {'method': 'GET', 'path': '/'})])
        (failed,) = tool_returns(result.all_messages())
        assert 'request failed: connection refused' in str(failed.content)
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert call.result == {'error': 'connection refused'}


async def test_inapplicable_check_is_skipped_in_the_deterministic_pass(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    registry = {'never': _Check('never', raises=RuntimeError('must not run'), applies=False)}
    async with live_session(
        engagement(tmp_path, target_app), tmp_store, authorized=True, checks=('never',), registry=registry
    ) as session:
        assert session.findings == []


# ── local observability: llm_usage + read-tool audit (#54) ────────────────────


async def test_run_agent_records_model_usage_and_read_tool_calls(
    tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session is auditable from the DB alone: model turns in llm_usage, read tools in tool_calls."""
    import sqlite3

    import partex.agent_adapter

    async def fake_chat(agent: Agent[TesterDeps, str], **kwargs: Any) -> None:
        # Stand in for the terminal: run one turn that reads findings, so a read-tool audit is written.
        await agent.run('what are the findings?', deps=kwargs['deps'], model=scripted([('list_findings', {})]))

    monkeypatch.setattr(partex.agent_adapter, 'chat', fake_chat)
    db = tmp_path / 'partex.db'
    run_id = await run_agent(
        engagement(tmp_path, target_app), db, TestModel(), authorized=True, checks=('version-disclosure',)
    )
    conn = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
    usage = conn.execute(
        'SELECT role, status, COUNT(*), SUM(output_tokens) FROM llm_usage WHERE run_id=? GROUP BY role, status',
        (run_id,),
    ).fetchall()
    assert usage and all(role == 'tester' and status == 'ok' for role, status, _, _ in usage)
    assert sum(count for _, _, count, _ in usage) >= 1  # briefing + the chat turn
    tools = dict(conn.execute('SELECT tool, COUNT(*) FROM tool_calls WHERE run_id=? GROUP BY tool', (run_id,)))
    assert tools.get('list_findings', 0) >= 1  # the read-tool call is now audited locally


async def test_read_tool_audit_is_compact_and_has_no_secrets(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    recorded: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    async def audit(tool: str, args: dict[str, Any], result: dict[str, Any]) -> None:
        recorded.append((tool, args, result))

    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        agent: Agent[TesterDeps, str] = build_tester_agent('test')
        deps = TesterDeps(run_id=session.run_id, reader=tmp_store, audit=audit, session=session, store=tmp_store)
        await agent.run(
            'look',
            deps=deps,
            model=scripted([('list_findings', {}), ('lookup_evidence', {'evidence_id': 'ev_nope'})]),
        )
    tools = {tool for tool, _, _ in recorded}
    assert tools == {'list_findings', 'lookup_evidence'}
    lookup = next(r for t, _, r in recorded if t == 'lookup_evidence')
    assert lookup == {'found': False}  # compact: no body, no evidence contents


async def test_chat_path_writes_nothing_to_the_run(tmp_path: Path, target_app: Any) -> None:
    """chat is read-only: reviewing a run records no llm_usage and no tool_calls against it."""
    import sqlite3

    from partex.agent_adapter import run_chat
    from partex.storage import RunStore as Store

    db = tmp_path / 'partex.db'
    async with (
        await Store.open(db) as store,
        live_session(engagement(tmp_path, target_app), store, authorized=True) as session,
    ):
        run_id = session.run_id

    import partex.agent_adapter

    async def fake_chat(agent: Agent[Any, str], **kwargs: Any) -> None:
        await agent.run('findings?', deps=kwargs['deps'], model=scripted([('list_findings', {})]))

    import pytest as _pytest

    monkeypatch = _pytest.MonkeyPatch()
    monkeypatch.setattr(partex.agent_adapter, 'chat', fake_chat)
    try:
        await run_chat(run_id, db, TestModel(), briefing=False)
    finally:
        monkeypatch.undo()
    conn = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
    assert conn.execute('SELECT COUNT(*) FROM llm_usage WHERE run_id=?', (run_id,)).fetchone()[0] == 0
    assert conn.execute('SELECT COUNT(*) FROM tool_calls WHERE run_id=?', (run_id,)).fetchone()[0] == 0


async def test_usage_recorder_covers_streaming_and_errors(tmp_store: RunStore) -> None:
    """UsageRecordingModel writes a row for the streamed path (what CLAI2 uses) and for a failed call."""
    from pydantic_ai import Agent as _Agent
    from pydantic_ai.models.function import AgentInfo as _AgentInfo
    from pydantic_ai.models.test import TestModel as _TestModel

    from partex.agent_adapter.usage import UsageRecordingModel

    run_id = await tmp_store.create_run(
        input_kind='engagement', input_ref='e', input_sha256='s', engine_version='0.1.0', selected_checks=[]
    )
    recorder = UsageRecordingModel(_TestModel(), store=tmp_store, run_id=run_id, role='tester')

    async with _Agent(recorder).run_stream('hi') as result:  # streamed path
        await result.get_output()
    rows = await tmp_store.llm_usage_totals(run_id)
    assert rows['calls'] == 1 and rows['input_tokens'] > 0

    async def boom_stream(messages: list[ModelMessage], info: _AgentInfo):  # type: ignore[no-untyped-def]
        raise RuntimeError('provider down')
        yield  # pragma: no cover -- makes this an async generator

    failing = UsageRecordingModel(
        FunctionModel(stream_function=boom_stream), store=tmp_store, run_id=run_id, role='tester'
    )
    with pytest.raises(RuntimeError, match='provider down'):  # streamed path, so the stream error branch runs
        async with _Agent(failing).run_stream('hi') as result:
            await result.get_output()

    def boom_sync(messages: list[ModelMessage], info: _AgentInfo) -> ModelResponse:
        raise RuntimeError('provider down')

    failing_sync = UsageRecordingModel(FunctionModel(boom_sync), store=tmp_store, run_id=run_id, role='tester')
    with pytest.raises(RuntimeError, match='provider down'):  # non-streamed request path
        await _Agent(failing_sync).run('hi')
    import sqlite3

    conn = sqlite3.connect(f'file:{tmp_store.path}?mode=ro', uri=True)
    statuses = dict(conn.execute('SELECT status, COUNT(*) FROM llm_usage WHERE run_id=? GROUP BY status', (run_id,)))
    assert statuses.get('error', 0) == 2 and statuses.get('ok', 0) == 1  # stream + non-stream failure, one ok


# ── operator-confirmed scope extension (issue #64) ────────────────────────────


async def test_scope_staging_changes_nothing_and_confirm_applies_and_audits(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The fixture binds IPv4 only; pin 'localhost' to it so a resolver that lists ::1 first cannot break CI.
    monkeypatch.setattr(target, '_default_resolver', lambda host: '127.0.0.1')
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        control = ScopeControl(session)
        url = f'http://localhost:{target_app.port}/'
        with pytest.raises(ScopeViolation):
            await session.request('GET', url)  # not in scope yet: refused before any send

        staged = await control.handle(['add', f'localhost:{target_app.port}'])
        assert '+ host localhost' in staged and 'Not in effect yet' in staged
        with pytest.raises(ScopeViolation):
            await session.request('GET', url)  # staged is still not in effect
        assert session.engagement.scope.hosts == ['127.0.0.1']

        confirmed = await control.handle(['confirm'])
        assert 'extended' in confirmed and 'localhost' in session.engagement.scope.hosts
        evidence = await session.request('GET', url)  # now in scope, through the same gate
        assert evidence.http.response.status_code == 200

        stored = (await tmp_store.get_run(session.run_id)).scope_snapshot
        assert stored is not None and stored.hosts == ['127.0.0.1', 'localhost']
        calls = [c for c in await tmp_store.tool_calls(session.run_id) if c.tool == 'scope_amend']
        assert len(calls) == 1 and calls[0].args['confirmed_by'] == 'test'
        assert calls[0].result['hosts_after'] == ['127.0.0.1', 'localhost']


async def test_scope_cancel_confirm_without_pending_and_bad_input(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        control = ScopeControl(session)
        assert 'Nothing pending' in await control.handle(['confirm'])
        await control.handle(['add', 'localhost'])
        assert 'dropped' in await control.handle(['cancel'])
        assert 'Nothing pending' in await control.handle(['confirm'])
        assert 'Refused' in await control.handle(['add', 'user@evil.test'])
        assert 'Usage' in await control.handle(['remove', 'x'])
        assert 'Already in scope' in await control.handle(['add', f'127.0.0.1:{target_app.port}'])
        assert session.engagement.scope.hosts == ['127.0.0.1']
        assert not [c for c in await tmp_store.tool_calls(session.run_id) if c.tool == 'scope_amend']


async def test_client_set_scope_is_extend_only(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        scope = session.engagement.scope
        for bad in (
            scope.model_copy(update={'hosts': ['other.test']}),
            scope.model_copy(update={'exclusions': []}),
            scope.model_copy(update={'max_requests': scope.max_requests + 1}),
        ):
            with pytest.raises(ScopeViolation):
                session.client.set_scope(bad)


def test_the_model_has_no_scope_tool() -> None:
    names = set(build_tester_agent('test')._function_toolset.tools)  # pyright: ignore[reportPrivateUsage]
    assert not {name for name in names if 'scope' in name}


def test_scope_command_registers_only_with_a_bound_session() -> None:
    plugin = ScopePlugin.__new__(ScopePlugin)
    assert current_control.get() is None and plugin.get_commands() == ()


async def test_failed_scope_persist_leaves_scope_snapshot_and_audit_unchanged(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(target, '_default_resolver', lambda host: '127.0.0.1')
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        control = ScopeControl(session)
        url = f'http://localhost:{target_app.port}/'
        await control.handle(['add', f'localhost:{target_app.port}'])

        async def boom(*args: Any, **kwargs: Any) -> str:
            raise OSError('disk full')

        monkeypatch.setattr(tmp_store, 'amend_scope', boom)
        message = await control.handle(['confirm'])
        assert 'Not applied' in message and 'still staged' in message and 'disk full' in message
        assert session.engagement.scope.hosts == ['127.0.0.1']  # effective scope unchanged...
        with pytest.raises(ScopeViolation):
            await session.request('GET', url)  # ...and the gate still refuses
        stored = (await tmp_store.get_run(session.run_id)).scope_snapshot
        assert stored is not None and stored.hosts == ['127.0.0.1']
        assert not [c for c in await tmp_store.tool_calls(session.run_id) if c.tool == 'scope_amend']

        monkeypatch.undo()  # storage recovers: the staged change can be retried and applies
        monkeypatch.setattr(target, '_default_resolver', lambda host: '127.0.0.1')
        assert 'extended' in await control.handle(['confirm'])
        assert (await session.request('GET', url)).http.response.status_code == 200
