"""``partex agent`` — live session + tester tools against the loopback fixture app (issue #54).

The model is a scripted ``FunctionModel``; the CLAI2 terminal is replaced. Every request goes to the
local fixture target, and scope refusals are asserted to leave its request log untouched.
"""

import importlib.util
import json
import stat
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, DeltaToolCall, DeltaToolCalls, FunctionModel
from pydantic_ai.models.test import TestModel

from partex import engine, target
from partex.agent_adapter import CHAT_SETTINGS, TesterDeps, build_tester_agent, run_agent
from partex.agent_adapter.scope_plugin import ScopeControl, ScopePlugin, current_control
from partex.agent_adapter.tester import (
    BATCH_MAX_ITEMS,
    CODE_MODE_TOOLS,
    MODEL_BODY_CHARS,
    TESTER_INSTRUCTIONS,
    TESTER_TOOLS,
)
from partex.agent_adapter.tools import REVIEWER_TOOLS
from partex.engine import LiveSession, LiveSessionRefused, live_session
from partex.errors import PartexError, ScopeViolation
from partex.models import REDACTED
from partex.storage import MAX_REPORT_BYTES, RunStore, artifact_dir, run_reports_dir

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


def streaming(respond: Callable[[list[ModelMessage], AgentInfo], ModelResponse]) -> FunctionModel:
    """A ``FunctionModel`` that also streams *respond*'s reply: Code Mode (#83) makes the agent stream."""

    async def stream(messages: list[ModelMessage], info: AgentInfo) -> AsyncIterator[str | DeltaToolCalls]:
        deltas: DeltaToolCalls = {}
        for part in respond(messages, info).parts:
            if isinstance(part, TextPart):
                yield part.content
            elif isinstance(part, ToolCallPart):
                deltas[len(deltas)] = DeltaToolCall(
                    name=part.tool_name, json_args=part.args_as_json_str(), tool_call_id=part.tool_call_id
                )
        if deltas:
            yield deltas

    return FunctionModel(respond, stream_function=stream)


def scripted(calls: list[tuple[str, dict[str, Any]]]) -> FunctionModel:
    """Call each tool in turn (one per step), then answer 'done'."""

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        index = sum(isinstance(part, ToolReturnPart) for m in messages for part in m.parts)  # incl. retried
        if index < len(calls):
            name, args = calls[index]
            return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=f'call_{index}')])
        return ModelResponse(parts=[TextPart('done')])

    return streaming(respond)


def tool_returns(messages: list[ModelMessage]) -> list[ToolReturnPart]:
    return [p for m in messages if isinstance(m, ModelRequest) for p in m.parts if isinstance(p, ToolReturnPart)]


async def drive(session: LiveSession, store: RunStore, calls: list[tuple[str, dict[str, Any]]], **deps: Any) -> Any:
    agent: Agent[TesterDeps, str] = build_tester_agent('test')
    tester_deps = TesterDeps(run_id=session.run_id, reader=store, session=session, store=store, **deps)
    return await agent.run('go', deps=tester_deps, model=scripted(calls))


async def drive_code(session: LiveSession, store: RunStore, snippets: list[str], **deps: Any) -> list[str]:
    """Run *snippets* through ``run_code`` (the read tools are only callable there, #83); return the outputs."""
    agent: Agent[TesterDeps, str] = build_tester_agent('test')
    tester_deps = TesterDeps(run_id=session.run_id, reader=store, session=session, store=store, **deps)
    result = await agent.run('go', deps=tester_deps, model=streaming(snippet_script(snippets)))
    return [str(part.content) for part in tool_returns(result.all_messages())]


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
        snippet = "print(await list_findings(run='previous'))"
        (listed,) = await drive_code(session, tmp_store, [snippet], previous_run_id=earlier_id)
        assert earlier_finding in listed
        (failed,) = await drive_code(session, tmp_store, [snippet])
        assert 'no previous run' in failed


async def test_earlier_runs_of_the_same_target_are_listed_and_readable(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    eng = engagement(tmp_path, target_app)
    async with live_session(eng, tmp_store, authorized=True, checks=('version-disclosure',)) as earlier:
        earlier_id = earlier.run_id
        earlier_finding = earlier.findings[0].id
    async with live_session(eng, tmp_store, authorized=True) as session:
        listed, by_id, current = await drive_code(
            session,
            tmp_store,
            [
                'print(await list_runs())',
                f"print(await list_findings(run='{earlier_id}'))",
                'print(await list_findings())',
            ],
        )
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
        listed, refused = await drive_code(
            session, tmp_store, ['print(await list_runs())', f"print(await list_findings(run='{foreign}'))"]
        )
        assert other_id in listed and foreign not in listed
        assert 'not a run against this target' in refused


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
        await build_tester_agent('test', briefing='earlier summary').run('hi', deps=deps, model=streaming(respond))
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
            model=streaming(
                snippet_script(['print(await list_findings())', "print(await lookup_evidence(evidence_id='ev_nope'))"])
            ),
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


# ── operator-only exports: /report and /secrets (issue #88) ───────────────────

_SECRET_VALUE = 'sk-live-ABCDEF0123456789'
_COOKIE_VALUE = 'sessionid=top-secret-cookie-value'


async def _seed_secrets(session: LiveSession) -> None:
    """A stored JS artifact holding a secret-shaped value, and an HTTP exchange with a Set-Cookie."""
    import hashlib

    from partex.ids import evidence_id
    from partex.models import ArtifactAsset, ArtifactEvidence, HttpEvidence, HttpExchange, HttpRequest, HttpResponse
    from partex.storage import artifact_dir

    data = f"const cfg = {{apiKey: '{_SECRET_VALUE}'}}; fetch('/api/v1/users');".encode()
    digest = hashlib.sha256(data).hexdigest()
    directory = artifact_dir(session.store.path)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / digest).write_bytes(data)
    artifact = ArtifactEvidence(
        id='',
        source='capture:test',
        artifact=ArtifactAsset(
            url='https://app.example.test/main.js',
            status_code=200,
            headers=[('Content-Type', 'application/javascript')],
            content_type='application/javascript',
            sha256=digest,
            size_bytes=len(data),
        ),
        file_path=str(directory / digest),
    )
    cookie = HttpEvidence(
        id='',
        source='capture:test',
        http=HttpExchange(
            request=HttpRequest(method='GET', url='https://app.example.test/login', headers=[]),
            response=HttpResponse(status_code=200, headers=[('Set-Cookie', _COOKIE_VALUE)], body='ok'),
        ),
        secret_fields=['$.http.response.headers[0][1]'],
    )
    for item in (artifact, cookie):
        stored = item.model_copy(update={'id': evidence_id(item)})
        await session.store.add_evidence(session.run_id, stored)


async def test_report_and_secrets_commands_write_private_files_and_never_echo_values(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    import stat

    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        await _seed_secrets(session)
        control = ScopeControl(session)

        said_report = await control.report([])
        said_secrets = await control.secrets([])
        for message in (said_report, said_secrets):  # what the operator sees (and could end up in a transcript)
            assert _SECRET_VALUE not in message and _COOKIE_VALUE not in message
        assert '1 JavaScript candidate' in said_secrets and '1 secret-marked' in said_secrets

        report = next(p for p in (tmp_store.path.parent / f'{tmp_store.path.name}.exports').glob('*.report.md'))
        secrets = next(p for p in (tmp_store.path.parent / f'{tmp_store.path.name}.exports').glob('*.secrets.md'))
        report_text, secrets_text = report.read_text(), secrets.read_text()
        assert f'# Partex report: {session.run_id}' in report_text and '## Evidence' in report_text
        assert _SECRET_VALUE not in report_text and _COOKIE_VALUE not in report_text  # reports stay redacted
        assert _SECRET_VALUE in secrets_text and _COOKIE_VALUE in secrets_text and 'UNREDACTED' in secrets_text
        assert 'apiKey' in secrets_text and 'Set-Cookie' in secrets_text
        for path in (report, secrets):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(report.parent.stat().st_mode) == 0o700


def test_markdown_report_lists_coverage_outcomes() -> None:
    from partex.operator_export import render_markdown_report

    payload: dict[str, Any] = {
        'run': {
            'state': 'checks_complete',
            'engine_version': '0',
            'input_kind': 'engagement',
            'input_ref': 'e',
            'selected_checks': [],
            'requests_spent': 1,
            'error': None,
            'scope_snapshot': None,
        },
        'findings': [],
        'evidence': [],
        'tool_calls': [],
        'verifications': [],
        'summary': None,
        'coverage': [
            {
                'surface': 'http://a.test',
                'risk_area': 'error-page-disclosure',
                'outcome': 'not_applicable',
                'reason': 'catch-all',
            }
        ],
    }
    assert 'error-page-disclosure: not_applicable (catch-all)' in render_markdown_report(payload, 'run_x')


async def test_report_and_secrets_accept_an_explicit_path_and_report_failures(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        control = ScopeControl(session)
        dest = tmp_path / 'out' / 'my-report.md'
        assert str(dest) in await control.report([str(dest)])
        assert dest.is_file()
        blocker = tmp_path / 'afile'
        blocker.write_text('x')
        assert 'not written' in await control.secrets([str(blocker / 'nested.md')])  # parent is a file


def test_the_model_has_no_export_tool_and_the_commands_exist_for_the_operator() -> None:
    names = set(build_tester_agent('test')._function_toolset.tools)  # pyright: ignore[reportPrivateUsage]
    # The model can access its Markdown reports. The /report and /secrets exports remain operator-only.
    report_tools = {'save_report', 'list_reports', 'read_report'}
    assert {name for name in names if 'report' in name or 'secret' in name or 'export' in name} == report_tools


async def test_plugin_registers_the_export_commands(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        token = current_control.set(ScopeControl(session))
        try:
            commands = ScopePlugin.__new__(ScopePlugin).get_commands()
        finally:
            current_control.reset(token)
    assert {command.name for command in commands} == {'scope', 'report', 'secrets'}


# ── Monty Code Mode (#83) ─────────────────────────────────────────────────────


def snippet_script(snippets: list[str]) -> Callable[[list[ModelMessage], AgentInfo], ModelResponse]:
    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        index = sum(isinstance(part, ToolReturnPart) for m in messages for part in m.parts)
        if index < len(snippets):
            return ModelResponse(parts=[ToolCallPart('run_code', {'code': snippets[index]}, tool_call_id=f'c{index}')])
        return ModelResponse(parts=[TextPart('done')])

    return respond


async def run_snippets(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, snippets: list[str], artifacts: Path | None = None
) -> tuple[list[str], int]:
    """Run each snippet through ``run_code``; return the tool results as text and the requests they sent."""
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        agent: Agent[TesterDeps, str] = build_tester_agent('test', artifacts_dir=artifacts)
        deps = TesterDeps(run_id=session.run_id, reader=tmp_store, session=session, store=tmp_store)
        opened = len(target_app.requests)  # the session's own baseline GET happens at open
        result = await agent.run('go', deps=deps, model=streaming(snippet_script(snippets)))
        sent = len(target_app.requests) - opened
    return [str(part.content) for part in tool_returns(result.all_messages())], sent


def test_code_mode_wraps_only_the_read_tools() -> None:
    assert set(CODE_MODE_TOOLS) == {name.__name__ for name in REVIEWER_TOOLS}
    assert not {'http_request', 'download_asset', 'discover_js_assets', 'run_check'} & set(CODE_MODE_TOOLS)


async def test_run_code_reads_artifacts_and_calls_read_tools(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    artifacts = tmp_path / 'arts'
    artifacts.mkdir()
    (artifacts / 'app.js').write_text('var apiKey = "x"; fetch("/api/v1/users");')
    out, _ = await run_snippets(
        tmp_store,
        tmp_path,
        target_app,
        [
            'import pathlib, re\nprint(re.findall(r"/api/[a-z0-9/]+", pathlib.Path("/artifacts/app.js").read_text()))',
            'print(await list_findings())',
        ],
        artifacts,
    )
    assert '/api/v1/users' in out[0]
    assert 'findings' in out[1] or 'partex_untrusted_data' in out[1]


async def test_save_report_writes_a_private_audited_file(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        result = await drive(
            session, tmp_store, [('save_report', {'name': 'summary-1', 'content': '# Findings\n\nSee ev_abc.'})]
        )
        (saved,) = tool_returns(result.all_messages())
        path = run_reports_dir(tmp_store.path, session.run_id) / 'summary-1.md'
        assert str(path) in str(saved.content)
        assert path.read_text() == '# Findings\n\nSee ev_abc.'
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.parent.parent.stat().st_mode) == 0o700
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert call.tool == 'save_report' and call.args['name'] == 'summary-1'
        assert 'Findings' not in json.dumps(call.args) + json.dumps(call.result)  # the audit never holds the text
        assert not any(artifact_dir(tmp_store.path).glob('**/summary-1*'))  # never beside captured evidence

        async def audit(tool: str, args: dict[str, Any], result: dict[str, Any]) -> None:
            await tmp_store.record_tool_call(session.run_id, tool, args, result)

        (read,) = await drive_code(
            session,
            tmp_store,
            ["print(await list_reports())\nprint(await read_report(name='summary-1'))"],
            audit=audit,
        )
        assert 'summary-1' in read
        assert 'See ev_abc.' in read
        _, listing, reading = await tmp_store.tool_calls(session.run_id)
        assert listing.tool == 'list_reports' and listing.result == {'count': 1}
        assert reading.tool == 'read_report' and reading.result == {'found': True}
        assert reading.args == {'name': 'summary-1', 'run': session.run_id}


@pytest.mark.parametrize(
    'name', ['', '../x', 'a/b', '/etc/passwd', '.hidden', 'x' * 65, 'a b', 'a\x00b', 'report.md/..', '..']
)
async def test_save_report_rejects_bad_names(tmp_store: RunStore, tmp_path: Path, target_app: Any, name: str) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        result = await drive(session, tmp_store, [('save_report', {'name': name, 'content': 'x'})])
        (failed,) = tool_returns(result.all_messages())
        assert getattr(failed, 'outcome', None) == 'failed'
        assert not run_reports_dir(tmp_store.path, session.run_id).exists()  # nothing was created
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert call.result['refused'] == 'invalid'


async def test_save_report_refuses_oversize_and_overwrite(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        result = await drive(
            session,
            tmp_store,
            [
                ('save_report', {'name': 'big', 'content': 'x' * (MAX_REPORT_BYTES + 1)}),
                ('save_report', {'name': 'one', 'content': 'first'}),
                ('save_report', {'name': 'one', 'content': 'second'}),
            ],
        )
        big, first, again = tool_returns(result.all_messages())
        assert getattr(big, 'outcome', None) == 'failed' and 'limit' in str(big.content)
        assert getattr(first, 'outcome', None) != 'failed'
        assert getattr(again, 'outcome', None) == 'failed' and 'already saved' in str(again.content)
        assert (run_reports_dir(tmp_store.path, session.run_id) / 'one.md').read_text() == 'first'
        assert not (run_reports_dir(tmp_store.path, session.run_id) / 'big.md').exists()


async def test_save_report_scrubs_engagement_credential_values(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    eng = engagement(tmp_path, target_app)
    manifest = json.loads((eng / 'engagement.json').read_text())
    manifest['credentials'] = {'token': 'PARTEX_CRED_TOKEN'}
    (eng / 'engagement.json').write_text(json.dumps(manifest))
    monkeypatch.setenv('PARTEX_CRED_TOKEN', 's3cr3t-value')
    async with live_session(eng, tmp_store, authorized=True) as session:
        await drive(session, tmp_store, [('save_report', {'name': 'leak', 'content': 'token is s3cr3t-value, ok'})])
        text = (run_reports_dir(tmp_store.path, session.run_id) / 'leak.md').read_text()
        assert 's3cr3t-value' not in text and REDACTED in text
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert call.result['redactions'] == 1


def test_save_report_is_a_direct_tool_not_a_code_mode_tool() -> None:
    assert 'save_report' in {tool.__name__ for tool in TESTER_TOOLS}
    assert 'save_report' not in CODE_MODE_TOOLS


def test_run_code_guidance_is_in_the_prompt() -> None:
    """The Monty-vs-CPython guidance (#103) is present and no literal ``\\n`` leaked into the prompt."""
    assert '\\n' not in TESTER_INSTRUCTIONS
    for phrase in ('Monty, a Python subset', 'sha256', '<partex_untrusted_data', 'key=str', 'read_text()'):
        assert phrase in TESTER_INSTRUCTIONS


async def test_run_code_guidance_patterns_work_in_the_sandbox(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    """What the prompt tells the model to do (#103) actually runs in Monty."""
    artifacts = tmp_path / 'arts'
    artifacts.mkdir()
    (artifacts / ('b' * 8)).write_text('two')
    (artifacts / ('a' * 8)).write_text('one')
    out, _ = await run_snippets(
        tmp_store,
        tmp_path,
        target_app,
        [
            (
                'import pathlib\n'
                'files = sorted(pathlib.Path("/artifacts").iterdir(), key=str)\n'
                'print([(p.name, p.read_text()) for p in files])'
            ),
            (
                'import re, json\n'
                'text = await list_findings()\n'
                'inner = re.sub(r"</?partex_untrusted_data[^>]*>", "", text).strip()\n'
                'print(type(json.loads(inner)).__name__)'
            ),
        ],
        artifacts,
    )
    assert "[('aaaaaaaa', 'one'), ('bbbbbbbb', 'two')]" in out[0]
    assert 'list' in out[1] or 'dict' in out[1]


@pytest.mark.parametrize(
    ('snippet', 'error'),
    [
        ('import pathlib\npathlib.Path("/artifacts/x.txt").write_text("hi")', 'PermissionError'),
        ('import socket', 'Cannot resolve imported module `socket`'),
        ('import subprocess', 'Cannot resolve imported module `subprocess`'),
        ('import os\nprint(os.environ["HOME"])', "'os.environ' is not supported"),
        ('import pathlib\nprint(pathlib.Path("/etc/passwd").read_text())', 'PermissionError'),
        ('await http_request("GET", "/")', 'Name `http_request` used when not defined'),
        ('await run_check("header-security")', 'Name `run_check` used when not defined'),
        ('await download_asset("/a.js")', 'Name `download_asset` used when not defined'),
    ],
)
async def test_run_code_cannot_escape(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, snippet: str, error: str
) -> None:
    artifacts = tmp_path / 'arts'
    artifacts.mkdir()
    out, sent = await run_snippets(tmp_store, tmp_path, target_app, [snippet], artifacts)
    assert error in out[0]
    assert sent == 0  # nothing reached the target
    assert not list(artifacts.iterdir())  # nothing was written to the mount


async def test_run_code_sees_only_this_runs_artifacts(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    """The mount is the run's own directory: earlier runs' downloads (maybe other targets') stay invisible (#83)."""
    from partex.storage import artifact_dir, run_artifact_dir

    first = tmp_path / 'first'
    first.mkdir()
    async with live_session(engagement(first, target_app), tmp_store, authorized=True, checks=()) as session:
        shared = artifact_dir(tmp_store.path)
        mine = run_artifact_dir(tmp_store.path, session.run_id)
        other = shared / 'run_someoneelse'
        for directory in (mine, other):
            directory.mkdir(parents=True)
        (shared / 'flat-old-download').write_text('from an earlier run, flat layout')
        (other / 'other-run-file').write_text('another run, maybe another target')
        (mine / 'mine.js').write_text('var mine = 1;')
    out, _ = await run_snippets(
        tmp_store,
        tmp_path,
        target_app,
        [
            'import pathlib\nprint(sorted(p.name for p in pathlib.Path("/artifacts").rglob("*")))',
            'import pathlib\nprint(pathlib.Path("/artifacts/../flat-old-download").read_text())',
            'import pathlib\nprint(pathlib.Path("/artifacts/run_someoneelse/other-run-file").read_text())',
        ],
        mine,
    )
    assert "['mine.js']" in out[0]
    assert 'earlier run' not in out[1] and 'another run' not in out[2]


def test_session_namer_is_off_for_chat_and_agent() -> None:
    """CLAI2 caps the namer at 250 output tokens, which a reasoning model spends before answering (#102)."""
    assert CHAT_SETTINGS.session_namer is False


def _unwrap_untrusted(payload: str) -> Any:
    return json.loads(payload.split('>', 1)[1].rsplit('<', 1)[0])


def _summary(result: Any) -> dict[str, Any]:
    return {k: v for k, v in result.items() if k != 'items'}


async def test_http_request_batch_sends_and_captures_evidence(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        before = len(target_app.requests)
        batch = [
            {'method': 'GET', 'path': '/'},
            {'method': 'get', 'path': '/robots.txt', 'headers': {'Authorization': 'Bearer t0k'}},
            {'method': 'GET', 'path': '/missing'},
        ]
        result = await drive(session, tmp_store, [('http_request_batch', {'requests': batch})])
        (returned,) = (str(p.content) for p in tool_returns(result.all_messages()))
        assert returned.startswith('<partex_untrusted_data kind="http_exchange_batch"')
        rows = _unwrap_untrusted(returned)
        assert [r['path'] for r in rows] == ['/', '/robots.txt', '/missing']
        assert [r['status'] for r in rows] == [200, 200, 404]
        assert all('evidence_id' in r and 'body' not in r for r in rows)
        assert len(target_app.requests) == before + 3

        stored_ids = {e.id for e in await tmp_store.evidence(session.run_id)}
        assert {r['evidence_id'] for r in rows} <= stored_ids

        (call,) = await tmp_store.tool_calls(session.run_id)
        assert call.tool == 'http_request_batch'
        assert _summary(call.result) == {'total': 3, 'sent': 3, 'refused': 0, 'errored': 0}
        assert [r['method'] for r in call.args['requests']] == ['GET', 'GET', 'GET']
        assert call.args['requests'][1]['header_names'] == ['Authorization']
        assert call.result['items'] == rows
        assert 't0k' not in json.dumps(call.args) + json.dumps(call.result)


async def test_http_request_batch_partial_failure_keeps_successful_results(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        before = len(target_app.requests)
        batch = [
            {'method': 'GET', 'path': '/robots.txt'},
            {'method': 'POST', 'path': '/'},
            {'method': 'GET', 'path': '/admin/shutdown'},
            {'method': 'GET', 'path': 'http://evil.test/'},
            {'method': 'GET', 'path': '/'},
        ]
        result = await drive(session, tmp_store, [('http_request_batch', {'requests': batch})])
        (returned,) = (str(p.content) for p in tool_returns(result.all_messages()))
        rows = _unwrap_untrusted(returned)
        assert len(rows) == 5
        assert rows[0]['path'] == '/robots.txt' and 'evidence_id' in rows[0]
        assert rows[1]['refused'] == 'method'
        assert rows[2]['refused'] == 'scope'
        assert rows[3]['refused'] == 'scope'
        assert rows[4]['path'] == '/' and 'evidence_id' in rows[4]
        assert len(target_app.requests) == before + 2

        (call,) = await tmp_store.tool_calls(session.run_id)
        assert _summary(call.result) == {'total': 5, 'sent': 2, 'refused': 3, 'errored': 0}
        assert [r.get('refused') for r in call.result['items']] == [None, 'method', 'scope', 'scope', None]
        assert rows[2]['kind'] == 'path'
        assert 'outside the engagement rules' in rows[2]['reason']


async def test_http_request_batch_enforces_item_cap(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        before = list(target_app.requests)
        batch = [{'method': 'GET', 'path': f'/p{i}'} for i in range(BATCH_MAX_ITEMS + 1)]
        result = await drive(session, tmp_store, [('http_request_batch', {'requests': batch})])
        (failed,) = tool_returns(result.all_messages())
        assert getattr(failed, 'outcome', None) == 'failed'
        assert str(BATCH_MAX_ITEMS) in str(failed.content)
        assert target_app.requests == before
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert call.result == {'refused': 'cap'}


async def test_http_request_batch_accepts_exactly_the_cap_and_empty(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        full = [{'method': 'GET', 'path': f'/p{i}'} for i in range(BATCH_MAX_ITEMS)]
        result = await drive(
            session,
            tmp_store,
            [('http_request_batch', {'requests': full}), ('http_request_batch', {'requests': []})],
        )
        first, second = (_unwrap_untrusted(str(p.content)) for p in tool_returns(result.all_messages()))
        assert len(first) == BATCH_MAX_ITEMS and all('evidence_id' in r for r in first)
        assert second == []


async def test_http_request_batch_reports_failed_and_unexpected_items(
    tmp_store: RunStore, tmp_path: Path, target_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        real = session.request

        async def flaky(method: str, url: str, **kwargs: Any) -> Any:
            if url.endswith('/boom'):
                raise PartexError('connection reset')
            if url.endswith('/bug'):
                raise RuntimeError('unexpected')
            return await real(method, url, **kwargs)

        monkeypatch.setattr(session, 'request', flaky)
        batch = [{'method': 'GET', 'path': p} for p in ('/', '/boom', '/bug', '/robots.txt')]
        result = await drive(session, tmp_store, [('http_request_batch', {'requests': batch})])
        (returned,) = (str(p.content) for p in tool_returns(result.all_messages()))
        rows = _unwrap_untrusted(returned)
        assert [r.get('error') for r in rows] == [None, 'request_failed', 'internal', None]
        assert 'evidence_id' in rows[0] and 'evidence_id' in rows[3]
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert _summary(call.result) == {'total': 4, 'sent': 2, 'refused': 0, 'errored': 2}


async def test_http_request_batch_respects_budget_under_concurrency(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    async with live_session(engagement(tmp_path, target_app, max_requests=4), tmp_store, authorized=True) as session:
        # Baseline used 1 request; 3 remain in the budget for the 6-item batch.
        batch = [{'method': 'GET', 'path': f'/item-{i}'} for i in range(6)]
        result = await drive(session, tmp_store, [('http_request_batch', {'requests': batch})])
        (returned,) = (str(p.content) for p in tool_returns(result.all_messages()))
        rows = _unwrap_untrusted(returned)
        sent_rows = [r for r in rows if 'evidence_id' in r]
        budget_rows = [r for r in rows if r.get('refused') == 'budget']
        assert len(sent_rows) == 3
        assert len(budget_rows) == 3
        assert len(target_app.requests) == 4
        assert session.requests_spent == 4

        (call,) = await tmp_store.tool_calls(session.run_id)
        assert _summary(call.result) == {'total': 6, 'sent': 3, 'refused': 3, 'errored': 0}


async def test_http_request_batch_is_direct_tool_not_code_mode_tool(
    tmp_store: RunStore, tmp_path: Path, target_app: Any
) -> None:
    assert 'http_request_batch' in {tool.__name__ for tool in TESTER_TOOLS}
    assert 'http_request_batch' not in CODE_MODE_TOOLS
    out, sent = await run_snippets(
        tmp_store,
        tmp_path,
        target_app,
        ['await http_request_batch([{"method": "GET", "path": "/"}])'],
    )
    assert 'Name `http_request_batch` used when not defined' in out[0]
    assert sent == 0


def test_tester_instructions_describe_batch_workflow() -> None:
    assert 'http_request_batch' in TESTER_INSTRUCTIONS
    assert 'run_code' in TESTER_INSTRUCTIONS
    assert str(BATCH_MAX_ITEMS) in TESTER_INSTRUCTIONS


def test_scope_refusal_advice_depends_on_the_rule() -> None:
    from partex.agent_adapter.tester import scope_refusal_advice
    from partex.errors import ScopeViolation

    assert '/scope add <url>' in scope_refusal_advice(ScopeViolation('x', kind='url-list'))
    assert '/scope add <host[:port]>' in scope_refusal_advice(ScopeViolation('x', kind='host'))
    assert '/scope add <host[:port]>' in scope_refusal_advice(ScopeViolation('x', kind='port'))
    assert 'outside the engagement rules' in scope_refusal_advice(ScopeViolation('x', kind='path'))


async def test_run_check_rule_id_names_the_owning_check(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True) as session:
        result = await drive(session, tmp_store, [('run_check', {'check_id': 'error-page-disclosure'})])
        [retried] = tool_returns(result.all_messages())
        assert retried.outcome == 'retried'
        assert 'reported by the version-disclosure check' in str(retried.content)


async def test_download_asset_audit_row_records_status(tmp_store: RunStore, tmp_path: Path, target_app: Any) -> None:
    """download_asset rows carry the response status and evidence ID, like http_request rows (#126)."""
    async with live_session(engagement(tmp_path, target_app), tmp_store, authorized=True, checks=()) as session:
        await drive(session, tmp_store, [('download_asset', {'path': '/robots.txt'})])
        (call,) = await tmp_store.tool_calls(session.run_id)
        assert call.tool == 'download_asset'
        assert call.result['status'] == 200 and call.result['evidence_id'].startswith('ev_')
