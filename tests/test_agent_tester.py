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

from partex import engine
from partex.agent_adapter import TesterDeps, build_tester_agent, run_agent
from partex.agent_adapter.tester import MODEL_BODY_CHARS
from partex.engine import LiveSession, LiveSessionRefused, live_session
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
    assert call['load_plugins'] is False and call['settings'].code_mode is False
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
