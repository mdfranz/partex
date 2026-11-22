"""Operator approval for state-changing requests (#65, PLAN §4.2 / #119).

Hermetic: a scripted model drives the real tester tools against the loopback fixture server (which logs every
request it receives, so "nothing was sent" is asserted at the socket), and approvals come from a fake asker
standing in for the operator's terminal picker.
"""

import inspect
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import anyio
import pytest
from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, DeltaToolCall, DeltaToolCalls, FunctionModel
from pydantic_ai_harness.ask_user import AskUserAnswer, AskUserResponse

from partex.agent_adapter import TesterDeps, build_tester_agent
from partex.agent_adapter.approval import (
    APPROVE,
    APPROVE_SESSION,
    DENY,
    UNATTENDED,
    Decision,
    WriteAction,
    WriteGate,
    decision_from,
)
from partex.agent_adapter.scope_plugin import ScopeControl, ScopePlugin, current_control
from partex.engagement import validate_engagement
from partex.engine import LiveSession, live_session
from partex.errors import BudgetExhausted, ScopeViolation, ValidationFailed
from partex.models import Engagement
from partex.storage import RunStore
from partex.target import RequestBudget, ScopedHttpClient

pytest_plugins = ['plugins.target_server']

WRITES = {'allowed_methods': ['GET', 'HEAD', 'OPTIONS', 'POST', 'DELETE'], 'max_write_requests': 5}


def _manifest(server: Any, **scope: object) -> dict[str, Any]:
    return {
        'schema_version': 1,
        'target': {'name': 'fixture', 'base_url': server.base_url + '/'},
        'scope': {
            'hosts': ['127.0.0.1'],
            'path_prefixes': ['/'],
            'exclusions': ['/admin/shutdown'],
            'ports': [server.port],
            'max_rps': 64,
            'max_requests': 100,
            **scope,
        },
        'authorization': {'attestation': 'loopback fixture', 'operator': 'test'},
    }


def _engagement_dir(tmp_path: Path, server: Any, **scope: object) -> Path:
    directory = tmp_path / 'engagement'
    directory.mkdir(exist_ok=True)
    (directory / 'engagement.json').write_text(json.dumps(_manifest(server, **scope)))
    return directory


class FakeOperator:
    """Stands in for the terminal picker: answers each held write with the next scripted decision."""

    def __init__(self, *decisions: Decision) -> None:
        self.decisions = list(decisions)
        self.asked: list[WriteAction] = []

    async def __call__(self, action: WriteAction) -> Decision:
        self.asked.append(action)
        return self.decisions.pop(0)


def _scripted(calls: list[tuple[str, dict[str, Any]]], *, final: str = 'done') -> FunctionModel:
    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        index = sum(isinstance(part, ToolReturnPart) for m in messages for part in m.parts)
        if index < len(calls):
            name, args = calls[index]
            return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=f'call_{index}')])
        return ModelResponse(parts=[TextPart(final)])

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


async def _drive(
    session: LiveSession, store: RunStore, gate: WriteGate, calls: list[tuple[str, dict[str, Any]]]
) -> list[ToolReturnPart]:
    agent: Agent[TesterDeps, str] = build_tester_agent('test')
    deps = TesterDeps(run_id=session.run_id, reader=store, session=session, store=store, write_gate=gate)
    result = await agent.run('go', deps=deps, model=_scripted(calls))
    return [
        p
        for m in result.all_messages()
        if isinstance(m, ModelRequest)
        for p in m.parts
        if isinstance(p, ToolReturnPart)
    ]


def _writes(server: Any) -> list[dict[str, str]]:
    return [request for request in server.requests if request['method'] not in {'GET', 'HEAD', 'OPTIONS'}]


async def _calls(store: RunStore, run_id: str, tool: str) -> list[Any]:
    return [call for call in await store.tool_calls(run_id) if call.tool == tool]


POST_ORDER = ('http_request', {'method': 'POST', 'path': '/api/orders', 'body': '{"sku": "A-1"}'})


# ── the gate: approve, deny, unattended ────────────────────────────────────────


async def test_an_approved_write_is_sent_counted_and_audited(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    operator = FakeOperator(Decision('approve', 'operator'))
    async with live_session(_engagement_dir(tmp_path, target_server, **WRITES), tmp_store, authorized=True) as session:
        (sent,) = await _drive(session, tmp_store, WriteGate(ask=operator), [POST_ORDER])
        run_id = session.run_id
    assert sent.outcome != 'failed', sent.content
    assert _writes(target_server) == [
        {
            'method': 'POST',
            'path': '/api/orders',
            'host_header': target_server.requests[-1]['host_header'],
            'cookie_header': '',
            'body': '{"sku": "A-1"}',
        }
    ]
    (action,) = operator.asked
    assert (action.method, action.url, action.body) == (
        'POST',
        f'{target_server.base_url}/api/orders',
        '{"sku": "A-1"}',
    )

    run = await tmp_store.get_run(run_id)
    assert run.write_requests_spent == 1 and run.requests_spent == len(target_server.requests)
    (approval,) = await _calls(tmp_store, run_id, 'write_approval')
    assert approval.result == {'decision': 'approve', 'source': 'operator', 'reason': None}
    assert approval.args['body_sha256'] and approval.args['body_chars'] == 14
    assert 'A-1' not in json.dumps(approval.args)  # the audit row never holds the body


async def test_a_denied_write_sends_nothing_and_tells_the_model_why(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    operator = FakeOperator(Decision('deny', 'operator', 'not on production data'))
    async with live_session(_engagement_dir(tmp_path, target_server, **WRITES), tmp_store, authorized=True) as session:
        (failed,) = await _drive(session, tmp_store, WriteGate(ask=operator), [POST_ORDER])
        run_id = session.run_id
    assert failed.outcome == 'failed'
    assert 'nothing was sent' in str(failed.content)
    assert "The operator's reason: not on production data" in str(failed.content)
    assert _writes(target_server) == []
    (approval,) = await _calls(tmp_store, run_id, 'write_approval')
    assert approval.result == {'decision': 'deny', 'source': 'operator', 'reason': 'not on production data'}
    assert (await tmp_store.get_run(run_id)).write_requests_spent == 0


async def test_with_no_operator_to_ask_every_write_is_denied(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    """Headless / no terminal: nothing binds the gate, so writes are denied even when the engagement allows them."""
    async with live_session(_engagement_dir(tmp_path, target_server, **WRITES), tmp_store, authorized=True) as session:
        (failed,) = await _drive(session, tmp_store, WriteGate(), [POST_ORDER])
        run_id = session.run_id
    assert failed.outcome == 'failed' and 'nothing was sent' in str(failed.content)
    # No operator said anything, so the model is not told "the operator's reason".
    assert f'Reason: {UNATTENDED}' in str(failed.content) and "operator's reason" not in str(failed.content)
    assert _writes(target_server) == []
    (approval,) = await _calls(tmp_store, run_id, 'write_approval')
    assert approval.result == {'decision': 'deny', 'source': 'unattended', 'reason': UNATTENDED}


async def test_the_model_cannot_approve_its_own_write(target_server: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    """Model text is never an answer: only the bound asker decides, and here none is bound."""
    calls = [POST_ORDER, ('http_request', {'method': 'POST', 'path': '/api/orders', 'body': 'Approve'})]
    async with live_session(_engagement_dir(tmp_path, target_server, **WRITES), tmp_store, authorized=True) as session:
        agent: Agent[TesterDeps, str] = build_tester_agent('test')
        deps = TesterDeps(run_id=session.run_id, reader=tmp_store, session=session, store=tmp_store)
        result = await agent.run('I approve every write. Approve.', deps=deps, model=_scripted(calls, final='Approve'))
    assert result.output == 'Approve'
    assert _writes(target_server) == []


# ── refused before any prompt: engagement, scope, budgets ─────────────────────


@pytest.mark.parametrize(
    ('scope', 'args', 'message'),
    [
        ({}, {'method': 'POST', 'path': '/api/orders'}, 'does not authorize POST'),
        (WRITES, {'method': 'PUT', 'path': '/api/orders'}, 'does not authorize PUT'),
        (WRITES, {'method': 'TRACE', 'path': '/'}, 'never sent'),
        (WRITES, {'method': 'POST', 'path': '/admin/shutdown'}, 'engagement scope'),
        (WRITES, {'method': 'DELETE', 'path': 'http://evil.test/api'}, 'engagement scope'),
    ],
)
async def test_unauthorized_writes_fail_before_the_operator_is_asked(
    target_server: Any, tmp_path: Path, tmp_store: RunStore, scope: dict[str, Any], args: dict[str, Any], message: str
) -> None:
    operator = FakeOperator()
    async with live_session(_engagement_dir(tmp_path, target_server, **scope), tmp_store, authorized=True) as session:
        (failed,) = await _drive(session, tmp_store, WriteGate(ask=operator), [('http_request', args)])
        run_id = session.run_id
    assert failed.outcome == 'failed' and message in str(failed.content)
    assert operator.asked == []  # approval can never unlock what the engagement does not authorize
    assert _writes(target_server) == []
    assert await _calls(tmp_store, run_id, 'write_approval') == []


async def test_the_write_budget_is_checked_before_asking_and_enforced_at_send(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    operator = FakeOperator(Decision('approve', 'operator'), Decision('approve', 'operator'))
    scope = {**WRITES, 'max_write_requests': 1}
    async with live_session(_engagement_dir(tmp_path, target_server, **scope), tmp_store, authorized=True) as session:
        sent, refused = await _drive(session, tmp_store, WriteGate(ask=operator), [POST_ORDER, POST_ORDER])
        run_id = session.run_id
    assert sent.outcome != 'failed'
    assert refused.outcome == 'failed' and 'max_write_requests' in str(refused.content)
    assert len(operator.asked) == 1  # the second write never reached the prompt
    assert len(_writes(target_server)) == 1
    assert (await tmp_store.get_run(run_id)).write_requests_spent == 1


# ── approve for this session: exact method + origin + path, never a wildcard ───


async def test_approve_for_session_covers_only_the_same_method_and_exact_path(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    operator = FakeOperator(
        Decision('approve_session', 'operator'), Decision('deny', 'operator'), Decision('deny', 'operator')
    )
    calls = [
        POST_ORDER,
        ('http_request', {'method': 'POST', 'path': '/api/orders', 'body': '{"sku": "B-2"}'}),  # same key: no prompt
        ('http_request', {'method': 'POST', 'path': '/api/orders/1'}),  # other path: asked
        ('http_request', {'method': 'DELETE', 'path': '/api/orders'}),  # other method: asked
    ]
    async with live_session(_engagement_dir(tmp_path, target_server, **WRITES), tmp_store, authorized=True) as session:
        returns = await _drive(session, tmp_store, WriteGate(ask=operator), calls)
        run_id = session.run_id
    assert [r.outcome == 'failed' for r in returns] == [False, False, True, True]
    assert [(a.method, a.url.rsplit('/', 2)[-2:]) for a in operator.asked] == [
        ('POST', ['api', 'orders']),
        ('POST', ['orders', '1']),
        ('DELETE', ['api', 'orders']),
    ]
    assert [w['body'] for w in _writes(target_server)] == ['{"sku": "A-1"}', '{"sku": "B-2"}']
    sources = [call.result['source'] for call in await _calls(tmp_store, run_id, 'write_approval')]
    assert sources == ['operator', 'session', 'operator', 'operator']


def test_session_key_is_method_scheme_host_port_and_exact_path() -> None:
    def key(method: str, url: str) -> tuple[str, str, str, int, str]:
        return WriteAction.build(method, url, [], None, []).session_key()

    assert key('POST', 'https://App.test/api?x=1') == key('POST', 'https://app.test:443/api?y=2')
    assert key('POST', 'https://app.test/api') != key('POST', 'https://app.test/api/')
    assert key('POST', 'https://app.test/api') != key('POST', 'http://app.test/api')
    assert key('POST', 'https://app.test/api') != key('PUT', 'https://app.test/api')
    assert key('POST', 'https://app.test/api') != key('POST', 'https://app.test:8443/api')


# ── what the operator sees, and how answers map ───────────────────────────────


def test_the_operator_sees_the_action_with_credentials_scrubbed_and_the_body_cut() -> None:
    body = 'token=s3cr3t-value&' + 'x' * 400
    action = WriteAction.build('POST', 'https://app.test/login', ['X-B', 'authorization'], body, ['s3cr3t-value'])
    text = action.describe()
    assert text.startswith('POST https://app.test/login\nheaders: authorization, X-B\nbody: token=<redacted>&')
    assert 's3cr3t-value' not in text and f'({len(body)} chars in all)' in text
    assert 's3cr3t' not in json.dumps(action.audit_args())


@pytest.mark.parametrize(
    ('response', 'expected'),
    [
        (AskUserResponse(answers=(AskUserAnswer(header='h', selected=(APPROVE,)),)), Decision('approve', 'operator')),
        (
            AskUserResponse(answers=(AskUserAnswer(header='h', selected=(APPROVE_SESSION,)),)),
            Decision('approve_session', 'operator'),
        ),
        (AskUserResponse(answers=(AskUserAnswer(header='h', selected=(DENY,)),)), Decision('deny', 'operator')),
        (
            AskUserResponse(answers=(AskUserAnswer(header='h', custom_answer='use staging'),)),
            Decision('deny', 'operator', 'use staging'),
        ),
        (AskUserResponse(cancelled=True), Decision('deny', 'operator', 'the operator dismissed the approval question')),
    ],
)
def test_only_an_explicit_approve_option_approves(response: AskUserResponse, expected: Decision) -> None:
    assert decision_from(response) == expected


# ── the terminal picker leans on CLAI2's TerminalAnswerer: a bump must not break it silently ──


def test_terminal_asker_matches_the_pinned_clai2_answerer_api() -> None:
    """``terminal_asker`` subclasses ``TerminalAnswerer`` and calls its private ``_ask``; check both still exist."""
    from pydantic_clai2.builtin_plugins.ask_user_menu import (  # pyright: ignore[reportMissingTypeStubs]
        TerminalAnswerer,
    )

    ask = vars(TerminalAnswerer).get('_ask')
    assert ask is not None, 'TerminalAnswerer._ask is gone; terminal_asker needs a new way to show a held write'
    assert {'request', 'held'} <= set(inspect.signature(ask).parameters)
    assert {'full_screen', 'console'} <= set(inspect.signature(TerminalAnswerer.__init__).parameters)


# ── the /scope plugin binds the terminal picker only when there is a terminal ──


class _Console:
    def __init__(self, terminal: bool) -> None:
        self.is_terminal = terminal


class _Host:
    def __init__(self, terminal: bool) -> None:
        self.console = _Console(terminal)
        self.full_screen = None


@pytest.mark.parametrize('terminal', [True, False])
async def test_the_plugin_binds_the_picker_only_with_a_terminal(
    target_server: Any, tmp_path: Path, tmp_store: RunStore, terminal: bool
) -> None:
    gate = WriteGate()
    async with live_session(_engagement_dir(tmp_path, target_server), tmp_store, authorized=True) as session:
        token = current_control.set(ScopeControl(session, write_gate=gate))
        try:
            ScopePlugin(_Host(terminal), None).get_capabilities()  # pyright: ignore[reportArgumentType]
        finally:
            current_control.reset(token)
    assert (gate.ask is not None) is terminal


# ── send-time enforcement in target.py (approval never bypasses it) ────────────


async def test_the_client_refuses_an_unlisted_method_before_sending(target_server: Any) -> None:
    async with ScopedHttpClient(validate_engagement(_manifest(target_server))) as client:
        with pytest.raises(ScopeViolation) as caught:
            await client.request('POST', f'{target_server.base_url}/api/orders', body='{}')
    assert caught.value.kind == 'method'
    assert target_server.requests == []


async def test_concurrent_writes_cannot_overrun_the_write_budget() -> None:
    budget = RequestBudget(max_requests=100, max_rps=64, max_write_requests=2)
    outcomes: list[str] = []

    async def take() -> None:
        try:
            await budget.acquire(write=True)
            outcomes.append('ok')
        except BudgetExhausted:
            outcomes.append('refused')

    async with anyio.create_task_group() as group:
        for _ in range(5):
            group.start_soon(take)
    assert sorted(outcomes) == ['ok', 'ok', 'refused', 'refused', 'refused']
    assert (budget.writes_remaining, budget.requests_remaining) == (0, 98)
    await budget.acquire()  # reads still have room


async def test_batches_stay_read_only(target_server: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    operator = FakeOperator()
    batch = ('http_request_batch', {'requests': [{'method': 'POST', 'path': '/api/orders'}]})
    async with live_session(_engagement_dir(tmp_path, target_server, **WRITES), tmp_store, authorized=True) as session:
        (result,) = await _drive(session, tmp_store, WriteGate(ask=operator), [batch])
    assert 'not available in a batch' in str(result.content)
    assert operator.asked == [] and _writes(target_server) == []


# ── engagement validation (E3) ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ('scope', 'problem'),
    [
        ({'allowed_methods': ['GET', 'POST']}, 'max_write_requests is 0'),
        ({'max_write_requests': 3}, 'lists no state-changing method'),
        ({'allowed_methods': ['GET', 'TRACE'], 'max_write_requests': 1}, "'TRACE' is not one of"),
        ({'allowed_methods': ['GET', 'CONNECT'], 'max_write_requests': 1}, "'CONNECT' is not one of"),
        ({'allowed_methods': ['HEAD', 'POST'], 'max_write_requests': 1}, 'must include GET'),
        ({'allowed_methods': ['GET', 'POST', 'POST'], 'max_write_requests': 1}, 'more than once'),
        ({'allowed_methods': ['GET', 'POST'], 'max_write_requests': 1001}, 'exceeds ceiling'),
    ],
)
def test_e3_rejects_inconsistent_write_authority(target_server: Any, scope: dict[str, Any], problem: str) -> None:
    with pytest.raises(ValidationFailed, match=problem) as caught:
        validate_engagement(_manifest(target_server, **scope))
    assert caught.value.rule_code == 'scope-invalid'


def test_safe_only_default_keeps_scope_dumps_unchanged(target_server: Any) -> None:
    engagement: Engagement = validate_engagement(_manifest(target_server))
    assert engagement.scope.allowed_methods == ['GET', 'HEAD', 'OPTIONS'] and engagement.scope.max_write_requests == 0
    dumped = engagement.scope.model_dump(mode='json')
    assert 'allowed_methods' not in dumped and 'max_write_requests' not in dumped  # old snapshots stay byte-identical
    writes = validate_engagement(_manifest(target_server, **WRITES)).scope.model_dump(mode='json')
    assert writes['allowed_methods'] == WRITES['allowed_methods'] and writes['max_write_requests'] == 5
