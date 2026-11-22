"""Role-scoped client handles — PLAN §4.1 D2 (issue #23).

Two roles against the localhost fixture server: isolated cookie jars, one
shared budget pool and DNS pin table, identical scope refusals, and
role-credential ``secret_fields`` marking.  No test opens a non-loopback
socket.
"""

import pytest

from partex.engagement import Engagement
from partex.errors import BudgetExhausted, ScopeViolation, ValidationFailed
from partex.models import redact
from partex.roles import resolve_role_credentials, role_handles
from partex.target import DEFAULT_SOURCE

pytest_plugins = ['plugins.target_server']

ROLE_ENV = {'PARTEX_CRED_OWNER': 'owner-secret-token', 'PARTEX_CRED_GUEST': 'guest-secret-token'}


def roles_engagement(target_server: object, **scope: object) -> Engagement:
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
    scope_data: dict[str, object] = {
        'hosts': ['127.0.0.1'],
        'path_prefixes': ['/'],
        'exclusions': ['/admin/shutdown'],
        'ports': [port],
        'max_rps': 64,
        'max_requests': 100,
    }
    scope_data.update(scope)
    return Engagement.model_validate(
        {
            'schema_version': 1,
            'target': {'name': 'fixture-app', 'base_url': base_url},
            'scope': scope_data,
            'authorization': {'attestation': 'local fixture app on loopback', 'operator': 'test'},
            'roles': {'owner': 'PARTEX_CRED_OWNER', 'guest': 'PARTEX_CRED_GUEST'},
        }
    )


async def close_all(handles: dict[str, object]) -> None:
    for handle in handles.values():
        await handle.client.aclose()  # pyright: ignore[reportAttributeAccessIssue]


# ── Handle creation ──────────────────────────────────────────────────────────


async def test_one_isolated_client_per_role(target_server: object) -> None:
    handles = role_handles(roles_engagement(target_server), env=ROLE_ENV)
    try:
        assert set(handles) == {'owner', 'guest'}
        owner, guest = handles['owner'], handles['guest']
        assert owner.role == 'owner'
        assert owner.env_var == 'PARTEX_CRED_OWNER'
        assert owner.credential == 'owner-secret-token'
        assert owner.client is not guest.client  # separate handles, separate cookie jars
    finally:
        await close_all(handles)


async def test_missing_role_env_fails_before_any_client(target_server: object) -> None:
    before = len(target_server.requests)  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(ValidationFailed) as excinfo:
        role_handles(roles_engagement(target_server), env={'PARTEX_CRED_OWNER': 'x'})
    assert excinfo.value.rule_code == 'credential-missing'
    assert 'guest' in str(excinfo.value)
    assert 'PARTEX_CRED_GUEST' in str(excinfo.value)
    assert len(target_server.requests) == before  # pyright: ignore[reportAttributeAccessIssue]


def test_resolve_role_credentials_returns_role_env_pairs() -> None:
    resolved = resolve_role_credentials(roles_engagement_from_manifest(), env=ROLE_ENV)
    assert resolved == {
        'owner': ('PARTEX_CRED_OWNER', 'owner-secret-token'),
        'guest': ('PARTEX_CRED_GUEST', 'guest-secret-token'),
    }


def roles_engagement_from_manifest() -> Engagement:
    import json
    from pathlib import Path

    from partex.engagement import load_engagement

    directory = Path(__file__).parent.parent / 'fixtures' / 'engagements' / 'roles'
    assert json.loads((directory / 'engagement.json').read_text())['roles'] == {
        'owner': 'PARTEX_CRED_OWNER',
        'guest': 'PARTEX_CRED_GUEST',
    }
    return load_engagement(directory)


# ── Provenance, isolation, and the shared gate ───────────────────────────────


async def test_captures_cite_their_role_in_source(target_server: object) -> None:
    handles = role_handles(roles_engagement(target_server), env=ROLE_ENV)
    try:
        base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
        owner = await handles['owner'].client.request('GET', f'{base_url}/api/owner')
        guest = await handles['guest'].client.request('GET', f'{base_url}/api/guest')
        assert owner.source == f'{DEFAULT_SOURCE}:role=owner'
        assert guest.source == f'{DEFAULT_SOURCE}:role=guest'
    finally:
        await close_all(handles)


async def test_cookie_jars_are_isolated_per_role(target_server: object) -> None:
    handles = role_handles(roles_engagement(target_server), env=ROLE_ENV)
    try:
        base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
        await handles['owner'].client.request('GET', f'{base_url}/set-cookie?value=owner-session')
        await handles['owner'].client.request('GET', f'{base_url}/api/again')
        await handles['guest'].client.request('GET', f'{base_url}/api/guest-view')
        owner_cookie = target_server.requests[-2]['cookie_header']  # pyright: ignore[reportAttributeAccessIssue]
        guest_cookie = target_server.requests[-1]['cookie_header']  # pyright: ignore[reportAttributeAccessIssue]
        assert owner_cookie == 'role_marker=owner-session'
        assert guest_cookie == ''  # guest never saw the owner's session
    finally:
        await close_all(handles)


async def test_scope_refusal_is_identical_per_role(target_server: object) -> None:
    handles = role_handles(roles_engagement(target_server), env=ROLE_ENV)
    try:
        port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
        before = len(target_server.requests)  # pyright: ignore[reportAttributeAccessIssue]
        with pytest.raises(ScopeViolation, match='not in scope hosts'):
            await handles['guest'].client.request('GET', f'http://evil-example.test:{port}/api/x')
        with pytest.raises(ScopeViolation, match='exclusion'):
            await handles['owner'].client.request('GET', f'{target_server.base_url}/admin/shutdown')  # pyright: ignore[reportAttributeAccessIssue]
        assert len(target_server.requests) == before  # pyright: ignore[reportAttributeAccessIssue]
    finally:
        await close_all(handles)


async def test_budget_is_shared_not_doubled(target_server: object) -> None:
    handles = role_handles(roles_engagement(target_server, max_requests=3), env=ROLE_ENV)
    try:
        base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
        await handles['owner'].client.request('GET', f'{base_url}/api/one')
        await handles['owner'].client.request('GET', f'{base_url}/api/two')
        await handles['guest'].client.request('GET', f'{base_url}/api/three')
        # With per-client budgets the 4th request would succeed; the shared
        # pool makes it the engagement's 4th, which is over.
        with pytest.raises(BudgetExhausted, match='max_requests'):
            await handles['owner'].client.request('GET', f'{base_url}/api/four')
        assert handles['owner'].client.requests_spent == 3
        assert handles['guest'].client.requests_spent == 3  # same pool, visible from either handle
    finally:
        await close_all(handles)


async def test_dns_pins_are_shared_across_roles(target_server: object) -> None:
    port = target_server.port  # pyright: ignore[reportAttributeAccessIssue]
    engagement = roles_engagement(target_server, hosts=['fixture.test'], ports=[port])
    resolutions: list[str] = []

    def resolver(host: str) -> str:
        resolutions.append(host)
        return '127.0.0.1'

    handles = role_handles(engagement, env=ROLE_ENV, resolver=resolver)
    try:
        url = f'http://fixture.test:{port}/api/x'
        await handles['owner'].client.request('GET', url)
        await handles['guest'].client.request('GET', url)
        assert resolutions == ['fixture.test']  # one pin per host per engagement, not per role
    finally:
        await close_all(handles)


# ── Secrets: role credentials marked and redactable ──────────────────────────


async def test_role_credentials_marked_secret_and_redacted(target_server: object) -> None:
    engagement = roles_engagement(
        target_server, allowed_methods=['GET', 'HEAD', 'OPTIONS', 'POST'], max_write_requests=5
    )
    handles = role_handles(engagement, env=ROLE_ENV)
    try:
        base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
        owner = await handles['owner'].client.request(
            'POST', f'{base_url}/api/login', headers={'Authorization': 'Bearer owner-secret-token'}
        )
        guest = await handles['guest'].client.request(
            'POST', f'{base_url}/api/login', headers={'Authorization': 'Bearer guest-secret-token'}
        )
        # Exactly one secret path per capture, wherever the header landed in
        # wire order; redaction replaces the bearer value, not its position.
        assert len(owner.secret_fields) == 1
        assert len(guest.secret_fields) == 1
        assert all('owner-secret-token' not in value for _, value in redact(owner).http.request.headers)
        assert all('guest-secret-token' not in value for _, value in redact(guest).http.request.headers)
        assert any(value == '<redacted>' for _, value in redact(owner).http.request.headers)
        assert any(value == '<redacted>' for _, value in redact(guest).http.request.headers)
    finally:
        await close_all(handles)


async def test_on_capture_receives_role_tagged_evidence(target_server: object) -> None:
    captured: list[object] = []

    async def on_capture(evidence: object) -> None:
        captured.append(evidence)

    handles = role_handles(roles_engagement(target_server), env=ROLE_ENV, on_capture=on_capture)
    try:
        base_url = target_server.base_url  # pyright: ignore[reportAttributeAccessIssue]
        await handles['guest'].client.request('GET', f'{base_url}/api/x')
        assert len(captured) == 1
        assert captured[0].source == f'{DEFAULT_SOURCE}:role=guest'  # pyright: ignore[reportAttributeAccessIssue]
    finally:
        await close_all(handles)
