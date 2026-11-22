"""authz-boundary — BOLA/IDOR/BFLA role-pair probing (issue #27).

All live tests run against the localhost fixture target app; the suite's non-loopback socket
block stays armed.  The two-role rule is asserted end to end: a finding never rests on a
single response, and enforced boundaries yield ``no_issue_found`` coverage rather than
findings.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from partex.checks.authorization import (
    CHECK_ID,
    authz_boundary_check,
    harvest_candidates,
)
from partex.engine import run_test
from partex.ids import evidence_id
from partex.models import Finding, HttpEvidence, HttpExchange, HttpRequest, HttpResponse
from partex.roles import RoleHandle
from partex.storage import RunStore

ROLE_ENV = {'PARTEX_CRED_OWNER': 'owner-secret-token', 'PARTEX_CRED_GUEST': 'guest-secret-token'}


# ── Fixtures and helpers ──────────────────────────────────────────────────────


def make_exchange(
    url: str,
    method: str = 'GET',
    headers: list[tuple[str, str]] | None = None,
    status: int = 200,
    body: str | None = 'ok',
) -> HttpEvidence:
    request = HttpRequest(method=method, url=url, headers=headers or [('Host', '127.0.0.1')])
    evidence = HttpEvidence(
        id='',
        source='capture:test',
        http=HttpExchange(
            request=request,
            response=HttpResponse(status_code=status, headers=[('Content-Type', 'application/json')], body=body),
        ),
    )
    return evidence.model_copy(update={'id': evidence_id(evidence)})


def write_bundle(root: Path, exchanges: Sequence[HttpEvidence]) -> Path:
    evidence_dir = root / 'evidence'
    evidence_dir.mkdir(parents=True)
    names: list[str] = []
    for index, item in enumerate(exchanges, start=1):
        name = f'evidence/{index:04d}.json'
        (root / name).write_text(json.dumps(item.model_dump(mode='json', exclude={'id', 'source'})))
        names.append(name)
    (root / 'bundle.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'target', 'base_url': 'http://127.0.0.1:1'},
                'evidence_files': names,
            }
        )
    )
    return root


def engagement_dir(tmp_path: Path, server: Any, *, roles: bool = True, **scope: object) -> Path:
    """A dynamic fixture engagement pointing at the ephemeral fixture app, optionally with roles."""
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
    manifest: dict[str, Any] = {
        'schema_version': 1,
        'target': {'name': 'fixture-app', 'base_url': base_url},
        'scope': scope_data,
        'authorization': {'attestation': 'local fixture app on loopback', 'operator': 'test'},
        'suggested_checks': ['authz-boundary'],
    }
    if roles:
        manifest['roles'] = {'owner': 'PARTEX_CRED_OWNER', 'guest': 'PARTEX_CRED_GUEST'}
    directory = tmp_path / 'engagement'
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'engagement.json').write_text(json.dumps(manifest))
    return directory


# ── Harvest: a pure function of evidence ──────────────────────────────────────


def test_harvest_extracts_object_and_privileged_candidates() -> None:
    evidence = [
        make_exchange('http://127.0.0.1:1/api/orders/42'),
        make_exchange('http://127.0.0.1:1/api/docs/7'),
        make_exchange('http://127.0.0.1:1/api/admin/audit'),
        make_exchange('http://127.0.0.1:1/api/admin/reports'),
        make_exchange('http://127.0.0.1:1/not-an-api'),
    ]
    candidates = harvest_candidates(evidence)
    by_key = {candidate.key: candidate for candidate in candidates}
    assert set(by_key) == {
        'GET /api/orders/{id}',
        'GET /api/docs/{id}',
        'GET /api/admin/audit',
        'GET /api/admin/reports',
    }
    assert by_key['GET /api/orders/{id}'].category == 'bola'
    assert by_key['GET /api/orders/{id}'].object_ids == ('42',)
    assert by_key['GET /api/admin/audit'].category == 'bfla'


def test_harvest_classifies_every_non_safe_method_as_gated() -> None:
    """Writes and odd verbs (PROPFIND, MKCOL, …) are never replayed: v1 is read-only."""
    evidence = [
        make_exchange('http://127.0.0.1:1/api/orders/42', method='DELETE', status=405),
        make_exchange('http://127.0.0.1:1/api/admin/x', method='MKCOL', status=405),
        make_exchange('http://127.0.0.1:1/api/orders/42', method='PROPFIND', status=207),
    ]
    assert {candidate.category for candidate in harvest_candidates(evidence)} == {'gated'}


def test_harvest_is_deterministic_and_deduplicates() -> None:
    evidence = [
        make_exchange('http://127.0.0.1:1/api/orders/2'),
        make_exchange('http://127.0.0.1:1/api/orders/1', status=404),
    ]
    assert harvest_candidates(evidence) == harvest_candidates(evidence)
    assert len(harvest_candidates(evidence)) == 1  # first exchange per normalized key wins


# ── Role clients and the two-request verify seam ──────────────────────────────


def test_verify_recipe_leads_with_the_cross_role_exchange() -> None:
    owner = make_exchange('http://127.0.0.1:1/api/orders/42', headers=[('Authorization', 'Bearer owner-secret-token')])
    guest = make_exchange('http://127.0.0.1:1/api/orders/42', headers=[('Authorization', 'Bearer guest-secret-token')])
    finding = Finding.model_validate(
        {
            'id': 'fn_x',
            'check_id': CHECK_ID,
            'check_version': '1.0',
            'severity': 'high',
            'subject': 'bola:GET /api/orders/{id}',
            'title': 't',
            'description': 'd',
            'evidence_ids': [owner.id, guest.id],
            'remediation': 'r',
            'status': 'reported',
        }
    )
    recipe = authz_boundary_check.verify_recipe(finding, [owner, guest])
    assert recipe is not None
    assert [request.headers for request in recipe.requests] == [
        {'Authorization': 'Bearer guest-secret-token'},
        {'Authorization': 'Bearer owner-secret-token'},
    ]
    assert recipe.requests[0].path == guest.http.request.url


def test_verify_match_confirms_the_cross_role_2xx_and_refuses_denials() -> None:
    owner = make_exchange('http://127.0.0.1:1/api/orders/42', body='{"id": "42"}')
    finding = Finding.model_validate(
        {
            'id': 'fn_x',
            'check_id': CHECK_ID,
            'check_version': '1.0',
            'severity': 'high',
            'subject': 'bola:GET /api/orders/{id}',
            'title': 't',
            'description': 'd',
            'evidence_ids': [owner.id],
            'remediation': 'r',
            'status': 'reported',
        }
    )
    open_replay = make_exchange('http://127.0.0.1:1/api/orders/42', status=200, body='{"id": "42"}')
    denied_replay = make_exchange('http://127.0.0.1:1/api/orders/42', status=403, body='{"error": "no"}')
    assert authz_boundary_check.verify_match(finding, owner, open_replay)
    assert not authz_boundary_check.verify_match(finding, owner, denied_replay)


def test_verify_match_needs_the_object_id_as_a_standalone_token() -> None:
    """Id ``4`` inside ``{"count": 14}`` is a substring, not exposure of object 4."""
    finding = Finding.model_validate(
        {
            'id': 'fn_x',
            'check_id': CHECK_ID,
            'check_version': '1.0',
            'severity': 'high',
            'subject': 'bola:GET /api/orders/{id}',
            'title': 't',
            'description': 'd',
            'evidence_ids': ['ev_x'],
            'remediation': 'r',
            'status': 'reported',
        }
    )
    original = make_exchange('http://127.0.0.1:1/api/orders/4')
    assert authz_boundary_check.verify_match(
        finding, original, make_exchange('http://127.0.0.1:1/api/orders/4', body='{"id": 4}')
    )
    assert not authz_boundary_check.verify_match(
        finding, original, make_exchange('http://127.0.0.1:1/api/orders/4', body='{"count": 14}')
    )


def test_verify_match_all_needs_two_crossings_across_every_replay() -> None:
    """A role-pair verdict counts crossings across every replay, never just the recipe's lead (#176).

    The finding claims ≥2 roles are granted on the operation, so a partial fix that denies one
    role — whichever one — must not confirm: one remaining crossing is a denied boundary for
    that role, not a reproduction of the multi-role claim.
    """
    finding = Finding.model_validate(
        {
            'id': 'fn_x',
            'check_id': CHECK_ID,
            'check_version': '1.0',
            'severity': 'high',
            'subject': 'bola:GET /api/orders/{id}',
            'title': 't',
            'description': 'd',
            'evidence_ids': ['ev_x'],
            'remediation': 'r',
            'status': 'reported',
        }
    )
    original = make_exchange('http://127.0.0.1:1/api/orders/42', body='{"id": "42"}')
    open_guest = make_exchange('http://127.0.0.1:1/api/orders/42', status=200, body='{"id": "42"}')
    open_owner = make_exchange('http://127.0.0.1:1/api/orders/42', status=200, body='{"id": "42"}')
    denied = make_exchange('http://127.0.0.1:1/api/orders/42', status=403, body='{"error": "no"}')
    assert authz_boundary_check.verify_match_all(finding, original, [open_guest, open_owner])
    # Partial fixes deny a single role — either side of the pair — and must not confirm.
    assert not authz_boundary_check.verify_match_all(finding, original, [open_guest, denied])
    assert not authz_boundary_check.verify_match_all(finding, original, [denied, open_owner])
    assert not authz_boundary_check.verify_match_all(finding, original, [open_guest])
    assert not authz_boundary_check.verify_match_all(finding, original, [])


def test_verify_match_all_bfla_counts_granted_replays() -> None:
    """BFLA has no object token to name: any 2xx replay crosses, so ≥2 of them confirm (#176)."""
    finding = Finding.model_validate(
        {
            'id': 'fn_x',
            'check_id': CHECK_ID,
            'check_version': '1.0',
            'severity': 'high',
            'subject': 'bfla:POST /api/admin',
            'title': 't',
            'description': 'd',
            'evidence_ids': ['ev_x'],
            'remediation': 'r',
            'status': 'reported',
        }
    )
    original = make_exchange('http://127.0.0.1:1/api/admin', method='POST')
    granted = make_exchange('http://127.0.0.1:1/api/admin', method='POST', status=200)
    denied = make_exchange('http://127.0.0.1:1/api/admin', method='POST', status=403)
    assert authz_boundary_check.verify_match_all(finding, original, [granted, granted])
    assert not authz_boundary_check.verify_match_all(finding, original, [granted, denied])
    assert not authz_boundary_check.verify_match_all(finding, original, [denied, denied])


async def test_probe_cites_baseline_first_so_the_recipe_leads_cross_role() -> None:
    """The draft cites evidence in engagement declaration order (baseline first), never id-sorted.

    ``evidence_id`` is a content hash, so sorting citations would make the recipe's lead a coin
    flip (#169 review); here the guest exchange hashes first, so only deliberate ordering puts
    the owner baseline in ``evidence_ids[0]`` and the cross-role replay in the recipe's lead.
    """

    class StubClient:
        """A TargetClient returning one pre-captured exchange per role — no sockets."""

        def __init__(self, exchange: HttpEvidence) -> None:
            self._exchange = exchange

        async def request(
            self, method: str, url: str, *, headers: object = None, body: str | None = None
        ) -> HttpEvidence:
            return self._exchange

    observed = make_exchange('http://127.0.0.1:1/api/orders/42')
    owner = make_exchange(
        'http://127.0.0.1:1/api/orders/42',
        headers=[('Authorization', 'Bearer owner-secret-token')],
        body='{"id": "42", "amount": 9}',
    )
    guest = make_exchange(
        'http://127.0.0.1:1/api/orders/42',
        headers=[('Authorization', 'Bearer guest-secret-token')],
        body='{"id": "42", "amount": 9}',
    )
    assert guest.id < owner.id  # the hash order is against the citation convention

    handles = {
        'owner': RoleHandle('owner', 'PARTEX_CRED_OWNER', ROLE_ENV['PARTEX_CRED_OWNER'], StubClient(owner)),
        'guest': RoleHandle('guest', 'PARTEX_CRED_GUEST', ROLE_ENV['PARTEX_CRED_GUEST'], StubClient(guest)),
    }
    (draft,) = await authz_boundary_check.probe([observed], handles['owner'].client, roles=handles)
    assert draft.evidence_ids == [owner.id, guest.id]  # baseline first — not id-sorted

    # The verify runner loads cited evidence in evidence_ids order, then builds the recipe.
    finding = Finding.model_validate(
        draft.model_dump()
        | {
            'id': 'fn_x',
            'status': 'reported',
        }
    )
    recipe = authz_boundary_check.verify_recipe(finding, [owner, guest])
    assert recipe is not None
    assert recipe.requests[0].headers == {'Authorization': 'Bearer guest-secret-token'}
    assert recipe.requests[1].headers == {'Authorization': 'Bearer owner-secret-token'}


# ── Live end-to-end over the fixture app ──────────────────────────────────────


async def test_live_run_finds_broken_boundaries_and_exonerates_enforced_ones(
    target_app: Any, tmp_store: RunStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('PARTEX_CRED_OWNER', 'owner-secret-token')
    monkeypatch.setenv('PARTEX_CRED_GUEST', 'guest-secret-token')
    base_url = target_app.base_url  # pyright: ignore[reportAttributeAccessIssue]
    seed_bundle = write_bundle(
        tmp_path / 'bundle',
        [
            make_exchange(f'{base_url}/api/orders/1'),  # broken BOLA: any authenticated role reads it
            make_exchange(f'{base_url}/api/docs/1'),  # enforced: owner-only
            make_exchange(f'{base_url}/api/admin/audit'),  # broken BFLA: read by guest
            make_exchange(f'{base_url}/api/admin/reports'),  # enforced: owner-only
        ],
    )
    result = await run_test(
        engagement_dir(tmp_path / 'eng', target_app),
        tmp_store,
        ['authz-boundary'],
        authorized=True,
        seed_bundle=seed_bundle,
    )
    assert result.state == 'checks_complete'
    by_subject = {finding.subject: finding for finding in result.findings}
    assert {'bola:GET /api/orders/{id}', 'bfla:GET /api/admin/audit'} <= set(by_subject)
    assert 'bola:GET /api/docs/{id}' not in by_subject
    assert 'bfla:GET /api/admin/reports' not in by_subject

    # Every finding cites two distinct evidence records (the two-role rule).
    for finding in result.findings:
        assert len(finding.evidence_ids) == 2
        assert len(set(finding.evidence_ids)) == 2

    coverage = {entry.surface: entry.outcome for entry in result.coverage}
    assert coverage['GET /api/orders/{id}'] == 'reported'
    assert coverage['GET /api/admin/audit'] == 'reported'
    assert coverage['GET /api/docs/{id}'] == 'no_issue_found'
    assert coverage['GET /api/admin/reports'] == 'no_issue_found'


async def test_no_second_role_marks_candidates_needs_follow_up(
    target_app: Any, tmp_store: RunStore, tmp_path: Path
) -> None:
    base_url = target_app.base_url  # pyright: ignore[reportAttributeAccessIssue]
    seed_bundle = write_bundle(tmp_path / 'bundle', [make_exchange(f'{base_url}/api/orders/1')])
    result = await run_test(
        engagement_dir(tmp_path / 'eng', target_app, roles=False),
        tmp_store,
        ['authz-boundary'],
        authorized=True,
        seed_bundle=seed_bundle,
    )
    assert result.state == 'checks_complete'
    assert result.findings == ()
    assert [entry.outcome for entry in result.coverage] == ['needs_follow_up']


async def test_no_object_traffic_is_missing_evidence(target_app: Any, tmp_store: RunStore, tmp_path: Path) -> None:
    base_url = target_app.base_url  # pyright: ignore[reportAttributeAccessIssue]
    seed_bundle = write_bundle(tmp_path / 'bundle', [make_exchange(f'{base_url}/account')])
    result = await run_test(
        engagement_dir(tmp_path / 'eng', target_app, roles=False),
        tmp_store,
        ['authz-boundary'],
        authorized=True,
        seed_bundle=seed_bundle,
    )
    assert result.state == 'checks_complete'
    assert result.findings == ()
    assert [entry.outcome for entry in result.coverage] == ['not_applicable']
