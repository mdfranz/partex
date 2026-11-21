"""Tests for S1 api-inventory / api-contract-conformance passive check (issue #24).

Covers the PARTX_SKILL_PLAN §6 fixture triad, normalized operation keys (PLAN §12),
finding ID stability across bundle revisions and route reordering, GraphQL/RPC single-endpoint
collapsing, surface_nodes + coverage_entries persistence, secret/value redaction, and passive
byte-identical export determinism.
"""

import json
from pathlib import Path
from typing import Any

import anyio
import pytest

from partex import cli
from partex.checks.api_inventory import (
    CHECK_ID,
    ApiContractConformanceCheck,
    api_contract_conformance_check,
    collapse_path_ids,
)
from partex.engine import CheckFailed, run_review
from partex.export import export_run_json
from partex.ids import evidence_id
from partex.models import ConfigEvidence, ConfigExcerpt, HttpEvidence, HttpExchange, HttpRequest, HttpResponse
from partex.registry import build_registry
from partex.storage import RunReader, RunStore

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'bundles'
API_FIXTURES = FIXTURES / 'api-inventory'
VALID_BUNDLE = FIXTURES / 'valid'

check = ApiContractConformanceCheck()


def _run_cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _http(
    method: str,
    url: str,
    status: int = 200,
    body: str | None = '{"ok":true}',
    *,
    ct: str = 'application/json',
) -> HttpEvidence:
    headers = [['Content-Type', ct]] if ct else []
    ev = HttpEvidence(
        id='placeholder',
        source='test',
        http=HttpExchange(
            request=HttpRequest(method=method, url=url, headers=[['Host', 'api.example.test']]),
            response=HttpResponse(status_code=status, headers=headers, body=body),
        ),
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


def _openapi(content: str, *, revision: str | None = 'v1') -> ConfigEvidence:
    ev = ConfigEvidence(
        id='placeholder',
        source='openapi.yaml',
        config=ConfigExcerpt(path='openapi.yaml', format='openapi', content=content, revision=revision),
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


# ── Registry join & baseline fixture compatibility ───────────────────────────


def test_registry_joins_api_inventory_skill_with_zero_warnings_for_it() -> None:
    registry = build_registry()
    assert CHECK_ID in registry.checks
    assert registry.checks[CHECK_ID] is api_contract_conformance_check
    assert registry.skills_for(CHECK_ID) == ['api-inventory']
    assert not [d for d in registry.diagnostics if d.skill == 'api-inventory']


async def test_valid_mixed_html_and_api_bundle_has_zero_false_positives(tmp_store: RunStore) -> None:
    """HTML page navigations in fixtures/bundles/valid are not misflagged as shadow API routes."""
    result = await run_review(VALID_BUNDLE, tmp_store, [CHECK_ID])
    assert result.state == 'checks_complete'
    assert result.findings == ()
    coverage = await tmp_store.coverage(result.run_id)
    assert [(c.surface, c.outcome) for c in coverage] == [('GET /api/health', 'no_issue_found')]


def test_applies_to_only_http_or_openapi_evidence() -> None:
    other_cfg = ConfigEvidence(
        id='ev_1',
        source='app.ini',
        config=ConfigExcerpt(path='app.ini', format='config', content='x=1'),
    )
    other_cfg = other_cfg.model_copy(update={'id': evidence_id(other_cfg)})
    assert not check.applies_to([])
    assert not check.applies_to([other_cfg])
    assert check.applies_to([_http('GET', 'https://api.example.test/v1/ping')])
    assert check.applies_to([_openapi('openapi: 3.1.0\ninfo: {title: t, version: "1"}\npaths: {}')])


# ── Fixture triad: 1. Conforming + unobserved coverage + GraphQL collapse ────


async def test_fixture_conforming_produces_no_findings_and_records_inventory_and_coverage(
    tmp_store: RunStore,
) -> None:
    result = await run_review(API_FIXTURES / 'conforming', tmp_store, [CHECK_ID])
    assert result.state == 'checks_complete'
    assert result.findings == ()

    coverage = {c.surface: c for c in await tmp_store.coverage(result.run_id)}
    assert coverage['GET /api/v2/users/me'].outcome == 'no_issue_found'
    assert coverage['GET /api/v2/users/{id}'].outcome == 'no_issue_found'
    assert coverage['GET /api/v2/projects/{id}'].outcome == 'no_issue_found'
    # Two GraphQL queries collapse to a single operation key (no synthetic per-query keys).
    assert coverage['POST /graphql'].outcome == 'no_issue_found'
    assert len(coverage['POST /graphql'].evidence_ids) == 2
    # Unobserved declared operation becomes a needs_follow_up coverage row, never a finding.
    assert coverage['POST /api/v2/orders'].outcome == 'needs_follow_up'
    assert 'unobserved in bundle' in coverage['POST /api/v2/orders'].reason
    assert '2026.11.1' in coverage['POST /api/v2/orders'].reason

    nodes, edges = await tmp_store.surface(result.run_id)
    endpoint_nodes = {n.key: n for n in nodes if n.kind == 'endpoint'}
    assert set(endpoint_nodes) == {
        'GET /api/v2/projects/{id}',
        'GET /api/v2/users/me',
        'GET /api/v2/users/{id}',
        'POST /api/v2/orders',
        'POST /graphql',
    }
    assert endpoint_nodes['GET /api/v2/users/{id}'].metadata['provenance'] == 'declared+observed'
    assert endpoint_nodes['GET /api/v2/users/{id}'].metadata['query_params'] == ['include']
    assert endpoint_nodes['GET /api/v2/users/{id}'].metadata['revision'] == '2026.11.1'
    assert endpoint_nodes['POST /api/v2/orders'].metadata['provenance'] == 'declared'
    assert any(n.kind == 'host' and n.key == 'api.example.test' for n in nodes)
    assert len(edges) == 4  # 4 observed endpoints exposed by api.example.test


# ── Fixture triad: 2. Disallowed / excessive response fields + redaction ─────


async def test_fixture_disallowed_fields_flags_medium_and_high_without_leaking_values(
    tmp_store: RunStore,
) -> None:
    result = await run_review(API_FIXTURES / 'disallowed-field', tmp_store, [CHECK_ID])
    assert result.state == 'checks_complete'
    by_subject = {f.subject: f for f in result.findings}
    assert set(by_subject) == {'op:GET /api/v2/users/{id}', 'op:GET /api/v2/projects/{id}'}

    user_finding = by_subject['op:GET /api/v2/users/{id}']
    assert user_finding.severity == 'high'
    assert user_finding.title == 'Disallowed response fields on GET /api/v2/users/{id}'
    assert '$.is_admin' in user_finding.description
    assert '$.password_hash' in user_finding.description
    assert 'sha-9a1b2c3' in user_finding.description
    assert 'API3:2023' in user_finding.description

    proj_finding = by_subject['op:GET /api/v2/projects/{id}']
    assert proj_finding.severity == 'medium'
    assert '$.internal_notes' in proj_finding.description

    # Redaction invariant: observed values and bearer secrets NEVER appear in findings or default export.
    exported = (await export_run_json(tmp_store, result.run_id)).decode('utf-8')
    for forbidden_secret in (
        'super-secret-live-token-xyz',
        '$2b$12$secretHashValueNeverEmit',
        'do-not-expose-note-val',
    ):
        assert forbidden_secret not in user_finding.description
        assert forbidden_secret not in proj_finding.description
        if forbidden_secret == 'super-secret-live-token-xyz':
            assert forbidden_secret not in exported


# ── Fixture triad: 3. Shadow route & no-matching-contract ────────────────────


async def test_fixture_shadow_route_and_no_matching_contract(tmp_store: RunStore) -> None:
    shadow_res = await run_review(API_FIXTURES / 'shadow-route', tmp_store, [CHECK_ID])
    assert shadow_res.state == 'checks_complete'
    by_subject = {f.subject: f for f in shadow_res.findings}
    assert set(by_subject) == {'op:DELETE /api/v2/users/{id}', 'op:GET /api/v1/admin/export'}
    assert all(f.severity == 'medium' and 'API9:2023' in f.description for f in shadow_res.findings)
    assert 'v1' in by_subject['op:GET /api/v1/admin/export'].description
    assert 'undeclared HTTP method DELETE' in by_subject['op:DELETE /api/v2/users/{id}'].description

    unmatched_res = await run_review(API_FIXTURES / 'no-matching-contract', tmp_store, [CHECK_ID])
    assert unmatched_res.state == 'checks_complete'
    # Concrete /orders/10 and /orders/11 collapse into one normalized finding citing both exchanges.
    (order_finding,) = unmatched_res.findings
    assert order_finding.subject == 'op:GET /api/v2/orders/{id}'
    assert order_finding.title == 'Undocumented API operation: GET /api/v2/orders/{id}'
    assert len(order_finding.evidence_ids) == 2

    cov = {c.surface: c for c in await tmp_store.coverage(unmatched_res.run_id)}
    assert cov['GET /api/v3/catalog/{sku}'].outcome == 'needs_follow_up'
    assert cov['GET /api/v2/orders/{id}'].outcome == 'reported'


# ── Fixture triad: 4. Insufficient evidence (no contract & external $ref) ────


async def test_fixture_no_contract_and_external_ref_record_insufficient_evidence(
    tmp_store: RunStore,
) -> None:
    no_contract = await run_review(API_FIXTURES / 'no-contract', tmp_store, [CHECK_ID])
    assert no_contract.state == 'checks_complete'
    assert no_contract.findings == ()
    (nc_cov,) = await tmp_store.coverage(no_contract.run_id)
    assert nc_cov.outcome == 'not_applicable'
    assert 'insufficient evidence' in nc_cov.reason and 'no OpenAPI contract' in nc_cov.reason
    nodes, _ = await tmp_store.surface(no_contract.run_id)
    assert [n.key for n in nodes if n.kind == 'endpoint'] == ['GET /api/v2/users/{id}']

    ext_ref = await run_review(API_FIXTURES / 'external-ref', tmp_store, [CHECK_ID])
    assert ext_ref.state == 'checks_complete'
    assert ext_ref.findings == ()
    (ext_cov,) = await tmp_store.coverage(ext_ref.run_id)
    assert ext_cov.surface == 'GET /api/v2/users/{id}'
    assert ext_cov.outcome == 'not_applicable'
    assert 'insufficient evidence' in ext_cov.reason and './common.yaml' in ext_cov.reason


# ── CLI acceptance & passive byte-determinism across stores and revisions ────


def test_cli_acceptance_and_byte_identical_exports_twice(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    db_a = tmp_path / 'a.db'
    db_b = tmp_path / 'b.db'
    out_a = tmp_path / 'export_a.json'
    out_b = tmp_path / 'export_b.json'

    code_a, stdout_a, err_a = _run_cli(
        capsys,
        'review',
        str(API_FIXTURES / 'violations'),
        '--checks',
        CHECK_ID,
        '--no-summary',
        '--workers',
        '1',
        '--db',
        str(db_a),
        '--out',
        str(out_a),
    )
    code_b, stdout_b, err_b = _run_cli(
        capsys,
        'review',
        str(API_FIXTURES / 'violations'),
        '--checks',
        CHECK_ID,
        '--no-summary',
        '--workers',
        '4',
        '--db',
        str(db_b),
        '--out',
        str(out_b),
    )
    assert (code_a, err_a) == (cli.EXIT_FINDINGS, '')
    assert (code_b, err_b) == (cli.EXIT_FINDINGS, '')
    assert out_a.read_bytes() == out_b.read_bytes()

    payload_a = json.loads(stdout_a)
    payload_b = json.loads(stdout_b)
    assert payload_a['findings'] == payload_b['findings']
    subjects = {f['subject']: f for f in payload_a['findings']}
    assert set(subjects) == {
        'op:GET /api/v2/users/{id}',
        'op:GET /api/v2/projects/{id}',
        'op:GET /api/v1/admin/export',
        'op:DELETE /api/v2/users/{id}',
    }
    assert subjects['op:GET /api/v2/users/{id}']['severity'] == 'high'
    assert subjects['op:GET /api/v2/projects/{id}']['severity'] == 'medium'
    assert subjects['op:GET /api/v1/admin/export']['severity'] == 'medium'
    assert subjects['op:DELETE /api/v2/users/{id}']['severity'] == 'medium'

    export_data = json.loads(out_a.read_text(encoding='utf-8'))
    for secret_val in (
        'super-secret-live-token-xyz',
        '$2b$12$secretHashValueNeverEmit',
        '$2b$12$anotherHashValueNeverEmit',
        's3cr3t-totp-seed-999',
        'private-roadmap-note-value',
    ):
        for finding_json in export_data['findings']:
            assert secret_val not in json.dumps(finding_json)
        for cov_json in export_data['coverage']:
            assert secret_val not in json.dumps(cov_json)
    assert 'super-secret-live-token-xyz' not in out_a.read_text(encoding='utf-8')

    async def _verify_surface() -> None:
        async with await RunReader.open(db_a) as reader_a, await RunReader.open(db_b) as reader_b:
            assert await reader_a.surface(payload_a['run_id']) == await reader_b.surface(payload_b['run_id'])

    anyio.run(_verify_surface)


async def test_finding_ids_survive_bundle_revisions_and_route_reordering(tmp_path: Path) -> None:
    """Reordering paths in OpenAPI and bumping revision produces the exact same fn_* IDs (PLAN §12)."""
    spec_v1 = """\
openapi: 3.1.0
info: {title: app, version: "1.0"}
paths:
  /api/users/me:
    get:
      responses:
        "200":
          description: me
  /api/users/{id}:
    get:
      responses:
        "200":
          description: user
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: {type: integer}
                additionalProperties: false
"""
    spec_v2_reordered = """\
openapi: 3.1.0
info: {title: app, version: "2.0"}
paths:
  /api/users/{id}:
    get:
      responses:
        "200":
          description: user updated doc
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: {type: integer}
                additionalProperties: false
  /api/users/me:
    get:
      responses:
        "200":
          description: me
"""
    http_leak = {
        'kind': 'http_exchange',
        'http': {
            'request': {'method': 'GET', 'url': 'https://api.example.test/api/users/42', 'headers': []},
            'response': {
                'status_code': 200,
                'headers': [['Content-Type', 'application/json']],
                'body': '{"id":42,"password_hash":"hash"}',
            },
        },
    }
    http_shadow = {
        'kind': 'http_exchange',
        'http': {
            'request': {'method': 'POST', 'url': 'https://api.example.test/api/debug', 'headers': []},
            'response': {'status_code': 200, 'headers': [['Content-Type', 'application/json']], 'body': '{}'},
        },
    }

    def make_bundle(root: Path, spec: str, rev: str) -> Path:
        (root / 'evidence').mkdir(parents=True)
        (root / 'evidence/0001.json').write_text(
            json.dumps(
                {
                    'kind': 'config_excerpt',
                    'config': {'path': 'openapi.yaml', 'format': 'openapi', 'content': spec, 'revision': rev},
                }
            )
        )
        (root / 'evidence/0002.json').write_text(json.dumps(http_leak))
        (root / 'evidence/0003.json').write_text(json.dumps(http_shadow))
        (root / 'bundle.json').write_text(
            json.dumps(
                {
                    'schema_version': 1,
                    'target': {'name': 't', 'base_url': 'https://api.example.test'},
                    'evidence_files': ['evidence/0001.json', 'evidence/0002.json', 'evidence/0003.json'],
                }
            )
        )
        return root

    b1 = make_bundle(tmp_path / 'b1', spec_v1, 'rev-1')
    b2 = make_bundle(tmp_path / 'b2', spec_v2_reordered, 'rev-2')

    async with await RunStore.open(tmp_path / 's.db') as store:
        r1 = await run_review(b1, store, [CHECK_ID])
        r2 = await run_review(b2, store, [CHECK_ID])

    assert [f.id for f in r1.findings] == [f.id for f in r2.findings]
    assert {f.subject for f in r1.findings} == {'op:GET /api/users/{id}', 'op:POST /api/debug'}


# ── Additional edge cases & engine surface/coverage validation ───────────────


def test_method_405_and_non_2xx_schema_gap_and_invalid_contract_coverage() -> None:
    spec = """\
openapi: 3.1.0
info: {title: t, version: "1.0"}
paths:
  /api/items/{id}:
    get:
      responses:
        "200":
          description: item
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: {type: integer}
"""
    contract = _openapi(spec, revision='r1')
    # 405 on undeclared method is proper enforcement, not a shadow operation.
    rejected_delete = _http(
        'DELETE', 'https://api.example.test/api/items/5', status=405, body='{"error":"not allowed"}'
    )
    # 401 on GET means operation was observed, but 2xx schema was never exercised.
    unauthorized_get = _http('GET', 'https://api.example.test/api/items/5', status=401, body='{"error":"unauth"}')
    assert check.review([contract, rejected_delete, unauthorized_get]) == []
    cov = {c.surface: c for c in check.coverage([contract, rejected_delete, unauthorized_get])}
    assert cov['GET /api/items/{id}'].outcome == 'needs_follow_up'
    assert 'no 2xx response captured' in cov['GET /api/items/{id}'].reason

    bad_contract = _openapi('swagger: "2.0"\npaths: {}', revision='legacy-2')
    (bad_cov,) = check.coverage([bad_contract])
    assert bad_cov.outcome == 'not_applicable'
    assert 'swagger' in bad_cov.reason and 'legacy-2' in bad_cov.reason


def test_collapse_path_ids_handles_numbers_uuids_hex_and_root() -> None:
    assert collapse_path_ids('https://api.example.test/') == '/'
    assert (
        collapse_path_ids(
            'https://api.example.test/api/v1/users/99/keys/0123456789abcdef0123/items/550e8400-e29b-41d4-a716-446655440000'
        )
        == '/api/v1/users/{id}/keys/{id}/items/{id}'
    )
    assert collapse_path_ids('https://api.example.test/graphql') == '/graphql'


async def test_passive_bad_surface_hook_fails_atomically_publishing_nothing(tmp_store: RunStore) -> None:
    class BadSurfaceCheck:
        check_id = 'bad-surface'
        version = '1'
        title = 'bad'
        description = 'bad'

        def applies_to(self, evidence: object) -> bool:
            return True

        def review(self, evidence: object) -> list[object]:
            return []

        def surface(self, evidence: object) -> dict[str, Any]:
            return {'nodes': [{'kind': 'endpoint', 'key': 'GET /x', 'evidence_ids': ['ev_missing']}], 'edges': []}

    result = await run_review(VALID_BUNDLE, tmp_store, ['bad-surface'], registry={'bad-surface': BadSurfaceCheck()})
    assert (result.state, result.failed_check) == ('checks_failed', 'bad-surface')
    assert 'unregistered evidence' in (result.error or '')
    assert await tmp_store.evidence(result.run_id) == []
    assert CheckFailed
