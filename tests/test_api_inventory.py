"""Tests for S1 api-inventory / api-contract-conformance passive check (issue #24).

Covers the docs/skills/PLAN.md §6 fixture triad, normalized operation keys (PLAN §12),
finding ID stability across bundle revisions and route reordering, GraphQL/RPC single-endpoint
collapsing, surface_nodes + coverage_entries persistence, secret/value redaction, and passive
byte-identical export determinism.
"""

import http.server
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from partex import cli
from partex.bundle import MAX_CONTENT_BYTES
from partex.checks.api_inventory import (
    CHECK_ID,
    ApiContractConformanceCheck,
    api_contract_conformance_check,
    collapse_path_ids,
)
from partex.engine import live_session, run_review, run_test
from partex.export import export_run_json
from partex.har_io import export_bundle
from partex.ids import evidence_id, sha256_hex
from partex.models import ConfigEvidence, ConfigExcerpt, HttpEvidence, HttpExchange, HttpRequest, HttpResponse
from partex.registry import build_registry
from partex.storage import RunStore

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
    headers = [('Content-Type', ct)] if ct else []
    ev = HttpEvidence(
        id='placeholder',
        source='test',
        http=HttpExchange(
            request=HttpRequest(method=method, url=url, headers=[('Host', 'api.example.test')]),
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


# ── Live OpenAPI capture -> ConfigEvidence registration (issue #155) ─────────


_LIVE_OPENAPI_JSON = json.dumps(
    {
        'openapi': '3.1.0',
        'info': {'title': 'Live Fixture API', 'version': '3.2.0'},
        'paths': {
            '/api/users/me': {
                'get': {
                    'responses': {
                        '200': {
                            'description': 'current user',
                            'content': {
                                'application/json': {
                                    'schema': {
                                        'type': 'object',
                                        'additionalProperties': False,
                                        'properties': {
                                            'id': {'type': 'integer'},
                                            'username': {'type': 'string'},
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            },
            '/api/users/{id}': {
                'get': {
                    'responses': {
                        '200': {
                            'description': 'user by id',
                            'content': {
                                'application/json': {
                                    'schema': {
                                        'type': 'object',
                                        'additionalProperties': False,
                                        'properties': {
                                            'id': {'type': 'integer'},
                                            'username': {'type': 'string'},
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            },
            '/api/items': {
                'post': {
                    'responses': {'201': {'description': 'created'}},
                }
            },
        },
    }
)

_LIVE_ASSET_OPENAPI_YAML = """\
openapi: 3.0.3
info:
  title: Asset Spec
paths:
  /api/ping:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                additionalProperties: false
                properties:
                  pong:
                    type: boolean
"""

_OVERSIZED_OPENAPI_JSON = json.dumps(
    {
        'openapi': '3.1.0',
        'info': {'title': 'Oversized', 'version': '1.0'},
        'paths': {'/api/big': {'get': {'description': 'x' * (MAX_CONTENT_BYTES + 1024)}}},
    }
)


class _OpenApiFixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(('127.0.0.1', 0), _OpenApiFixtureHandler)
        self.seq = 0

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    @property
    def base_url(self) -> str:
        return f'http://127.0.0.1:{self.port}'


class _OpenApiFixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:
        self._dispatch(send_body=False)

    def do_GET(self) -> None:
        self._dispatch(send_body=True)

    def _dispatch(self, *, send_body: bool) -> None:
        srv: _OpenApiFixtureServer = self.server  # type: ignore[assignment]
        srv.seq += 1
        path = urlsplit(self.path).path
        routes: dict[str, tuple[int, str, str]] = {
            '/': (200, 'text/html', '<html><body>live fixture</body></html>'),
            '/openapi.json': (200, 'application/json', _LIVE_OPENAPI_JSON),
            '/specs/service.yaml': (200, 'application/yaml', _LIVE_ASSET_OPENAPI_YAML),
            '/api/users/me': (200, 'application/json', '{"id":1,"username":"alice"}'),
            '/api/users/42': (
                200,
                'application/json',
                '{"id":42,"username":"bob","password_hash":"$2b$12$secretvalue"}',
            ),
            '/api/internal/debug': (200, 'application/json', '{"env":"staging"}'),
            '/api/ping': (200, 'application/json', '{"pong":true}'),
            '/non-openapi.json': (200, 'application/json', '{"status":"ok","openapi":"nope"}'),
            '/swagger.json': (
                200,
                'application/json',
                '{"swagger":"2.0","info":{"title":"v2","version":"1"},"paths":{}}',
            ),
            '/error-spec.json': (500, 'application/json', _LIVE_OPENAPI_JSON),
            '/missing-spec.json': (404, 'application/json', _LIVE_OPENAPI_JSON),
            '/huge-spec.json': (200, 'application/json', _OVERSIZED_OPENAPI_JSON),
        }
        status, ct, body = routes.get(path, (404, 'application/json', '{"error":"not found"}'))
        payload = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('X-Seq', str(srv.seq))
        self.end_headers()
        if send_body:
            self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def live_openapi_server() -> Iterator[_OpenApiFixtureServer]:
    srv = _OpenApiFixtureServer()
    thread = threading.Thread(target=srv.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _write_live_engagement(root: Path, srv: _OpenApiFixtureServer) -> Path:
    eng_dir = root / 'engagement'
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'live-openapi', 'base_url': srv.base_url},
                'scope': {
                    'hosts': ['127.0.0.1'],
                    'path_prefixes': ['/'],
                    'exclusions': [],
                    'ports': [srv.port],
                    'max_rps': 64,
                    'max_requests': 50,
                },
                'authorization': {'attestation': 'loopback test', 'operator': 'pytest'},
                'suggested_checks': [CHECK_ID],
            }
        ),
        encoding='utf-8',
    )
    return eng_dir


def test_api_inventory_skill_documents_live_openapi_registration() -> None:
    skill_md = (Path(__file__).resolve().parents[1] / 'skills' / 'api-inventory' / 'SKILL.md').read_text(
        encoding='utf-8'
    )
    assert "automatically registers a derived `ConfigEvidence(format='openapi')`" in skill_md
    assert 'download_asset' in skill_md
    assert 'even if `/openapi.json` was fetched over' not in skill_md


async def test_live_session_registers_openapi_spec_idempotently_and_checks_conformance(
    live_openapi_server: _OpenApiFixtureServer,
    tmp_path: Path,
    tmp_store: RunStore,
) -> None:
    eng_dir = _write_live_engagement(tmp_path, live_openapi_server)
    base = live_openapi_server.base_url

    async with live_session(eng_dir, tmp_store, authorized=True) as session:
        # Before fetching a spec, api-contract-conformance records not_applicable.
        assert await session.run_check(CHECK_ID) == []
        pre_cov = await tmp_store.coverage(session.run_id)
        assert [(c.surface, c.outcome) for c in pre_cov] == [(base, 'not_applicable')]

        # Live fetch of /openapi.json derives ConfigEvidence(format='openapi') without extra request spend.
        spent_before = session.requests_spent
        spec_http = await session.request('GET', f'{base}/openapi.json')
        assert session.requests_spent == spent_before + 1

        cfg_items = [item for item in session.captured if isinstance(item, ConfigEvidence)]
        assert len(cfg_items) == 1
        cfg_ev = cfg_items[0]
        assert cfg_ev.config.format == 'openapi'
        assert cfg_ev.config.path == '/openapi.json'
        assert cfg_ev.config.revision == '3.2.0'
        assert cfg_ev.source == f'derived:{spec_http.id}:{base}/openapi.json'

        # Running api-contract-conformance right after fetching the spec does NOT self-flag GET /openapi.json,
        # and reports needs_follow_up coverage for every declared operation (not not_applicable).
        await session.request('HEAD', f'{base}/openapi.json')
        assert await session.run_check(CHECK_ID) == []
        spec_only_cov = {c.surface: c.outcome for c in await tmp_store.coverage(session.run_id) if c.surface != base}
        assert spec_only_cov == {
            'GET /api/users/me': 'needs_follow_up',
            'GET /api/users/{id}': 'needs_follow_up',
            'POST /api/items': 'needs_follow_up',
        }

        # Re-fetching the same spec (even with a new X-Seq response header and ?v=2 query) does not duplicate it.
        spec_http_2 = await session.request('GET', f'{base}/openapi.json?v=2')
        assert spec_http_2.id != spec_http.id
        assert [item.id for item in session.captured if isinstance(item, ConfigEvidence)] == [cfg_ev.id]
        stored_cfg = [item for item in await tmp_store.evidence(session.run_id) if isinstance(item, ConfigEvidence)]
        assert [item.id for item in stored_cfg] == [cfg_ev.id]

        # Exercise conforming, BOPLA-violating, and undocumented endpoints, then run api-contract-conformance.
        await session.request('GET', f'{base}/api/users/me')
        await session.request('GET', f'{base}/api/users/42')
        await session.request('GET', f'{base}/api/internal/debug')
        findings = await session.run_check(CHECK_ID)
        assert {(f.subject, f.severity) for f in findings} == {
            ('op:GET /api/users/{id}', 'high'),
            ('op:GET /api/internal/debug', 'medium'),
        }
        assert all('$2b$12$secretvalue' not in f.description for f in findings)

        cov_after = {c.surface: c.outcome for c in await tmp_store.coverage(session.run_id) if c.surface != base}
        assert cov_after == {
            'GET /api/users/me': 'no_issue_found',
            'GET /api/users/{id}': 'reported',
            'POST /api/items': 'needs_follow_up',
            'GET /api/internal/debug': 'reported',
        }

        # Non-OpenAPI JSON, Swagger 2.0, non-2xx (500 & 404 with spec body), and oversized bodies are ignored.
        for ignored_path in (
            '/non-openapi.json',
            '/swagger.json',
            '/error-spec.json',
            '/missing-spec.json',
            '/huge-spec.json',
        ):
            await session.request('GET', f'{base}{ignored_path}')
        assert [item.id for item in session.captured if isinstance(item, ConfigEvidence)] == [cfg_ev.id]
        assert [item.id for item in await tmp_store.evidence(session.run_id) if isinstance(item, ConfigEvidence)] == [
            cfg_ev.id
        ]


async def test_live_session_download_asset_registers_openapi_spec_and_rejects_oversized(
    live_openapi_server: _OpenApiFixtureServer,
    tmp_path: Path,
    tmp_store: RunStore,
) -> None:
    eng_dir = _write_live_engagement(tmp_path, live_openapi_server)
    base = live_openapi_server.base_url

    async with live_session(eng_dir, tmp_store, authorized=True) as session:
        # Oversized and Swagger 2.0 downloaded assets are not registered as ConfigEvidence.
        await session.download_asset(f'{base}/huge-spec.json')
        await session.download_asset(f'{base}/swagger.json')
        assert not [item for item in session.captured if isinstance(item, ConfigEvidence)]

        # Downloading a valid OpenAPI 3.0 YAML spec registers ConfigEvidence with body sha256 fallback revision.
        art_ev = await session.download_asset(f'{base}/specs/service.yaml')
        cfg_items = [item for item in session.captured if isinstance(item, ConfigEvidence)]
        assert len(cfg_items) == 1
        cfg_ev = cfg_items[0]
        assert cfg_ev.config.format == 'openapi'
        assert cfg_ev.config.path == '/specs/service.yaml'
        assert cfg_ev.config.revision == sha256_hex(_LIVE_ASSET_OPENAPI_YAML.encode('utf-8'))
        assert cfg_ev.source == f'derived:{art_ev.id}:{base}/specs/service.yaml'

        # Re-fetching the same spec via http_request or download_asset does not duplicate ConfigEvidence.
        await session.download_asset(f'{base}/specs/service.yaml')
        await session.request('GET', f'{base}/specs/service.yaml')
        assert [item.id for item in session.captured if isinstance(item, ConfigEvidence)] == [cfg_ev.id]
        assert [item.id for item in await tmp_store.evidence(session.run_id) if isinstance(item, ConfigEvidence)] == [
            cfg_ev.id
        ]

        await session.request('GET', f'{base}/api/ping')
        assert await session.run_check(CHECK_ID) == []
        cov = {c.surface: c.outcome for c in await tmp_store.coverage(session.run_id)}
        assert cov == {'GET /api/ping': 'no_issue_found'}


async def test_run_test_registers_live_openapi_and_roundtrips_through_export_bundle(
    live_openapi_server: _OpenApiFixtureServer,
    tmp_path: Path,
    tmp_store: RunStore,
) -> None:
    base = live_openapi_server.base_url
    urls = tmp_path / 'urls.txt'
    urls.write_text(f'{base}/\n{base}/openapi.json\n{base}/api/users/42\n', encoding='utf-8')

    # Seed via an earlier run or pass /openapi.json as base_url so run_test captures it before passive checks.
    spec_eng_dir = tmp_path / 'spec_engagement'
    spec_eng_dir.mkdir()
    (spec_eng_dir / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'live-openapi', 'base_url': f'{base}/openapi.json'},
                'scope': {
                    'hosts': ['127.0.0.1'],
                    'path_prefixes': ['/'],
                    'exclusions': [],
                    'ports': [live_openapi_server.port],
                    'max_rps': 64,
                    'max_requests': 20,
                },
                'authorization': {'attestation': 'loopback test', 'operator': 'pytest'},
                'suggested_checks': [CHECK_ID],
            }
        ),
        encoding='utf-8',
    )
    live_res = await run_test(spec_eng_dir, tmp_store, [CHECK_ID], authorized=True, urls_file=urls)
    assert live_res.state == 'checks_complete'
    # The #215 initial probe pass GETs every listed entry, so /api/users/42 is captured — and its
    # response's `password_hash` (disallowed by the contract response schema) is a real leak the
    # old baseline-only capture silently missed. The pass is what makes the URL list meaningful.
    (user_finding,) = live_res.findings
    assert user_finding.check_id == CHECK_ID and user_finding.severity == 'high'
    assert user_finding.subject == 'op:GET /api/users/{id}'
    assert user_finding.title == 'Disallowed response fields on GET /api/users/{id}'
    assert '$.password_hash' in user_finding.description
    assert '$2b$12$secretvalue' not in user_finding.description  # observed values never appear in findings
    assert {(c.surface, c.outcome) for c in live_res.coverage} == {
        ('GET /api/users/me', 'needs_follow_up'),
        ('GET /api/users/{id}', 'reported'),  # observed by the probe pass, carrying the disallowed-field violation
        ('POST /api/items', 'needs_follow_up'),
    }

    exported = tmp_path / 'exported-bundle'
    await export_bundle(tmp_store, live_res.run_id, exported)
    replay = await run_review(exported, tmp_store, [CHECK_ID])
    assert replay.state == 'checks_complete'
    (replay_finding,) = replay.findings
    assert replay_finding.subject == 'op:GET /api/users/{id}' and replay_finding.severity == 'high'
    assert {(c.surface, c.outcome) for c in await tmp_store.coverage(replay.run_id)} == {
        ('GET /api/users/me', 'needs_follow_up'),
        ('GET /api/users/{id}', 'reported'),
        ('POST /api/items', 'needs_follow_up'),
    }
