"""Unit tests for the minimal in-package OpenAPI subset resolver (issue #24; DEPS.md §3.1)."""

import json
import socket
import time

import pytest

from partex.bundle import MAX_CONTENT_BYTES
from partex.ids import evidence_id, sha256_hex
from partex.models import ConfigEvidence, ConfigExcerpt
from partex.openapi_resolver import (
    MAX_OPENAPI_NODES,
    check_response_body,
    derive_openapi_config_evidence,
    is_high_signal_secret_field,
    is_sensitive_field,
    load_openapi_contract,
    load_openapi_contracts,
    match_operation,
    max_violation_severity,
    normalize_request_path,
    resolve_local_pointer,
    resolve_schema,
)


def _cfg(
    content: str,
    *,
    fmt: str = 'openapi',
    path: str = 'openapi.yaml',
    revision: str | None = 'rev-1',
) -> ConfigEvidence:
    ev = ConfigEvidence(
        id='placeholder',
        source=path,
        config=ConfigExcerpt(path=path, format=fmt, content=content, revision=revision),
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


# ── Loading, formats, versions, and safety guards ────────────────────────────


def test_loads_json_and_yaml_openapi_30_and_31() -> None:
    yaml_contract = load_openapi_contract(
        _cfg(
            'openapi: 3.1.0\ninfo:\n  title: t\n  version: 1.2.3\npaths:\n  /ping:\n    get:\n      responses:\n        "200":\n          description: ok\n',
            revision=None,
        )
    )
    assert yaml_contract.load_error is None
    assert yaml_contract.openapi_version == '3.1.0'
    assert yaml_contract.revision == '1.2.3'  # falls back to info.version when config.revision is None
    assert [op.key for op in yaml_contract.operations] == ['GET /ping']

    json_doc = {
        'openapi': '3.0.3',
        'info': {'title': 't', 'version': '0.9.0'},
        'paths': {'/items/{itemId}': {'post': {'responses': {'201': {'description': 'created'}}}}},
    }
    json_contract = load_openapi_contract(_cfg(json.dumps(json_doc), path='openapi.json', revision='git-abc123'))
    assert json_contract.load_error is None
    assert json_contract.openapi_version == '3.0.3'
    assert json_contract.revision == 'git-abc123'  # explicit config.revision wins over info.version
    assert [op.key for op in json_contract.operations] == ['POST /items/{itemId}']


def test_load_openapi_contracts_filters_by_format() -> None:
    openapi_ev = _cfg('openapi: 3.1.0\ninfo: {title: a, version: "1"}\npaths: {}')
    ini_ev = _cfg('debug=true', fmt='config', path='app.ini')
    loaded = load_openapi_contracts([openapi_ev, ini_ev, 'not-evidence'])
    assert [c.evidence_id for c in loaded] == [openapi_ev.id]


def test_rejects_swagger_20_empty_malformed_and_missing_paths_without_raising() -> None:
    swagger = load_openapi_contract(_cfg('swagger: "2.0"\ninfo: {title: old, version: "1"}\npaths: {}'))
    assert swagger.load_error is not None and 'swagger' in swagger.load_error

    empty = load_openapi_contract(_cfg('   \n'))
    assert empty.load_error is not None and 'empty' in empty.load_error

    bad_yaml = load_openapi_contract(_cfg('openapi: [unclosed'))
    assert bad_yaml.load_error is not None and 'invalid OpenAPI' in bad_yaml.load_error

    bad_json_brace = load_openapi_contract(_cfg('{broken: [unclosed'))
    assert bad_json_brace.load_error is not None and 'invalid OpenAPI' in bad_json_brace.load_error

    scalar_root = load_openapi_contract(_cfg('- just\n- a\n- list\n'))
    assert scalar_root.load_error == 'OpenAPI root must be a mapping'

    no_paths = load_openapi_contract(_cfg('openapi: 3.1.0\ninfo: {title: x, version: "1"}\n'))
    assert no_paths.load_error is not None and 'paths' in no_paths.load_error


def test_yaml_alias_bomb_exceeding_node_cap_is_refused_cleanly() -> None:
    # 2^16 = 65,536 leaf nodes from tiny YAML text (> MAX_OPENAPI_NODES = 25,000).
    lines = ['openapi: 3.1.0', 'info: {title: bomb, version: "1"}', 'x-a0: &a0 [1, 2]']
    for i in range(1, 16):
        lines.append(f'x-a{i}: &a{i} [*a{i - 1}, *a{i - 1}]')
    lines.append('paths: {}')
    contract = load_openapi_contract(_cfg('\n'.join(lines)))
    assert contract.load_error is not None
    assert str(MAX_OPENAPI_NODES) in contract.load_error


# ── JSON Pointer, $ref siblings, allOf, oneOf/anyOf, cycles, external $refs ──


def test_json_pointer_rfc6901_unescaping_and_errors() -> None:
    doc = {'a/b': {'c~d': ['zero', {'ok': True}]}}
    assert resolve_local_pointer(doc, '#') == (doc, None)
    assert resolve_local_pointer(doc, '#/a~1b/c~0d/1/ok') == (True, None)
    assert resolve_local_pointer(doc, '#/a~1b/c~0d/99') == (None, '#/a~1b/c~0d/99')
    assert resolve_local_pointer(doc, '#/a~1b/c~0d/notanint') == (None, '#/a~1b/c~0d/notanint')
    assert resolve_local_pointer(doc, './external.yaml#/User') == (None, './external.yaml#/User')
    assert resolve_local_pointer(doc, '#bad-fragment') == (None, '#bad-fragment')


def test_allof_and_oas31_ref_siblings_merge_properties_and_closure() -> None:
    spec = """\
openapi: 3.1.0
info: {title: test, version: "1.0"}
paths:
  /users/{id}:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/UserPublic"
                unevaluatedProperties: false
components:
  schemas:
    Base:
      type: object
      properties:
        id: {type: integer}
    UserPublic:
      allOf:
        - $ref: "#/components/schemas/Base"
        - type: object
          properties:
            username: {type: string}
            nickname:
              anyOf:
                - type: string
                - type: "null"
"""
    contract = load_openapi_contract(_cfg(spec))
    (op,) = contract.operations
    ok = check_response_body(op, 200, json.dumps({'id': 1, 'username': 'alice', 'nickname': None}))
    assert ok.violations == () and ok.unresolved_ref is None and ok.evaluated is True

    extra = check_response_body(
        op,
        200,
        json.dumps({'id': 1, 'username': 'alice', 'debug_flag': True, 'password_hash': 'xxx'}),
    )
    assert [(v.path, v.severity) for v in extra.violations] == [
        ('$.debug_flag', 'medium'),
        ('$.password_hash', 'high'),
    ]
    assert max_violation_severity(extra.violations) == 'high'


def test_external_and_missing_refs_yield_insufficient_evidence_never_raise() -> None:
    spec = """\
openapi: 3.1.0
info: {title: ext, version: "1.0"}
paths:
  /external:
    get:
      responses:
        "200":
          description: ext
          content:
            application/json:
              schema:
                $ref: "./common.yaml#/components/schemas/User"
  /missing-local:
    get:
      responses:
        "200":
          $ref: "#/components/responses/DoesNotExist"
"""
    contract = load_openapi_contract(_cfg(spec))
    assert contract.load_error is None
    assert './common.yaml#/components/schemas/User' in contract.unresolved_refs
    assert '#/components/responses/DoesNotExist' in contract.unresolved_refs

    by_key = {op.key: op for op in contract.operations}
    ext_outcome = check_response_body(by_key['GET /external'], 200, '{"id": 1}')
    assert ext_outcome.violations == ()
    assert ext_outcome.unresolved_ref == './common.yaml#/components/schemas/User'
    assert ext_outcome.evaluated is False

    missing_outcome = check_response_body(by_key['GET /missing-local'], 200, '{"id": 1}')
    assert missing_outcome.unresolved_ref == '#/components/responses/DoesNotExist'
    assert missing_outcome.evaluated is False


def test_circular_ref_terminates_without_recursion_error() -> None:
    doc = {
        'components': {
            'schemas': {
                'Node': {
                    'type': 'object',
                    'properties': {
                        'name': {'type': 'string'},
                        'parent': {'$ref': '#/components/schemas/Node'},
                        'children': {'type': 'array', 'items': {'$ref': '#/components/schemas/Node'}},
                    },
                    'additionalProperties': False,
                }
            }
        }
    }
    schema = resolve_schema({'$ref': '#/components/schemas/Node'}, doc)
    assert set(schema.properties) == {'name', 'parent', 'children'}
    assert schema.properties['parent'].cyclic is True
    assert schema.properties['children'].items is not None
    assert schema.properties['children'].items.cyclic is True


def test_oneof_branches_and_array_items_deduplicate_paths() -> None:
    spec = """\
openapi: 3.1.0
info: {title: union, version: "1.0"}
paths:
  /events:
    get:
      responses:
        2XX:
          description: event list
          content:
            application/vnd.api+json:
              schema:
                type: array
                items:
                  oneOf:
                    - type: object
                      properties:
                        kind: {type: string}
                        actor: {type: string}
                      additionalProperties: false
                    - type: object
                      properties:
                        kind: {type: string}
                        system_code: {type: integer}
                      additionalProperties: false
"""
    contract = load_openapi_contract(_cfg(spec))
    (op,) = contract.operations

    clean_body = json.dumps([{'kind': 'user', 'actor': 'alice'}, {'kind': 'sys', 'system_code': 10}])
    assert check_response_body(op, 200, clean_body, 'application/vnd.api+json').violations == ()

    leaky_body = json.dumps(
        [
            {'kind': 'user', 'actor': 'alice', 'api_secret': 'sec1'},
            {'kind': 'user', 'actor': 'bob', 'api_secret': 'sec2'},
        ]
    )
    leaky = check_response_body(op, 200, leaky_body, 'application/vnd.api+json')
    assert [(v.path, v.severity) for v in leaky.violations] == [('$[*].api_secret', 'high')]


def test_open_additional_properties_allows_map_keys_but_flags_high_signal_secrets() -> None:
    spec = """\
openapi: 3.0.3
info: {title: map, version: "1.0"}
paths:
  /labels:
    get:
      responses:
        default:
          description: dynamic map
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: {type: integer}
                additionalProperties:
                  type: string
"""
    (op,) = load_openapi_contract(_cfg(spec)).operations
    assert check_response_body(op, 200, json.dumps({'id': 1, 'env': 'prod', 'team': 'core'})).violations == ()
    leak = check_response_body(op, 200, json.dumps({'id': 1, 'env': 'prod', 'private_key': 'PEM'}))
    assert [(v.path, v.severity) for v in leak.violations] == [('$.private_key', 'high')]


def test_pattern_properties_and_special_json_keys() -> None:
    spec = """\
openapi: 3.1.0
info: {title: pat, version: "1.0"}
paths:
  /meta:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: {type: integer}
                patternProperties:
                  "^x-": {type: string}
                additionalProperties: false
"""
    (op,) = load_openapi_contract(_cfg(spec)).operations
    assert check_response_body(op, 200, json.dumps({'id': 1, 'x-trace': 'abc'})).violations == ()
    bad = check_response_body(op, 200, json.dumps({'id': 1, 'bad.key': 1}))
    assert [(v.path, v.severity) for v in bad.violations] == [('$["bad.key"]', 'medium')]


def test_non_2xx_non_json_and_boolean_schemas() -> None:
    doc: dict[str, object] = {}
    assert resolve_schema(True, doc).allows_arbitrary_props is True
    assert resolve_schema(False, doc).closed is True

    spec = """\
openapi: 3.1.0
info: {title: edge, version: "1.0"}
paths:
  /strict-empty:
    get:
      responses:
        "200":
          description: closed false schema
          content:
            "*/*":
              schema: false
"""
    (op,) = load_openapi_contract(_cfg(spec)).operations
    assert check_response_body(op, 404, '{"a": 1}').evaluated is False
    assert check_response_body(op, 204, None).violations == ()
    assert check_response_body(op, 200, 'plain text', 'text/plain').violations == ()
    assert check_response_body(op, 200, '{invalid json', 'application/json').evaluated is False
    closed_hit = check_response_body(op, 200, '{"extra": 1}', 'application/json')
    assert [(v.path, v.severity) for v in closed_hit.violations] == [('$.extra', 'medium')]


# ── Server prefixes and path-template specificity matching ───────────────────


def test_server_variables_and_path_specificity_precedence() -> None:
    spec = """\
openapi: 3.1.0
info: {title: routing, version: "2.0"}
servers:
  - url: https://{env}.example.test/{basePath}
    variables:
      env:
        default: staging
      basePath:
        default: api/v2
paths:
  /users/{id}:
    get:
      responses: {"200": {description: by id}}
  /users/me:
    get:
      responses: {"200": {description: current user}}
  /files/{name}.json:
    get:
      responses: {"200": {description: json file}}
  /files/{slug}:
    get:
      responses: {"200": {description: generic file}}
"""
    ops = load_openapi_contract(_cfg(spec)).operations

    # Exact static segment '/users/me' wins over '/users/{id}' regardless of declaration order.
    me_match = match_operation(ops, 'get', 'https://app.example.test/api/v2/users/me?verbose=1#top')
    assert me_match is not None and me_match.operation is not None
    assert me_match.operation.key == 'GET /api/v2/users/me'

    id_match = match_operation(ops, 'GET', 'https://app.example.test/api/v2/users/42/')
    assert id_match is not None and id_match.operation is not None
    assert id_match.operation.key == 'GET /api/v2/users/{id}'

    # Mixed literal+param segment '{name}.json' (score 1) beats pure param '{slug}' (score 0).
    mixed = match_operation(ops, 'GET', 'https://app.example.test/api/v2/files/report.json')
    assert mixed is not None and mixed.operation is not None
    assert mixed.operation.key == 'GET /api/v2/files/{name}.json'

    # Encoded '%2F' inside a path parameter stays one segment and matches '/files/{slug}'.
    encoded_slash = match_operation(ops, 'GET', 'https://app.example.test/api/v2/files/dir%2Fdoc.pdf')
    assert encoded_slash is not None and encoded_slash.operation is not None
    assert encoded_slash.operation.key == 'GET /api/v2/files/{slug}'

    # Path matches '/users/{id}', but DELETE is undeclared -> PathMatch(operation=None).
    undeclared_method = match_operation(ops, 'DELETE', 'https://app.example.test/api/v2/users/42')
    assert undeclared_method is not None
    assert undeclared_method.path_template == '/api/v2/users/{id}'
    assert undeclared_method.operation is None

    # Completely unknown path -> None.
    assert match_operation(ops, 'GET', 'https://app.example.test/api/v1/legacy') is None


def test_normalize_request_path_decodes_unreserved_only() -> None:
    assert normalize_request_path('https://x.test/api/%7Ealice/file%2F1?a=1#f') == '/api/~alice/file%2F1'
    assert normalize_request_path('/') == '/'
    assert normalize_request_path('relative/path') == '/relative/path'


def test_sensitive_field_classifiers() -> None:
    for sensitive in (
        'password_hash',
        'passwordHash',
        'isAdmin',
        'is_admin',
        'secret',
        'token',
        'role',
        'ssn',
        'apiKey',
    ):
        assert is_sensitive_field(sensitive), sensitive
    for benign in ('username', 'created_at', 'title', 'internal_notes', 'total_count'):
        assert not is_sensitive_field(benign), benign

    assert is_high_signal_secret_field('password_hash')
    assert is_high_signal_secret_field('totpSecret')
    assert not is_high_signal_secret_field('token')  # login endpoints may legitimately return token without schema


# ── Live OpenAPI detection & ConfigEvidence derivation (issue #155) ──────────


def test_derive_openapi_config_evidence_json_yaml_revision_and_idempotence() -> None:
    json_spec = json.dumps(
        {
            'openapi': '3.1.0',
            'info': {'title': 'Users API', 'version': '2.4.1'},
            'paths': {'/api/users': {'get': {'responses': {'200': {'description': 'ok'}}}}},
        }
    )
    ev1 = derive_openapi_config_evidence(
        json_spec,
        origin_id='ev_http_first',
        url='https://user:secret@app.example.test:8443/openapi.json?token=abc#frag',
    )
    assert ev1 is not None
    assert ev1.kind == 'config_excerpt'
    assert ev1.config.format == 'openapi'
    assert ev1.config.path == '/openapi.json'
    assert ev1.config.revision == '2.4.1'
    assert ev1.config.content == json_spec
    assert ev1.source == 'derived:ev_http_first:https://app.example.test:8443/openapi.json'
    assert 'secret' not in ev1.source and 'token=' not in ev1.source

    # Re-fetching the same spec (new originating ev_ ID, different query string) yields identical evidence ID.
    ev2 = derive_openapi_config_evidence(
        json_spec,
        origin_id='ev_http_second',
        url='https://app.example.test:8443/openapi.json?cachebust=2',
    )
    assert ev2 is not None
    assert ev2.id == ev1.id
    assert ev2.source == 'derived:ev_http_second:https://app.example.test:8443/openapi.json'

    # Missing or boolean info.version falls back to body sha256.
    yaml_spec = 'openapi: 3.0.3\ninfo:\n  title: Minimal\n  version: true\npaths:\n  /ping:\n    get:\n      responses:\n        "200":\n          description: pong\n'
    yaml_ev = derive_openapi_config_evidence(yaml_spec, origin_id='ev_art_1', url='http://127.0.0.1:8000/spec.yaml')
    assert yaml_ev is not None
    assert yaml_ev.config.path == '/spec.yaml'
    assert yaml_ev.config.revision == sha256_hex(yaml_spec.encode('utf-8'))


def test_derive_openapi_config_evidence_rejects_non_openapi_swagger2_and_oversized() -> None:
    url = 'http://127.0.0.1:8000/openapi.json'
    # Empty, HTML, JS, plain JSON, Swagger 2.0, unsupported OAS 4.x, missing/non-dict paths.
    assert derive_openapi_config_evidence('', origin_id='ev_1', url=url) is None
    assert (
        derive_openapi_config_evidence('<html><body>openapi: 3.1.0 paths: {}</body></html>', origin_id='ev_1', url=url)
        is None
    )
    assert (
        derive_openapi_config_evidence(
            'const cfg = {openapi: "3.1.0", paths: {}};',
            origin_id='ev_1',
            url=url,
        )
        is None
    )
    assert derive_openapi_config_evidence('{"status":"ok","paths":{}}', origin_id='ev_1', url=url) is None
    assert (
        derive_openapi_config_evidence(
            '{"swagger":"2.0","info":{"title":"old","version":"1"},"paths":{}}',
            origin_id='ev_1',
            url=url,
        )
        is None
    )
    assert derive_openapi_config_evidence('{"openapi":"4.0.0","paths":{}}', origin_id='ev_1', url=url) is None
    assert (
        derive_openapi_config_evidence('{"openapi":"3.1.0","info":{"version":"1"}}', origin_id='ev_1', url=url) is None
    )
    assert derive_openapi_config_evidence('{"openapi":"3.1.0","paths":[]}', origin_id='ev_1', url=url) is None

    # Oversized UTF-8 payload (> MAX_CONTENT_BYTES).
    oversized = json.dumps(
        {
            'openapi': '3.1.0',
            'info': {'title': 'big', 'version': '1.0'},
            'paths': {'/x': {'get': {'description': 'a' * (MAX_CONTENT_BYTES + 64)}}},
        }
    )
    assert len(oversized.encode('utf-8')) > MAX_CONTENT_BYTES
    assert derive_openapi_config_evidence(oversized, origin_id='ev_big', url=url) is None

    # YAML alias expansion exceeding MAX_OPENAPI_NODES.
    bomb_lines = ['openapi: 3.1.0', 'info: {title: bomb, version: "1"}', 'x-base: &a0 [1, 2, 3, 4]']
    for idx in range(1, 16):
        bomb_lines.append(f'x-lvl{idx}: &a{idx} [*a{idx - 1}, *a{idx - 1}]')
    bomb_lines.append('paths: {}')
    assert derive_openapi_config_evidence('\n'.join(bomb_lines), origin_id='ev_bomb', url=url) is None
    assert MAX_OPENAPI_NODES == 25_000


# ── referencing ($id, $anchor, no-retriever, memoization, budget) (#153) ─────


def test_oas31_dollar_id_and_dollar_anchor_refs_resolve() -> None:
    spec = """\
openapi: 3.1.0
info: {title: anchors, version: "1.0"}
paths:
  /profiles/{id}:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "https://schemas.example.test/profile.json"
components:
  schemas:
    AnchoredMeta:
      $anchor: sharedMeta
      type: object
      properties:
        version: {type: integer}
      additionalProperties: false
    Profile:
      $id: "https://schemas.example.test/profile.json"
      type: object
      properties:
        id: {type: integer}
        badge:
          $ref: "#badgeAnchor"
        meta:
          $ref: "urn:partex:openapi#sharedMeta"
      additionalProperties: false
      $defs:
        Badge:
          $anchor: badgeAnchor
          type: object
          properties:
            label: {type: string}
          additionalProperties: false
"""
    contract = load_openapi_contract(_cfg(spec))
    assert contract.load_error is None
    assert contract.unresolved_refs == ()
    (op,) = contract.operations

    ok = check_response_body(op, 200, json.dumps({'id': 1, 'badge': {'label': 'pro'}, 'meta': {'version': 2}}))
    assert ok.violations == () and ok.evaluated is True

    bad = check_response_body(
        op,
        200,
        json.dumps({'id': 1, 'badge': {'label': 'pro', 'secret': 'x'}, 'meta': {'version': 2, 'extra': True}}),
    )
    assert [(v.path, v.severity) for v in bad.violations] == [
        ('$.badge.secret', 'high'),
        ('$.meta.extra', 'medium'),
    ]


def test_external_ref_never_opens_a_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbid_socket(*args: object, **kwargs: object) -> None:
        raise AssertionError('external $ref resolution must never open a socket')

    monkeypatch.setattr(socket, 'socket', _forbid_socket)
    monkeypatch.setattr(socket, 'create_connection', _forbid_socket)

    spec = """\
openapi: 3.1.0
info: {title: ext-net, version: "1.0"}
paths:
  /remote:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "https://external.invalid/schemas/user.json"
"""
    contract = load_openapi_contract(_cfg(spec))
    assert contract.load_error is None
    assert contract.unresolved_refs == ('https://external.invalid/schemas/user.json',)
    (op,) = contract.operations
    outcome = check_response_body(op, 200, '{"id": 1}')
    assert outcome.evaluated is False
    assert outcome.unresolved_ref == 'https://external.invalid/schemas/user.json'


def test_doubled_ref_chain_resolves_quickly_via_memoization() -> None:
    # A 24-level doubled $ref chain has 2^24 (~16.7M) uncached paths; memoization makes it linear.
    levels = 24
    schemas: dict[str, object] = {
        f'L{levels}': {
            'type': 'object',
            'properties': {'leaf': {'type': 'string'}},
            'additionalProperties': False,
        }
    }
    for i in range(levels - 1, -1, -1):
        target = f'#/components/schemas/L{i + 1}'
        schemas[f'L{i}'] = {'allOf': [{'$ref': target}, {'$ref': target}]}
    spec = {
        'openapi': '3.1.0',
        'info': {'title': 'chain', 'version': '1.0'},
        'paths': {
            '/chain': {
                'get': {
                    'responses': {
                        '200': {
                            'description': 'ok',
                            'content': {'application/json': {'schema': {'$ref': '#/components/schemas/L0'}}},
                        }
                    }
                }
            }
        },
        'components': {'schemas': schemas},
    }
    start = time.monotonic()
    contract = load_openapi_contract(_cfg(json.dumps(spec), path='chain.json'))
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, f'doubled $ref chain took {elapsed:.2f}s (expected memoized linear resolution)'
    assert contract.load_error is None
    (op,) = contract.operations
    assert check_response_body(op, 200, json.dumps({'leaf': 'ok'})).violations == ()
    bad = check_response_body(op, 200, json.dumps({'leaf': 'ok', 'extra': 1}))
    assert [(v.path, v.severity) for v in bad.violations] == [('$.extra', 'medium')]


def test_resolution_budget_degrades_to_unresolved_ref() -> None:
    doc = {
        'components': {
            'schemas': {
                'A': {'type': 'object', 'properties': {'b': {'$ref': '#/components/schemas/B'}}},
                'B': {'type': 'object', 'properties': {'c': {'type': 'string'}}},
            }
        }
    }
    schema = resolve_schema({'$ref': '#/components/schemas/A'}, doc, max_steps=2)
    assert schema.unresolved_ref is not None
    assert 'resolution-budget-exceeded' in schema.unresolved_ref
