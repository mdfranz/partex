"""Unit tests for the minimal in-package OpenAPI subset resolver (issue #24; DEPS.md §3.1)."""

import json

from partex.ids import evidence_id
from partex.models import ConfigEvidence, ConfigExcerpt
from partex.openapi_resolver import (
    MAX_OPENAPI_NODES,
    check_response_body,
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
