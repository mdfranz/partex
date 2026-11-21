"""Tests for the openapi-spec-review passive check (issue #156)."""

import json
from typing import Any

from partex.agent_adapter.skills import skill_text
from partex.checks.openapi_spec_review import CHECK_ID, openapi_spec_review_check
from partex.ids import evidence_id, finding_id
from partex.models import (
    ConfigEvidence,
    ConfigExcerpt,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
)
from partex.openapi_resolver import derive_openapi_config_evidence
from partex.registry import build_registry


def _spec_ev(
    doc: dict[str, Any] | str, *, path: str = 'openapi.json', source: str = 'bundle/openapi.json'
) -> ConfigEvidence:
    content = doc if isinstance(doc, str) else json.dumps(doc)
    ev = ConfigEvidence(
        id='placeholder',
        source=source,
        config=ConfigExcerpt(path=path, format='openapi', content=content, revision='1.0'),
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


def _http_ev(
    url: str,
    *,
    body: str,
    status: int = 200,
    req_headers: list[tuple[str, str]] = (),  # type: ignore[assignment]
) -> HttpEvidence:
    ev = HttpEvidence(
        id='placeholder',
        source='capture:live',
        http=HttpExchange(
            request=HttpRequest(method='GET', url=url, headers=list(req_headers)),
            response=HttpResponse(status_code=status, headers=[('Content-Type', 'application/json')], body=body),
        ),
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


def _clean_spec() -> dict[str, Any]:
    return {
        'openapi': '3.1.0',
        'info': {'title': 'Clean API', 'version': '1.0.0'},
        'servers': [{'url': 'https://api.acme.com/v1'}],
        'security': [{'bearerAuth': []}],
        'components': {
            'securitySchemes': {
                'bearerAuth': {'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'JWT'},
                'headerKey': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'},
                'oauth': {
                    'type': 'oauth2',
                    'flows': {
                        'authorizationCode': {
                            'authorizationUrl': 'https://auth.acme.com/authorize',
                            'tokenUrl': 'https://auth.acme.com/token',
                            'scopes': {'read': 'Read access'},
                        }
                    },
                },
            },
            'schemas': {
                'User': {
                    'type': 'object',
                    'properties': {
                        'id': {'type': 'integer'},
                        'username': {'type': 'string'},
                        'email': {'type': 'string'},
                    },
                    'additionalProperties': False,
                }
            },
        },
        'paths': {
            '/users': {
                'get': {
                    'parameters': [{'name': 'page', 'in': 'query', 'schema': {'type': 'integer'}}],
                    'responses': {
                        '200': {
                            'description': 'ok',
                            'content': {'application/json': {'schema': {'$ref': '#/components/schemas/User'}}},
                        }
                    },
                }
            }
        },
    }


def test_applies_to_and_clean_spec_produces_no_findings_or_leads() -> None:
    clean = _spec_ev(_clean_spec())
    non_openapi = ConfigEvidence(
        id='ev_non_openapi',
        source='bundle/app.ini',
        config=ConfigExcerpt(path='app.ini', format='config', content='debug=false'),
    )
    assert openapi_spec_review_check.applies_to([non_openapi]) is False
    assert openapi_spec_review_check.applies_to([clean]) is True
    assert list(openapi_spec_review_check.review([clean])) == []
    assert list(openapi_spec_review_check.coverage([clean])) == []


def test_no_auth_declared_emits_one_finding_per_spec_not_per_operation() -> None:
    readonly_spec = {
        'openapi': '3.1.0',
        'info': {'title': 'ReadOnly', 'version': '1.0'},
        'paths': {
            '/a': {'get': {'responses': {'200': {'description': 'ok'}}}},
            '/b': {'get': {'responses': {'200': {'description': 'ok'}}}},
            '/c': {'head': {'responses': {'200': {'description': 'ok'}}}},
        },
    }
    (ro_finding,) = openapi_spec_review_check.review([_spec_ev(readonly_spec, path='ro.json')])
    assert ro_finding.check_id == CHECK_ID
    assert ro_finding.subject.endswith(':no-auth-declared')
    assert ro_finding.severity == 'low'
    assert '3 operation(s) (0 state-changing)' in ro_finding.description

    mutating_spec = {
        'openapi': '3.1.0',
        'info': {'title': 'Mutating', 'version': '1.0'},
        'paths': {
            '/items': {
                'get': {'responses': {'200': {'description': 'ok'}}},
                'post': {'responses': {'201': {'description': 'created'}}},
            },
            '/items/{id}': {
                'delete': {'responses': {'204': {'description': 'deleted'}}},
                'patch': {'responses': {'200': {'description': 'updated'}}},
            },
        },
    }
    drafts = list(openapi_spec_review_check.review([_spec_ev(mutating_spec, path='mut.json')]))
    assert len(drafts) == 1  # one finding per spec, never one per operation
    assert drafts[0].severity == 'medium'
    assert '4 operation(s) (3 state-changing)' in drafts[0].description
    assert '#/paths' in drafts[0].description


def test_weak_security_schemes_rule() -> None:
    doc = _clean_spec()
    doc['components']['securitySchemes'] = {
        'basicAuth': {'type': 'http', 'scheme': 'basic'},
        'queryKey': {'type': 'apiKey', 'in': 'query', 'name': 'key'},
        'cleartextOAuth': {
            'type': 'oauth2',
            'flows': {
                'implicit': {
                    'authorizationUrl': 'http://auth.acme.com/authorize',
                    'scopes': {},
                }
            },
        },
        'cleartextOidc': {'type': 'openIdConnect', 'openIdConnectUrl': 'http://auth.acme.com/.well-known/openid'},
    }
    (finding,) = openapi_spec_review_check.review([_spec_ev(doc)])
    assert finding.subject.endswith(':weak-security-scheme')
    assert finding.severity == 'medium'
    assert '#/components/securitySchemes/basicAuth' in finding.description
    assert '#/components/securitySchemes/queryKey' in finding.description
    assert '#/components/securitySchemes/cleartextOAuth/flows/implicit/authorizationUrl' in finding.description
    assert '#/components/securitySchemes/cleartextOidc/openIdConnectUrl' in finding.description


def test_internal_server_url_rule() -> None:
    doc = _clean_spec()
    doc['servers'] = [
        {'url': 'https://api.acme.com'},
        {'url': 'http://localhost:8080/api'},
        {'url': 'https://10.0.1.5/v1'},
        {'url': 'https://api.staging.acme.com'},
        {'url': 'https://svc.internal'},
    ]
    (finding,) = openapi_spec_review_check.review([_spec_ev(doc)])
    assert finding.subject.endswith(':internal-server-url')
    assert finding.severity == 'low'
    for idx in (1, 2, 3, 4):
        assert f'#/servers/{idx}/url' in finding.description
    assert '#/servers/0/url' not in finding.description


def test_credential_query_param_rule() -> None:
    doc = _clean_spec()
    doc['paths']['/users']['get']['parameters'] = [
        {'name': 'page', 'in': 'query'},
        {'name': 'api_key', 'in': 'query'},
        {'name': 'access_token', 'in': 'query'},
        {'name': 'jwt', 'in': 'query'},
        {'name': 'X-Auth-Token', 'in': 'header'},  # header is fine
    ]
    (finding,) = openapi_spec_review_check.review([_spec_ev(doc)])
    assert finding.subject.endswith(':credential-query-param')
    assert finding.severity == 'medium'
    assert '#/paths/~1users/get/parameters/1 (name=api_key)' in finding.description
    assert '#/paths/~1users/get/parameters/2 (name=access_token)' in finding.description
    assert '#/paths/~1users/get/parameters/3 (name=jwt)' in finding.description
    assert 'X-Auth-Token' not in finding.description


def test_sensitive_response_property_rule() -> None:
    doc_med = _clean_spec()
    doc_med['components']['schemas']['User']['properties']['role'] = {'type': 'string'}
    (med_finding,) = openapi_spec_review_check.review([_spec_ev(doc_med)])
    assert med_finding.subject.endswith(':sensitive-response-property')
    assert med_finding.severity == 'medium'
    assert 'GET /v1/users [200] #/role' in med_finding.description

    doc_high = _clean_spec()
    doc_high['components']['schemas']['User']['properties']['password_hash'] = {'type': 'string'}
    (high_finding,) = openapi_spec_review_check.review([_spec_ev(doc_high)])
    assert high_finding.subject.endswith(':sensitive-response-property')
    assert high_finding.severity == 'high'
    assert 'GET /v1/users [200] #/password_hash' in high_finding.description


def test_unauthenticated_spec_exposure_on_prod_vs_authenticated_and_nonprod() -> None:
    spec_text = json.dumps(_clean_spec())

    # 1. Production-looking host, unauthenticated 200 -> finding citing both config and HTTP evidence.
    prod_http = _http_ev('https://api.acme.com/openapi.json', body=spec_text)
    prod_cfg = derive_openapi_config_evidence(spec_text, origin_id=prod_http.id, url=prod_http.http.request.url)
    assert prod_cfg is not None
    (finding,) = openapi_spec_review_check.review([prod_http, prod_cfg])
    assert finding.subject.endswith(':unauthenticated-spec-exposure')
    assert finding.severity == 'low'
    assert set(finding.evidence_ids) == {prod_http.id, prod_cfg.id}

    # 2. Same production host, authenticated request -> clean.
    auth_http = _http_ev(
        'https://api.acme.com/openapi.json',
        body=spec_text,
        req_headers=[('Authorization', 'Bearer token123')],
    )
    auth_cfg = derive_openapi_config_evidence(spec_text, origin_id=auth_http.id, url=auth_http.http.request.url)
    assert auth_cfg is not None
    assert list(openapi_spec_review_check.review([auth_http, auth_cfg])) == []

    # 3. Localhost / staging host, unauthenticated -> clean (not a production-looking host).
    for nonprod_url in ('http://127.0.0.1:8000/openapi.json', 'https://staging.acme.com/openapi.json'):
        np_http = _http_ev(nonprod_url, body=spec_text)
        np_cfg = derive_openapi_config_evidence(spec_text, origin_id=np_http.id, url=nonprod_url)
        assert np_cfg is not None
        assert list(openapi_spec_review_check.review([np_http, np_cfg])) == []


def test_ssrf_and_redirect_params_produce_coverage_leads_not_findings() -> None:
    doc = _clean_spec()
    doc['paths']['/hooks'] = {
        'post': {
            'parameters': [
                {'name': 'callback', 'in': 'query'},
                {'name': 'webhook_url', 'in': 'query'},
                {'name': 'return_to', 'in': 'query'},
            ],
            'responses': {'200': {'description': 'ok'}},
        }
    }
    ev = _spec_ev(doc)
    assert list(openapi_spec_review_check.review([ev])) == []  # leads are NOT findings
    (lead,) = openapi_spec_review_check.coverage([ev])
    assert lead.outcome == 'needs_follow_up'
    assert lead.risk_area == 'ssrf-or-open-redirect'
    assert lead.surface == 'POST /hooks'
    assert lead.evidence_ids == [ev.id]
    for param in ('callback', 'webhook_url', 'return_to'):
        assert f'name={param}' in lead.reason


def test_output_and_ids_are_stable_across_spec_key_reordering() -> None:
    doc_a: dict[str, Any] = {
        'openapi': '3.1.0',
        'info': {'title': 'Order', 'version': '1.0'},
        'servers': [{'url': 'http://localhost:8000'}, {'url': 'https://dev.acme.com'}],
        'components': {
            'securitySchemes': {
                'zScheme': {'type': 'http', 'scheme': 'basic'},
                'aScheme': {'type': 'apiKey', 'in': 'query', 'name': 'k'},
            },
            'schemas': {
                'Item': {
                    'type': 'object',
                    'properties': {'ssn': {'type': 'string'}, 'role': {'type': 'string'}},
                }
            },
        },
        'paths': {
            '/z': {
                'get': {
                    'parameters': [{'name': 'token', 'in': 'query'}, {'name': 'next', 'in': 'query'}],
                    'responses': {
                        '200': {
                            'description': 'ok',
                            'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Item'}}},
                        }
                    },
                }
            },
            '/a': {
                'post': {
                    'parameters': [{'name': 'api_key', 'in': 'query'}, {'name': 'redirect', 'in': 'query'}],
                    'responses': {'200': {'description': 'ok'}},
                }
            },
        },
    }
    # Reverse key orders everywhere (note: servers is a list, so keep list order while reversing all dicts).
    doc_b: dict[str, Any] = {
        'paths': {
            '/a': doc_a['paths']['/a'],
            '/z': doc_a['paths']['/z'],
        },
        'components': {
            'schemas': {
                'Item': {
                    'properties': {'role': {'type': 'string'}, 'ssn': {'type': 'string'}},
                    'type': 'object',
                }
            },
            'securitySchemes': {
                'aScheme': doc_a['components']['securitySchemes']['aScheme'],
                'zScheme': doc_a['components']['securitySchemes']['zScheme'],
            },
        },
        'servers': doc_a['servers'],
        'info': {'version': '1.0', 'title': 'Order'},
        'openapi': '3.1.0',
    }
    ev_a = ConfigEvidence(
        id='ev_fixed_spec_id',
        source='bundle/openapi.json',
        config=ConfigExcerpt(path='openapi.json', format='openapi', content=json.dumps(doc_a), revision='1.0'),
    )
    ev_b = ConfigEvidence(
        id='ev_fixed_spec_id',
        source='bundle/openapi.json',
        config=ConfigExcerpt(path='openapi.json', format='openapi', content=json.dumps(doc_b), revision='1.0'),
    )
    drafts_a = list(openapi_spec_review_check.review([ev_a]))
    drafts_b = list(openapi_spec_review_check.review([ev_b]))
    assert drafts_a == drafts_b
    assert [finding_id(d.check_id, d.subject, d.title, d.evidence_ids) for d in drafts_a] == [
        finding_id(d.check_id, d.subject, d.title, d.evidence_ids) for d in drafts_b
    ]
    assert list(openapi_spec_review_check.coverage([ev_a])) == list(openapi_spec_review_check.coverage([ev_b]))


def test_skill_playbook_covers_every_rule() -> None:
    registry = build_registry()
    skill = registry.skills['openapi-spec-review']
    assert 'openapi-spec-review' in skill.checks
    body = skill_text(skill)
    for rule in (
        'no-auth-declared',
        'weak-security-scheme',
        'internal-server-url',
        'credential-query-param',
        'sensitive-response-property',
        'unauthenticated-spec-exposure',
        'needs_follow_up',
    ):
        assert rule in body, f'skill playbook missing rule {rule}'
