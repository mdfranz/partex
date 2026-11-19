"""Tests for data contracts — PLAN §5.

Validates models parse, reject extra fields, enforce bounds, and handle
the discriminated evidence union correctly.
"""

import pytest
from pydantic import ValidationError

from partex.models import (
    Authorization,
    ConfigEvidence,
    ConfigExcerpt,
    CoverageEntry,
    Engagement,
    EngagementTarget,
    EvidenceAdapter,
    Finding,
    FindingDraft,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
    ReviewSummary,
    Scope,
    Verification,
    VerificationRecipe,
    VerificationRequest,
    get_all,
    get_header,
    parse_secret_path,
    redact,
)

# ── HttpExchange ───────────────────────────────────────────────────────────────


def test_http_exchange_round_trip():
    req = HttpRequest(method='GET', url='https://example.test/', headers=[('Host', 'example.test')])
    resp = HttpResponse(status_code=200, headers=[('Content-Type', 'text/html')], body='<html>ok</html>')
    exchange = HttpExchange(request=req, response=resp)
    assert exchange.request.method == 'GET'
    assert exchange.response.status_code == 200
    assert exchange.response.body == '<html>ok</html>'


def test_http_exchange_forbids_extra():
    with pytest.raises(ValidationError):
        HttpExchange(
            request=HttpRequest(method='GET', url='https://example.test/', headers=[]),
            response=HttpResponse(status_code=200, headers=[]),
            bogus=1,
        )


def test_http_request_optional_body():
    req = HttpRequest(method='GET', url='https://example.test/', headers=[])
    assert req.body is None


def test_http_response_optional_body():
    resp = HttpResponse(status_code=204, headers=[])
    assert resp.body is None


# ── ConfigExcerpt ──────────────────────────────────────────────────────────────


def test_config_excerpt():
    ex = ConfigExcerpt(path='api.yaml', format='openapi', content='openapi: 3.0.0', revision='abc123')
    assert ex.revision == 'abc123'


def test_config_excerpt_default_revision():
    ex = ConfigExcerpt(path='api.yaml', format='openapi', content='openapi: 3.0.0')
    assert ex.revision is None


# ── Evidence discriminated union ────────────────────────────────────────────────


def test_http_evidence_model():
    ex = HttpExchange(
        request=HttpRequest(method='GET', url='https://example.test/', headers=[]),
        response=HttpResponse(status_code=200, headers=[]),
    )
    ev = HttpEvidence(id='ev_abc', source='file1.json', http=ex, secret_fields=['$.http.request.url'])
    assert ev.kind == 'http_exchange'
    assert ev.id == 'ev_abc'


def test_config_evidence_model():
    cfg = ConfigExcerpt(path='api.yaml', format='openapi', content='openapi: 3.0.0')
    ev = ConfigEvidence(id='ev_def', source='file2.yaml', config=cfg)
    assert ev.kind == 'config_excerpt'
    assert ev.secret_fields == []


def test_evidence_type_adapter_round_trip_http():
    ex = HttpExchange(
        request=HttpRequest(method='POST', url='https://example.test/a', headers=[('Accept', 'application/json')]),
        response=HttpResponse(status_code=201, headers=[('Location', '/a/1')]),
    )
    original = HttpEvidence(id='ev_abc', source='file1.json', http=ex)
    serialised = original.model_dump(mode='json')
    deserialised = EvidenceAdapter.validate_python(serialised)
    assert isinstance(deserialised, HttpEvidence)
    assert deserialised.id == 'ev_abc'
    assert deserialised.http.request.method == 'POST'


def test_evidence_type_adapter_round_trip_config():
    cfg = ConfigExcerpt(path='api.yaml', format='openapi', content='openapi: 3.0.0', revision='v1')
    original = ConfigEvidence(id='ev_def', source='file2.yaml', config=cfg)
    serialised = original.model_dump(mode='json')
    deserialised = EvidenceAdapter.validate_python(serialised)
    assert isinstance(deserialised, ConfigEvidence)
    assert deserialised.config.revision == 'v1'


def test_evidence_discriminated_union_requires_kind():
    with pytest.raises(ValidationError):
        EvidenceAdapter.validate_python({'id': 'x', 'source': 'f', 'http': {}})


# ── FindingDraft ───────────────────────────────────────────────────────────────


def test_finding_draft_requires_non_empty_evidence_ids():
    with pytest.raises(ValidationError, match='evidence_ids'):
        FindingDraft(
            check_id='header-security',
            check_version='1.0',
            severity='medium',
            subject='test',
            title='Missing HSTS',
            description='...',
            evidence_ids=[],
            remediation='...',
        )


def test_finding_draft_requires_non_empty_subject():
    with pytest.raises(ValidationError, match='subject'):
        FindingDraft(
            check_id='c',
            check_version='1.0',
            severity='low',
            subject='',
            title='t',
            description='d',
            evidence_ids=['ev_abc'],
            remediation='r',
        )


def test_finding_draft_minimal():
    d = FindingDraft(
        check_id='test-check',
        check_version='1.0',
        severity='info',
        subject='test',
        title='Test',
        description='desc',
        evidence_ids=['ev_abc'],
        remediation='fix',
    )
    assert d.check_id == 'test-check'
    assert len(d.evidence_ids) == 1


def test_finding_draft_rejects_extra():
    with pytest.raises(ValidationError):
        FindingDraft(
            check_id='test-check',
            check_version='1.0',
            severity='info',
            subject='test',
            title='Test',
            description='desc',
            evidence_ids=['ev_abc'],
            remediation='fix',
            not_a_field=42,
        )


# ── Finding ────────────────────────────────────────────────────────────────────


def test_finding_minimal():
    f = Finding(
        id='fn_01',
        check_id='test-check',
        check_version='1.0',
        severity='high',
        subject='test',
        title='Test',
        description='desc',
        evidence_ids=['ev_abc'],
        remediation='fix',
        status='reported',
    )
    assert f.status == 'reported'
    assert f.verification_id is None


def test_finding_with_verification():
    f = Finding(
        id='fn_01',
        check_id='test-check',
        check_version='1.0',
        severity='high',
        subject='test',
        title='Test',
        description='desc',
        evidence_ids=['ev_abc'],
        remediation='fix',
        status='verified',
        verification_id='vf_01',
    )
    assert f.verification_id == 'vf_01'


def test_finding_invalid_severity():
    with pytest.raises(ValidationError):
        Finding(
            id='fn_01',
            check_id='test',
            check_version='1.0',
            severity='unknown',  # type: ignore[arg-type]
            subject='test',
            title='Test',
            description='desc',
            evidence_ids=['ev_abc'],
            remediation='fix',
            status='reported',
        )


# ── Verification ───────────────────────────────────────────────────────────────


def test_verification():
    v = Verification(
        id='vf_01',
        finding_id='fn_01',
        check_id='version-disclosure',
        requests=['ev_02'],
        verdict='confirmed',
        replayable=True,
        detail='Server header matched known CVE signature',
        counterevidence='Verified against two endpoints; banner present on both',
    )
    assert v.replayable is True
    assert v.verdict == 'confirmed'


def test_verification_verdict_literals():
    for verdict in ('confirmed', 'not_reproduced', 'inconclusive'):
        v = Verification(
            id='vf_x',
            finding_id='fn_x',
            check_id='test',
            requests=[],
            verdict=verdict,  # type: ignore[arg-type]
            replayable=False,
            detail='',
            counterevidence='',
        )
        assert v.verdict == verdict


# ── VerificationRecipe ────────────────────────────────────────────────────────


def test_verification_recipe():
    recipe = VerificationRecipe(
        description='Replay the single banner-bearing request',
        requests=[VerificationRequest(method='GET', path='/')],
    )
    assert len(recipe.requests) == 1
    assert recipe.requests[0].method == 'GET'


# ── CoverageEntry ─────────────────────────────────────────────────────────────


def test_coverage_entry_defaults():
    ce = CoverageEntry(
        surface='GET /api/users/{id}', risk_area='authz', outcome='no_issue_found', source='check_observed'
    )
    assert ce.goal_attempts == 0
    assert ce.evidence_ids == []
    assert ce.reason == ''


# ── ReviewSummary ──────────────────────────────────────────────────────────────


def test_review_summary():
    s = ReviewSummary(narrative='All clean.', finding_ids=['fn_01', 'fn_02'])
    assert s.narrative == 'All clean.'
    assert s.finding_ids == ['fn_01', 'fn_02']


def test_review_summary_empty_finding_ids():
    s = ReviewSummary(narrative='No findings.', finding_ids=[])
    assert s.finding_ids == []


# ── Engagement ─────────────────────────────────────────────────────────────────


def test_engagement_minimal():
    eng = Engagement(
        target=EngagementTarget(name='app', base_url='https://example.test'),
        scope=Scope(hosts=['example.test'], path_prefixes=['/'], exclusions=[], ports=[443]),
        authorization=Authorization(attestation='SOW-2026-114', operator='j.operator'),
    )
    assert eng.schema_version == 1
    assert eng.target.name == 'app'


def test_engagement_with_credentials_and_roles():
    eng = Engagement(
        target=EngagementTarget(name='app', base_url='https://example.test'),
        scope=Scope(hosts=['example.test'], path_prefixes=['/'], ports=[443]),
        authorization=Authorization(attestation='SOW-2026-114', operator='j.operator'),
        credentials={'session': 'PARTEX_CRED_SESSION'},
        roles={'owner': 'PARTEX_CRED_OWNER'},
        suggested_checks=['header-security'],
    )
    assert eng.credentials == {'session': 'PARTEX_CRED_SESSION'}
    assert eng.roles == {'owner': 'PARTEX_CRED_OWNER'}


def test_engagement_rejects_extra():
    with pytest.raises(ValidationError):
        Engagement(
            target=EngagementTarget(name='app', base_url='https://example.test'),
            scope=Scope(hosts=['example.test']),
            authorization=Authorization(attestation='x', operator='j'),
            bogus='nope',
        )


# ── Scope ──────────────────────────────────────────────────────────────────────


def test_scope_requires_hosts():
    with pytest.raises(ValidationError, match='hosts'):
        Scope(hosts=[])  # type: ignore[arg-type]


def test_scope_max_rps_positive():
    with pytest.raises(ValidationError):
        Scope(hosts=['example.test'], max_rps=0)


def test_scope_max_requests_positive():
    with pytest.raises(ValidationError):
        Scope(hosts=['example.test'], max_requests=0)


# ── Headers ────────────────────────────────────────────────────────────────────


def test_headers_preserve_repeats_order_and_casing():
    resp = HttpResponse(status_code=200, headers=[('Set-Cookie', 'a=1'), ('set-cookie', 'b=2'), ('X-A', 'v')])
    assert get_all(resp.headers, 'SET-COOKIE') == ['a=1', 'b=2']
    assert get_header(resp.headers, 'set-cookie') == 'a=1'
    assert get_header(resp.headers, 'x-a') == 'v'
    assert get_header(resp.headers, 'missing') is None
    assert get_all(resp.headers, 'missing') == []
    assert [name for name, _ in resp.headers] == ['Set-Cookie', 'set-cookie', 'X-A']


def test_headers_serialize_as_pairs():
    resp = HttpResponse(status_code=200, headers=[('A', '1'), ('A', '2')])
    assert resp.model_dump(mode='json')['headers'] == [['A', '1'], ['A', '2']]
    assert HttpResponse.model_validate_json(resp.model_dump_json()) == resp


def test_headers_reject_mapping():
    with pytest.raises(ValidationError):
        HttpResponse.model_validate({'status_code': 200, 'headers': {'A': '1'}})


# ── Secret paths ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ('path', 'parts'),
    [
        ('$.http.request.body', ('http', 'request', 'body')),
        ('$.http.request.headers[2][1]', ('http', 'request', 'headers', 2, 1)),
        ('$.config.content', ('config', 'content')),
    ],
)
def test_parse_secret_path(path: str, parts: tuple[str | int, ...]):
    assert parse_secret_path(path) == parts


@pytest.mark.parametrize('path', ['', '$', 'http.request.body', '$.http..body', '$.headers[x]', '$.a[-1]', '$.a.b-c'])
def test_parse_secret_path_rejects_malformed(path: str):
    with pytest.raises(ValueError):
        parse_secret_path(path)


def _exchange(*, request_headers: list[tuple[str, str]] | None = None, **response: object) -> HttpExchange:
    return HttpExchange(
        request=HttpRequest(
            method='POST', url='https://example.test/', headers=request_headers or [], body='token=abc'
        ),
        response=HttpResponse.model_validate({'status_code': 200, 'headers': []} | response),
    )


@pytest.mark.parametrize(
    'path',
    [
        '$.http.request.headers.Authorization',  # names are never path steps
        '$.http.request.headers[0][1]',  # no header 0
        '$.http.request',  # not a string leaf
        '$.http.response.body',  # body is None
        '$.http.response.status_code',  # not a string
        '$.nonexistent.path',
        '$.kind',  # outside the payload
        '$.source',
        'garbage',
    ],
)
def test_unresolvable_secret_field_is_rejected(path: str):
    """Fail closed: a secret marking that cannot be applied is a construction error."""
    with pytest.raises(ValidationError, match='secret_fields'):
        HttpEvidence(id='ev_01', source='f', http=_exchange(), secret_fields=[path])


# ── Redaction ──────────────────────────────────────────────────────────────────


def test_redact_no_secrets():
    ev = HttpEvidence(id='ev_01', source='f', http=_exchange())
    assert redact(ev) is ev


def test_redact_header_value_by_index_keeps_name():
    ev = HttpEvidence(
        id='ev_01',
        source='f',
        http=_exchange(request_headers=[('authorization', 'Bearer secret'), ('Accept', 'application/json')]),
        secret_fields=['$.http.request.headers[0][1]'],
    )
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.request.headers == [('authorization', '<redacted>'), ('Accept', 'application/json')]


def test_redact_is_casing_and_dot_agnostic():
    """The #35 failure modes: lowercase names and dotted names redact like any other."""
    ev = HttpEvidence(
        id='ev_01',
        source='f',
        http=_exchange(request_headers=[('authorization', 'Bearer s1'), ('X.Api.Key', 'k2')]),
        secret_fields=['$.http.request.headers[0][1]', '$.http.request.headers[1][1]'],
    )
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert [value for _, value in result.http.request.headers] == ['<redacted>', '<redacted>']
    assert len(result.http.request.headers) == 2  # nothing added


def test_redact_one_of_repeated_set_cookie():
    ev = HttpEvidence(
        id='ev_01',
        source='f',
        http=_exchange(headers=[('Set-Cookie', 'sid=secret; Secure'), ('Set-Cookie', 'theme=dark')]),
        secret_fields=['$.http.response.headers[0][1]'],
    )
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    # Value-only (PLAN §5): the cookie's attributes stay reviewable after redaction.
    assert get_all(result.http.response.headers, 'set-cookie') == ['sid=<redacted>; Secure', 'theme=dark']


def test_redact_request_body_secret():
    ev = HttpEvidence(id='ev_01', source='f', http=_exchange(), secret_fields=['$.http.request.body'])
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.request.body == '<redacted>'


def test_redact_config_evidence():
    cfg = ConfigExcerpt(path='app.env', format='config', content='DB_PASSWORD=hunter2')
    ev = ConfigEvidence(id='ev_01', source='f', config=cfg, secret_fields=['$.config.content'])
    result = redact(ev)
    assert isinstance(result, ConfigEvidence)
    assert result.config.content == '<redacted>'


def test_redact_preserves_input():
    """redact returns a new object without mutating the original."""
    ev = HttpEvidence(
        id='ev_01',
        source='f',
        http=_exchange(request_headers=[('Authorization', 'Bearer token')]),
        secret_fields=['$.http.request.headers[0][1]'],
    )
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.request.headers == [('Authorization', '<redacted>')]
    assert ev.http.request.headers == [('Authorization', 'Bearer token')]


def test_redacted_evidence_still_validates():
    """Redacted output keeps its secret_fields and still satisfies the resolve rule."""
    ev = HttpEvidence(id='ev_01', source='f', http=_exchange(), secret_fields=['$.http.request.body'])
    assert EvidenceAdapter.validate_python(redact(ev).model_dump(mode='json')) == redact(ev)


# ── Cookie-aware redaction and body_note (#37) ────────────────────────────────


@pytest.mark.parametrize(
    ('name', 'value', 'expected'),
    [
        (
            'Set-Cookie',
            'sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax',
            'sid=<redacted>; Path=/; Secure; HttpOnly; SameSite=Lax',
        ),
        ('set-cookie', 'sid=abc', 'sid=<redacted>'),
        ('Set-Cookie', 'malformed-no-equals; Secure', '<redacted>'),
        ('Cookie', 'a=1; b=two; flag', 'a=<redacted>; b=<redacted>; <redacted>'),
        ('Authorization', 'Bearer xyz', '<redacted>'),
    ],
)
def test_cookie_headers_redact_values_only(name: str, value: str, expected: str) -> None:
    ev = HttpEvidence(
        id='ev_01',
        source='f',
        http=_exchange(headers=[(name, value)])
        if name.lower() == 'set-cookie'
        else _exchange(request_headers=[(name, value)]),
        secret_fields=[
            '$.http.response.headers[0][1]' if name.lower() == 'set-cookie' else '$.http.request.headers[0][1]'
        ],
    )
    once = redact(ev)
    assert isinstance(once, HttpEvidence)
    side = once.http.response if name.lower() == 'set-cookie' else once.http.request
    assert side.headers == [(name, expected)]
    assert redact(once) == once  # idempotent


def test_body_note_is_omitted_when_unset_so_evidence_ids_are_stable() -> None:
    from partex.ids import evidence_id

    plain = HttpResponse(status_code=200, headers=[], body='x')
    assert 'body_note' not in plain.model_dump(mode='json')
    noted = HttpResponse(status_code=200, headers=[], body='x', body_note='truncated')
    assert noted.model_dump(mode='json')['body_note'] == 'truncated'
    assert HttpResponse.model_validate_json(noted.model_dump_json()) == noted

    def ev(response: HttpResponse) -> HttpEvidence:
        exchange = HttpExchange(request=HttpRequest(method='GET', url='https://e.test/', headers=[]), response=response)
        return HttpEvidence(id='x', source='s', http=exchange)

    assert evidence_id(ev(plain)) != evidence_id(ev(noted))  # a truncated body is different evidence
    with pytest.raises(ValidationError):
        HttpResponse.model_validate({'status_code': 200, 'headers': [], 'body_note': 'gzip'})
