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
    redact,
)

# ── HttpExchange ───────────────────────────────────────────────────────────────


def test_http_exchange_round_trip():
    req = HttpRequest(method='GET', url='https://example.test/', headers={'Host': 'example.test'})
    resp = HttpResponse(status_code=200, headers={'Content-Type': 'text/html'}, body='<html>ok</html>')
    exchange = HttpExchange(request=req, response=resp)
    assert exchange.request.method == 'GET'
    assert exchange.response.status_code == 200
    assert exchange.response.body == '<html>ok</html>'


def test_http_exchange_forbids_extra():
    with pytest.raises(ValidationError):
        HttpExchange(
            request=HttpRequest(method='GET', url='https://example.test/', headers={}),
            response=HttpResponse(status_code=200, headers={}),
            bogus=1,
        )


def test_http_request_optional_body():
    req = HttpRequest(method='GET', url='https://example.test/', headers={})
    assert req.body is None


def test_http_response_optional_body():
    resp = HttpResponse(status_code=204, headers={})
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
        request=HttpRequest(method='GET', url='https://example.test/', headers={}),
        response=HttpResponse(status_code=200, headers={}),
    )
    ev = HttpEvidence(id='ev_abc', source='file1.json', http=ex, secret_fields=['$.http.request.headers.Authorization'])
    assert ev.kind == 'http_exchange'
    assert ev.id == 'ev_abc'


def test_config_evidence_model():
    cfg = ConfigExcerpt(path='api.yaml', format='openapi', content='openapi: 3.0.0')
    ev = ConfigEvidence(id='ev_def', source='file2.yaml', config=cfg)
    assert ev.kind == 'config_excerpt'
    assert ev.secret_fields == []


def test_evidence_type_adapter_round_trip_http():
    ex = HttpExchange(
        request=HttpRequest(method='POST', url='https://example.test/a', headers={'Accept': 'application/json'}),
        response=HttpResponse(status_code=201, headers={'Location': '/a/1'}),
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
            title='Missing HSTS',
            description='...',
            evidence_ids=[],
            remediation='...',
        )


def test_finding_draft_minimal():
    d = FindingDraft(
        check_id='test-check',
        check_version='1.0',
        severity='info',
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


# ── Redaction ──────────────────────────────────────────────────────────────────


def test_redact_no_secrets():
    ex = HttpExchange(
        request=HttpRequest(method='GET', url='https://example.test/', headers={}),
        response=HttpResponse(status_code=200, headers={}),
    )
    ev = HttpEvidence(id='ev_01', source='f', http=ex, secret_fields=[])
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.response.status_code == 200  # unchanged


def test_redact_single_secret_header():
    ex = HttpExchange(
        request=HttpRequest(
            method='GET',
            url='https://example.test/',
            headers={'Authorization': 'Bearer secret-token', 'Accept': 'application/json'},
        ),
        response=HttpResponse(status_code=200, headers={}),
    )
    ev = HttpEvidence(
        id='ev_01',
        source='f',
        http=ex,
        secret_fields=['$.http.request.headers.Authorization'],
    )
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.request.headers['Authorization'] == '<redacted>'
    assert result.http.request.headers['Accept'] == 'application/json'


def test_redact_multiple_secret_fields():
    ex = HttpExchange(
        request=HttpRequest(
            method='GET',
            url='https://example.test/',
            headers={'Cookie': 'session=abc', 'Authorization': 'Bearer xyz'},
        ),
        response=HttpResponse(status_code=200, headers={'Set-Cookie': 'session=abc'}),
    )
    ev = HttpEvidence(
        id='ev_01',
        source='f',
        http=ex,
        secret_fields=[
            '$.http.request.headers.Cookie',
            '$.http.request.headers.Authorization',
        ],
    )
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.request.headers['Cookie'] == '<redacted>'
    assert result.http.request.headers['Authorization'] == '<redacted>'


def test_redact_response_header():
    ex = HttpExchange(
        request=HttpRequest(method='GET', url='https://example.test/', headers={}),
        response=HttpResponse(status_code=200, headers={'Set-Cookie': 'token=secret; Secure'}),
    )
    ev = HttpEvidence(
        id='ev_01',
        source='f',
        http=ex,
        secret_fields=['$.http.response.headers.Set-Cookie'],
    )
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.response.headers['Set-Cookie'] == '<redacted>'


def test_redact_request_body_secret():
    ex = HttpExchange(
        request=HttpRequest(
            method='POST',
            url='https://example.test/login',
            headers={'Content-Type': 'application/json'},
            body='{"password": "hunter2", "username": "admin"}',
        ),
        response=HttpResponse(status_code=200, headers={}),
    )
    ev = HttpEvidence(id='ev_01', source='f', http=ex, secret_fields=['$.http.request.body'])
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.request.body == '<redacted>'


def test_redact_missing_path_is_noop():
    """A secret_field path that doesn't resolve is silently skipped."""
    ex = HttpExchange(
        request=HttpRequest(method='GET', url='https://example.test/', headers={}),
        response=HttpResponse(status_code=200, headers={}),
    )
    ev = HttpEvidence(id='ev_01', source='f', http=ex, secret_fields=['$.nonexistent.path'])
    result = redact(ev)
    assert isinstance(result, HttpEvidence)
    assert result.http.response.status_code == 200


def test_redact_config_evidence():
    cfg = ConfigExcerpt(path='settings.ini', format='config', content='password=secret\napi_key=abc')
    ev = ConfigEvidence(id='ev_01', source='f', config=cfg, secret_fields=['$.config.content'])
    result = redact(ev)
    assert isinstance(result, ConfigEvidence)
    assert result.config.content == '<redacted>'


def test_redact_preserves_input():
    """redact returns a new object without mutating the original."""
    ex = HttpExchange(
        request=HttpRequest(
            method='GET',
            url='https://example.test/',
            headers={'Authorization': 'Bearer token'},
        ),
        response=HttpResponse(status_code=200, headers={}),
    )
    ev = HttpEvidence(id='ev_01', source='f', http=ex, secret_fields=['$.http.request.headers.Authorization'])
    result = redact(ev)
    assert result.http.request.headers['Authorization'] == '<redacted>'
    assert ev.http.request.headers['Authorization'] == 'Bearer token'  # original untouched
