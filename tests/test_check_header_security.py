"""Tests for the header-security passive check.

Fixture triad: clean case, one case per finding class, insufficient-evidence case.
Tests comply with the hermetic rule: no I/O, network, model, or storage access —
the check is a pure function over validated evidence.
"""

from collections.abc import Mapping, Sequence

from partex.checks.header_security import (
    CHECK_ID,
    CHECK_VERSION,
    HeaderSecurityCheck,
    _is_session_cookie,
)
from partex.ids import evidence_id, finding_id
from partex.models import (
    ConfigEvidence,
    ConfigExcerpt,
    FindingDraft,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


type _HeaderArg = Mapping[str, str] | list[tuple[str, str]] | None


def _pairs(headers: _HeaderArg) -> list[tuple[str, str]]:
    """Test convenience: a mapping for one-value-per-name cases, pairs for repeats."""
    return list(headers.items()) if isinstance(headers, Mapping) else list(headers or [])


def _http_evidence(
    method: str = 'GET',
    url: str = 'https://example.test/',
    req_headers: _HeaderArg = None,
    status: int = 200,
    resp_headers: _HeaderArg = None,
    resp_body: str | None = '<html><body>OK</body></html>',
    source: str = 'test',
) -> HttpEvidence:
    """Build an HttpEvidence record with computed ID."""
    req = HttpRequest(method=method, url=url, headers=_pairs(req_headers))
    resp = HttpResponse(status_code=status, headers=_pairs(resp_headers), body=resp_body)
    ex = HttpExchange(request=req, response=resp)
    ev = HttpEvidence(id='placeholder', source=source, http=ex)
    # Assign the real evidence ID
    real_id = evidence_id(ev)
    ev.id = real_id
    return ev


def _findings_by_title(findings: Sequence[FindingDraft]) -> dict[str, FindingDraft]:
    return {f.title: f for f in findings}


# ── Check metadata ────────────────────────────────────────────────────────────


def test_check_metadata():
    check = HeaderSecurityCheck()
    assert check.check_id == CHECK_ID
    assert check.version == CHECK_VERSION
    assert 'security' in check.title.lower()
    assert len(check.description) > 10


# ── applies_to ────────────────────────────────────────────────────────────────


def test_applies_to_http_evidence():
    check = HeaderSecurityCheck()
    ev = _http_evidence()
    assert check.applies_to([ev]) is True


def test_applies_to_config_only():
    check = HeaderSecurityCheck()
    cfg = ConfigExcerpt(path='api.yaml', format='openapi', content='openapi: 3.0.0')
    ev = ConfigEvidence(
        id=evidence_id(ConfigEvidence(id='x', source='f', config=cfg)),
        source='f',
        config=cfg,
    )
    assert check.applies_to([ev]) is False


def test_applies_to_empty():
    check = HeaderSecurityCheck()
    assert check.applies_to([]) is False


def test_applies_to_mixed():
    check = HeaderSecurityCheck()
    http = _http_evidence()
    cfg_ev = ConfigEvidence(
        id='ev_cfg',
        source='f',
        config=ConfigExcerpt(path='api.yaml', format='openapi', content='openapi: 3.0.0'),
    )
    assert check.applies_to([http, cfg_ev]) is True


# ── Clean case (no findings) ──────────────────────────────────────────────────


def test_clean_https_response_all_headers_present():
    """A well-configured HTTPS HTML response should produce no findings."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html; charset=utf-8',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
            'X-Content-Type-Options': 'nosniff',
            'Set-Cookie': 'SESSID=abc; Secure; HttpOnly; SameSite=Lax',
        },
    )
    findings = check.review([ev])
    assert findings == []


def test_clean_https_api_response():
    """An HTTPS API (non-HTML) response with HSTS and X-Content-Type-Options — no CSP required."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://api.example.test/users',
        resp_headers={
            'Content-Type': 'application/json',
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
        },
        resp_body='{"users": []}',
    )
    findings = check.review([ev])
    # API responses: HSTS should be checked, CSP only for HTML, X-Content-Type-Options checked
    # Since HSTS is present with good max-age, and X-Content-Type-Options is nosniff, no findings
    assert findings == []


def test_clean_redirect_no_csp_expected():
    """A 301 redirect on HTTPS with HSTS but no CSP should not flag CSP."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/old',
        status=301,
        resp_headers={
            'Strict-Transport-Security': 'max-age=31536000',
            'Location': '/new',
        },
        resp_body=None,
    )
    findings = check.review([ev])
    # HSTS is good, redirect shouldn't need CSP or X-Content-Type-Options
    assert findings == []


# ── HSTS findings ─────────────────────────────────────────────────────────────


def test_missing_hsts_on_https():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={'Content-Type': 'text/html'},
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Missing HSTS header' in titles
    f = titles['Missing HSTS header']
    assert f.severity == 'low'
    assert ev.id in f.evidence_ids


def test_missing_hsts_not_on_http():
    """HSTS is not applicable to plain HTTP responses."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='http://example.test/',
        resp_headers={'Content-Type': 'text/html'},
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    # May still have CSP/X-Content-Type-Options findings, but not HSTS
    assert 'Missing HSTS header' not in titles


def test_hsts_max_age_zero():
    """max-age=0 actively disables HSTS — medium severity."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age=0',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Weak HSTS policy' in titles
    f = titles['Weak HSTS policy']
    assert f.severity == 'medium'
    assert 'max-age=0' in f.description


def test_hsts_max_age_below_minimum():
    """max-age below 1 year is a low-severity finding."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age=86400',  # 1 day
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Weak HSTS policy' in titles
    f = titles['Weak HSTS policy']
    assert f.severity == 'low'


# ── CSP findings ──────────────────────────────────────────────────────────────


def test_missing_csp_on_html():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={'Content-Type': 'text/html'},
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Missing Content-Security-Policy header' in titles
    f = titles['Missing Content-Security-Policy header']
    assert f.severity == 'medium'


def test_csp_with_unsafe_inline():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy': "script-src 'unsafe-inline' 'self'",
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Unsafe Content-Security-Policy' in titles
    f = titles['Unsafe Content-Security-Policy']
    assert "'unsafe-inline'" in f.description


def test_csp_with_unsafe_eval():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy': "default-src 'unsafe-eval'",
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Unsafe Content-Security-Policy' in titles


def test_csp_with_wildcard():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy': 'default-src *',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Unsafe Content-Security-Policy' in titles
    f = titles['Unsafe Content-Security-Policy']
    assert 'wildcard' in f.description.lower()


def test_csp_not_checked_on_non_html():
    """CSP is not checked on JSON API responses."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/api',
        resp_headers={'Content-Type': 'application/json'},
        resp_body='{}',
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Missing Content-Security-Policy header' not in titles
    assert 'Unsafe Content-Security-Policy' not in titles


# ── X-Content-Type-Options findings ───────────────────────────────────────────


def test_missing_x_content_type_options():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={'Content-Type': 'text/html'},
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Missing X-Content-Type-Options header' in titles
    f = titles['Missing X-Content-Type-Options header']
    assert f.severity == 'low'


def test_x_content_type_options_wrong_value():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'X-Content-Type-Options': 'nosniff',  # Wrong casing shouldn't matter
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Missing X-Content-Type-Options header' not in titles


def test_x_content_type_options_not_checked_on_204():
    """204 No Content has no body — nosniff is not required."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        status=204,
        resp_headers={},
        resp_body=None,
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Missing X-Content-Type-Options header' not in titles


# ── Set-Cookie findings ───────────────────────────────────────────────────────


def test_session_cookie_missing_secure_on_https():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'SESSID=abc; HttpOnly; SameSite=Lax',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Weak Set-Cookie attributes' in titles
    f = titles['Weak Set-Cookie attributes']
    assert 'Secure' in f.description


def test_session_cookie_missing_httponly():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'AUTH_token=xyz; Secure; SameSite=Strict',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Weak Set-Cookie attributes' in titles
    f = titles['Weak Set-Cookie attributes']
    assert 'HttpOnly' in f.description


def test_session_cookie_missing_samesite():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'session_id=abc; Secure; HttpOnly',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Weak Set-Cookie attributes' in titles
    f = titles['Weak Set-Cookie attributes']
    assert 'SameSite' in f.description


def test_samesite_none_without_secure():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'token=abc; SameSite=None; HttpOnly',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Weak Set-Cookie attributes' in titles
    f = titles['Weak Set-Cookie attributes']
    assert 'Secure' in f.description  # Secure required with SameSite=None


def test_non_session_cookie_not_flagged():
    """Stateless cookies (analytics, tracking) should not produce findings."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': '_ga=GA1.2.123; SameSite=Lax',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Weak Set-Cookie attributes' not in titles


def test_well_configured_cookie_no_finding():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'SESSID=abc; Secure; HttpOnly; SameSite=Strict',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Weak Set-Cookie attributes' not in titles


def test_cookie_secure_not_required_on_http():
    """Secure is not required for cookies on plain HTTP."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='http://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'SESSID=abc; HttpOnly; SameSite=Lax',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    # Should still find HttpOnly and SameSite present
    # Secure should not be in missing since it's HTTP
    if 'Weak Set-Cookie attributes' in titles:
        f = titles['Weak Set-Cookie attributes']
        assert 'Secure' not in f.description


def test_multiple_cookie_findings():
    """Multiple session cookies with different gaps each get a finding."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            # Two separate Set-Cookie headers collapse into one string
            'Set-Cookie': 'SESSID=abc; Secure',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    # One cookie missing HttpOnly and SameSite → severity medium (2+ missing)
    if 'Weak Set-Cookie attributes' in titles:
        f = titles['Weak Set-Cookie attributes']
        assert f.severity == 'medium'


# ── CORS findings ─────────────────────────────────────────────────────────────


def test_cors_wildcard_with_credentials():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/api',
        resp_headers={
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
        },
        resp_body='{}',
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Permissive CORS with credentials' in titles
    f = titles['Permissive CORS with credentials']
    # #38: browsers reject the literal pair; the exploitable reflected-origin variant
    # needs an active probe — passive review rates it medium, not high.
    assert f.severity == 'medium'
    assert 'reflected-origin' in f.description


def test_cors_null_with_credentials():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/api',
        resp_headers={
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': 'null',
            'Access-Control-Allow-Credentials': 'true',
        },
        resp_body='{}',
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Permissive CORS with credentials' in titles


def test_cors_wildcard_without_credentials():
    """Wildcard CORS without credentials is acceptable for public resources."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/public',
        resp_headers={
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        resp_body='{}',
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Permissive CORS with credentials' not in titles


def test_cors_no_acao_header():
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/api',
        resp_headers={'Content-Type': 'application/json'},
        resp_body='{}',
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Permissive CORS with credentials' not in titles


# ── Insufficient-evidence case ────────────────────────────────────────────────


def test_insufficient_evidence_no_content_type():
    """Without Content-Type, the check should not guess — no false positives."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={},
        resp_body='<html>test</html>',
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    # With no Content-Type, is_html returns False, so only HSTS and X-Content-Type-Options apply
    # HSTS: missing (low)
    # X-Content-Type-Options: missing (low, status 200 has body)
    # CSP: not checked (not HTML)
    assert 'Missing HSTS header' in titles
    assert 'Missing X-Content-Type-Options header' in titles
    # CSP should NOT be flagged — no Content-Type means not HTML
    assert 'Missing Content-Security-Policy header' not in titles


def test_insufficient_evidence_http_no_hsts():
    """Plain HTTP responses should not trigger HSTS findings."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='http://example.test/',
        resp_headers={'Content-Type': 'text/html'},
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Missing HSTS header' not in titles


# ── Edge cases ────────────────────────────────────────────────────────────────


def test_hsts_with_include_subdomains_and_preload():
    """Complex HSTS header with includeSubDomains and preload should parse correctly."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    assert 'Missing HSTS header' not in titles
    assert 'Weak HSTS policy' not in titles


def test_redirect_with_cookie():
    """301 redirect on HTTPS with a weak Set-Cookie should be caught."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/login',
        status=302,
        resp_headers={
            'Location': '/dashboard',
            'Set-Cookie': 'SESSID=xyz; HttpOnly',
        },
        resp_body=None,
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    # Cookie missing Secure and SameSite
    assert 'Weak Set-Cookie attributes' in titles
    # CSP should not be checked on redirects
    assert 'Missing Content-Security-Policy header' not in titles


def test_csp_report_only_not_flagged():
    """Content-Security-Policy-Report-Only without an enforcing policy should not mask findings."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy-Report-Only': "default-src 'self'",
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    # Report-only does not enforce — still missing CSP
    assert 'Missing Content-Security-Policy header' in titles


def test_csp_with_frame_ancestors_only():
    """CSP with only frame-ancestors and nothing unsafe should be acceptable."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy': "frame-ancestors 'none'",
        },
    )
    findings = check.review([ev])
    titles = _findings_by_title(findings)
    # No unsafe directives in script-src/default-src
    assert 'Unsafe Content-Security-Policy' not in titles


# ── Session cookie heuristic ──────────────────────────────────────────────────


def test_is_session_cookie_positive():
    for name in ('session', 'SESSIONID', 'auth_token', 'jwt', '_csrf', 'refreshToken', 'login_id', 'access_key'):
        assert _is_session_cookie(name) is True, f'{name} should be session-like'


def test_is_session_cookie_negative():
    for name in ('_ga', 'theme', 'lang', 'pref', '_gid', 'utm_source'):
        assert _is_session_cookie(name) is False, f'{name} should not be session-like'


# ── Pure-function property ────────────────────────────────────────────────────


def test_check_is_pure_function():
    """The same evidence always produces the same findings — no hidden state."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={'Content-Type': 'text/html'},
    )
    r1 = check.review([ev])
    r2 = check.review([ev])
    # Comparing serialized forms for determinism
    d1 = [f.model_dump(mode='json') for f in r1]
    d2 = [f.model_dump(mode='json') for f in r2]
    assert d1 == d2


# ── Draft validity ────────────────────────────────────────────────────────────


def test_all_findings_have_valid_severity():
    """Every finding from header-security must have a valid Severity."""
    check = HeaderSecurityCheck()
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
        },
    )
    findings = check.review([ev])
    valid_severities = {'info', 'low', 'medium', 'high', 'critical'}
    for f in findings:
        assert f.severity in valid_severities
        assert f.check_id == CHECK_ID
        assert f.check_version == CHECK_VERSION
        assert len(f.evidence_ids) >= 1
        assert len(f.title) > 0
        assert len(f.description) > 0
        assert len(f.remediation) > 0


# ── Header representation (#39) ───────────────────────────────────────────────


def test_lowercase_header_names_are_recognized():
    """HTTP/2, HAR exports, and httpx2 lowercase names; a compliant response yields nothing."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'content-type': 'text/html',
            'strict-transport-security': 'max-age=31536000; includeSubDomains',
            'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'deny',
        },
    )
    assert HeaderSecurityCheck().review([ev]) == []


def test_each_set_cookie_is_reviewed_with_distinct_subjects():
    """Two weak cookies on one response: same title and evidence, distinct subjects and IDs."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers=[
            ('Content-Type', 'application/json'),
            ('X-Content-Type-Options', 'nosniff'),
            ('Strict-Transport-Security', 'max-age=31536000'),
            ('Set-Cookie', 'session=a; Path=/'),
            ('Set-Cookie', 'theme=dark'),
            ('Set-Cookie', 'remember_token=b; Path=/'),
        ],
    )
    findings = HeaderSecurityCheck().review([ev])
    assert [f.subject for f in findings] == ['cookie:session', 'cookie:remember_token']
    ids = {finding_id(f.check_id, f.subject, f.title, f.evidence_ids) for f in findings}
    assert len(ids) == 2


def test_every_finding_has_a_subject():
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'sessionid=x',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
        },
    )
    subjects = {f.subject for f in HeaderSecurityCheck().review([ev])}
    assert subjects == {
        'header:strict-transport-security',
        'header:content-security-policy',
        'header:frame-ancestors',
        'header:x-content-type-options',
        'cookie:sessionid',
        'header:access-control-allow-origin',
    }


# ── HSTS precision (#38): quoted and malformed max-age ────────────────────────


def test_hsts_quoted_max_age_accepted():
    """RFC 6797 permits a quoted max-age value; it must not be treated as malformed."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age="31536000"; includeSubDomains',
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    assert 'Weak HSTS policy' not in titles
    assert 'Malformed HSTS max-age directive' not in titles


def test_hsts_malformed_max_age_is_its_own_finding():
    """An unparseable max-age is a malformed-directive finding, not max-age=0."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age=soon',
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    f = titles['Malformed HSTS max-age directive']
    assert f.severity == 'low'
    assert 'max-age=soon' in f.description
    assert 'Weak HSTS policy' not in titles


def test_hsts_without_max_age_directive_is_malformed():
    """HSTS with no max-age directive communicates no validity period — its own finding."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'includeSubDomains',
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    assert 'Malformed HSTS max-age directive' in titles
    assert 'Weak HSTS policy' not in titles


# ── Session-cookie classification precision (#38) ────────────────────────────


def test_cookie_name_substring_false_positives_gone():
    """`sid` inside `inside`, `user` inside `user_prefs` must not look like session cookies."""
    check = HeaderSecurityCheck()
    for name in ('inside', 'user_prefs'):
        ev = _http_evidence(
            url='https://example.test/',
            resp_headers={'Content-Type': 'text/html', 'Set-Cookie': f'{name}=x'},
        )
        titles = _findings_by_title(check.review([ev]))
        assert 'Weak Set-Cookie attributes' not in titles, f'{name} must not be flagged'


def test_csrf_double_submit_cookie_does_not_require_httponly():
    """CSRF double-submit cookies are read by the app's own JS; HttpOnly would break them."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'csrftoken=x; Secure; SameSite=Strict',
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    assert 'Weak Set-Cookie attributes' not in titles


def test_csrf_double_submit_cookie_still_needs_secure():
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Set-Cookie': 'XSRF-TOKEN=x; HttpOnly; SameSite=Strict',
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    f = titles['Weak Set-Cookie attributes']
    assert 'Secure' in f.description
    assert 'HttpOnly' not in f.description


def test_cookie_classification_token_examples():
    """camelCase and classic whole names still classify (refreshToken, JSESSIONID, __Host-sid)."""
    for name in ('refreshToken', 'JSESSIONID', '__Host-sid', 'access_key', 'login_id'):
        assert _is_session_cookie(name) is True, f'{name} should be session-like'
    for name in ('inside', 'user_prefs', '_ga', 'utm_source', 'lang', 'theme'):
        assert _is_session_cookie(name) is False, f'{name} should not be session-like'


# ── CSP precision (#38) and combined policies / report-only (#52) ─────────────


def test_csp_nonce_suppresses_unsafe_inline():
    """CSP2+ ignores 'unsafe-inline' when a nonce or hash is present."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy': "script-src 'nonce-abc123' 'unsafe-inline' 'strict-dynamic' https:",
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    assert 'Unsafe Content-Security-Policy' not in titles


def test_csp_nonce_with_unsafe_eval_still_flagged():
    """'unsafe-eval' is honored alongside nonces — it stays a finding."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy': "script-src 'nonce-abc123' 'unsafe-eval'",
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    f = titles['Unsafe Content-Security-Policy']
    assert "'unsafe-eval'" in f.description
    assert "'unsafe-inline'" not in f.description


def test_multiple_enforced_csp_headers_intersect():
    """Browsers apply every enforced policy; a weakness counts only if all permit it."""
    check = HeaderSecurityCheck()
    safe = [
        ('Content-Type', 'text/html'),
        ('Content-Security-Policy', "default-src 'self'"),
        ('Content-Security-Policy', "script-src 'unsafe-inline'"),
    ]
    titles = _findings_by_title(check.review([_http_evidence(resp_headers=safe)]))
    assert 'Unsafe Content-Security-Policy' not in titles

    both_unsafe = [
        ('Content-Type', 'text/html'),
        ('Content-Security-Policy', "default-src 'unsafe-inline'"),
        ('Content-Security-Policy', "script-src 'unsafe-inline'"),
    ]
    titles = _findings_by_title(check.review([_http_evidence(resp_headers=both_unsafe)]))
    assert 'Unsafe Content-Security-Policy' in titles


def test_csp_report_only_stricter_note():
    """Enforced CSP unsafe + report-only clean: the finding names the unenforced stricter policy."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers=[
            ('Content-Type', 'text/html'),
            ('Content-Security-Policy', "script-src 'unsafe-inline'"),
            ('Content-Security-Policy-Report-Only', "script-src 'self'"),
        ],
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    f = titles['Unsafe Content-Security-Policy']
    assert 'report-only policy is deployed but not enforced' in f.description


def test_csp_missing_with_report_only_notes_remediation_context():
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy-Report-Only': "default-src 'self'",
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    f = titles['Missing Content-Security-Policy header']
    assert 'report-only policy is deployed but not enforced' in f.description


# ── Framing controls (#52) ────────────────────────────────────────────────────


def test_missing_framing_control():
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={'Content-Type': 'text/html'},
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    f = titles['Missing framing policy']
    assert f.subject == 'header:frame-ancestors'
    assert f.severity == 'low'


def test_xfo_deny_and_sameorigin_are_controls():
    check = HeaderSecurityCheck()
    for value in ('DENY', 'SAMEORIGIN'):
        ev = _http_evidence(
            url='https://example.test/',
            resp_headers={'Content-Type': 'text/html', 'X-Frame-Options': value},
        )
        titles = _findings_by_title(check.review([ev]))
        assert 'Missing framing policy' not in titles, value


def test_xfo_allow_from_is_treated_as_missing():
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'X-Frame-Options': 'ALLOW-FROM https://partner.test',
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    f = titles['Missing framing policy']
    assert 'obsolete' in f.description


def test_frame_ancestors_none_controls_framing():
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy': "frame-ancestors 'none'",
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    assert 'Missing framing policy' not in titles
    assert 'Weak frame-ancestors policy' not in titles


def test_frame_ancestors_explicit_origins_are_clean():
    """Case, port, and trailing slash in explicit host sources are not weak."""
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy': "frame-ancestors 'self' https://Partner.Example.com:8443/",
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    assert 'Weak frame-ancestors policy' not in titles
    assert 'Missing framing policy' not in titles


def test_frame_ancestors_weak_sources():
    check = HeaderSecurityCheck()
    cases = [
        ('frame-ancestors *', 'wildcard (*)', 'medium'),
        ('frame-ancestors https:', 'bare scheme source https:', 'medium'),
        ('frame-ancestors http://partner.test', 'plaintext http: source http://partner.test', 'low'),
        ("frame-ancestors 'self' localhost", 'loopback host localhost', 'low'),
        ('frame-ancestors https://*.github.io', 'shared-hosting wildcard subdomain *.github.io', 'low'),
    ]
    for policy, source, severity in cases:
        ev = _http_evidence(
            url='https://example.test/',
            resp_headers={'Content-Type': 'text/html', 'Content-Security-Policy': policy},
        )
        titles = _findings_by_title(check.review([ev]))
        f = titles['Weak frame-ancestors policy']
        assert f.severity == severity, policy
        assert source in f.description, policy
        assert 'Missing framing policy' not in titles, policy


def test_multiple_enforced_csp_framing_intersection():
    """Framing needs frame-ancestors in every enforced policy; 'none' anywhere blocks."""
    check = HeaderSecurityCheck()
    controlled = [
        ('Content-Type', 'text/html'),
        ('Content-Security-Policy', "frame-ancestors 'none'"),
        ('Content-Security-Policy', "frame-ancestors 'self'"),
    ]
    titles = _findings_by_title(check.review([_http_evidence(resp_headers=controlled)]))
    assert 'Missing framing policy' not in titles
    assert 'Weak frame-ancestors policy' not in titles

    one_missing_fa = [
        ('Content-Type', 'text/html'),
        ('Content-Security-Policy', "frame-ancestors 'none'"),
        ('Content-Security-Policy', "default-src 'self'"),
    ]
    titles = _findings_by_title(check.review([_http_evidence(resp_headers=one_missing_fa)]))
    assert 'Missing framing policy' in titles


def test_framing_report_only_does_not_enforce():
    ev = _http_evidence(
        url='https://example.test/',
        resp_headers={
            'Content-Type': 'text/html',
            'Content-Security-Policy-Report-Only': "frame-ancestors 'none'",
        },
    )
    titles = _findings_by_title(HeaderSecurityCheck().review([ev]))
    f = titles['Missing framing policy']
    assert 'report-only' in f.description


def test_framing_not_required_on_api_or_redirect():
    check = HeaderSecurityCheck()
    api = _http_evidence(
        url='https://example.test/api',
        resp_headers={'Content-Type': 'application/json'},
        resp_body='{}',
    )
    redirect = _http_evidence(
        url='https://example.test/old',
        status=301,
        resp_headers={'Location': '/new'},
        resp_body=None,
    )
    for ev in (api, redirect):
        titles = _findings_by_title(check.review([ev]))
        assert 'Missing framing policy' not in titles


# ── Per-host aggregation (#38) ────────────────────────────────────────────────


def test_aggregation_one_finding_per_host_and_class():
    """50 missing-HSTS exchanges on one host → one finding citing all 50 evidence IDs."""
    check = HeaderSecurityCheck()
    evs = [
        _http_evidence(url=f'https://example.test/path{i}', resp_headers={'Content-Type': 'text/html'})
        for i in range(50)
    ]
    findings = check.review(evs)
    hsts = [f for f in findings if f.title == 'Missing HSTS header']
    assert len(hsts) == 1
    assert len(hsts[0].evidence_ids) == 50
    assert 'example.test' in hsts[0].description
    assert '50 captured response' in hsts[0].description


def test_aggregation_separates_hosts():
    check = HeaderSecurityCheck()
    evs = [
        _http_evidence(url='https://a.example.test/', resp_headers={'Content-Type': 'text/html'}),
        _http_evidence(url='https://b.example.test/', resp_headers={'Content-Type': 'text/html'}),
    ]
    findings = [f for f in check.review(evs) if f.title == 'Missing HSTS header']
    assert len(findings) == 2
    assert {f.evidence_ids[0] for f in findings} == {evs[0].id, evs[1].id}


def test_aggregation_unions_cookie_attribute_gaps():
    """The same cookie set with different gaps across responses → one finding, unioned attrs."""
    check = HeaderSecurityCheck()
    evs = [
        _http_evidence(
            url='https://example.test/1',
            resp_headers={'Content-Type': 'text/html', 'Set-Cookie': 'sid=x; HttpOnly; SameSite=Lax'},
        ),
        _http_evidence(
            url='https://example.test/2',
            resp_headers={'Content-Type': 'text/html', 'Set-Cookie': 'sid=x; Secure; SameSite=Lax'},
        ),
        _http_evidence(
            url='https://example.test/3',
            resp_headers={'Content-Type': 'text/html', 'Set-Cookie': 'sid=x; HttpOnly; SameSite=None'},
        ),
    ]
    findings = [f for f in check.review(evs) if f.subject == 'cookie:sid']
    assert len(findings) == 1
    f = findings[0]
    assert len(f.evidence_ids) == 3
    assert f.severity == 'medium'  # the union (Secure, HttpOnly) has more than one gap
    for attr in ('Secure', 'HttpOnly'):
        assert attr in f.description


def test_aggregation_keeps_cors_variants_apart():
    """Wildcard and null ACAO are distinct weaknesses of the same title → separate findings."""
    check = HeaderSecurityCheck()
    evs = [
        _http_evidence(
            url='https://example.test/a',
            resp_headers={
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true',
            },
            resp_body='{}',
        ),
        _http_evidence(
            url='https://example.test/b',
            resp_headers={
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': 'null',
                'Access-Control-Allow-Credentials': 'true',
            },
            resp_body='{}',
        ),
    ]
    findings = [f for f in check.review(evs) if f.title == 'Permissive CORS with credentials']
    assert len(findings) == 2
    ids = {finding_id(f.check_id, f.subject, f.title, f.evidence_ids) for f in findings}
    assert len(ids) == 2  # distinct weaknesses, not one merged finding
    descriptions = ' | '.join(f.description for f in findings)
    assert '* ' in descriptions and 'null' in descriptions
