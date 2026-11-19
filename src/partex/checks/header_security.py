"""header-security — built-in passive check for HTTP response security headers.

PLAN §10 fixture 1.  Pure function over validated evidence: no I/O, network,
model or storage access.  Registered via ``partex.checks`` entry point.
"""

from collections.abc import Sequence

from ..models import Evidence, FindingDraft, HttpEvidence, Severity, get_all, get_header

# ── Check metadata ────────────────────────────────────────────────────────────

CHECK_ID = 'header-security'
CHECK_VERSION = '1.0'
CHECK_TITLE = 'HTTP Response Header Security'
CHECK_DESCRIPTION = (
    'Evaluate HTTP responses for missing or misconfigured security headers: '
    'HSTS, CSP, X-Content-Type-Options, Set-Cookie attributes, and CORS.'
)

# ── Policy baselines ──────────────────────────────────────────────────────────

HSTS_MIN_MAX_AGE = 31_536_000  # 1 year

# Cookie names that are likely session/authentication tokens.
# A cookie containing any of these substrings is treated as security-relevant.
SESSION_COOKIE_PATTERNS = (
    'session',
    'sess',
    'auth',
    'token',
    'jwt',
    'sid',
    'sso',
    'csrf',
    'xsrf',
    'refresh',
    'user',
    'login',
    'access',
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_html(exchange: HttpEvidence) -> bool:
    """Return True if the response is an HTML document."""
    ct = (get_header(exchange.http.response.headers, 'Content-Type') or '').lower()
    return 'text/html' in ct or 'application/xhtml+xml' in ct


def _is_https(url: str) -> bool:
    return url.startswith('https://')


def _is_session_cookie(cookie_name: str) -> bool:
    """Heuristic: a cookie is session-like if its name suggests auth/session state.

    Per response-policies.md: only flag cookies that carry session or
    authentication state.  Stateless cookies (ga, _ga, theme, etc.) are
    not security-relevant and should not produce findings.
    """
    lower = cookie_name.lower()
    return any(p in lower for p in SESSION_COOKIE_PATTERNS)


def _parse_set_cookie(header_value: str) -> tuple[str, dict[str, str]]:
    """Parse a Set-Cookie header into (name, attributes).

    Hand-rolled RFC 6265 attribute parsing per DEPS.md §3.3.
    """
    parts = [p.strip() for p in header_value.split(';')]
    name_value, *attr_parts = parts

    # Extract cookie name (before the first '=')
    if '=' in name_value:
        name = name_value.split('=', 1)[0].strip()
    else:
        name = name_value.strip()

    lower_attrs: dict[str, str] = {}
    for attr in attr_parts:
        if '=' in attr:
            key, val = attr.split('=', 1)
            lower_attrs[key.strip().lower()] = val.strip()
        else:
            lower_attrs[attr.strip().lower()] = ''

    return name, lower_attrs


def _parse_csp(header_value: str) -> dict[str, str]:
    """Parse a Content-Security-Policy header into directives.

    CSP directives are semicolon-separated; each directive is a name
    followed by space-separated values.  DEPS.md §3.4 — stdlib only.
    """
    directives: dict[str, str] = {}
    for part in header_value.split(';'):
        part = part.strip()
        if ' ' in part:
            name, values = part.split(' ', 1)
            directives[name.strip().lower()] = values.strip().lower()
        elif part:
            directives[part.lower()] = ''
    return directives


# ── Finding logic ─────────────────────────────────────────────────────────────


def _check_hsts(exchange: HttpEvidence) -> FindingDraft | None:
    """Check for missing or weak HSTS on HTTPS responses."""
    url = exchange.http.request.url
    if not _is_https(url):
        return None

    hsts = get_header(exchange.http.response.headers, 'Strict-Transport-Security') or ''
    if not hsts:
        return FindingDraft(
            check_id=CHECK_ID,
            check_version=CHECK_VERSION,
            severity='low',
            subject='header:strict-transport-security',
            title='Missing HSTS header',
            description=f'HTTPS response from {url} (status {exchange.http.response.status_code}) '
            'lacks a Strict-Transport-Security header, allowing downgrade attacks.',
            evidence_ids=[exchange.id],
            remediation='Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all HTTPS responses.',
        )

    # Parse max-age
    max_age = 0
    for part in hsts.split(';'):
        part = part.strip()
        if part.lower().startswith('max-age='):
            try:
                max_age = int(part.split('=', 1)[1].strip())
            except ValueError:
                pass

    if max_age == 0:
        severity: Severity = 'medium'
        detail = f'HSTS header `{hsts}` contains max-age=0, actively disabling HSTS.'
    elif max_age < HSTS_MIN_MAX_AGE:
        severity = 'low'
        detail = (
            f'HSTS header `{hsts}` has max-age={max_age} which is below '
            f'the minimum policy of {HSTS_MIN_MAX_AGE} (1 year).'
        )
    else:
        return None

    return FindingDraft(
        check_id=CHECK_ID,
        check_version=CHECK_VERSION,
        severity=severity,
        subject='header:strict-transport-security',
        title='Weak HSTS policy',
        description=f'HTTPS response from {url} (status {exchange.http.response.status_code}): {detail}',
        evidence_ids=[exchange.id],
        remediation='Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.',
    )


def _check_csp(exchange: HttpEvidence) -> FindingDraft | None:
    """Check for missing or unsafe CSP on HTML responses."""
    if not _is_html(exchange) or exchange.http.response.status_code >= 300:
        return None

    csp = get_header(exchange.http.response.headers, 'Content-Security-Policy') or ''
    if not csp:
        return FindingDraft(
            check_id=CHECK_ID,
            check_version=CHECK_VERSION,
            severity='medium',
            subject='header:content-security-policy',
            title='Missing Content-Security-Policy header',
            description=f'HTML response from {exchange.http.request.url} '
            f'(status {exchange.http.response.status_code}) lacks a Content-Security-Policy header.',
            evidence_ids=[exchange.id],
            remediation="Add a Content-Security-Policy header with at least `default-src 'self'` "
            'to all HTML responses.',
        )

    directives = _parse_csp(csp)

    # Check for unsafe-inline / unsafe-eval in script-src or default-src
    src_directive = directives.get('script-src', directives.get('default-src', ''))
    if src_directive:
        unsafe_parts: list[str] = []
        if "'unsafe-inline'" in src_directive:
            unsafe_parts.append("'unsafe-inline'")
        if "'unsafe-eval'" in src_directive:
            unsafe_parts.append("'unsafe-eval'")
        if '*' in src_directive.split():
            unsafe_parts.append('wildcard (*)')

        if unsafe_parts:
            return FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='medium',
                subject='header:content-security-policy',
                title='Unsafe Content-Security-Policy',
                description=f'HTML response from {exchange.http.request.url} '
                f'(status {exchange.http.response.status_code}) has CSP `{csp}` '
                f'permitting {", ".join(unsafe_parts)}, which allows script injection.',
                evidence_ids=[exchange.id],
                remediation='Remove unsafe CSP sources: replace `*` with explicit origins, '
                "avoid 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes for inline scripts.",
            )

    return None


def _check_x_content_type_options(exchange: HttpEvidence) -> FindingDraft | None:
    """Check for missing X-Content-Type-Options on responses with bodies."""
    status = exchange.http.response.status_code
    if status >= 300 or status == 204:
        return None

    xcto = get_header(exchange.http.response.headers, 'X-Content-Type-Options') or ''
    if xcto.lower() != 'nosniff':
        return FindingDraft(
            check_id=CHECK_ID,
            check_version=CHECK_VERSION,
            severity='low',
            subject='header:x-content-type-options',
            title='Missing X-Content-Type-Options header',
            description=f'Response from {exchange.http.request.url} '
            f'(status {exchange.http.response.status_code}) lacks '
            'X-Content-Type-Options: nosniff, enabling MIME-sniffing attacks.',
            evidence_ids=[exchange.id],
            remediation='Set `X-Content-Type-Options: nosniff` on all responses that carry a body.',
        )

    return None


def _check_set_cookie(exchange: HttpEvidence) -> list[FindingDraft]:
    """Check Set-Cookie headers for weak attributes."""
    findings: list[FindingDraft] = []
    is_https_exchange = _is_https(exchange.http.request.url)

    # Each Set-Cookie header is its own (name, value) pair; findings are keyed by cookie name.
    for header_value in get_all(exchange.http.response.headers, 'Set-Cookie'):
        if not header_value.strip():
            continue
        cookie_name, attrs = _parse_set_cookie(header_value)

        if not _is_session_cookie(cookie_name):
            continue

        missing: list[str] = []

        if is_https_exchange and 'secure' not in attrs:
            missing.append('Secure')

        if 'httponly' not in attrs:
            missing.append('HttpOnly')

        samesite_found = False
        for k in attrs:
            if k.lower() == 'samesite':
                samesite_found = True
                val = attrs[k].lower() if attrs[k] else ''
                if val == 'none' and is_https_exchange and 'secure' not in [ak.lower() for ak in attrs]:
                    # SameSite=None requires Secure
                    missing.append('Secure (required with SameSite=None)')
                break

        if not samesite_found:
            missing.append('SameSite')

        if not missing:
            continue

        evidence_url = exchange.http.request.url

        findings.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='low' if len(missing) <= 1 else 'medium',
                subject=f'cookie:{cookie_name}',
                title='Weak Set-Cookie attributes',
                description=f'Session cookie `{cookie_name}` set by {evidence_url} '
                f'(status {exchange.http.response.status_code}) is missing: '
                f'{", ".join(missing)}.',
                evidence_ids=[exchange.id],
                remediation=f'Set `{", ".join(missing)}` on the Set-Cookie header for `{cookie_name}`. '
                'HttpOnly prevents JS access, Secure ensures HTTPS-only transport, and '
                'SameSite=Lax or Strict prevents cross-site request forgery.',
            )
        )

    return findings


def _check_cors(exchange: HttpEvidence) -> FindingDraft | None:
    """Check for permissive CORS with credentials."""
    headers = exchange.http.response.headers
    acao = get_header(headers, 'Access-Control-Allow-Origin') or ''
    acac = get_header(headers, 'Access-Control-Allow-Credentials') or ''

    if not acao:
        return None

    if acac.lower() == 'true' and (acao == '*' or acao == 'null'):
        return FindingDraft(
            check_id=CHECK_ID,
            check_version=CHECK_VERSION,
            severity='high',
            subject='header:access-control-allow-origin',
            title='Permissive CORS with credentials',
            description=f'Response from {exchange.http.request.url} '
            f'(status {exchange.http.response.status_code}) sets '
            f'Access-Control-Allow-Origin: {acao} with '
            'Access-Control-Allow-Credentials: true, exposing '
            'authenticated resources to arbitrary origins.',
            evidence_ids=[exchange.id],
            remediation='Never combine `Access-Control-Allow-Origin: *` or `null` with '
            '`Access-Control-Allow-Credentials: true`. Restrict ACAO to explicit, '
            'trusted origins when credentials are enabled.',
        )

    return None


# ── Main check function ───────────────────────────────────────────────────────


def _review_header_security(evidence: Sequence[Evidence]) -> list[FindingDraft]:
    """Run all header-security checks over the given evidence."""
    findings: list[FindingDraft] = []

    for ev in evidence:
        if not isinstance(ev, HttpEvidence):
            continue

        if f := _check_hsts(ev):
            findings.append(f)
        if f := _check_csp(ev):
            findings.append(f)
        if f := _check_x_content_type_options(ev):
            findings.append(f)
        findings.extend(_check_set_cookie(ev))
        if f := _check_cors(ev):
            findings.append(f)

    return findings


class HeaderSecurityCheck:
    """Passive check: HTTP response security headers across HTTP exchanges."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        """Applies if at least one HttpEvidence record is present."""
        return any(isinstance(ev, HttpEvidence) for ev in evidence)

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        """Evaluate HTTP responses for missing/weak security headers."""
        return _review_header_security(evidence)


# Module-level instance registered via entry point.
header_security_check = HeaderSecurityCheck()
