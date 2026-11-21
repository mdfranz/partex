"""header-security — built-in passive check for HTTP response security headers.

PLAN §10 fixture 1; issues #38 and #52.  Pure function over validated evidence: no I/O, network,
model or storage access.  Registered via ``partex.checks`` entry point.

Findings aggregate per host and rule (#38, #127), with distinct non-default ports
and every affected URL and evidence ID attached.

Precision rules (false positives fixed by #38):

- HSTS ``max-age`` accepts quoted values (``max-age="31536000"``); a missing or unparseable
  ``max-age`` is its own ``Malformed HSTS max-age directive`` finding, not ``max-age=0``.
- Session-cookie classification matches whole name tokens (``sid`` no longer matches
  ``inside``); CSRF double-submit cookies are security-relevant but legitimately not
  ``HttpOnly``, so that attribute is not required of them.
- CSP: ``'unsafe-inline'`` alongside a nonce or hash is ignored by CSP2+ browsers and is not
  flagged; a full CSP3 ``'strict-dynamic'`` policy makes legacy host-source wildcards
  fallback-only, so ``*``/``https:`` are not flagged in that pattern.  Multiple enforced CSP
  headers are evaluated as their combined effect (intersection): a weakness counts only if
  every enforced policy permits it.
- ``Access-Control-Allow-Origin: *``/``null`` with credentials is rated ``medium`` passively:
  browsers reject the combination outright; the genuinely dangerous reflected-origin case
  needs an active probe to confirm.

Framing controls (#52): HTML responses need ``X-Frame-Options: DENY|SAMEORIGIN`` **or** an
enforced CSP ``frame-ancestors``.  ``ALLOW-FROM`` is obsolete and treated as absent.  Weak
``frame-ancestors`` sources (``*``, bare scheme sources, ``http:`` origins, loopback hosts,
wildcard subdomains of shared hosting) are each named in the finding.  Report-only policies
never count as enforcement; when a report-only policy is stricter than the enforced one, the
finding says so.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from ..models import Evidence, FindingDraft, HttpEvidence, Severity, get_all, get_header, redact

# ── Check metadata ────────────────────────────────────────────────────────────

CHECK_ID = 'header-security'
CHECK_VERSION = '1.3'  # 1.3: the affected-URL list in a grouped finding is capped (#140)

MAX_LISTED_URLS = 50
"""Affected URLs named in one grouped finding's description; the rest are counted (every evidence ID is kept)."""
CHECK_TITLE = 'HTTP Response Header Security'
CHECK_DESCRIPTION = (
    'Evaluate HTTP responses for missing or misconfigured security headers: HSTS, CSP '
    '(enforced and report-only), framing controls, X-Content-Type-Options, Set-Cookie '
    'attributes, and CORS.'
)

# ── Policy baselines ──────────────────────────────────────────────────────────

HSTS_MIN_MAX_AGE = 31_536_000  # 1 year

# Session/auth cookie classification (#38): whole-token matching, never substrings, so `sid`
# does not match `inside` and `user` does not match `user_prefs`.
_SESSION_TOKENS = frozenset({'session', 'sess', 'sid', 'auth', 'token', 'jwt', 'sso', 'login', 'access', 'refresh'})
# Classic whole names (compared on the alphanumeric-normalized lowercase name).
_CLASSIC_SESSION_NAMES = frozenset(
    {'sessionid', 'jsessionid', 'phpsessid', 'aspnetsessionid', 'sessid', 'session', 'sid'}
)
# CSRF double-submit cookies: security-relevant (Secure/SameSite apply) but must stay
# JS-readable, so HttpOnly is not required of them.
_CSRF_TOKENS = frozenset({'csrf', 'xsrf'})

# Shared or user-controlled hosting suffixes (#52): anyone who can publish a preview or a site
# under the suffix can frame the app. Data, not code — extend as suffixes surface in reviews.
_SHARED_HOSTING_SUFFIXES = (
    'pages.dev',
    'vercel.app',
    'netlify.app',
    'github.io',
    'herokuapp.com',
    'web.app',
    'azurewebsites.net',
)

_LOOPBACK_HOSTS = frozenset({'localhost', '127.0.0.1', '::1'})

_SEVERITY_RANK: dict[Severity, int] = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

_NON_ALNUM = re.compile(r'[^A-Za-z0-9]+')
_CAMEL_BOUNDARY = re.compile(r'(?<=[a-z0-9])(?=[A-Z])')
_BARE_SCHEME = re.compile(r'^[a-z][a-z0-9+.-]*:$')
_NON_LOWER = re.compile(r'[^a-z0-9]')

_CSP_NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


# ── Host / response classification helpers ────────────────────────────────────


def _host_of(url: str) -> str:
    """The identity findings aggregate by: lowercase host with explicit non-default port."""
    parts = urlsplit(url)
    host = (parts.hostname or '').lower()
    if not host:
        return '(unknown host)'
    port = parts.port
    default_port = {'http': 80, 'https': 443}.get(parts.scheme)
    if port is not None and port != default_port:
        authority = f'[{host}]' if ':' in host else host
        return f'{authority}:{port}'
    return host


def _is_html(exchange: HttpEvidence) -> bool:
    """True when the response is an HTML document."""
    ct = (get_header(exchange.http.response.headers, 'Content-Type') or '').lower()
    return 'text/html' in ct or 'application/xhtml+xml' in ct


def _is_https(url: str) -> bool:
    return url.startswith('https://')


# ── Cookie classification (#38) ──────────────────────────────────────────────


def _cookie_tokens(name: str) -> list[str]:
    """Split a cookie name into lowercase tokens on separators and camelCase boundaries."""
    stripped = name
    for prefix in ('__secure-', '__host-'):
        if stripped.lower().startswith(prefix):
            stripped = stripped[len(prefix) :]
            break
    parts: list[str] = []
    # camelCase boundaries vanish under lowercasing, so split before lowering.
    for chunk in _CAMEL_BOUNDARY.split(stripped):
        parts.extend(_NON_ALNUM.split(chunk))
    return [part.lower() for part in parts if part]


def _is_session_cookie(cookie_name: str) -> bool:
    """Heuristic: a cookie is security-relevant if its name suggests auth/session state.

    Per response-policies.md: only flag cookies that carry session or authentication state.
    Stateless cookies (ga, _ga, theme, lang, …) must not produce findings. Whole-token matching
    keeps `inside` (sid), `user_prefs` (user) and similar false positives out (#38).
    """
    if _NON_LOWER.sub('', cookie_name.lower()) in _CLASSIC_SESSION_NAMES:
        return True
    tokens = _cookie_tokens(cookie_name)
    return any(token in _SESSION_TOKENS or token in _CSRF_TOKENS for token in tokens)


def _is_csrf_cookie(cookie_name: str) -> bool:
    """True for CSRF double-submit cookies, which legitimately cannot be HttpOnly."""
    return any(token in _CSRF_TOKENS for token in _cookie_tokens(cookie_name))


def _parse_set_cookie(header_value: str) -> tuple[str, dict[str, str]]:
    """Parse a Set-Cookie header into ``(name, attributes)``; attribute keys are lowercase."""
    parts = [p.strip() for p in header_value.split(';')]
    name_value, *attr_parts = parts
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


# ── CSP parsing and combined-effect evaluation (#38, #52) ─────────────────────


def _parse_csp(header_value: str) -> dict[str, list[str]]:
    """Parse one CSP header into directives: lowercase names → lowercase token lists."""
    directives: dict[str, list[str]] = {}
    for part in header_value.split(';'):
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return directives


@dataclass(frozen=True, slots=True)
class _ScriptEffect:
    """What a set of CSP policies (combined by intersection) permits for scripts."""

    allows_inline: bool
    allows_eval: bool
    allows_wildcard: bool

    def weaknesses(self) -> list[str]:
        parts: list[str] = []
        if self.allows_inline:
            parts.append("'unsafe-inline'")
        if self.allows_eval:
            parts.append("'unsafe-eval'")
        if self.allows_wildcard:
            parts.append('wildcard (*)')
        return parts


def _has_nonce_or_hash(tokens: Sequence[str]) -> bool:
    return any(any(token.startswith(prefix) for prefix in _CSP_NONCE_OR_HASH) for token in tokens)


def _script_effect(values: Sequence[str]) -> _ScriptEffect:
    """Combined script-source effect of *values* (each one enforced CSP header).

    Browsers intersect multiple policies: a source is script-executable only if **every**
    policy allows it. With one header this is that header's effect. Within one policy,
    CSP2+ ignores ``'unsafe-inline'`` when a nonce/hash is present, and ``'strict-dynamic'``
    makes host-source allowlists fallback-only for supporting browsers (#38 precision rules).
    """
    allows_inline = True
    allows_eval = True
    allows_wildcard = True
    for value in values:
        directives = _parse_csp(value)
        tokens = directives.get('script-src', directives.get('default-src', []))
        has_nonce = _has_nonce_or_hash(tokens)
        strict_dynamic = "'strict-dynamic'" in tokens
        allows_inline &= "'unsafe-inline'" in tokens and not has_nonce
        allows_eval &= "'unsafe-eval'" in tokens
        allows_wildcard &= '*' in tokens and not (has_nonce and strict_dynamic)
    return _ScriptEffect(allows_inline, allows_eval, allows_wildcard)


def _framing_sources(values: Sequence[str]) -> tuple[bool, frozenset[str]]:
    """Combined ``frame-ancestors`` effect of *values* (each one enforced CSP header).

    Returns ``(controls_framing, effective_sources)``: framing is CSP-controlled only when
    **every** enforced policy defines ``frame-ancestors``; the effective source set is then
    the intersection (framing is allowed only by sources every policy allows). ``'none'`` in
    any defining policy blocks framing outright.
    """
    token_lists: list[list[str]] = []
    for value in values:
        tokens = _parse_csp(value).get('frame-ancestors')
        if tokens is None:
            return False, frozenset()  # this policy leaves framing unrestricted
        token_lists.append(tokens)
    if not token_lists:
        return False, frozenset()
    if any("'none'" in tokens for tokens in token_lists):
        return True, frozenset()
    effective: frozenset[str] | None = None
    for tokens in token_lists:
        current = frozenset(token.rstrip('/') for token in tokens)
        effective = current if effective is None else effective & current
    assert effective is not None  # token_lists is non-empty here
    return True, effective


def _weak_frame_sources(sources: frozenset[str]) -> list[tuple[str, Severity]]:
    """The weak sources among effective ``frame-ancestors`` sources, in deterministic order."""
    weak: list[tuple[str, Severity]] = []
    for token in sorted(sources):
        if token in ("'self'", "'none'"):
            continue
        if token == '*':
            weak.append(('wildcard (*)', 'medium'))
            continue
        if _BARE_SCHEME.fullmatch(token):
            severity: Severity = 'medium' if token != 'http:' else 'low'
            weak.append((f'bare scheme source {token}', severity))
            continue
        source = token if '//' in token else f'//{token}'
        parts = urlsplit(source)
        scheme = parts.scheme
        hostname = (parts.hostname or '').lower().rstrip('.')
        if scheme == 'http':
            weak.append((f'plaintext http: source {token}', 'low'))
            continue
        if hostname in _LOOPBACK_HOSTS:
            weak.append((f'loopback host {hostname}', 'low'))
            continue
        if hostname.startswith('*.'):
            suffix = hostname[2:].split(':')[0]
            if suffix in _SHARED_HOSTING_SUFFIXES:
                weak.append((f'shared-hosting wildcard subdomain {hostname}', 'low'))
    return weak


# ── Instances and aggregation (#38) ──────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Instance:
    """One exchange's occurrence of a finding class, before per-host aggregation."""

    subject: str
    title: str
    severity: Severity
    summary: str
    """Host-level fragment; may contain a ``{details}`` placeholder filled at aggregation."""
    remediation: str
    details: tuple[str, ...] = ()
    """Per-instance pieces unioned at aggregation (missing cookie attributes, HSTS values)."""
    note: str = ''
    """Extra context (report-only policy, obsolete X-Frame-Options); retained across the group."""
    severity_by_details: bool = False
    """Cookie class: final severity depends on the unioned details (medium when 2+)."""


def _exchange_instances(exchange: HttpEvidence) -> list[_Instance]:
    """Every finding-class occurrence this exchange exhibits (the old per-exchange drafts)."""
    instances: list[_Instance] = []
    instances.extend(_hsts_instances(exchange))
    instances.extend(_csp_instances(exchange))
    instances.extend(_framing_instances(exchange))
    if inst := _xcto_instance(exchange):
        instances.append(inst)
    instances.extend(_cookie_instances(exchange))
    if inst := _cors_instance(exchange):
        instances.append(inst)
    return instances


# ── HSTS (#38: quoted/malformed max-age) ─────────────────────────────────────


def _hsts_max_age(hsts: str) -> tuple[int | None, str | None]:
    """``(value, raw)``: parsed max-age and the raw directive text; ``(None, raw)`` when absent
    or unparseable (RFC 6797 allows a quoted value: ``max-age="31536000"``)."""
    for part in hsts.split(';'):
        piece = part.strip()
        if piece.lower().startswith('max-age='):
            raw = piece.split('=', 1)[1].strip()
            if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            try:
                return int(raw), piece.split('=', 1)[1].strip()
            except ValueError:
                return None, piece.split('=', 1)[1].strip()
    return None, None


def _hsts_instances(exchange: HttpEvidence) -> list[_Instance]:
    url = exchange.http.request.url
    if not _is_https(url):
        return []
    hsts = get_header(exchange.http.response.headers, 'Strict-Transport-Security') or ''
    if not hsts:
        return [
            _Instance(
                subject='header:strict-transport-security',
                title='Missing HSTS header',
                severity='low',
                summary='HTTPS responses lack a Strict-Transport-Security header, allowing downgrade attacks.',
                remediation='Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all HTTPS responses.',
            )
        ]
    max_age, raw = _hsts_max_age(hsts)
    if max_age is None:
        if raw is None:
            summary = 'The HSTS header carries no max-age directive, so no validity period is communicated.'
        else:
            summary = 'The HSTS max-age directive is unparseable: {details}.'
        return [
            _Instance(
                subject='header:strict-transport-security',
                title='Malformed HSTS max-age directive',
                severity='low',
                summary=summary,
                remediation='Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`; max-age must be a decimal seconds value.',
                details=() if raw is None else (f'observed max-age={raw}',),
            )
        ]
    if max_age == 0:
        return [
            _Instance(
                subject='header:strict-transport-security',
                title='Weak HSTS policy',
                severity='medium',
                summary='HSTS is actively disabled: max-age=0: {details}.',
                remediation='Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.',
                details=('max-age=0',),
            )
        ]
    if max_age < HSTS_MIN_MAX_AGE:
        return [
            _Instance(
                subject='header:strict-transport-security',
                title='Weak HSTS policy',
                severity='low',
                summary='HSTS max-age is below the 1-year minimum: {details}.',
                remediation='Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.',
                details=(f'max-age={max_age}',),
            )
        ]
    return []


# ── CSP (#38: nonce/hash precision; #52: report-only, combined headers) ───────


def _csp_instances(exchange: HttpEvidence) -> list[_Instance]:
    if not _is_html(exchange) or exchange.http.response.status_code >= 300:
        return []
    enforced = get_all(exchange.http.response.headers, 'Content-Security-Policy')
    report_only = get_all(exchange.http.response.headers, 'Content-Security-Policy-Report-Only')
    report_only_note = ''
    if report_only:
        report_only_note = 'A stricter report-only policy is deployed but not enforced.'

    if not enforced:
        return [
            _Instance(
                subject='header:content-security-policy',
                title='Missing Content-Security-Policy header',
                severity='medium',
                summary='HTML responses lack an enforced Content-Security-Policy header.',
                remediation="Add a Content-Security-Policy header with at least `default-src 'self'` to all HTML responses.",
                note=report_only_note,
            )
        ]

    effect = _script_effect(enforced)
    weaknesses = effect.weaknesses()
    if not weaknesses:
        return []
    note = ''
    if report_only and not _script_effect(report_only).weaknesses():
        note = report_only_note
    return [
        _Instance(
            subject='header:content-security-policy',
            title='Unsafe Content-Security-Policy',
            severity='medium',
            summary='The enforced CSP permits {details}, which allows script injection.',
            remediation='Remove unsafe CSP sources: replace `*` with explicit origins, avoid '
            "'unsafe-inline' and 'unsafe-eval'; use nonces or hashes for inline scripts.",
            details=tuple(weaknesses),
            note=note,
        )
    ]


# ── Framing (#52) ────────────────────────────────────────────────────────────


def _framing_instances(exchange: HttpEvidence) -> list[_Instance]:
    if not _is_html(exchange) or exchange.http.response.status_code >= 300:
        return []
    headers = exchange.http.response.headers
    enforced = get_all(headers, 'Content-Security-Policy')
    report_only = get_all(headers, 'Content-Security-Policy-Report-Only')

    xfo_raw = get_header(headers, 'X-Frame-Options') or ''
    xfo_valid = xfo_raw.strip().upper() in ('DENY', 'SAMEORIGIN')

    controlled, effective = _framing_sources(enforced)
    if controlled:
        weak = _weak_frame_sources(effective)
        if not weak and xfo_valid:
            return []
        if weak:
            sources = [item[0] for item in weak]
            severity: Severity = 'low'
            for _, candidate in weak:
                if _SEVERITY_RANK[candidate] > _SEVERITY_RANK[severity]:
                    severity = candidate
            note = ''
            if report_only:
                ro_controlled, ro_effective = _framing_sources(report_only)
                if ro_controlled and not _weak_frame_sources(ro_effective):
                    note = 'A stricter report-only policy is deployed but not enforced.'
            return [
                _Instance(
                    subject='header:frame-ancestors',
                    title='Weak frame-ancestors policy',
                    severity=severity,
                    summary='The enforced CSP frame-ancestors permits {details}, allowing '
                    'framing by untrusted origins (clickjacking).',
                    remediation="Restrict `frame-ancestors` to `'self'` or `'none'`, or to explicit trusted origins.",
                    details=tuple(sources),
                    note=note,
                )
            ]
        # Controlled by CSP with no weak sources: framing is fine (X-Frame-Options optional).
        return []

    # No effective CSP framing control.
    if xfo_valid:
        return []
    note = ''
    if report_only and _framing_sources(report_only)[0]:
        note = 'A report-only frame-ancestors policy is deployed but not enforced.'
    xfo_note = ''
    if xfo_raw:
        xfo_note = (
            'X-Frame-Options: ALLOW-FROM is obsolete and ignored by modern browsers'
            if 'allow-from' in xfo_raw.lower()
            else f'X-Frame-Options: {xfo_raw.strip()!r} is not a framing control (expected DENY or SAMEORIGIN)'
        )
    summary = (
        'HTML responses have neither X-Frame-Options (DENY/SAMEORIGIN) nor an enforced CSP '
        'frame-ancestors directive, allowing framing by untrusted origins (clickjacking).'
    )
    if xfo_note:
        summary = f'{summary} {xfo_note}.'
    return [
        _Instance(
            subject='header:frame-ancestors',
            title='Missing framing policy',
            severity='low',
            summary=summary,
            remediation="Set `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`), "
            'or `X-Frame-Options: DENY`/`SAMEORIGIN` on HTML responses.',
            note=note,
        )
    ]


# ── X-Content-Type-Options ───────────────────────────────────────────────────


def _xcto_instance(exchange: HttpEvidence) -> _Instance | None:
    status = exchange.http.response.status_code
    if status >= 300 or status == 204:
        return None
    xcto = get_header(exchange.http.response.headers, 'X-Content-Type-Options') or ''
    if xcto.lower() != 'nosniff':
        return _Instance(
            subject='header:x-content-type-options',
            title='Missing X-Content-Type-Options header',
            severity='low',
            summary='Responses lack X-Content-Type-Options: nosniff, enabling MIME-sniffing attacks.',
            remediation='Set `X-Content-Type-Options: nosniff` on all responses that carry a body.',
        )
    return None


# ── Set-Cookie (#38: token classification, CSRF double-submit, cleanup) ──────


def _cookie_instances(exchange: HttpEvidence) -> list[_Instance]:
    instances: list[_Instance] = []
    is_https_exchange = _is_https(exchange.http.request.url)
    for header_value in get_all(exchange.http.response.headers, 'Set-Cookie'):
        if not header_value.strip():
            continue
        cookie_name, attrs = _parse_set_cookie(header_value)
        if not _is_session_cookie(cookie_name):
            continue

        missing: list[str] = []
        if is_https_exchange and 'secure' not in attrs:
            missing.append('Secure')
        if not _is_csrf_cookie(cookie_name) and 'httponly' not in attrs:
            missing.append('HttpOnly')
        samesite = attrs.get('samesite', '')
        if not samesite:
            missing.append('SameSite')
        elif samesite.lower() == 'none' and 'secure' not in attrs and 'Secure' not in missing:
            # SameSite=None requires Secure; avoid listing Secure twice under two names.
            missing.append('Secure (required with SameSite=None)')

        if not missing:
            continue
        instances.append(
            _Instance(
                subject=f'cookie:{cookie_name}',
                title='Weak Set-Cookie attributes',
                severity='medium',  # recomputed from the unioned details at aggregation
                summary=f'Session cookie `{cookie_name}` is set without required attributes: {{details}}.',
                remediation=f'Set the missing attributes on the Set-Cookie header for `{cookie_name}`. '
                'HttpOnly prevents JS access, Secure ensures HTTPS-only transport, and '
                'SameSite=Lax or Strict prevents cross-site request forgery.',
                details=tuple(missing),
                severity_by_details=True,
            )
        )
    return instances


# ── CORS (#38: passive severity re-rate) ────────────────────────────────────


def _cors_instance(exchange: HttpEvidence) -> _Instance | None:
    headers = exchange.http.response.headers
    acao = get_header(headers, 'Access-Control-Allow-Origin') or ''
    acac = get_header(headers, 'Access-Control-Allow-Credentials') or ''
    if not acao:
        return None
    if acac.lower() == 'true' and acao in ('*', 'null'):
        return _Instance(
            subject='header:access-control-allow-origin',
            title='Permissive CORS with credentials',
            severity='medium',
            summary=f'Responses set Access-Control-Allow-Origin: {acao} with '
            'Access-Control-Allow-Credentials: true — a server misconfiguration that '
            'signals credential-bearing cross-origin intent; browsers reject the literal '
            'pair, and the genuinely exploitable reflected-origin variant needs an active '
            'probe to confirm.',
            remediation='Never combine `Access-Control-Allow-Origin: *` or `null` with '
            '`Access-Control-Allow-Credentials: true`. Restrict ACAO to explicit, '
            'trusted origins when credentials are enabled.',
        )
    return None


# ── Aggregation (#38): one finding per host × class, all evidence attached ────


def _review_header_security(evidence: Sequence[Evidence]) -> list[FindingDraft]:
    """Run all header-security checks and aggregate the drafts per host and issue class."""
    groups: dict[tuple[str, str, str], list[tuple[_Instance, str, str]]] = {}

    for ev in evidence:
        if not isinstance(ev, HttpEvidence):
            continue
        host = _host_of(ev.http.request.url)
        redacted = redact(ev)
        assert isinstance(redacted, HttpEvidence)
        parts = urlsplit(redacted.http.request.url)
        url = urlunsplit((parts.scheme, parts.netloc.rsplit('@', 1)[-1], parts.path, '', ''))
        for inst in _exchange_instances(ev):
            key = (host, inst.subject, inst.title)
            groups.setdefault(key, []).append((inst, ev.id, url))

    drafts: list[FindingDraft] = []
    for (host, subject, title), group in groups.items():
        first = group[0][0]
        ids = sorted({evidence_id for _, evidence_id, _ in group})
        urls = sorted({url for _, _, url in group if url})
        details_by_summary: dict[str, set[str]] = {}
        notes: set[str] = set()
        for inst, _, _ in group:
            details_by_summary.setdefault(inst.summary, set()).update(inst.details)
            if inst.note:
                notes.add(inst.note)
        summaries = [
            summary.replace('{details}', ', '.join(sorted(details)))
            for summary, details in sorted(details_by_summary.items())
        ]
        severity = max((inst for inst, _, _ in group), key=lambda inst: _SEVERITY_RANK[inst.severity]).severity
        if first.severity_by_details:
            severity = 'medium' if len(details_by_summary[first.summary]) > 1 else 'low'
        description = ' '.join([*summaries, f'Affected host: {host}. {len(ids)} captured response(s).', *sorted(notes)])
        if urls:
            listed = urls[:MAX_LISTED_URLS]
            description += '\n\nAffected URLs:\n' + '\n'.join(f'- {url}' for url in listed)
            if len(urls) > len(listed):
                description += f'\n- … and {len(urls) - len(listed)} more (see the evidence IDs)'
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity=severity,
                subject=subject,
                title=title,
                description=description,
                evidence_ids=ids,
                remediation=first.remediation,
            )
        )
    return drafts


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
