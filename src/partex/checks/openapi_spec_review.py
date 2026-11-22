"""openapi-spec-review — built-in passive check for security issues visible in an OpenAPI spec.

Issue #156.  Pure function over validated evidence: no I/O, network, model, or storage access.
Registered via the ``partex.checks`` entry point; guidance lives in ``skills/openapi-spec-review/``.

Inspects ``ConfigEvidence`` items with ``config.format == 'openapi'`` (both bundle-supplied and
live-captured via #155) and emits at most **one finding per (spec, rule)**, citing JSON Pointer
paths and ``ev_`` IDs, never observed values:

- ``no-auth-declared``: spec declares no ``securitySchemes`` and no global/per-operation ``security``
  (counts total and state-changing operations; one finding per spec, never per operation).
- ``weak-security-scheme``: ``http basic``, ``apiKey`` in ``query``, or OAuth2 / OpenID Connect
  URLs over cleartext ``http://``.
- ``internal-server-url``: ``servers`` entries naming localhost, private/loopback IPs, or
  internal/non-production hosts.
- ``credential-query-param``: query parameters with credential- or secret-like names.
- ``sensitive-response-property``: 2xx/default JSON response schemas declaring sensitive property
  names (reusing :func:`~partex.openapi_resolver.is_sensitive_field`).
- ``unauthenticated-spec-exposure``: live-captured ``2xx`` OpenAPI spec fetched without
  ``Authorization`` or ``Cookie`` headers from a production-looking host.

SSRF- and redirect-prone parameter names (``url``, ``callback``, ``webhook``, ``redirect``,
``next``, ``return_to``, etc.) are emitted as ``needs_follow_up`` leads in :meth:`coverage`, not
findings.
"""

import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, cast
from urllib.parse import urlsplit

import yaml

from ..models import (
    ConfigEvidence,
    CoverageEntry,
    Evidence,
    FindingDraft,
    HttpEvidence,
    Severity,
    get_header,
)
from ..openapi_resolver import (
    HTTP_METHODS,
    MAX_OPENAPI_NODES,
    MAX_SCHEMA_DEPTH,
    ResolvedSchema,
    is_high_signal_secret_field,
    is_sensitive_field,
    load_openapi_contract,
    resolve_local_pointer,
)

CHECK_ID = 'openapi-spec-review'
CHECK_VERSION = '1.0'
CHECK_TITLE = 'OpenAPI Specification Security Review'
CHECK_DESCRIPTION = (
    'Review captured or supplied OpenAPI 3.0/3.1 specifications for missing or weak authentication '
    'declarations, internal server URLs, credential query parameters, sensitive response schema '
    'properties, unauthenticated production spec exposure, and SSRF/redirect parameter leads.'
)

_STATE_CHANGING_METHODS = frozenset({'post', 'put', 'patch', 'delete'})
_OAS_VERSION_RE = re.compile(r'^3\.(?:0|1)(?:\.\d+.*)?$')
_TEMPLATE_TOKEN_RE = re.compile(r'\{([^{}/]+)\}')
_CAMEL_BOUNDARY_RE = re.compile(r'(?<=[a-z0-9])(?=[A-Z])')
_NON_ALNUM_RE = re.compile(r'[^A-Za-z0-9]+')

_INTERNAL_TLDS = frozenset({'internal', 'local', 'localhost', 'corp', 'lan', 'intranet', 'home', 'arpa'})
_NON_PROD_LABELS = frozenset(
    {'dev', 'devel', 'development', 'staging', 'stage', 'stg', 'qa', 'uat', 'sandbox', 'preprod', 'internal', 'local'}
)
_CREDENTIAL_QUERY_EXTRA = frozenset(
    {'auth', 'authorization', 'bearer', 'credential', 'credentials', 'jwt', 'pass', 'session_id', 'sid', 'x_api_key'}
)
_SSRF_REDIRECT_NAMES = frozenset(
    {
        'url',
        'uri',
        'target',
        'target_url',
        'dest',
        'destination',
        'callback',
        'callback_url',
        'webhook',
        'webhook_url',
        'redirect',
        'redirect_uri',
        'redirect_url',
        'next',
        'next_url',
        'return_to',
        'return_url',
        'continue',
        'goto',
        'image_url',
        'avatar_url',
        'endpoint',
    }
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _escape_pointer_token(token: str) -> str:
    return token.replace('~', '~0').replace('/', '~1')


def _json_pointer(*tokens: str | int) -> str:
    return '#/' + '/'.join(_escape_pointer_token(str(tok)) for tok in tokens)


def _normalize_name(name: str) -> tuple[list[str], str]:
    parts: list[str] = []
    for chunk in _CAMEL_BOUNDARY_RE.split(name):
        parts.extend(_NON_ALNUM_RE.split(chunk))
    tokens = [part.lower() for part in parts if part]
    return tokens, '_'.join(tokens)


def _is_credential_query_param(name: str) -> bool:
    if is_sensitive_field(name):
        return True
    tokens, normalized = _normalize_name(name)
    return normalized in _CREDENTIAL_QUERY_EXTRA or any(tok in {'jwt', 'credential', 'credentials'} for tok in tokens)


def _is_ssrf_or_redirect_param(name: str) -> bool:
    _, normalized = _normalize_name(name)
    return normalized in _SSRF_REDIRECT_NAMES


def _parse_openapi_mapping(content: str) -> dict[str, Any] | None:
    stripped = content.lstrip()
    if not stripped:
        return None
    parsed: Any
    if stripped.startswith('{'):
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            try:
                parsed = yaml.safe_load(content)
            except yaml.YAMLError:
                return None
    else:
        try:
            parsed = yaml.safe_load(content)
        except yaml.YAMLError:
            return None
    if not isinstance(parsed, dict):
        return None
    # Node budget guard (mirrors openapi_resolver._check_node_budget).
    count = 0
    stack: list[tuple[Any, int]] = [(parsed, 0)]
    while stack:
        current, depth = stack.pop()
        count += 1
        if count > MAX_OPENAPI_NODES or depth > MAX_SCHEMA_DEPTH:
            return None
        if isinstance(current, dict):
            for val in cast(dict[Any, Any], current).values():
                stack.append((val, depth + 1))
        elif isinstance(current, list):
            for item in cast(list[Any], current):
                stack.append((item, depth + 1))
    doc = cast(dict[str, Any], parsed)
    raw_version = doc.get('openapi')
    if not isinstance(raw_version, str) or not _OAS_VERSION_RE.match(raw_version.strip()):
        return None
    if not isinstance(doc.get('paths'), dict):
        return None
    return doc


def _deref_local(raw: Any, doc: Mapping[str, Any], seen: frozenset[str] = frozenset()) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    obj = cast(dict[str, Any], raw)
    ref = obj.get('$ref')
    if not isinstance(ref, str):
        return obj
    if ref in seen:
        return {k: v for k, v in obj.items() if k != '$ref'}
    target, err = resolve_local_pointer(doc, ref)
    if err is not None or not isinstance(target, dict):
        return None
    resolved = _deref_local(target, doc, seen | {ref})
    if resolved is None:
        return None
    siblings = {k: v for k, v in obj.items() if k != '$ref'}
    return {**resolved, **siblings}


def _expand_server_url(server_obj: Mapping[str, Any]) -> str | None:
    url = server_obj.get('url')
    if not isinstance(url, str) or not url.strip():
        return None
    variables = server_obj.get('variables')
    if isinstance(variables, dict):
        var_map = cast(dict[str, Any], variables)

        def _sub(match: re.Match[str]) -> str:
            entry = var_map.get(match.group(1))
            if isinstance(entry, dict):
                default = cast(dict[str, Any], entry).get('default')
                if isinstance(default, str):
                    return default
            return match.group(0)

        url = _TEMPLATE_TOKEN_RE.sub(_sub, url)
    return url.strip()


def _classify_non_prod_host(host: str) -> str | None:
    """Return a non-production/internal host class, or ``None`` if *host* looks production-like."""
    cleaned = host.strip().rstrip('.').lower()
    if not cleaned:
        return None
    if cleaned in {'localhost', 'localhost.localdomain'}:
        return 'localhost'
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        addr = None
    if addr is not None:
        if addr.is_loopback or addr.is_unspecified:
            return 'loopback-ip'
        if addr.is_private or addr.is_link_local or addr.is_reserved:
            return 'private-ip'
        return None
    labels = [label for label in cleaned.split('.') if label]
    if not labels:
        return None
    if labels[-1] in _INTERNAL_TLDS:
        return 'internal-tld'
    for label in labels[:-1] if len(labels) > 1 else labels:
        sub_tokens = [tok for tok in re.split(r'[-_]', label) if tok]
        if label in _NON_PROD_LABELS or any(tok in _NON_PROD_LABELS for tok in sub_tokens):
            return 'non-production-host'
    return None


def _has_nonempty_security(raw_security: Any) -> bool:
    if not isinstance(raw_security, list):
        return False
    for entry in cast(list[Any], raw_security):
        if isinstance(entry, dict) and len(cast(dict[Any, Any], entry)) > 0:
            return True
    return False


def _collect_sensitive_schema_props(
    schema: ResolvedSchema,
    prefix: str,
    out: list[tuple[str, str, bool]],
    *,
    seen: frozenset[int] = frozenset(),
    depth: int = 0,
) -> None:
    if depth > MAX_SCHEMA_DEPTH or id(schema) in seen:
        return
    next_seen = seen | {id(schema)}
    for prop_name in sorted(schema.properties):
        prop_path = f'{prefix}.{prop_name}' if prefix else prop_name
        if is_sensitive_field(prop_name):
            out.append((prop_path, prop_name, is_high_signal_secret_field(prop_name)))
        _collect_sensitive_schema_props(schema.properties[prop_name], prop_path, out, seen=next_seen, depth=depth + 1)
    if schema.items is not None:
        item_prefix = f'{prefix}[]' if prefix else '[]'
        _collect_sensitive_schema_props(schema.items, item_prefix, out, seen=next_seen, depth=depth + 1)
    for branch in schema.any_of:
        _collect_sensitive_schema_props(branch, prefix, out, seen=next_seen, depth=depth + 1)


def _origin_http_for_spec(
    spec_ev: ConfigEvidence, http_by_id: Mapping[str, HttpEvidence]
) -> tuple[HttpEvidence | None, str | None]:
    """Return ``(origin_http, clean_url)`` when *spec_ev* was derived from a live 2xx capture (#155)."""
    source = spec_ev.source
    if not source.startswith('derived:'):
        return None, None
    rest = source.removeprefix('derived:')
    origin_id, sep, url = rest.partition(':')
    if not sep or not origin_id:
        return None, None
    return http_by_id.get(origin_id), url or None


def _is_unauthenticated_request(http_ev: HttpEvidence) -> bool:
    headers = http_ev.http.request.headers
    return get_header(headers, 'Authorization') is None and get_header(headers, 'Cookie') is None


def _spec_subject_key(spec_ev: ConfigEvidence, clean_url: str | None) -> str:
    if clean_url:
        parts = urlsplit(clean_url)
        if parts.netloc:
            return f'{parts.netloc}{parts.path or "/"}'
    return spec_ev.config.path


# ── Per-spec analysis ────────────────────────────────────────────────────────


def _review_spec(
    spec_ev: ConfigEvidence,
    http_by_id: Mapping[str, HttpEvidence],
) -> tuple[list[FindingDraft], list[CoverageEntry]]:
    doc = _parse_openapi_mapping(spec_ev.config.content)
    if doc is None:
        return [], []

    origin_http, clean_url = _origin_http_for_spec(spec_ev, http_by_id)
    spec_label = _spec_subject_key(spec_ev, clean_url)
    drafts: list[FindingDraft] = []
    coverage_entries: list[CoverageEntry] = []

    raw_paths = cast(dict[Any, Any], doc['paths'])
    total_ops = 0
    state_changing_ops = 0
    any_op_security = False
    server_hits: list[tuple[str, str]] = []  # (json_pointer, classification)
    cred_query_hits: list[tuple[str, str]] = []  # (json_pointer, param_name)
    ssrf_leads_by_op: dict[str, list[tuple[str, str]]] = {}  # op_key -> [(json_pointer, param_name)]

    def _inspect_servers(raw_servers: Any, pointer_prefix: tuple[str | int, ...]) -> None:
        if not isinstance(raw_servers, list):
            return
        for idx, entry in enumerate(cast(list[Any], raw_servers)):
            if not isinstance(entry, dict):
                continue
            expanded = _expand_server_url(cast(dict[str, Any], entry))
            if not expanded:
                continue
            host = urlsplit(expanded).hostname or ''
            kind = _classify_non_prod_host(host)
            if kind is not None:
                server_hits.append((_json_pointer(*pointer_prefix, idx, 'url'), kind))

    def _inspect_params(
        raw_params: Any,
        pointer_prefix: tuple[str | int, ...],
        op_label: str,
    ) -> None:
        if not isinstance(raw_params, list):
            return
        for idx, raw_param in enumerate(cast(list[Any], raw_params)):
            param = _deref_local(raw_param, doc)
            if param is None:
                continue
            name = param.get('name')
            loc = param.get('in')
            if not isinstance(name, str) or not name or not isinstance(loc, str):
                continue
            ptr = _json_pointer(*pointer_prefix, idx)
            if loc.lower() == 'query' and _is_credential_query_param(name):
                cred_query_hits.append((ptr, name))
            if loc.lower() in {'query', 'path', 'header'} and _is_ssrf_or_redirect_param(name):
                ssrf_leads_by_op.setdefault(op_label, []).append((ptr, name))

    _inspect_servers(doc.get('servers'), ('servers',))

    for raw_tpl, raw_item in sorted(raw_paths.items(), key=lambda kv: str(kv[0])):
        if not isinstance(raw_tpl, str) or not raw_tpl.startswith('/'):
            continue
        path_item = _deref_local(raw_item, doc)
        if path_item is None:
            continue
        _inspect_servers(path_item.get('servers'), ('paths', raw_tpl, 'servers'))
        _inspect_params(path_item.get('parameters'), ('paths', raw_tpl, 'parameters'), f'PATH {raw_tpl}')

        for method in sorted(HTTP_METHODS):
            raw_op = path_item.get(method)
            if not isinstance(raw_op, dict):
                continue
            op_dict = cast(dict[str, Any], raw_op)
            total_ops += 1
            if method in _STATE_CHANGING_METHODS:
                state_changing_ops += 1
            if _has_nonempty_security(op_dict.get('security')):
                any_op_security = True
            _inspect_servers(op_dict.get('servers'), ('paths', raw_tpl, method, 'servers'))
            _inspect_params(
                op_dict.get('parameters'),
                ('paths', raw_tpl, method, 'parameters'),
                f'{method.upper()} {raw_tpl}',
            )

    # 1. No authentication declared (one finding per spec, never per operation).
    components = doc.get('components')
    raw_schemes = cast(dict[Any, Any], components).get('securitySchemes') if isinstance(components, dict) else None
    has_schemes = isinstance(raw_schemes, dict) and len(cast(dict[Any, Any], raw_schemes)) > 0
    has_global_security = _has_nonempty_security(doc.get('security'))

    if total_ops > 0 and not has_schemes and not has_global_security and not any_op_security:
        severity: Severity = 'medium' if state_changing_ops > 0 else 'low'
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity=severity,
                subject=f'spec:{spec_label}:no-auth-declared',
                title='OpenAPI specification declares no authentication',
                description=(
                    f'OpenAPI specification {spec_label} ({spec_ev.id}) declares {total_ops} operation(s) '
                    f'({state_changing_ops} state-changing) under #/paths with no #/components/securitySchemes '
                    'and no global (#/security) or per-operation security requirements (OWASP API2:2023).'
                ),
                evidence_ids=[spec_ev.id],
                remediation=(
                    'Declare explicit authentication schemes in #/components/securitySchemes and apply '
                    'global or per-operation security requirements to every non-public operation.'
                ),
            )
        )

    # 2. Weak security schemes (http basic, apiKey in query, OAuth2/OIDC over http://).
    weak_schemes: list[tuple[str, str]] = []  # (json_pointer, reason)
    if isinstance(raw_schemes, dict):
        for scheme_name, raw_scheme in sorted(cast(dict[Any, Any], raw_schemes).items(), key=lambda kv: str(kv[0])):
            if not isinstance(scheme_name, str):
                continue
            scheme = _deref_local(raw_scheme, doc)
            if scheme is None:
                continue
            ptr = _json_pointer('components', 'securitySchemes', scheme_name)
            stype = str(scheme.get('type', '')).lower()
            if stype == 'http' and str(scheme.get('scheme', '')).lower() == 'basic':
                weak_schemes.append((ptr, 'HTTP Basic authentication'))
            elif stype == 'apikey' and str(scheme.get('in', '')).lower() == 'query':
                weak_schemes.append((ptr, 'API key transmitted in query string'))
            elif stype == 'oauth2' and isinstance(scheme.get('flows'), dict):
                flows = cast(dict[Any, Any], scheme['flows'])
                for flow_name, raw_flow in sorted(flows.items(), key=lambda kv: str(kv[0])):
                    if not isinstance(raw_flow, dict):
                        continue
                    flow = cast(dict[Any, Any], raw_flow)
                    for url_key in ('authorizationUrl', 'tokenUrl', 'refreshUrl'):
                        val = flow.get(url_key)
                        if isinstance(val, str) and val.strip().lower().startswith('http://'):
                            flow_ptr = _json_pointer(
                                'components', 'securitySchemes', scheme_name, 'flows', str(flow_name), url_key
                            )
                            weak_schemes.append((flow_ptr, f'OAuth2 {url_key} uses cleartext http://'))
            elif stype == 'openidconnect':
                oidc_url = scheme.get('openIdConnectUrl')
                if isinstance(oidc_url, str) and oidc_url.strip().lower().startswith('http://'):
                    oidc_ptr = _json_pointer('components', 'securitySchemes', scheme_name, 'openIdConnectUrl')
                    weak_schemes.append((oidc_ptr, 'OpenID Connect discovery URL uses cleartext http://'))

    if weak_schemes:
        weak_schemes.sort()
        details = '; '.join(f'{ptr} ({reason})' for ptr, reason in weak_schemes)
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='medium',
                subject=f'spec:{spec_label}:weak-security-scheme',
                title='OpenAPI specification declares weak authentication scheme(s)',
                description=(
                    f'OpenAPI specification {spec_label} ({spec_ev.id}) defines {len(weak_schemes)} weak '
                    f'authentication scheme configuration(s): {details} (CWE-522, OWASP API2:2023).'
                ),
                evidence_ids=[spec_ev.id],
                remediation=(
                    'Prefer bearer tokens or OAuth2/OIDC over HTTPS with credentials sent in the '
                    'Authorization header rather than HTTP Basic, query-string API keys, or cleartext http:// URLs.'
                ),
            )
        )

    # 3. Internal or non-production server URLs.
    if server_hits:
        dedup_servers = sorted(set(server_hits))
        details = ', '.join(f'{ptr} ({kind})' for ptr, kind in dedup_servers)
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='low',
                subject=f'spec:{spec_label}:internal-server-url',
                title='OpenAPI specification exposes internal or non-production server URL(s)',
                description=(
                    f'OpenAPI specification {spec_label} ({spec_ev.id}) lists {len(dedup_servers)} '
                    f'internal or non-production server entry(ies): {details} (CWE-200).'
                ),
                evidence_ids=[spec_ev.id],
                remediation=(
                    'Remove localhost, private IP, and internal/staging hostnames from published OpenAPI '
                    'server definitions.'
                ),
            )
        )

    # 4. Credential-like query parameters.
    if cred_query_hits:
        dedup_creds = sorted(set(cred_query_hits))
        details = ', '.join(f'{ptr} (name={name})' for ptr, name in dedup_creds)
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='medium',
                subject=f'spec:{spec_label}:credential-query-param',
                title='OpenAPI specification accepts credential-like query parameter(s)',
                description=(
                    f'OpenAPI specification {spec_label} ({spec_ev.id}) declares {len(dedup_creds)} '
                    f'credential- or secret-like query parameter(s): {details}. Query parameters leak into '
                    'access logs, browser history, and Referer headers (CWE-598).'
                ),
                evidence_ids=[spec_ev.id],
                remediation=(
                    'Move credentials, tokens, and API keys out of URL query parameters into the '
                    'Authorization header or a POST request body over TLS.'
                ),
            )
        )

    # 5. Response schemas declaring sensitive properties (reusing openapi_resolver).
    contract = load_openapi_contract(spec_ev)
    sensitive_hits: list[tuple[str, str, bool]] = []  # (location, prop_name, high_signal)
    for op in sorted(contract.operations, key=lambda o: o.key):
        for status_key in sorted(op.responses):
            resp = op.responses[status_key]
            if resp.schema is None:
                continue
            props_found: list[tuple[str, str, bool]] = []
            _collect_sensitive_schema_props(resp.schema, '', props_found)
            for prop_path, prop_name, high_signal in props_found:
                loc = f'{op.key} [{status_key}] #/{prop_path.replace(".", "/")}'
                sensitive_hits.append((loc, prop_name, high_signal))

    if sensitive_hits:
        dedup_sens = sorted({(loc, prop, hi) for loc, prop, hi in sensitive_hits})
        has_high = any(hi for _, _, hi in dedup_sens)
        details = ', '.join(loc for loc, _, _ in dedup_sens)
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='high' if has_high else 'medium',
                subject=f'spec:{spec_label}:sensitive-response-property',
                title='OpenAPI response schema declares sensitive property name(s)',
                description=(
                    f'OpenAPI specification {spec_label} ({spec_ev.id}) declares {len(dedup_sens)} '
                    f'sensitive response schema property(ies): {details} (OWASP API3:2023, CWE-200).'
                ),
                evidence_ids=[spec_ev.id],
                remediation=(
                    'Remove credential, secret, PII, and privilege fields from public API response DTOs '
                    'and enforce explicit output serialization schemas.'
                ),
            )
        )

    # 6. Spec exposed without authentication on a production-looking host.
    if (
        origin_http is not None
        and 200 <= origin_http.http.response.status_code < 300
        and _is_unauthenticated_request(origin_http)
    ):
        host = urlsplit(origin_http.http.request.url).hostname or ''
        if host and _classify_non_prod_host(host) is None:
            drafts.append(
                FindingDraft(
                    check_id=CHECK_ID,
                    check_version=CHECK_VERSION,
                    severity='low',
                    subject=f'spec:{spec_label}:unauthenticated-spec-exposure',
                    title='OpenAPI specification exposed without authentication',
                    description=(
                        f'OpenAPI specification {spec_label} was retrieved with HTTP '
                        f'{origin_http.http.response.status_code} ({origin_http.id}, derived {spec_ev.id}) '
                        'without Authorization or Cookie headers on a production-looking host (CWE-200).'
                    ),
                    evidence_ids=sorted([spec_ev.id, origin_http.id]),
                    remediation=(
                        'Restrict public access to OpenAPI/Swagger documentation on production hosts '
                        '(require authentication or disable spec publishing outside developer portals).'
                    ),
                )
            )

    # 7. SSRF- or redirect-prone parameter names -> coverage leads (not findings).
    for op_label in sorted(ssrf_leads_by_op):
        leads = sorted(set(ssrf_leads_by_op[op_label]))
        lead_desc = ', '.join(f'{ptr} (name={name})' for ptr, name in leads)
        coverage_entries.append(
            CoverageEntry(
                surface=op_label,
                risk_area='ssrf-or-open-redirect',
                source='check_observed',
                outcome='needs_follow_up',
                reason=f'OpenAPI parameter(s) warrant SSRF/redirect testing: {lead_desc}',
                evidence_ids=[spec_ev.id],
            )
        )

    return drafts, coverage_entries


# ── Check entry point ────────────────────────────────────────────────────────


class OpenApiSpecReviewCheck:
    """Passive check: per-spec security review of OpenAPI 3.0 / 3.1 ``ConfigEvidence``."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        """Applies when at least one ``format == 'openapi'`` ``ConfigEvidence`` is present."""
        return any(isinstance(ev, ConfigEvidence) and ev.config.format.lower() == 'openapi' for ev in evidence)

    def _run(self, evidence: Sequence[Evidence]) -> tuple[list[FindingDraft], list[CoverageEntry]]:
        http_by_id = {ev.id: ev for ev in evidence if isinstance(ev, HttpEvidence)}
        specs = sorted(
            (ev for ev in evidence if isinstance(ev, ConfigEvidence) and ev.config.format.lower() == 'openapi'),
            key=lambda ev: (ev.config.path, ev.id),
        )
        all_drafts: list[FindingDraft] = []
        all_coverage: list[CoverageEntry] = []
        for spec_ev in specs:
            drafts, cov = _review_spec(spec_ev, http_by_id)
            all_drafts.extend(drafts)
            all_coverage.extend(cov)
        all_drafts.sort(key=lambda d: (d.subject, d.title))
        all_coverage.sort(key=lambda c: (c.surface, c.risk_area, c.reason))
        return all_drafts, all_coverage

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        drafts, _ = self._run(evidence)
        return drafts

    def coverage(self, evidence: Sequence[Evidence]) -> Sequence[CoverageEntry]:
        _, cov = self._run(evidence)
        return cov


openapi_spec_review_check = OpenApiSpecReviewCheck()
