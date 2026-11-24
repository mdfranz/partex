"""api-contract-conformance — built-in passive check for OpenAPI inventory and contract conformance.

Issue #24 (Slice S1, docs/skills/PLAN.md §4 P1.1).  Pure function over validated evidence: no I/O,
network, model, or storage access.  Registered via the ``partex.checks`` entry point; guidance lives
in ``skills/api-inventory/`` (data, never executed).

Reconciles captured ``HttpEvidence`` exchanges against ``ConfigEvidence`` items with
``config.format == 'openapi'``:

- Normalized operation keys (PLAN §12): ``METHOD /path/{param}`` (static segments win over
  parameterized segments; single-endpoint GraphQL/RPC surfaces collapse to one key).
- Findings:
  - Shadow / undocumented operations (``medium``, OWASP API9:2023)
  - Disallowed / excessive response fields (``medium`` / ``high``, OWASP API3:2023 BOPLA)
- Coverage ledger (``coverage(evidence)``):
  - Conforming operations -> ``no_issue_found``
  - Finding-bearing operations -> ``reported``
  - Unobserved declared operations -> ``needs_follow_up`` (not findings)
  - No contract in bundle / unresolvable external ``$ref`` -> ``not_applicable`` (insufficient evidence)
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ..ids import normalized_operation_key
from ..models import ConfigEvidence, CoverageEntry, Evidence, FindingDraft, HttpEvidence, Severity, get_header
from ..openapi_resolver import (
    DeclaredOperation,
    FieldViolation,
    LoadedContract,
    check_response_body,
    load_openapi_contracts,
    match_operation,
    max_violation_severity,
    normalize_request_path,
)

CHECK_ID = 'api-contract-conformance'
CHECK_VERSION = '1.0'
CHECK_TITLE = 'API Contract Conformance and Surface Inventory'
CHECK_DESCRIPTION = (
    'Build a normalized API operation inventory from captured HTTP exchanges and reconcile '
    'observed traffic against OpenAPI config excerpts for undocumented shadow routes (API9:2023) '
    'and disallowed or sensitive response properties (API3:2023).'
)

_NUMERIC_SEG = re.compile(r'^\d+$')
_UUID_SEG = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_LONG_HEX_SEG = re.compile(r'^[0-9a-fA-F]{16,}$')
_API_LIKE_PREFIX = re.compile(r'^/(?:api|v\d+|graphql|gql|rpc|jsonrpc)(?:/|$)', re.IGNORECASE)
_VERSION_PREFIX_RE = re.compile(r'^/(?:api/)?(v\d+)(?:/|$)', re.IGNORECASE)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme and parts.netloc:
        return f'{parts.scheme}://{parts.netloc}'
    return url


def _host_of(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or '').lower()
    if not host:
        return ''
    port = parts.port
    default_port = {'http': 80, 'https': 443}.get(parts.scheme.lower())
    if port is not None and port != default_port:
        authority = f'[{host}]' if ':' in host else host
        return f'{authority}:{port}'
    return host


def _query_param_names(url: str) -> tuple[str, ...]:
    query = urlsplit(url).query
    if not query:
        return ()
    names = {name for name, _ in parse_qsl(query, keep_blank_values=True) if name}
    return tuple(sorted(names))


def collapse_path_ids(url_or_path: str) -> str:
    """Collapse concrete numeric, UUID, and long-hex path segments to ``{id}`` on unmatched paths.

    Static segments (including single-endpoint surfaces like ``/graphql`` or ``/rpc``) stay intact,
    so no raw identifier values enter finding titles, subjects, coverage surfaces, or surface keys.
    """
    norm = normalize_request_path(url_or_path)
    if norm == '/':
        return '/'
    stripped = norm.rstrip('/') if norm != '/' else '/'
    segments = [
        '{id}' if (_NUMERIC_SEG.fullmatch(seg) or _UUID_SEG.fullmatch(seg) or _LONG_HEX_SEG.fullmatch(seg)) else seg
        for seg in stripped.strip('/').split('/')
    ]
    return '/' + '/'.join(segments)


def _is_html_document_navigation(exchange: HttpEvidence, server_prefixes: Sequence[str]) -> bool:
    """True for browser HTML page navigations outside API prefixes (avoids flagging ``GET /login`` HTML as an API)."""
    method = exchange.http.request.method.upper()
    if method not in {'GET', 'HEAD'}:
        return False
    status = exchange.http.response.status_code
    if not (200 <= status < 400):
        return False
    ct = (get_header(exchange.http.response.headers, 'Content-Type') or '').lower()
    if 'text/html' not in ct and 'application/xhtml+xml' not in ct:
        return False
    path = normalize_request_path(exchange.http.request.url)
    if _API_LIKE_PREFIX.match(path):
        return False
    return not any(prefix and (path == prefix or path.startswith(prefix + '/')) for prefix in server_prefixes)


def _revision_label(revision: str | None, contract_path: str | None = None) -> str:
    if revision:
        return f'contract revision {revision}'
    if contract_path:
        return f'contract {contract_path}'
    return 'contract revision unspecified'


def _declared_versions(operations: Sequence[DeclaredOperation]) -> frozenset[str]:
    versions: set[str] = set()
    for op in operations:
        if match := _VERSION_PREFIX_RE.match(op.path_template):
            versions.add(match.group(1).lower())
    return frozenset(versions)


# ── Reconciliation core ──────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _ShadowGroup:
    key: str
    method: str
    path_template: str
    matched_declared_path: bool
    evidence_ids: tuple[str, ...]
    query_params: tuple[str, ...]
    hosts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _MatchedGroup:
    operation: DeclaredOperation
    evidence_ids: tuple[str, ...]
    has_2xx: bool
    violations: tuple[FieldViolation, ...]
    unresolved_ref: str | None
    observed_query_params: tuple[str, ...]
    hosts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class InventoryAnalysis:
    """Deterministic reconciliation of OpenAPI contracts and HTTP exchanges."""

    contracts: tuple[LoadedContract, ...]
    valid_contracts: tuple[LoadedContract, ...]
    invalid_contracts: tuple[LoadedContract, ...]
    http_exchanges: tuple[HttpEvidence, ...]
    declared_operations: tuple[DeclaredOperation, ...]
    matched: Mapping[str, _MatchedGroup]
    unobserved: tuple[DeclaredOperation, ...]
    shadows: tuple[_ShadowGroup, ...]
    observed_without_contract: tuple[_ShadowGroup, ...]


def build_operation_inventory(evidence: Sequence[Evidence]) -> InventoryAnalysis:
    """Reconcile *evidence* into declared, matched, unobserved, and shadow API operations."""
    contracts = tuple(load_openapi_contracts(evidence))
    valid_contracts = tuple(c for c in contracts if c.load_error is None)
    invalid_contracts = tuple(c for c in contracts if c.load_error is not None)
    http_exchanges = tuple(item for item in evidence if isinstance(item, HttpEvidence))

    ops_by_key: dict[str, DeclaredOperation] = {}
    server_prefixes: list[str] = []
    for contract in valid_contracts:
        for prefix in contract.server_prefixes:
            if prefix and prefix not in server_prefixes:
                server_prefixes.append(prefix)
        for op in contract.operations:
            ops_by_key.setdefault(op.key, op)
    declared_ops = tuple(ops_by_key.values())

    if not valid_contracts:
        # No usable OpenAPI contract: still normalize observed non-404/non-OPTIONS API/HTTP surface.
        obs_groups: dict[str, tuple[str, str, list[str], set[str], set[str]]] = {}
        for ex in http_exchanges:
            method = ex.http.request.method.upper()
            if method == 'OPTIONS' or ex.http.response.status_code == 404:
                continue
            collapsed = collapse_path_ids(ex.http.request.url)
            op_key = normalized_operation_key(method, collapsed)
            _, _, ev_ids, qparams, hosts = obs_groups.setdefault(op_key, (method, collapsed, [], set(), set()))
            if ex.id not in ev_ids:
                ev_ids.append(ex.id)
            qparams.update(_query_param_names(ex.http.request.url))
            if host := _host_of(ex.http.request.url):
                hosts.add(host)
        observed_only = tuple(
            _ShadowGroup(
                key=k,
                method=m,
                path_template=tpl,
                matched_declared_path=False,
                evidence_ids=tuple(ids),
                query_params=tuple(sorted(qp)),
                hosts=tuple(sorted(hs)),
            )
            for k, (m, tpl, ids, qp, hs) in obs_groups.items()
        )
        return InventoryAnalysis(
            contracts=contracts,
            valid_contracts=valid_contracts,
            invalid_contracts=invalid_contracts,
            http_exchanges=http_exchanges,
            declared_operations=(),
            matched={},
            unobserved=(),
            shadows=(),
            observed_without_contract=observed_only,
        )

    contract_bodies = {
        item.config.content
        for item in evidence
        if isinstance(item, ConfigEvidence) and item.config.format.lower() == 'openapi'
    }
    valid_contract_paths = {c.path for c in valid_contracts if c.path.startswith('/')}

    matched_acc: dict[
        str, tuple[DeclaredOperation, list[str], bool, dict[str, FieldViolation], str | None, set[str], set[str]]
    ] = {}
    shadow_acc: dict[str, tuple[str, str, bool, list[str], set[str], set[str]]] = {}

    for ex in http_exchanges:
        method = ex.http.request.method.upper()
        url = ex.http.request.url
        status = ex.http.response.status_code
        match = match_operation(declared_ops, method, url)

        if match is not None and match.operation is not None:
            op = match.operation
            entry = matched_acc.get(op.key)
            if entry is None:
                ev_ids: list[str] = []
                has_2xx = False
                viol_map: dict[str, FieldViolation] = {}
                unres_ref: str | None = op.unresolved_ref
                qparams: set[str] = set()
                hosts: set[str] = set()
            else:
                _, ev_ids, has_2xx, viol_map, unres_ref, qparams, hosts = entry

            if ex.id not in ev_ids:
                ev_ids.append(ex.id)
            qparams.update(_query_param_names(url))
            if host := _host_of(url):
                hosts.add(host)

            if 200 <= status < 300 and ex.http.response.body_note != 'truncated':
                has_2xx = True
                ct = get_header(ex.http.response.headers, 'Content-Type')
                outcome = check_response_body(op, status, ex.http.response.body, ct)
                if outcome.unresolved_ref is not None and unres_ref is None:
                    unres_ref = outcome.unresolved_ref
                for viol in outcome.violations:
                    prev = viol_map.get(viol.path)
                    if prev is None or (viol.severity == 'high' and prev.severity != 'high'):
                        viol_map[viol.path] = viol

            matched_acc[op.key] = (op, ev_ids, has_2xx, viol_map, unres_ref, qparams, hosts)
            continue

        # Unmatched operation: apply false-positive guardrails (docs/skills/api-inventory.md §4.1).
        if method == 'OPTIONS':
            continue
        if status == 404:
            continue
        if match is not None and status == 405:
            # Declared path template properly rejected the undeclared HTTP method with 405.
            continue
        if match is None and _is_html_document_navigation(ex, server_prefixes):
            continue
        if (
            match is None
            and 200 <= status < 300
            and (
                (method == 'GET' and ex.http.response.body is not None and ex.http.response.body in contract_bodies)
                or (method == 'HEAD' and normalize_request_path(url) in valid_contract_paths)
            )
        ):
            # Live spec fetch that delivered the registered OpenAPI contract itself (#155).
            continue

        tpl = match.path_template if match is not None else collapse_path_ids(url)
        shadow_key = normalized_operation_key(method, tpl)
        _, _, prev_matched_path, s_ids, s_qp, s_hosts = shadow_acc.setdefault(
            shadow_key, (method, tpl, match is not None, [], set(), set())
        )
        if ex.id not in s_ids:
            s_ids.append(ex.id)
        s_qp.update(_query_param_names(url))
        if host := _host_of(url):
            s_hosts.add(host)
        shadow_acc[shadow_key] = (method, tpl, prev_matched_path or (match is not None), s_ids, s_qp, s_hosts)

    matched_groups = {
        op_key: _MatchedGroup(
            operation=op,
            evidence_ids=tuple(ev_ids),
            has_2xx=has_2xx,
            violations=tuple(viol_map[p] for p in sorted(viol_map)),
            unresolved_ref=unres_ref,
            observed_query_params=tuple(sorted(qparams)),
            hosts=tuple(sorted(hosts)),
        )
        for op_key, (op, ev_ids, has_2xx, viol_map, unres_ref, qparams, hosts) in matched_acc.items()
    }
    unobserved = tuple(op for op in declared_ops if op.key not in matched_groups)
    shadows = tuple(
        _ShadowGroup(
            key=k,
            method=m,
            path_template=tpl,
            matched_declared_path=matched_path,
            evidence_ids=tuple(ids),
            query_params=tuple(sorted(qp)),
            hosts=tuple(sorted(hs)),
        )
        for k, (m, tpl, matched_path, ids, qp, hs) in shadow_acc.items()
    )
    return InventoryAnalysis(
        contracts=contracts,
        valid_contracts=valid_contracts,
        invalid_contracts=invalid_contracts,
        http_exchanges=http_exchanges,
        declared_operations=declared_ops,
        matched=matched_groups,
        unobserved=unobserved,
        shadows=shadows,
        observed_without_contract=(),
    )


# ── PassiveCheck + coverage & surface hooks ──────────────────────────────────


class ApiContractConformanceCheck:
    """Passive check: OpenAPI contract conformance and normalized API surface inventory."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return any(
            isinstance(item, HttpEvidence)
            or (isinstance(item, ConfigEvidence) and item.config.format.lower() == 'openapi')
            for item in evidence
        )

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        analysis = build_operation_inventory(evidence)
        if not analysis.valid_contracts:
            return []

        primary = analysis.valid_contracts[0]
        primary_rev = _revision_label(primary.revision, primary.path)
        declared_vers = _declared_versions(analysis.declared_operations)
        drafts: list[FindingDraft] = []

        # 1. Undocumented / shadow operations (OWASP API9:2023).
        for shadow in sorted(analysis.shadows, key=lambda s: s.key):
            version_match = _VERSION_PREFIX_RE.match(shadow.path_template)
            obs_ver = version_match.group(1).lower() if version_match else None
            version_note = ''
            if obs_ver and declared_vers and obs_ver not in declared_vers:
                version_note = (
                    f' Path uses undocumented version prefix {obs_ver} while declared contract '
                    f'specifies {", ".join(sorted(declared_vers))}.'
                )
            kind_detail = (
                f'Captured traffic invokes undeclared HTTP method {shadow.method} on declared path '
                f'{shadow.path_template}'
                if shadow.matched_declared_path
                else f'Captured traffic invokes {shadow.key}, which matches no declared path template'
            )
            drafts.append(
                FindingDraft(
                    check_id=CHECK_ID,
                    check_version=CHECK_VERSION,
                    severity='medium',
                    subject=f'op:{shadow.key}',
                    title=f'Undocumented API operation: {shadow.key}',
                    description=(
                        f'{kind_detail} in OpenAPI ({primary_rev}; {len(shadow.evidence_ids)} captured '
                        f'exchange(s)).{version_note} (OWASP API9:2023 Improper Inventory Management).'
                    ),
                    evidence_ids=sorted(shadow.evidence_ids),
                    remediation=(
                        'Document authorized endpoints and methods in the OpenAPI contract and enforce '
                        'authentication/authorization controls, or retire shadow and legacy API routes '
                        'at the gateway/router.'
                    ),
                )
            )

        # 2. Disallowed / excessive response fields (OWASP API3:2023 BOPLA).
        for op_key in sorted(analysis.matched):
            group = analysis.matched[op_key]
            if not group.violations:
                continue
            op = group.operation
            rev_text = _revision_label(op.revision, op.contract_path)
            severity: Severity = max_violation_severity(group.violations)
            paths_text = ', '.join(v.path for v in group.violations)
            sensitive_paths = [v.path for v in group.violations if v.sensitive]
            sens_note = f' Sensitive property names exposed: {", ".join(sensitive_paths)}.' if sensitive_paths else ''
            drafts.append(
                FindingDraft(
                    check_id=CHECK_ID,
                    check_version=CHECK_VERSION,
                    severity=severity,
                    subject=f'op:{op.key}',
                    title=f'Disallowed response fields on {op.key}',
                    description=(
                        f'2xx JSON response(s) for {op.key} expose undeclared property path(s) beyond '
                        f'the OpenAPI schema ({rev_text}): {paths_text}.{sens_note} '
                        '(OWASP API3:2023 Broken Object Property Level Authorization).'
                    ),
                    evidence_ids=sorted(group.evidence_ids),
                    remediation=(
                        'Serialize responses through explicit output DTOs matching the declared OpenAPI '
                        'schema and strip internal, credential, or privilege fields before returning.'
                    ),
                )
            )

        return drafts

    def coverage(self, evidence: Sequence[Evidence]) -> list[CoverageEntry]:
        """Ledger entries distinguishing conformance, findings, unobserved declared ops, and insufficient evidence."""
        analysis = build_operation_inventory(evidence)
        entries: list[CoverageEntry] = []

        for invalid in analysis.invalid_contracts:
            rev_suffix = f' ({_revision_label(invalid.revision)})' if invalid.revision else ''
            entries.append(
                CoverageEntry(
                    surface=invalid.path,
                    risk_area=CHECK_ID,
                    outcome='not_applicable',
                    source='check_observed',
                    evidence_ids=[invalid.evidence_id],
                    reason=f'insufficient evidence: {invalid.load_error}{rev_suffix}',
                )
            )

        if not analysis.valid_contracts:
            if analysis.http_exchanges and not analysis.invalid_contracts:
                first = analysis.http_exchanges[0]
                entries.append(
                    CoverageEntry(
                        surface=_origin_of(first.http.request.url),
                        risk_area=CHECK_ID,
                        outcome='not_applicable',
                        source='check_observed',
                        evidence_ids=[first.id],
                        reason='insufficient evidence: no OpenAPI contract (format: openapi) in bundle',
                    )
                )
            return entries

        primary = analysis.valid_contracts[0]
        primary_rev = _revision_label(primary.revision, primary.path)

        for op in analysis.declared_operations:
            rev_text = _revision_label(op.revision, op.contract_path)
            matched = analysis.matched.get(op.key)
            if matched is None:
                reason = f'unobserved in bundle ({rev_text})' if op.revision else 'unobserved in bundle'
                entries.append(
                    CoverageEntry(
                        surface=op.key,
                        risk_area=CHECK_ID,
                        outcome='needs_follow_up',
                        source='check_observed',
                        evidence_ids=[op.contract_evidence_id],
                        reason=reason,
                    )
                )
                continue

            if matched.violations:
                entries.append(
                    CoverageEntry(
                        surface=op.key,
                        risk_area=CHECK_ID,
                        outcome='reported',
                        source='check_observed',
                        evidence_ids=sorted(matched.evidence_ids),
                        reason=f'disallowed response fields against OpenAPI ({rev_text})',
                    )
                )
            elif matched.unresolved_ref is not None:
                entries.append(
                    CoverageEntry(
                        surface=op.key,
                        risk_area=CHECK_ID,
                        outcome='not_applicable',
                        source='check_observed',
                        evidence_ids=sorted({*matched.evidence_ids, op.contract_evidence_id}),
                        reason=f'insufficient evidence: unresolvable $ref {matched.unresolved_ref} ({rev_text})',
                    )
                )
            elif not matched.has_2xx and any(r.schema is not None for r in op.responses.values()):
                entries.append(
                    CoverageEntry(
                        surface=op.key,
                        risk_area=CHECK_ID,
                        outcome='needs_follow_up',
                        source='check_observed',
                        evidence_ids=sorted(matched.evidence_ids),
                        reason=f'no 2xx response captured to verify response schema ({rev_text})',
                    )
                )
            else:
                entries.append(
                    CoverageEntry(
                        surface=op.key,
                        risk_area=CHECK_ID,
                        outcome='no_issue_found',
                        source='check_observed',
                        evidence_ids=sorted(matched.evidence_ids),
                        reason=f'conforms to OpenAPI ({rev_text})',
                    )
                )

        for shadow in sorted(analysis.shadows, key=lambda s: s.key):
            entries.append(
                CoverageEntry(
                    surface=shadow.key,
                    risk_area=CHECK_ID,
                    outcome='reported',
                    source='check_observed',
                    evidence_ids=sorted(shadow.evidence_ids),
                    reason=f'undocumented operation not in OpenAPI ({primary_rev})',
                )
            )

        return entries


api_contract_conformance_check = ApiContractConformanceCheck()
