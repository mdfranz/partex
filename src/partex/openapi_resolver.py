"""Minimal in-package OpenAPI 3.0 / 3.1 subset resolver — DEPS.md §3.1, PLAN §12.

Loads ``ConfigEvidence`` items with ``config.format == 'openapi'`` (JSON or YAML via ``pyyaml``),
resolves local ``$ref`` pointers (including OAS 3.1 ``$ref`` siblings and cycle guards) plus
``allOf`` / ``oneOf`` / ``anyOf`` compositions, matches concrete captured request paths against
declared path templates using OAS §4.8.9 specificity rules, and checks ``2xx`` JSON responses for
undeclared or sensitive fields without external dependencies, filesystem I/O, or network access.
"""

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, cast
from urllib.parse import unquote, urlsplit, urlunsplit

import yaml

from .bundle import MAX_CONTENT_BYTES
from .ids import evidence_id, normalized_operation_key, sha256_hex
from .models import ConfigEvidence, ConfigExcerpt, Severity

HTTP_METHODS = frozenset({'get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'})

MAX_OPENAPI_NODES = 25_000
MAX_SCHEMA_DEPTH = 64

_OAS_VERSION_RE = re.compile(r'^3\.(?:0|1)(?:\.\d+.*)?$')
_YAML_OPENAPI_KEY_RE = re.compile(r'(?m)^["\']?openapi["\']?\s*:')
_TEMPLATE_TOKEN_RE = re.compile(r'\{([^{}/]+)\}')
_PERCENT_PAIR_RE = re.compile(r'%([0-9A-Fa-f]{2})')
_UNRESERVED_CHARS = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~')
_SIMPLE_JSON_KEY_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]*$')
_CAMEL_BOUNDARY_RE = re.compile(r'(?<=[a-z0-9])(?=[A-Z])')
_NON_ALNUM_RE = re.compile(r'[^A-Za-z0-9]+')

# Sensitive property tokens when undeclared against an explicit DTO schema or closed object
# (skills/api-inventory/SKILL.md, reference/contract-matching.md §3).
_SENSITIVE_FIELD_TOKENS = frozenset(
    {
        'password',
        'passwd',
        'pwd',
        'secret',
        'token',
        'ssn',
        'cvv',
        'salt',
        'admin',
        'superadmin',
        'role',
        'roles',
        'permissions',
    }
)
_SENSITIVE_WHOLE_NAMES = frozenset(
    {
        'password_hash',
        'hashed_password',
        'password',
        'passwd',
        'secret',
        'api_secret',
        'client_secret',
        'totp_secret',
        'mfa_secret',
        'private_key',
        'api_key',
        'apikey',
        'access_key',
        'token',
        'access_token',
        'refresh_token',
        'session_token',
        'auth_token',
        'is_admin',
        'is_superadmin',
        'internal_role',
        'role',
        'ssn',
        'tax_id',
        'credit_card',
        'cvv',
    }
)
# High-signal credential/secret exposure flagged even when additionalProperties is omitted/open
# (docs/skills/api-inventory.md §4.2 signal 2).
_HIGH_SIGNAL_SECRET_NAMES = frozenset(
    {
        'password_hash',
        'hashed_password',
        'password',
        'passwd',
        'salt',
        'totp_secret',
        'mfa_secret',
        'private_key',
        'api_secret',
        'client_secret',
        'refresh_token',
        'session_token',
        'ssn',
        'tax_id',
        'credit_card',
        'cvv',
        'is_superadmin',
        'internal_role',
    }
)


# ── Resolved contract & schema models ────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ResolvedSchema:
    """Resolved JSON Schema / OpenAPI subset needed for response-property conformance."""

    types: frozenset[str] = frozenset()
    nullable: bool = False
    properties: Mapping[str, ResolvedSchema] = field(default_factory=dict[str, 'ResolvedSchema'])
    pattern_properties: tuple[re.Pattern[str], ...] = ()
    closed: bool = False
    allows_arbitrary_props: bool = False
    additional_prop_schema: ResolvedSchema | None = None
    items: ResolvedSchema | None = None
    any_of: tuple[ResolvedSchema, ...] = ()
    unresolved_ref: str | None = None
    cyclic: bool = False


_OPEN_SCHEMA = ResolvedSchema()


@dataclass(frozen=True, slots=True)
class ResolvedResponse:
    """Resolved response entry for one status code pattern (e.g. ``'200'``, ``'2XX'``, ``'default'``)."""

    status_key: str
    has_json_media: bool
    schema: ResolvedSchema | None = None
    unresolved_ref: str | None = None


@dataclass(frozen=True, slots=True)
class DeclaredOperation:
    """One normalized operation extracted from an OpenAPI ``ConfigEvidence`` item."""

    key: str
    method: str
    path_template: str
    contract_evidence_id: str
    contract_path: str
    revision: str | None
    deprecated: bool = False
    path_params: tuple[str, ...] = ()
    query_params: tuple[str, ...] = ()
    responses: Mapping[str, ResolvedResponse] = field(default_factory=dict[str, ResolvedResponse])
    unresolved_ref: str | None = None


@dataclass(frozen=True, slots=True)
class LoadedContract:
    """Result of loading one ``format == 'openapi'`` ``ConfigEvidence`` record."""

    evidence_id: str
    path: str
    revision: str | None
    openapi_version: str | None
    operations: tuple[DeclaredOperation, ...] = ()
    server_prefixes: tuple[str, ...] = ()
    unresolved_refs: tuple[str, ...] = ()
    load_error: str | None = None


@dataclass(frozen=True, slots=True)
class PathMatch:
    """Result of matching a concrete request against declared operations."""

    path_template: str
    operation: DeclaredOperation | None
    """Set when both path template and HTTP method match; ``None`` when only the path template matched."""


@dataclass(frozen=True, slots=True)
class FieldViolation:
    """One undeclared or sensitive response property path (never carries observed values)."""

    path: str
    severity: Literal['medium', 'high']
    sensitive: bool


@dataclass(frozen=True, slots=True)
class SchemaCheckOutcome:
    """Outcome of checking a ``2xx`` response against a declared operation's schema."""

    violations: tuple[FieldViolation, ...] = ()
    unresolved_ref: str | None = None
    evaluated: bool = True


# ── Field name sensitivity helpers ───────────────────────────────────────────


def _field_tokens(name: str) -> tuple[list[str], str]:
    parts: list[str] = []
    for chunk in _CAMEL_BOUNDARY_RE.split(name):
        parts.extend(_NON_ALNUM_RE.split(chunk))
    tokens = [part.lower() for part in parts if part]
    normalized = '_'.join(tokens)
    return tokens, normalized


def is_sensitive_field(name: str) -> bool:
    """Whether an undeclared DTO field name indicates credentials, secrets, PII, or privilege state."""
    tokens, normalized = _field_tokens(name)
    if normalized in _SENSITIVE_WHOLE_NAMES:
        return True
    if any(tok in _SENSITIVE_FIELD_TOKENS for tok in tokens):
        return True
    token_set = set(tokens)
    return (
        {'api', 'key'} <= token_set
        or {'private', 'key'} <= token_set
        or {'access', 'key'} <= token_set
        or {'tax', 'id'} <= token_set
        or {'credit', 'card'} <= token_set
    )


def is_high_signal_secret_field(name: str) -> bool:
    """High-confidence credential/PII field names flagged even on open/schemaless objects."""
    tokens, normalized = _field_tokens(name)
    if normalized in _HIGH_SIGNAL_SECRET_NAMES:
        return True
    token_set = set(tokens)
    return (
        any(tok in {'password', 'passwd', 'ssn', 'cvv', 'superadmin'} for tok in tokens)
        or ({'private', 'key'} <= token_set)
        or ({'client', 'secret'} <= token_set)
        or ({'api', 'secret'} <= token_set)
        or ({'totp', 'secret'} <= token_set)
        or ({'mfa', 'secret'} <= token_set)
    )


# ── Loading and YAML/JSON safety ─────────────────────────────────────────────


def _check_node_budget(root: Any) -> bool:
    """Return ``True`` if *root* stays within node-count and nesting caps (guards YAML alias expansion)."""
    count = 0
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        count += 1
        if count > MAX_OPENAPI_NODES or depth > MAX_SCHEMA_DEPTH:
            return False
        if isinstance(current, dict):
            mapping = cast(dict[Any, Any], current)
            for val in mapping.values():
                stack.append((val, depth + 1))
        elif isinstance(current, list):
            items = cast(list[Any], current)
            for item in items:
                stack.append((item, depth + 1))
    return True


def _parse_document(content: str) -> tuple[dict[str, Any] | None, str | None]:
    stripped = content.lstrip()
    if not stripped:
        return None, 'empty OpenAPI config excerpt'
    parsed: Any
    if stripped.startswith('{'):
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            try:
                parsed = yaml.safe_load(content)
            except yaml.YAMLError as exc:
                return None, f'invalid OpenAPI JSON/YAML: {exc}'
    else:
        try:
            parsed = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            return None, f'invalid OpenAPI YAML: {exc}'
    if not isinstance(parsed, dict):
        return None, 'OpenAPI root must be a mapping'
    if not _check_node_budget(parsed):
        return None, f'OpenAPI document exceeds complexity cap ({MAX_OPENAPI_NODES} nodes)'
    return cast(dict[str, Any], parsed), None


# ── JSON Pointer & $ref / allOf resolution ───────────────────────────────────


def _unescape_pointer_token(token: str) -> str:
    # RFC 6901 §4: decode percent-encoding in URI fragment, then '~1' -> '/', then '~0' -> '~'.
    return unquote(token).replace('~1', '/').replace('~0', '~')


def resolve_local_pointer(doc: Mapping[str, Any], ref: str) -> tuple[Any, str | None]:
    """Resolve a JSON Pointer ``#/...`` inside *doc*, or return ``(None, ref)`` when external/missing."""
    if not ref.startswith('#'):
        return None, ref
    if ref == '#':
        return doc, None
    if not ref.startswith('#/'):
        return None, ref
    current: Any = doc
    for raw_token in ref[2:].split('/'):
        token = _unescape_pointer_token(raw_token)
        if isinstance(current, Mapping) and token in current:
            current = cast(Mapping[str, Any], current)[token]
        elif isinstance(current, list):
            items = cast(list[Any], current)
            if not token.isdigit():
                return None, ref
            idx = int(token)
            if idx < 0 or idx >= len(items):
                return None, ref
            current = items[idx]
        else:
            return None, ref
    return current, None


def _deref_object(
    raw: Any, doc: Mapping[str, Any], active_refs: frozenset[str] = frozenset()
) -> tuple[dict[str, Any] | None, str | None]:
    """Dereference non-schema OpenAPI objects (PathItem, Parameter, Response) following local ``$ref``s."""
    if not isinstance(raw, dict):
        return None, None
    obj = cast(dict[str, Any], raw)
    ref = obj.get('$ref')
    if not isinstance(ref, str):
        return obj, None
    if ref in active_refs:
        return {k: v for k, v in obj.items() if k != '$ref'}, None
    target, err = resolve_local_pointer(doc, ref)
    if err is not None or not isinstance(target, dict):
        return None, err or ref
    resolved_target, inner_err = _deref_object(target, doc, active_refs | {ref})
    if inner_err is not None or resolved_target is None:
        return None, inner_err or ref
    siblings = {k: v for k, v in obj.items() if k != '$ref'}
    return {**resolved_target, **siblings}, None


def _extract_types(raw_type: Any, raw_nullable: Any) -> tuple[frozenset[str], bool]:
    types: set[str] = set()
    nullable = raw_nullable is True
    if isinstance(raw_type, str):
        if raw_type == 'null':
            nullable = True
        else:
            types.add(raw_type)
    elif isinstance(raw_type, list):
        for entry in cast(list[Any], raw_type):
            if entry == 'null':
                nullable = True
            elif isinstance(entry, str):
                types.add(entry)
    return frozenset(types), nullable


def _merge_schemas(schemas: Sequence[ResolvedSchema]) -> ResolvedSchema:
    if not schemas:
        return _OPEN_SCHEMA
    if len(schemas) == 1:
        return schemas[0]
    types: set[str] = set()
    nullable = False
    merged_props: dict[str, list[ResolvedSchema]] = {}
    pattern_props: list[re.Pattern[str]] = []
    seen_patterns: set[str] = set()
    closed = False
    allows_arbitrary = False
    addl_schemas: list[ResolvedSchema] = []
    item_schemas: list[ResolvedSchema] = []
    any_of_branches: list[ResolvedSchema] = []
    unresolved_ref: str | None = None
    cyclic = False

    for sch in schemas:
        types.update(sch.types)
        nullable = nullable or sch.nullable
        for prop_name, prop_schema in sch.properties.items():
            merged_props.setdefault(prop_name, []).append(prop_schema)
        for pat in sch.pattern_properties:
            if pat.pattern not in seen_patterns:
                seen_patterns.add(pat.pattern)
                pattern_props.append(pat)
        closed = closed or sch.closed
        allows_arbitrary = allows_arbitrary or sch.allows_arbitrary_props
        if sch.additional_prop_schema is not None:
            addl_schemas.append(sch.additional_prop_schema)
        if sch.items is not None:
            item_schemas.append(sch.items)
        if sch.any_of:
            any_of_branches.extend(sch.any_of)
        if unresolved_ref is None and sch.unresolved_ref is not None:
            unresolved_ref = sch.unresolved_ref
        cyclic = cyclic or sch.cyclic

    final_props = {name: _merge_schemas(group) for name, group in merged_props.items()}
    return ResolvedSchema(
        types=frozenset(types),
        nullable=nullable,
        properties=final_props,
        pattern_properties=tuple(pattern_props),
        closed=closed,
        allows_arbitrary_props=False if closed else allows_arbitrary,
        additional_prop_schema=None if closed or not addl_schemas else _merge_schemas(addl_schemas),
        items=_merge_schemas(item_schemas) if item_schemas else None,
        any_of=tuple(any_of_branches),
        unresolved_ref=unresolved_ref,
        cyclic=cyclic,
    )


def resolve_schema(
    raw: Any,
    doc: Mapping[str, Any],
    *,
    active_refs: frozenset[str] = frozenset(),
    depth: int = 0,
) -> ResolvedSchema:
    """Resolve an OpenAPI 3.0 / 3.1 schema (boolean or mapping) into a :class:`ResolvedSchema`."""
    if depth > MAX_SCHEMA_DEPTH:
        return ResolvedSchema(cyclic=True)
    if isinstance(raw, bool):
        return ResolvedSchema(allows_arbitrary_props=True) if raw else ResolvedSchema(closed=True)
    if not isinstance(raw, dict):
        return _OPEN_SCHEMA

    schema_dict = cast(dict[str, Any], raw)

    # 1. Handle $ref (plus OAS 3.1 sibling keywords when present).
    ref = schema_dict.get('$ref')
    if isinstance(ref, str):
        if ref in active_refs:
            return ResolvedSchema(cyclic=True)
        target, err = resolve_local_pointer(doc, ref)
        if err is not None or not isinstance(target, (dict, bool)):
            return ResolvedSchema(unresolved_ref=err or ref)
        ref_resolved = resolve_schema(target, doc, active_refs=active_refs | {ref}, depth=depth + 1)
        siblings = {k: v for k, v in schema_dict.items() if k != '$ref'}
        if not siblings:
            return ref_resolved
        sibling_resolved = resolve_schema(siblings, doc, active_refs=active_refs, depth=depth + 1)
        return _merge_schemas([ref_resolved, sibling_resolved])

    # 2. Extract direct schema facets.
    types, nullable = _extract_types(schema_dict.get('type'), schema_dict.get('nullable'))

    properties: dict[str, ResolvedSchema] = {}
    raw_props = schema_dict.get('properties')
    if isinstance(raw_props, dict):
        for key, prop_raw in cast(dict[Any, Any], raw_props).items():
            if isinstance(key, str):
                properties[key] = resolve_schema(prop_raw, doc, active_refs=active_refs, depth=depth + 1)

    pattern_props: list[re.Pattern[str]] = []
    raw_pattern_props = schema_dict.get('patternProperties')
    if isinstance(raw_pattern_props, dict):
        for pat_str in cast(dict[Any, Any], raw_pattern_props):
            if isinstance(pat_str, str):
                try:
                    pattern_props.append(re.compile(pat_str))
                except re.error:
                    continue

    addl = schema_dict.get('additionalProperties')
    uneval = schema_dict.get('unevaluatedProperties')
    closed = (addl is False) or (uneval is False)
    allows_arbitrary = False
    addl_schema: ResolvedSchema | None = None
    if not closed:
        if addl is True or uneval is True:
            allows_arbitrary = True
        elif isinstance(addl, dict):
            allows_arbitrary = True
            addl_schema = resolve_schema(addl, doc, active_refs=active_refs, depth=depth + 1)

    items_schema: ResolvedSchema | None = None
    raw_items = schema_dict.get('items')
    if isinstance(raw_items, (dict, bool)):
        items_schema = resolve_schema(raw_items, doc, active_refs=active_refs, depth=depth + 1)

    unresolved_ref: str | None = None
    for child in (*properties.values(), *(s for s in (addl_schema, items_schema) if s is not None)):
        if child.unresolved_ref is not None:
            unresolved_ref = child.unresolved_ref
            break

    base = ResolvedSchema(
        types=types,
        nullable=nullable,
        properties=properties,
        pattern_properties=tuple(pattern_props),
        closed=closed,
        allows_arbitrary_props=allows_arbitrary,
        additional_prop_schema=addl_schema,
        items=items_schema,
        unresolved_ref=unresolved_ref,
    )

    # 3. Compose allOf branches.
    parts: list[ResolvedSchema] = [base]
    raw_all_of = schema_dict.get('allOf')
    if isinstance(raw_all_of, list):
        for sub in cast(list[Any], raw_all_of):
            parts.append(resolve_schema(sub, doc, active_refs=active_refs, depth=depth + 1))
    composed = _merge_schemas(parts)

    # 4. Handle oneOf / anyOf (including OAS 3.1 nullable unions).
    union_raw: list[Any] = []
    for union_key in ('oneOf', 'anyOf'):
        candidate = schema_dict.get(union_key)
        if isinstance(candidate, list):
            union_raw.extend(cast(list[Any], candidate))
    if not union_raw:
        return composed

    non_null_branches: list[ResolvedSchema] = []
    union_nullable = composed.nullable
    union_unresolved = composed.unresolved_ref
    for branch_raw in union_raw:
        branch = resolve_schema(branch_raw, doc, active_refs=active_refs, depth=depth + 1)
        if branch.unresolved_ref is not None and union_unresolved is None:
            union_unresolved = branch.unresolved_ref
        if branch.types == frozenset({'null'}) and not branch.properties and branch.items is None:
            union_nullable = True
        else:
            if branch.nullable:
                union_nullable = True
            non_null_branches.append(branch)

    if len(non_null_branches) == 1 and not composed.properties and not composed.closed:
        single = non_null_branches[0]
        return _merge_schemas(
            [
                composed,
                ResolvedSchema(
                    types=single.types,
                    nullable=union_nullable,
                    properties=single.properties,
                    pattern_properties=single.pattern_properties,
                    closed=single.closed,
                    allows_arbitrary_props=single.allows_arbitrary_props,
                    additional_prop_schema=single.additional_prop_schema,
                    items=single.items,
                    any_of=single.any_of,
                    unresolved_ref=union_unresolved or single.unresolved_ref,
                    cyclic=single.cyclic,
                ),
            ]
        )

    return ResolvedSchema(
        types=composed.types,
        nullable=union_nullable,
        properties=composed.properties,
        pattern_properties=composed.pattern_properties,
        closed=composed.closed,
        allows_arbitrary_props=composed.allows_arbitrary_props,
        additional_prop_schema=composed.additional_prop_schema,
        items=composed.items,
        any_of=tuple(non_null_branches),
        unresolved_ref=union_unresolved,
        cyclic=composed.cyclic,
    )


# ── Server prefixes and operation extraction ─────────────────────────────────


def _server_path_prefix(server_raw: Any) -> str:
    if not isinstance(server_raw, dict):
        return ''
    srv = cast(dict[str, Any], server_raw)
    url = srv.get('url')
    if not isinstance(url, str) or not url.strip():
        return ''
    variables = srv.get('variables')
    if isinstance(variables, dict):
        var_map = cast(dict[str, Any], variables)

        def _sub_var(match: re.Match[str]) -> str:
            var_name = match.group(1)
            entry = var_map.get(var_name)
            if isinstance(entry, dict):
                default = cast(dict[str, Any], entry).get('default')
                if isinstance(default, str):
                    return default
            return match.group(0)

        url = _TEMPLATE_TOKEN_RE.sub(_sub_var, url)

    parsed_path = urlsplit(url).path
    cleaned = '/' + parsed_path.strip('/') if parsed_path.strip('/') else ''
    return cleaned


def _extract_server_prefixes(servers_raw: Any) -> tuple[str, ...]:
    if not isinstance(servers_raw, list) or not servers_raw:
        return ('',)
    prefixes = list(dict.fromkeys(_server_path_prefix(item) for item in cast(list[Any], servers_raw)))
    return tuple(prefixes) if prefixes else ('',)


def _join_prefix_and_template(prefix: str, template: str) -> str:
    norm_tpl = '/' + template.lstrip('/')
    if not prefix:
        return norm_tpl
    if norm_tpl == '/':
        return prefix
    return prefix + norm_tpl


def _extract_parameters(
    raw_params: Sequence[Any], doc: Mapping[str, Any]
) -> tuple[dict[tuple[str, str], str], list[str]]:
    params: dict[tuple[str, str], str] = {}
    unresolved: list[str] = []
    for entry in raw_params:
        param_obj, err = _deref_object(entry, doc)
        if err is not None:
            unresolved.append(err)
            continue
        if param_obj is None:
            continue
        name = param_obj.get('name')
        loc = param_obj.get('in')
        if isinstance(name, str) and name and isinstance(loc, str) and loc in {'path', 'query'}:
            params[(loc, name)] = name
    return params, unresolved


def _select_json_media(content_map: Mapping[str, Any]) -> tuple[bool, Any]:
    if 'application/json' in content_map:
        return True, content_map['application/json']
    for media_type in sorted(content_map):
        if 'json' in media_type.lower():
            return True, content_map[media_type]
    if '*/*' in content_map:
        return True, content_map['*/*']
    return False, None


def _extract_responses(raw_responses: Any, doc: Mapping[str, Any]) -> tuple[dict[str, ResolvedResponse], list[str]]:
    resolved: dict[str, ResolvedResponse] = {}
    unresolved: list[str] = []
    if not isinstance(raw_responses, dict):
        return resolved, unresolved
    for raw_code, raw_resp in cast(dict[Any, Any], raw_responses).items():
        code = str(raw_code).upper()
        if not (code == 'DEFAULT' or code == '2XX' or (len(code) == 3 and code.isdigit() and code.startswith('2'))):
            continue
        status_key = 'default' if code == 'DEFAULT' else code
        resp_obj, err = _deref_object(raw_resp, doc)
        if err is not None:
            resolved[status_key] = ResolvedResponse(status_key=status_key, has_json_media=True, unresolved_ref=err)
            unresolved.append(err)
            continue
        if resp_obj is None:
            continue
        content = resp_obj.get('content')
        if not isinstance(content, dict):
            resolved[status_key] = ResolvedResponse(status_key=status_key, has_json_media=False)
            continue
        has_json, media_obj = _select_json_media(cast(dict[str, Any], content))
        if not has_json or not isinstance(media_obj, dict):
            resolved[status_key] = ResolvedResponse(status_key=status_key, has_json_media=False)
            continue
        media_dict = cast(dict[str, Any], media_obj)
        if 'schema' not in media_dict:
            resolved[status_key] = ResolvedResponse(status_key=status_key, has_json_media=True, schema=None)
            continue
        schema = resolve_schema(media_dict['schema'], doc)
        if schema.unresolved_ref is not None:
            unresolved.append(schema.unresolved_ref)
        resolved[status_key] = ResolvedResponse(
            status_key=status_key,
            has_json_media=True,
            schema=schema,
            unresolved_ref=schema.unresolved_ref,
        )
    return resolved, unresolved


def load_openapi_contract(evidence: ConfigEvidence) -> LoadedContract:
    """Load and resolve one ``format == 'openapi'`` :class:`~partex.models.ConfigEvidence` record."""
    cfg = evidence.config
    doc, parse_err = _parse_document(cfg.content)
    if doc is None:
        return LoadedContract(
            evidence_id=evidence.id,
            path=cfg.path,
            revision=cfg.revision,
            openapi_version=None,
            load_error=parse_err,
        )

    raw_version = doc.get('openapi')
    if not isinstance(raw_version, str) or not _OAS_VERSION_RE.match(raw_version.strip()):
        swagger = doc.get('swagger')
        found = f'swagger {swagger!r}' if swagger is not None else f'openapi {raw_version!r}'
        return LoadedContract(
            evidence_id=evidence.id,
            path=cfg.path,
            revision=cfg.revision,
            openapi_version=raw_version if isinstance(raw_version, str) else None,
            load_error=f'unsupported OpenAPI specification version ({found}; expected 3.0.x or 3.1.x)',
        )

    info_version = _extract_info_version(doc)
    effective_revision = cfg.revision if cfg.revision is not None else info_version

    raw_paths = doc.get('paths')
    if not isinstance(raw_paths, dict):
        return LoadedContract(
            evidence_id=evidence.id,
            path=cfg.path,
            revision=effective_revision,
            openapi_version=raw_version.strip(),
            load_error='OpenAPI document is missing a valid paths object',
        )

    root_prefixes = _extract_server_prefixes(doc.get('servers'))
    operations_by_key: dict[str, DeclaredOperation] = {}
    all_unresolved: list[str] = []

    for raw_tpl, raw_item in sorted(cast(dict[Any, Any], raw_paths).items(), key=lambda kv: str(kv[0])):
        if not isinstance(raw_tpl, str) or not raw_tpl.startswith('/'):
            continue
        path_item, path_err = _deref_object(raw_item, doc)
        if path_err is not None:
            all_unresolved.append(path_err)
            continue
        if path_item is None:
            continue

        item_prefixes = _extract_server_prefixes(path_item['servers']) if 'servers' in path_item else root_prefixes
        raw_item_params = path_item.get('parameters')
        item_params, item_unres = _extract_parameters(
            cast(list[Any], raw_item_params) if isinstance(raw_item_params, list) else (),
            doc,
        )
        all_unresolved.extend(item_unres)

        for method_lower in sorted(HTTP_METHODS):
            raw_op = path_item.get(method_lower)
            if not isinstance(raw_op, dict):
                continue
            op_dict = cast(dict[str, Any], raw_op)
            op_prefixes = _extract_server_prefixes(op_dict['servers']) if 'servers' in op_dict else item_prefixes

            raw_op_params = op_dict.get('parameters')
            op_params, op_unres = _extract_parameters(
                cast(list[Any], raw_op_params) if isinstance(raw_op_params, list) else (),
                doc,
            )
            merged_params = {**item_params, **op_params}
            responses, resp_unres = _extract_responses(op_dict.get('responses'), doc)
            op_unresolved_list = [*item_unres, *op_unres, *resp_unres]
            all_unresolved.extend(op_unres)
            all_unresolved.extend(resp_unres)

            query_params = tuple(sorted(name for (loc, _), name in merged_params.items() if loc == 'query'))
            deprecated = bool(op_dict.get('deprecated', False))

            for prefix in op_prefixes:
                full_template = _join_prefix_and_template(prefix, raw_tpl)
                if full_template != '/' and full_template.endswith('/'):
                    full_template = full_template.rstrip('/')
                template_params = tuple(dict.fromkeys(_TEMPLATE_TOKEN_RE.findall(full_template)))
                declared_path_params = tuple(
                    dict.fromkeys(
                        [*template_params, *(name for (loc, _), name in merged_params.items() if loc == 'path')]
                    )
                )
                key = normalized_operation_key(method_lower, full_template)
                operations_by_key.setdefault(
                    key,
                    DeclaredOperation(
                        key=key,
                        method=method_lower.upper(),
                        path_template=full_template,
                        contract_evidence_id=evidence.id,
                        contract_path=cfg.path,
                        revision=effective_revision,
                        deprecated=deprecated,
                        path_params=declared_path_params,
                        query_params=query_params,
                        responses=responses,
                        unresolved_ref=op_unresolved_list[0] if op_unresolved_list else None,
                    ),
                )

    return LoadedContract(
        evidence_id=evidence.id,
        path=cfg.path,
        revision=effective_revision,
        openapi_version=raw_version.strip(),
        operations=tuple(operations_by_key.values()),
        server_prefixes=root_prefixes,
        unresolved_refs=tuple(dict.fromkeys(all_unresolved)),
    )


def _extract_info_version(doc: Mapping[str, Any]) -> str | None:
    info = doc.get('info')
    if not isinstance(info, dict):
        return None
    raw_info_ver = cast(dict[str, Any], info).get('version')
    if not isinstance(raw_info_ver, bool) and isinstance(raw_info_ver, (str, int, float)):
        version = str(raw_info_ver).strip()
        if version:
            return version
    return None


def _clean_spec_url(url: str) -> str:
    """Strip userinfo, query string, and fragment from *url* so URL secrets never enter ``source``."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.split('?', 1)[0].split('#', 1)[0]
    netloc = parts.netloc.rsplit('@', 1)[-1]
    return urlunsplit((parts.scheme, netloc, parts.path, '', ''))


def derive_openapi_config_evidence(
    content: str,
    *,
    origin_id: str,
    url: str,
) -> ConfigEvidence | None:
    """Derive a ``format='openapi'`` :class:`~partex.models.ConfigEvidence` when *content* is an OpenAPI 3.0/3.1 spec.

    Pure, deterministic, and idempotent:
    - Rejects empty strings, payloads exceeding :data:`~partex.bundle.MAX_CONTENT_BYTES`, non-OpenAPI JSON/YAML,
      Swagger ``2.0``, documents without a ``paths`` mapping, and documents exceeding :data:`MAX_OPENAPI_NODES`
      or :data:`MAX_SCHEMA_DEPTH`.
    - ``source`` records the originating ``ev_`` ID and sanitized URL (excluded from ``evidence_id``).
    - ``revision`` is ``info.version`` when non-empty, else the UTF-8 body's ``sha256`` hex digest.
    """
    if not content or 'openapi' not in content or 'paths' not in content:
        return None
    stripped = content.lstrip('\ufeff \t\r\n')
    if not stripped or stripped.startswith(('<', '[')):
        return None
    if not stripped.startswith(('{', '---')) and _YAML_OPENAPI_KEY_RE.search(content) is None:
        return None
    raw_bytes = content.encode('utf-8')
    if len(raw_bytes) > MAX_CONTENT_BYTES:
        return None
    doc, parse_err = _parse_document(content)
    if doc is None or parse_err is not None:
        return None
    raw_version = doc.get('openapi')
    if not isinstance(raw_version, str) or not _OAS_VERSION_RE.match(raw_version.strip()):
        return None
    if not isinstance(doc.get('paths'), dict):
        return None

    revision = _extract_info_version(doc) or sha256_hex(raw_bytes)
    path = normalize_request_path(url)
    clean_url = _clean_spec_url(url)
    ev = ConfigEvidence(
        id='',
        source=f'derived:{origin_id}:{clean_url}',
        config=ConfigExcerpt(
            path=path,
            format='openapi',
            content=content,
            revision=revision,
        ),
    )
    return ev.model_copy(update={'id': evidence_id(ev)})


def load_openapi_contracts(evidence: Sequence[Any]) -> list[LoadedContract]:
    """Load every ``ConfigEvidence`` in *evidence* whose ``config.format == 'openapi'``."""
    return [
        load_openapi_contract(item)
        for item in evidence
        if isinstance(item, ConfigEvidence) and item.config.format.lower() == 'openapi'
    ]


# ── Deterministic path-template specificity matching (OAS §4.8.9, PLAN §12) ──


def _decode_unreserved(segment: str) -> str:
    """Decode percent-encoded RFC 3986 unreserved bytes while preserving ``%2F`` inside segments."""

    def _replace(match: re.Match[str]) -> str:
        byte_val = int(match.group(1), 16)
        ch = chr(byte_val)
        return ch if ch in _UNRESERVED_CHARS else f'%{match.group(1).upper()}'

    return _PERCENT_PAIR_RE.sub(_replace, segment)


def normalize_request_path(url_or_path: str) -> str:
    """Extract and normalize the URL path (query/fragment stripped, unreserved chars decoded)."""
    raw_path = urlsplit(url_or_path).path or '/'
    if not raw_path.startswith('/'):
        raw_path = '/' + raw_path
    if raw_path == '/':
        return '/'
    trailing = raw_path.endswith('/')
    segments = [_decode_unreserved(seg) for seg in raw_path.strip('/').split('/')]
    rebuilt = '/' + '/'.join(segments)
    return rebuilt + '/' if trailing else rebuilt


def _split_segments(path: str) -> list[str]:
    stripped = path.strip('/')
    return [] if not stripped else stripped.split('/')


def _match_segment(template_seg: str, concrete_seg: str) -> int | None:
    """Return segment specificity score (``2`` static, ``1`` mixed, ``0`` pure param), or ``None``."""
    if '{' not in template_seg and '}' not in template_seg:
        return 2 if template_seg == concrete_seg else None
    if not concrete_seg:
        return None
    if _TEMPLATE_TOKEN_RE.fullmatch(template_seg):
        return 0
    # Mixed literal + template segment, e.g. 'v{version}' or '{id}.json'.
    regex_pieces: list[str] = ['^']
    pos = 0
    matched_any = False
    for m in _TEMPLATE_TOKEN_RE.finditer(template_seg):
        matched_any = True
        regex_pieces.append(re.escape(template_seg[pos : m.start()]))
        regex_pieces.append('[^/]+')
        pos = m.end()
    if not matched_any:
        return 2 if template_seg == concrete_seg else None
    regex_pieces.append(re.escape(template_seg[pos:]))
    regex_pieces.append('$')
    pattern = re.compile(''.join(regex_pieces))
    return 1 if pattern.fullmatch(concrete_seg) else None


def _template_score(template: str, concrete_path: str) -> tuple[int, ...] | None:
    tpl_segs = _split_segments(template)
    path_segs = _split_segments(concrete_path)
    if len(tpl_segs) != len(path_segs):
        return None
    scores: list[int] = []
    for tpl_seg, path_seg in zip(tpl_segs, path_segs, strict=True):
        seg_score = _match_segment(tpl_seg, path_seg)
        if seg_score is None:
            return None
        scores.append(seg_score)
    return tuple(scores)


def match_operation(
    operations: Sequence[DeclaredOperation],
    method: str,
    url_or_path: str,
) -> PathMatch | None:
    """Match ``(method, url_or_path)`` against *operations*, preferring static segments over parameters.

    Returns :class:`PathMatch` with ``operation`` set when both path and method match, or with
    ``operation=None`` when the path matches a declared template whose OpenAPI entry does not declare
    *method*. Returns ``None`` when no declared path template matches *url_or_path*.
    """
    norm_path = normalize_request_path(url_or_path)
    candidates_paths = [norm_path]
    if norm_path != '/' and norm_path.endswith('/'):
        candidates_paths.append(norm_path.rstrip('/'))

    by_template: dict[str, dict[str, DeclaredOperation]] = {}
    for op in operations:
        by_template.setdefault(op.path_template, {})[op.method] = op

    scored: list[tuple[tuple[int, ...], str]] = []
    for template in by_template:
        for candidate in candidates_paths:
            score = _template_score(template, candidate)
            if score is not None:
                # Negate segment scores so standard ascending sort ranks highest specificity first,
                # breaking structural ties deterministically by lexicographical template string.
                scored.append((tuple(-s for s in score), template))
                break

    if not scored:
        return None
    scored.sort()
    best_template = scored[0][1]
    upper_method = method.upper()
    matched_op = by_template[best_template].get(upper_method)
    return PathMatch(path_template=best_template, operation=matched_op)


# ── Response JSON property conformance ───────────────────────────────────────


def _join_json_path(prefix: str, key: str) -> str:
    if _SIMPLE_JSON_KEY_RE.fullmatch(key):
        return f'{prefix}.{key}'
    escaped = key.replace('\\', '\\\\').replace('"', '\\"')
    return f'{prefix}["{escaped}"]'


def _select_response_spec(op: DeclaredOperation, status_code: int) -> ResolvedResponse | None:
    exact = op.responses.get(str(status_code))
    if exact is not None:
        return exact
    if 200 <= status_code < 300 and '2XX' in op.responses:
        return op.responses['2XX']
    return op.responses.get('default')


def _collect_violations(
    value: Any,
    schema: ResolvedSchema,
    json_path: str,
    *,
    depth: int = 0,
) -> tuple[list[FieldViolation], str | None]:
    if value is None or depth > MAX_SCHEMA_DEPTH:
        return [], schema.unresolved_ref
    if schema.unresolved_ref is not None and not schema.properties and schema.items is None and not schema.any_of:
        return [], schema.unresolved_ref

    if schema.any_of and isinstance(value, dict):
        best_violations: list[FieldViolation] | None = None
        first_unresolved: str | None = schema.unresolved_ref
        for branch in schema.any_of:
            branch_v, branch_unres = _collect_violations(value, branch, json_path, depth=depth + 1)
            if branch_unres is not None and first_unresolved is None:
                first_unresolved = branch_unres
            if not branch_v and branch_unres is None:
                return [], None
            if best_violations is None or len(branch_v) < len(best_violations):
                best_violations = branch_v
        return best_violations or [], first_unresolved

    violations: list[FieldViolation] = []
    unresolved_seen = schema.unresolved_ref

    if isinstance(value, dict):
        obj = cast(dict[Any, Any], value)
        strict_keys = not schema.cyclic and (
            schema.closed or (bool(schema.properties) and not schema.allows_arbitrary_props)
        )
        for raw_key in sorted(obj, key=str):
            key = str(raw_key)
            child_val = obj[raw_key]
            child_path = _join_json_path(json_path, key)
            if key in schema.properties:
                child_v, child_unres = _collect_violations(
                    child_val, schema.properties[key], child_path, depth=depth + 1
                )
                violations.extend(child_v)
                if child_unres is not None and unresolved_seen is None:
                    unresolved_seen = child_unres
                continue
            if any(pat.search(key) for pat in schema.pattern_properties):
                continue

            if strict_keys:
                sens = is_sensitive_field(key)
                violations.append(
                    FieldViolation(path=child_path, severity='high' if sens else 'medium', sensitive=sens)
                )
                nested_v, _ = _collect_violations(child_val, _OPEN_SCHEMA, child_path, depth=depth + 1)
                violations.extend(nested_v)
            else:
                if is_high_signal_secret_field(key):
                    violations.append(FieldViolation(path=child_path, severity='high', sensitive=True))
                next_schema = (
                    schema.additional_prop_schema if schema.additional_prop_schema is not None else _OPEN_SCHEMA
                )
                nested_v, child_unres = _collect_violations(child_val, next_schema, child_path, depth=depth + 1)
                violations.extend(nested_v)
                if child_unres is not None and unresolved_seen is None:
                    unresolved_seen = child_unres

    elif isinstance(value, list):
        elem_path = f'{json_path}[*]'
        elem_schema = schema.items if schema.items is not None else _OPEN_SCHEMA
        for elem in cast(list[Any], value):
            elem_v, elem_unres = _collect_violations(elem, elem_schema, elem_path, depth=depth + 1)
            violations.extend(elem_v)
            if elem_unres is not None and unresolved_seen is None:
                unresolved_seen = elem_unres

    # Deduplicate violations by JSON path, preserving highest severity.
    by_path: dict[str, FieldViolation] = {}
    for v in violations:
        existing = by_path.get(v.path)
        if existing is None or (v.severity == 'high' and existing.severity != 'high'):
            by_path[v.path] = v
    return [by_path[p] for p in sorted(by_path)], unresolved_seen


def check_response_body(
    op: DeclaredOperation,
    status_code: int,
    body: str | None,
    content_type: str | None = None,
) -> SchemaCheckOutcome:
    """Validate a ``2xx`` response body against *op*'s declared response schema."""
    if not (200 <= status_code < 300):
        return SchemaCheckOutcome(evaluated=False)
    if op.unresolved_ref is not None and not op.responses:
        return SchemaCheckOutcome(unresolved_ref=op.unresolved_ref, evaluated=False)

    resp_spec = _select_response_spec(op, status_code)
    if resp_spec is not None and resp_spec.unresolved_ref is not None and resp_spec.schema is None:
        return SchemaCheckOutcome(unresolved_ref=resp_spec.unresolved_ref, evaluated=False)

    if body is None or not body.strip():
        return SchemaCheckOutcome(evaluated=True)

    ct_lower = (content_type or '').lower()
    if ct_lower and 'json' not in ct_lower and not body.lstrip().startswith(('{', '[')):
        return SchemaCheckOutcome(evaluated=True)

    try:
        parsed_json = json.loads(body)
    except json.JSONDecodeError:
        return SchemaCheckOutcome(evaluated=False)

    active_schema = resp_spec.schema if resp_spec is not None and resp_spec.schema is not None else _OPEN_SCHEMA
    violations, unresolved = _collect_violations(parsed_json, active_schema, '$')
    return SchemaCheckOutcome(
        violations=tuple(violations),
        unresolved_ref=unresolved,
        evaluated=unresolved is None,
    )


def max_violation_severity(violations: Sequence[FieldViolation]) -> Severity:
    return 'high' if any(v.severity == 'high' for v in violations) else 'medium'
