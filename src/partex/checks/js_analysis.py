"""js-analysis — built-in passive check for downloaded JavaScript bundles and JS responses.

Parses JavaScript offline using ``tree-sitter`` + ``tree-sitter-javascript`` (never executes JS).
Extracts API endpoints, embedded secrets/config (redacted in output), version/build metadata,
``sourceMappingURL`` comments, and risky DOM/JS sinks as low-confidence leads.
"""

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin, urlsplit, urlunsplit

import tree_sitter
import tree_sitter_javascript

from ..models import ArtifactEvidence, Evidence, FindingDraft, HttpEvidence, Scope, get_header
from ..scope import ScopeViolation, check_url

CHECK_ID = 'js-analysis'
CHECK_VERSION = '0.3'
CHECK_TITLE = 'JavaScript Bundle Analysis'
CHECK_DESCRIPTION = (
    'Analyze downloaded or captured JavaScript offline with tree-sitter for API endpoints, '
    'embedded secrets/config (redacted), version/build metadata, sourceMappingURL comments, '
    'and risky DOM/JS sinks.'
)

_JS_LANGUAGE = tree_sitter.Language(tree_sitter_javascript.language())

_API_PATH_RE = re.compile(r'^/(?:api|v\d+|graphql|auth|oauth|admin|internal)(?:/[A-Za-z0-9_./{}:-]+)?$')
_SECRET_KEY_RE = re.compile(
    r'(?:api_?key|secret|token|password|passwd|private_?key|auth_?token|client_?secret|access_?key)',
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r'^(?:sk-[A-Za-z0-9_-]{10,}|sk_live_[A-Za-z0-9]{10,}|pk_live_[A-Za-z0-9]{10,}|'
    r'ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|'
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})$'
)
_PLAIN_URL_RE = re.compile(r'^(?:https?:)?//[^\s/@]+(?:[/?#]\S*)?$', re.IGNORECASE)
"""An ``http(s)://host/...`` link with no ``user:pass@`` userinfo: a destination, not a credential (#274)."""
_PLACEHOLDERS = frozenset(
    {'<redacted>', 'changeme', 'placeholder', 'example', 'your_api_key', 'todo', 'null', 'undefined', 'test', 'dummy'}
)
_VERSION_KEY_RE = re.compile(
    r'^(?:app_?version|version|build_?version|release_?tag|commit_?sha|git_?commit|build_?id|bundle_?id)$',
    re.IGNORECASE,
)
_VERSION_VAL_RE = re.compile(r'(?:v?\d+(?:\.\d+)+|v\d+|[0-9a-f]{7,40})', re.IGNORECASE)
_SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')
_ROUTER_PATH_KEY_RE = re.compile(r'^(?:path|pathname|route|to)$', re.IGNORECASE)
"""Object keys whose string value is a router path literal (``{ path: '/account' }``)."""
_CHUNK_URL_RE = re.compile(r'\.chunk\.(?:js|mjs)$')
"""Webpack chunk outputs (``/static/js/admin.chunk.js``) — a feature/route lead in minified bundles."""
_BASE64_TOKEN_RE = re.compile(r'^[A-Za-z0-9+/=_-]{20,512}$')
_HEX40_RE = re.compile(r'^[0-9a-fA-F]{40}$')
_NON_SECRET_KEY_RE = re.compile(r'(?:integrity|hash|checksum|digest|etag|nonce|chunk)', re.IGNORECASE)
"""Keys whose long random-looking value is an integrity/cache token, not a credential (SRI, content hashes)."""
_HASH_PREFIX_RE = re.compile(r'^(?:sha(?:1|224|256|384|512)|md5)-', re.IGNORECASE)
"""Subresource-integrity style values (``sha384-<base64>``): high entropy by construction, never secrets."""
_VENDOR_SOURCE_RE = re.compile(
    r'(?:^|[/\\])node_modules[/\\]|(?:^|[/\\:])webpack[/\\](?:bootstrap|runtime)\b|^external\b', re.IGNORECASE
)
"""Third-party and bundler-runtime entries in a source map's ``sources`` (not the application's own code)."""
_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]+')
MAX_SOURCE_NAME_CHARS = 120
"""A source-map ``sources`` entry is target-controlled text; it is cleaned and capped before it reaches a finding."""
_HIGH_ENTROPY_MIN_BITS = 4.5
"""Shannon entropy (bits/char) floor for an identifier-independent secret-shaped token (truffleHog/gitleaks
model: random base64 clears it, random hex (~4.0) does not, so commit/build hashes stay out)."""

_HTTP_METHODS = frozenset({'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'})
_HTTP_CALL_CALLEES = frozenset({'fetch', 'axios'})
MAX_LISTED = 20
"""Occurrences, lines or endpoints listed in one finding; the rest are counted."""
_AXIOS_METHODS = frozenset({'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request'})


@dataclass(frozen=True, slots=True)
class JsAnalysisResult:
    """Structured findings extracted from one JavaScript source by tree-sitter."""

    endpoints: tuple[str, ...]
    secrets: tuple[tuple[str, int], ...]  # (key_or_kind, 1-based line) — values are never stored
    versions: tuple[tuple[str, str, int], ...]  # (key, value, line)
    sourcemaps: tuple[tuple[str, int], ...]  # (url, line)
    sinks: tuple[tuple[str, int], ...]  # (sink_name, line)
    import_urls: tuple[str, ...]
    has_syntax_errors: bool
    secret_values: tuple[tuple[str, int, str], ...] = field(default=(), repr=False)
    """(key_or_kind, line, value) for the operator-only ``/secrets`` export. Never put these in a finding,
    a log or a model-visible result."""


@dataclass(frozen=True, slots=True)
class JsDiscovery:
    """Discovered script/chunk URLs partitioned by engagement scope (never auto-fetched)."""

    in_scope: tuple[str, ...]
    out_of_scope: tuple[str, ...]


class _ScriptTagParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != 'script':
            return
        for name, value in attrs:
            if name.lower() == 'src' and value and value.strip():
                self.srcs.append(value.strip())


def _is_js_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    lower = content_type.lower()
    return 'javascript' in lower or 'ecmascript' in lower


def _is_js_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(('.js', '.mjs', '.cjs'))


def _is_html_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    lower = content_type.lower()
    return 'text/html' in lower or 'application/xhtml+xml' in lower


def _is_js_evidence(item: Evidence) -> bool:
    """A successful, non-HTML response that is JavaScript by content type or URL (a ``/x.js`` 404 page is not)."""
    if isinstance(item, ArtifactEvidence):
        asset = item.artifact
        if _is_html_content_type(asset.content_type) or not 200 <= asset.status_code < 300:
            return False
        return _is_js_content_type(asset.content_type) or _is_js_url(asset.url)
    if isinstance(item, HttpEvidence):
        response = item.http.response
        if response.body is None or not 200 <= response.status_code < 300:
            return False
        ct = get_header(response.headers, 'content-type')
        if _is_html_content_type(ct):
            return False
        return _is_js_content_type(ct) or _is_js_url(item.http.request.url)
    return False


def _is_sourcemap_evidence(item: Evidence) -> bool:
    """A successfully downloaded artifact whose URL references a source map (``*.map``)."""
    if not isinstance(item, ArtifactEvidence):
        return False
    asset = item.artifact
    return 200 <= asset.status_code < 300 and urlsplit(asset.url).path.lower().endswith('.map')


def _clean_endpoint(url: str) -> str:
    """An endpoint without userinfo, query string or fragment, so no credential in a URL reaches a finding."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.split('?', 1)[0].split('#', 1)[0]
    netloc = parts.netloc.rsplit('@', 1)[-1]
    return urlunsplit((parts.scheme, netloc, parts.path, '', ''))


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _same_identifier(key: str, value: str) -> bool:
    """Whether *value* is just *key* spelled again (``write_api_key: 'write_api_key'``), ignoring case and ``_``/``-``."""
    return key.lower().replace('-', '_') == value.lower().replace('-', '_')


def _looks_like_secret(value: str, key: str | None = None) -> bool:
    """Value-shape check for a secret-named key: one token (no spaces), long enough, and not a plain word.

    UI strings (``'Enter your password'``), enum words (``'Bearer'``), short labels, plain links to docs or
    settings pages, and a key's own name used as its value (an identity map of scope labels) do not qualify (#274).
    """
    value = value.strip()
    if not 8 <= len(value) <= 512 or any(ch.isspace() for ch in value) or value.lower() in _PLACEHOLDERS:
        return False
    if _PLAIN_URL_RE.match(value) or (key is not None and _same_identifier(key, value)):
        return False
    has_digit = any(ch.isdigit() for ch in value)
    has_alpha = any(ch.isalpha() for ch in value)
    return (has_digit and has_alpha) or (len(value) >= 16 and _entropy(value) >= 3.5)


def _high_entropy_token(value: str) -> bool:
    """A long, high-entropy token in the base64/url-safe alphabet regardless of its identifier name.

    Catches ``const innocuous = 'q8Kd…'`` that name-based matching misses, while short noise, words, and
    40-char hex (a git commit SHA) stay out (#193)."""
    value = value.strip()
    if value.lower() in _PLACEHOLDERS or not _BASE64_TOKEN_RE.fullmatch(value):
        return False
    if not any(ch.isdigit() for ch in value) or not any(ch.isalpha() for ch in value):
        return False
    if _HEX40_RE.fullmatch(value) or _HASH_PREFIX_RE.match(value):
        return False
    return _entropy(value) >= _HIGH_ENTROPY_MIN_BITS


def _node_text(node: tree_sitter.Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode('utf-8', errors='replace')


def _unquote_string(node: tree_sitter.Node, source: bytes) -> str | None:
    if node.type == 'string':
        raw = _node_text(node, source)
        return raw[1:-1] if len(raw) >= 2 else ''
    if node.type == 'template_string' and not any(c.type == 'template_substitution' for c in node.children):
        raw = _node_text(node, source)
        return raw[1:-1] if len(raw) >= 2 else ''
    return None


def _key_name(node: tree_sitter.Node, source: bytes) -> str | None:
    if node.type in {'identifier', 'property_identifier'}:
        return _node_text(node, source)
    if node.type == 'member_expression':
        prop = node.child_by_field_name('property')
        return _node_text(prop, source) if prop is not None else None
    return _unquote_string(node, source)


def _callee_parts(node: tree_sitter.Node, source: bytes) -> tuple[str | None, str | None]:
    if node.type == 'identifier':
        return _node_text(node, source), None
    if node.type == 'member_expression':
        obj = node.child_by_field_name('object')
        prop = node.child_by_field_name('property')
        return (
            _node_text(obj, source) if obj is not None else None,
            _node_text(prop, source) if prop is not None else None,
        )
    if node.type == 'import':
        return 'import', None
    return None, None


def _walk_nodes(root: tree_sitter.Node) -> list[tree_sitter.Node]:
    stack = [root]
    nodes: list[tree_sitter.Node] = []
    while stack:
        current = stack.pop()
        nodes.append(current)
        stack.extend(reversed(current.children))
    return nodes


@lru_cache(maxsize=16)
def _analyze_cached(digest: str, source: bytes) -> JsAnalysisResult:
    return _analyze(source)


def analyze_js_bytes(source: bytes) -> JsAnalysisResult:
    """Parse *source* with tree-sitter and extract deterministic, redacted analysis results (cached by content)."""
    return _analyze_cached(hashlib.sha256(source).hexdigest(), source)


def _analyze(source: bytes) -> JsAnalysisResult:
    parser = tree_sitter.Parser(_JS_LANGUAGE)
    tree = parser.parse(source)

    endpoints: set[str] = set()
    secrets: list[tuple[str, int]] = []
    seen_secrets: set[tuple[str, int]] = set()
    secret_values: list[tuple[str, int, str]] = []
    versions: list[tuple[str, str, int]] = []
    sourcemaps: list[tuple[str, int]] = []
    sinks: list[tuple[str, int]] = []
    import_urls: list[str] = []

    def add_secret(kind: str, line: int, value: str) -> None:
        entry = (kind, line)
        if entry not in seen_secrets:
            seen_secrets.add(entry)
            secret_values.append((kind, line, value))
            secrets.append(entry)

    def check_key_value(key: str | None, value_node: tree_sitter.Node | None, line: int) -> None:
        if key is None or value_node is None:
            return
        val = _unquote_string(value_node, source)
        if val is None or not val.strip():
            return
        if _VERSION_KEY_RE.fullmatch(key) and _VERSION_VAL_RE.fullmatch(val.strip()):
            versions.append((key, val, line))
        # Secret detection is layered: a secret-named key first, then identifier-independent high entropy (something
        # innocuous-looking assigned a long random token). Known token structure (``ghp_``, ``AKIA``, ``eyJ``) is
        # reported once, as ``token-literal``, by the string visitor below, so it is not repeated here.
        stripped = val.strip()
        kind: str | None = None
        if _SECRET_KEY_RE.search(key) and _looks_like_secret(val, key):
            kind = key
        elif (
            not _NON_SECRET_KEY_RE.search(key)
            and not _SECRET_VALUE_RE.match(stripped)
            and _high_entropy_token(stripped)
        ):
            kind = 'high-entropy-value'
        if kind is not None:
            add_secret(kind, line, val)

    for node in _walk_nodes(tree.root_node):
        line = node.start_point.row + 1
        ntype = node.type

        if ntype == 'comment':
            text = _node_text(node, source)
            if match := _SOURCEMAP_RE.search(text):
                map_url = match.group(1)
                sourcemaps.append((map_url, line))
                if not map_url.startswith('data:'):
                    import_urls.append(map_url)

        elif ntype == 'import_statement':
            src = node.child_by_field_name('source')
            if src is not None and (url := _unquote_string(src, source)):
                import_urls.append(url)

        elif ntype == 'call_expression':
            fn = node.child_by_field_name('function')
            args_node = node.child_by_field_name('arguments')
            if fn is None or args_node is None:
                continue
            args = [c for c in args_node.named_children]
            obj, prop = _callee_parts(fn, source)
            if args and ((obj in _HTTP_CALL_CALLEES and prop is None) or (obj == 'axios' and prop in _AXIOS_METHODS)):
                if url := _unquote_string(args[0], source):
                    endpoints.add(_clean_endpoint(url))
            elif (
                prop == 'open' and len(args) >= 2 and (_unquote_string(args[0], source) or '').upper() in _HTTP_METHODS
            ):
                if url := _unquote_string(args[1], source):  # XMLHttpRequest.open(method, url); not window.open
                    endpoints.add(_clean_endpoint(url))
            elif obj in {'import', 'importScripts'} and prop is None and args:
                if url := _unquote_string(args[0], source):
                    import_urls.append(url)
            elif obj == 'eval' and prop is None:
                sinks.append(('eval', line))
            elif obj == 'document' and prop == 'write':
                sinks.append(('document.write', line))
            elif prop == 'postMessage':
                sinks.append(('postMessage', line))

        elif ntype == 'pair':
            key_node = node.child_by_field_name('key')
            key = _key_name(key_node or node, source)
            check_key_value(key, node.child_by_field_name('value'), line)
            value_node = node.child_by_field_name('value')
            # Router path literals (React/Vue route tables) are endpoints the /api/ regex misses.
            if (
                key
                and value_node is not None
                and (val := _unquote_string(value_node, source))
                and _ROUTER_PATH_KEY_RE.fullmatch(key)
                and val.startswith('/')
            ):
                endpoints.add(_clean_endpoint(val))

        elif ntype == 'variable_declarator':
            check_key_value(
                _key_name(node.child_by_field_name('name') or node, source), node.child_by_field_name('value'), line
            )

        elif ntype == 'assignment_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            if left is not None and left.type == 'member_expression':
                prop = left.child_by_field_name('property')
                if prop is not None and _node_text(prop, source) in {'innerHTML', 'outerHTML'}:
                    sinks.append((_node_text(prop, source), line))
            if left is not None:
                check_key_value(_key_name(left, source), right, line)

        elif ntype in {'string', 'template_string'} and (val := _unquote_string(node, source)):
            if _API_PATH_RE.match(val) or _CHUNK_URL_RE.search(val):
                endpoints.add(_clean_endpoint(val))
            if _SECRET_VALUE_RE.match(val):
                add_secret('token-literal', line, val)

    return JsAnalysisResult(
        endpoints=tuple(sorted(endpoints)),
        secrets=tuple(sorted(secrets)),
        versions=tuple(sorted(versions)),
        sourcemaps=tuple(sorted(sourcemaps)),
        sinks=tuple(sorted(sinks)),
        import_urls=tuple(dict.fromkeys(import_urls)),
        has_syntax_errors=tree.root_node.has_error,
        secret_values=tuple(sorted(secret_values)),
    )


def _read_artifact(item: ArtifactEvidence) -> tuple[bytes | None, str | None]:
    """Read a stored artifact only if it is the content-addressed file ``partex`` wrote for it.

    ``file_path`` is not part of the evidence ID, so imported or edited evidence could name any local file.
    The file must sit in an ``*.artifacts`` directory (directly, or in a ``<run_id>`` subdirectory of it),
    be named by the declared sha256, and hash to it.
    """
    if item.file_path is None:
        return None, 'artifact has no local file_path'
    path = Path(item.file_path)
    digest = item.artifact.sha256
    in_artifacts = path.parent.name.endswith('.artifacts') or (
        path.parent.parent.name.endswith('.artifacts') and path.parent.name.startswith('run_')
    )
    if path.name != digest or not in_artifacts:
        return None, 'artifact file_path is not a partex artifact file'
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, f'cannot read artifact file: {exc}'
    if hashlib.sha256(data).hexdigest() != digest:
        return None, 'artifact file does not match its recorded sha256'
    return data, None


def _read_js_source(item: Evidence) -> tuple[bytes | None, str, bool, str | None]:
    """Return ``(bytes_or_None, url, truncated, read_error)`` for a JS evidence item."""
    if isinstance(item, ArtifactEvidence):
        data, error = _read_artifact(item)
        return data, item.artifact.url, False, error
    assert isinstance(item, HttpEvidence)
    body = item.http.response.body
    assert body is not None
    return body.encode('utf-8'), item.http.request.url, item.http.response.body_note == 'truncated', None


def iter_js_sources(evidence: Sequence[Evidence]) -> Iterator[tuple[str, str, bytes]]:
    """Yield ``(evidence_id, url, source_bytes)`` for each readable JavaScript evidence item."""
    for item in evidence:
        if not _is_js_evidence(item):
            continue
        data, url, _, _ = _read_js_source(item)
        if data is not None:
            yield item.id, url, data


@dataclass(frozen=True, slots=True)
class SourcemapInfo:
    """Metadata parsed from a source-map v3 document.  ``sources`` are *filenames* (paths), never contents."""

    sources: tuple[str, ...]
    has_content: bool
    """Whether original *first-party* source bodies are present (third-party ``node_modules`` bodies do not count)."""
    vendor_count: int = 0
    error: str | None = None


def _safe_name(name: str) -> str:
    """A ``sources`` entry for a finding: control characters and newlines removed, length capped (target-controlled)."""
    cleaned = _CONTROL_RE.sub(' ', name).strip()
    if len(cleaned) > MAX_SOURCE_NAME_CHARS:
        return cleaned[: MAX_SOURCE_NAME_CHARS - 1] + '…'
    return cleaned


def _without_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))


def _load_sourcemap(data: bytes) -> dict[str, Any] | None:
    """The source-map JSON object, or ``None`` when *data* is not one.  Parsed once and shared by the readers below."""
    try:
        raw = json.loads(data.decode('utf-8', 'replace'))
    except json.JSONDecodeError:
        return None
    return cast(dict[str, Any], raw) if isinstance(raw, dict) else None


def _parse_sourcemap(record: dict[str, Any] | None) -> SourcemapInfo:
    """Describe a loaded source-map v3 document.  ``sourcesContent`` is only *counted*, never copied out here."""
    if record is None:
        return SourcemapInfo((), False, error='not a JSON object')
    sources = record.get('sources')
    if not isinstance(sources, list):
        return SourcemapInfo((), False, error='no `sources` list (not a v3 source map)')
    source_items = cast(list[Any], sources)
    if not all(isinstance(item, str) for item in source_items):
        return SourcemapInfo((), False, error='no `sources` string list (not a v3 source map)')
    names = [cast(str, item) for item in source_items]
    content = record.get('sourcesContent')
    has_content = False
    if isinstance(content, list):
        bodies = cast(list[Any], content)
        has_content = any(
            isinstance(body, str) and bool(body) and index < len(names) and not _VENDOR_SOURCE_RE.search(names[index])
            for index, body in enumerate(bodies)
        )
    vendor = sum(1 for name in names if _VENDOR_SOURCE_RE.search(name))
    return SourcemapInfo(tuple(names), has_content, vendor_count=vendor)


def _sourcemap_sources(record: dict[str, Any] | None) -> list[tuple[str, bytes]]:
    """``(source_name, source_bytes)`` for each present first-party ``sourcesContent`` entry.

    Third-party (``node_modules``) and bundler-runtime entries are skipped: their sinks and tokens are the library's,
    not the application's, and analyzing them buries the first-party results.
    """
    if record is None:
        return []
    sources = record.get('sources')
    content = record.get('sourcesContent')
    if not isinstance(sources, list) or not isinstance(content, list):
        return []
    source_names = cast(list[Any], sources)
    bodies = cast(list[Any], content)
    pairs: list[tuple[str, bytes]] = []
    for index, body in enumerate(bodies):
        if not (isinstance(body, str) and body and index < len(source_names)):
            continue
        name = source_names[index]
        if isinstance(name, str) and not _VENDOR_SOURCE_RE.search(name):
            pairs.append((name, body.encode('utf-8')))
    return pairs


def _sourcemap_findings(
    item: ArtifactEvidence, info: SourcemapInfo, sources: list[tuple[str, bytes]]
) -> list[FindingDraft]:
    """Findings for a parsed source map: the upgraded sourcemap finding plus the existing js-analysis classes
    run over ``sourcesContent``.  Source *filenames* may appear; source bodies and secret values never do."""
    url = item.artifact.url
    drafts: list[FindingDraft] = []
    listed = ', '.join(_safe_name(name) for name in info.sources[:MAX_LISTED])
    more = f' (+{len(info.sources) - MAX_LISTED} more)' if len(info.sources) > MAX_LISTED else ''
    disclosure = (
        'original source bodies are present (sourcesContent)'
        if info.has_content
        else 'only original source filenames are present (sourcesContent absent)'
    )
    if info.vendor_count:
        disclosure += f'; {info.vendor_count} third-party/runtime source(s) were not analyzed'
    drafts.append(
        FindingDraft(
            check_id=CHECK_ID,
            check_version=CHECK_VERSION,
            severity='medium' if info.has_content else 'low',
            subject='js:sourcemap-parsed',
            title='Original source recovered from exposed source map',
            description=(
                f'{url} was downloaded and parsed as a source map: {len(info.sources)} original source(s) '
                f'disclosed ({disclosure}): {listed}{more}'
            ),
            evidence_ids=[item.id],
            remediation='Serve source maps only outside production, or restrict them so original source is not public.',
        )
    )

    analyzed = [(name, analyze_js_bytes(body)) for name, body in sources]

    endpoints = sorted({ep for _, result in analyzed for ep in result.endpoints})
    if endpoints:
        endpoint_list = ', '.join(endpoints[:MAX_LISTED])
        endpoint_more = f' (+{len(endpoints) - MAX_LISTED} more)' if len(endpoints) > MAX_LISTED else ''
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='info',
                subject='js:endpoints',
                title='JavaScript API endpoints discovered in a source map',
                description=(
                    f'{url} original sources reference {len(endpoints)} endpoint(s): {endpoint_list}{endpoint_more}.'
                ),
                evidence_ids=[item.id],
                remediation='Verify discovered endpoints are documented and enforce server-side authorization.',
            )
        )

    secret_sources: dict[str, list[str]] = {}
    for name, result in analyzed:
        for kind, _line in result.secrets:
            secret_sources.setdefault(kind, []).append(name)
    for kind, names in sorted(secret_sources.items()):
        shown = ', '.join(_safe_name(name) for name in list(dict.fromkeys(names))[:MAX_LISTED])
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='medium',
                subject=f'js:secret:{kind}',
                title='Potential secret or credential embedded in original source',
                description=(
                    f'{url} original source assigns a secret-shaped value (<redacted>) to {kind!r} in '
                    f'{len(names)} location(s) across {len(set(names))} source(s): {shown}.'
                ),
                evidence_ids=[item.id],
                remediation='Remove credentials/API keys from client-side JavaScript and rotate any exposed secrets.',
            )
        )

    version_keys: set[str] = {key for _, result in analyzed for key, _, _ in result.versions}
    if version_keys:
        keys = ', '.join(sorted(version_keys))
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='info',
                subject='js:version-disclosure',
                title='Application version or build metadata in original source',
                description=f'{url} original sources disclose build/version metadata under: {keys}.',
                evidence_ids=[item.id],
                remediation='Avoid shipping internal commit SHAs or build identifiers in public client bundles if not intended.',
            )
        )

    sink_sources: dict[str, set[str]] = {}
    for name, result in analyzed:
        for sink, _line in result.sinks:
            sink_sources.setdefault(sink, set()).add(name)
    for sink, names in sorted(sink_sources.items()):
        shown = ', '.join(_safe_name(name) for name in sorted(names)[:MAX_LISTED])
        drafts.append(
            FindingDraft(
                check_id=CHECK_ID,
                check_version=CHECK_VERSION,
                severity='low',
                subject=f'js:sink:{sink}',
                title=f'Risky DOM/JS sink ({sink}) in original source',
                description=(
                    f'{url} original sources use {sink} in {len(names)} source(s): {shown} '
                    '(low-confidence lead; verify reachability).'
                ),
                evidence_ids=[item.id],
                remediation='Ensure untrusted input is sanitized or avoided before reaching DOM/JS execution sinks.',
            )
        )

    return drafts


def discover_js_urls(evidence: Sequence[Evidence], scope: Scope | None = None) -> JsDiscovery:
    """Collect ``<script src>`` and JS import/sourcemap URLs from captured evidence (never fetches)."""
    discovered: list[str] = []
    for item in evidence:
        if isinstance(item, HttpEvidence) and item.http.response.body is not None:
            ct = get_header(item.http.response.headers, 'content-type')
            if _is_html_content_type(ct):
                parser = _ScriptTagParser()
                parser.feed(item.http.response.body)
                for src in parser.srcs:
                    discovered.append(urljoin(item.http.request.url, src))
        if _is_js_evidence(item):
            data, base_url, _, _ = _read_js_source(item)
            if data is not None:
                parsed = analyze_js_bytes(data)
                for ref in parsed.import_urls:
                    discovered.append(urljoin(base_url, ref))

    deduped = list(dict.fromkeys(discovered))
    if scope is None:
        return JsDiscovery(in_scope=tuple(deduped), out_of_scope=())
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    for url in deduped:
        try:
            check_url(scope, url)
        except ScopeViolation:
            out_of_scope.append(url)
        else:
            in_scope.append(url)
    return JsDiscovery(in_scope=tuple(in_scope), out_of_scope=tuple(out_of_scope))


def extract_js_surface(evidence: Sequence[Evidence]) -> list[dict[str, Any]]:
    """Return deterministic endpoint surface rows extracted from JS evidence."""
    by_endpoint: dict[str, set[str]] = {}
    for item in evidence:
        if not _is_js_evidence(item):
            continue
        data, _, _, _ = _read_js_source(item)
        if data is None:
            continue
        for ep in analyze_js_bytes(data).endpoints:
            by_endpoint.setdefault(ep, set()).add(item.id)
    return [{'kind': 'endpoint', 'key': ep, 'evidence_ids': sorted(ids)} for ep, ids in sorted(by_endpoint.items())]


def _lines(lines: list[int]) -> str:
    shown = ', '.join(f'line {n}' for n in sorted(set(lines))[:MAX_LISTED])
    extra = len(set(lines)) - MAX_LISTED
    return shown + (f' (+{extra} more)' if extra > 0 else '')


class JsAnalysisCheck:
    """Passive check: deterministic tree-sitter analysis of JavaScript artifacts and responses."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return any(_is_js_evidence(item) or _is_sourcemap_evidence(item) for item in evidence)

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        drafts: list[FindingDraft] = []
        # Parse captured source maps first, so a bundle whose map was downloaded-and-parsed gets the upgraded
        # ``js:sourcemap-parsed`` finding instead of the bare ``js:sourcemap`` low finding (#193).
        parsed_maps: dict[str, tuple[ArtifactEvidence, SourcemapInfo, list[tuple[str, bytes]]]] = {}
        parsed_map_urls: set[str] = set()
        for item in evidence:
            if not _is_sourcemap_evidence(item):
                continue
            map_item = cast(ArtifactEvidence, item)
            data, _, _, _ = _read_js_source(map_item)
            if data is None:
                continue  # unreadable map artifact → the bundle keeps today's low finding
            record = _load_sourcemap(data)
            info = _parse_sourcemap(record)
            if info.error is None:
                parsed_maps[map_item.id] = (map_item, info, _sourcemap_sources(record))
                parsed_map_urls.add(_without_query(map_item.artifact.url))

        for item in evidence:
            if not _is_js_evidence(item):
                continue
            data, url, truncated, read_error = _read_js_source(item)
            if data is None:
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='info',
                        subject='js:parse-status',
                        title='JavaScript artifact unreadable (analysis skipped)',
                        description=f'Could not read JavaScript asset {url} ({read_error}).',
                        evidence_ids=[item.id],
                        remediation='Re-download the asset through download_asset so the full body is available locally.',
                    )
                )
                continue

            result = analyze_js_bytes(data)

            if truncated or result.has_syntax_errors:
                reasons: list[str] = []
                if truncated:
                    reasons.append('captured body was truncated at the inline cap')
                if result.has_syntax_errors:
                    reasons.append('tree-sitter reported syntax errors')
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='info',
                        subject='js:parse-status',
                        title='JavaScript analysis partial (truncated or syntax errors)',
                        description=(
                            f'Analysis of {url} is partial because {" and ".join(reasons)}. '
                            'Results below reflect only the recovered AST.'
                        ),
                        evidence_ids=[item.id],
                        remediation='Download the full JavaScript asset with download_asset for complete analysis.',
                    )
                )

            if result.endpoints:
                listed = ', '.join(result.endpoints[:20])
                more = f' (+{len(result.endpoints) - 20} more)' if len(result.endpoints) > 20 else ''
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='info',
                        subject='js:endpoints',
                        title='JavaScript API endpoints discovered',
                        description=f'{url} references {len(result.endpoints)} endpoint(s): {listed}{more}.',
                        evidence_ids=[item.id],
                        remediation='Verify discovered endpoints are documented and enforce server-side authorization.',
                    )
                )

            secret_lines: dict[str, list[int]] = {}
            for key_or_kind, line in result.secrets:
                secret_lines.setdefault(key_or_kind, []).append(line)
            for key_or_kind, lines in sorted(secret_lines.items()):  # one finding per key, however many hits
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='medium',
                        subject=f'js:secret:{key_or_kind}',
                        title='Potential secret or credential embedded in JavaScript',
                        description=(
                            f'{url} assigns a secret-shaped value (<redacted>) to {key_or_kind!r} '
                            f'at {_lines(lines)}. Client-side bundles are public to all users.'
                        ),
                        evidence_ids=[item.id],
                        remediation='Remove credentials/API keys from client-side JavaScript and rotate any exposed secrets.',
                    )
                )

            if result.versions:
                formatted = ', '.join(f'{k}={v!r} (line {ln})' for k, v, ln in result.versions)
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='info',
                        subject='js:version-disclosure',
                        title='Application version or build metadata in JavaScript',
                        description=f'{url} discloses build/version metadata: {formatted}.',
                        evidence_ids=[item.id],
                        remediation='Avoid shipping internal commit SHAs or build identifiers in public client bundles if not intended.',
                    )
                )

            if result.sourcemaps:
                # A referenced map that is already captured and parsed is superseded by js:sourcemap-parsed.
                unparsed = [
                    (m, ln)
                    for m, ln in result.sourcemaps
                    if m.startswith('data:') or _without_query(urljoin(url, m)) not in parsed_map_urls
                ]
                if unparsed:
                    external = [(m, ln) for m, ln in unparsed if not m.startswith('data:')]
                    inline = [ln for m, ln in unparsed if m.startswith('data:')]
                    parts: list[str] = []
                    if external:
                        maps = ', '.join(f'{m} (line {ln})' for m, ln in external)
                        parts.append(
                            f'declares sourceMappingURL: {maps}. No matching source map artifact was captured, so '
                            'the referenced map was not fetched or parsed (out of scope, missing, or 404).'
                        )
                    if inline:  # the data: URI itself can be megabytes; never put it in a finding
                        lines = ', '.join(str(ln) for ln in inline)
                        parts.append(
                            f'embeds an inline (data:) source map at line {lines}; inline maps are not parsed by '
                            'this check, so the original source it carries was not analyzed.'
                        )
                    drafts.append(
                        FindingDraft(
                            check_id=CHECK_ID,
                            check_version=CHECK_VERSION,
                            severity='low',
                            subject='js:sourcemap',
                            title='JavaScript sourceMappingURL exposed',
                            description=f'{url} {" ".join(parts)}',
                            evidence_ids=[item.id],
                            remediation='Restrict or omit source map references in production builds if original source should not be public.',
                        )
                    )

            sink_lines: dict[str, list[int]] = {}
            for sink_name, line in result.sinks:
                sink_lines.setdefault(sink_name, []).append(line)
            for sink_name, lines in sorted(sink_lines.items()):  # one finding per sink kind, however many hits
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='low',
                        subject=f'js:sink:{sink_name}',
                        title=f'Risky DOM/JS sink ({sink_name}) in JavaScript',
                        description=(
                            f'{url} uses {sink_name} {len(lines)} time(s), at {_lines(lines)} (low-confidence lead; '
                            'verify whether attacker-controlled input can reach this sink).'
                        ),
                        evidence_ids=[item.id],
                        remediation='Ensure untrusted input is sanitized or avoided before reaching DOM/JS execution sinks.',
                    )
                )

        for map_item, info, sources in parsed_maps.values():
            drafts.extend(_sourcemap_findings(map_item, info, sources))

        return drafts


js_analysis_check = JsAnalysisCheck()
