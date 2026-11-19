"""js-analysis — built-in passive check for downloaded JavaScript bundles and JS responses.

Parses JavaScript offline using ``tree-sitter`` + ``tree-sitter-javascript`` (never executes JS).
Extracts API endpoints, embedded secrets/config (redacted in output), version/build metadata,
``sourceMappingURL`` comments, and risky DOM/JS sinks as low-confidence leads.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import tree_sitter
import tree_sitter_javascript

from ..models import ArtifactEvidence, Evidence, FindingDraft, HttpEvidence, Scope, get_header
from ..scope import ScopeViolation, check_url

CHECK_ID = 'js-analysis'
CHECK_VERSION = '0.1'
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
_PLACEHOLDERS = frozenset(
    {'<redacted>', 'changeme', 'placeholder', 'example', 'your_api_key', 'todo', 'null', 'undefined', 'test', 'dummy'}
)
_VERSION_KEY_RE = re.compile(
    r'^(?:app_?version|version|build_?version|release_?tag|commit_?sha|git_?commit|build_?id|bundle_?id)$',
    re.IGNORECASE,
)
_VERSION_VAL_RE = re.compile(r'(?:\d+(?:\.\d+)+|v\d+|[0-9a-f]{7,40})', re.IGNORECASE)
_SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')

_HTTP_CALL_CALLEES = frozenset({'fetch', 'axios'})
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
    if isinstance(item, ArtifactEvidence):
        return _is_js_content_type(item.artifact.content_type) or _is_js_url(item.artifact.url)
    if isinstance(item, HttpEvidence):
        if item.http.response.body is None:
            return False
        ct = get_header(item.http.response.headers, 'content-type')
        return _is_js_content_type(ct) or _is_js_url(item.http.request.url)
    return False


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


def analyze_js_bytes(source: bytes) -> JsAnalysisResult:
    """Parse *source* with tree-sitter and extract deterministic, redacted analysis results."""
    parser = tree_sitter.Parser(_JS_LANGUAGE)
    tree = parser.parse(source)

    endpoints: set[str] = set()
    secrets: list[tuple[str, int]] = []
    seen_secrets: set[tuple[str, int]] = set()
    versions: list[tuple[str, str, int]] = []
    sourcemaps: list[tuple[str, int]] = []
    sinks: list[tuple[str, int]] = []
    import_urls: list[str] = []

    def add_secret(kind: str, line: int) -> None:
        entry = (kind, line)
        if entry not in seen_secrets:
            seen_secrets.add(entry)
            secrets.append(entry)

    def check_key_value(key: str | None, value_node: tree_sitter.Node | None, line: int) -> None:
        if key is None or value_node is None:
            return
        val = _unquote_string(value_node, source)
        if val is None or not val.strip():
            return
        if _SECRET_KEY_RE.search(key) and len(val) >= 6 and val.strip().lower() not in _PLACEHOLDERS:
            add_secret(key, line)
        if _VERSION_KEY_RE.fullmatch(key) and _VERSION_VAL_RE.search(val):
            versions.append((key, val, line))

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
                    endpoints.add(url)
            elif prop == 'open' and len(args) >= 2:
                if url := _unquote_string(args[1], source):
                    endpoints.add(url)
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
            check_key_value(
                _key_name(node.child_by_field_name('key') or node, source), node.child_by_field_name('value'), line
            )

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
            if _API_PATH_RE.match(val):
                endpoints.add(val)
            if _SECRET_VALUE_RE.match(val):
                add_secret('token-literal', line)

    return JsAnalysisResult(
        endpoints=tuple(sorted(endpoints)),
        secrets=tuple(sorted(secrets)),
        versions=tuple(sorted(versions)),
        sourcemaps=tuple(sorted(sourcemaps)),
        sinks=tuple(sorted(sinks)),
        import_urls=tuple(dict.fromkeys(import_urls)),
        has_syntax_errors=tree.root_node.has_error,
    )


def _read_js_source(item: Evidence) -> tuple[bytes | None, str, bool, str | None]:
    """Return ``(bytes_or_None, url, truncated, read_error)`` for a JS evidence item."""
    if isinstance(item, ArtifactEvidence):
        if item.file_path is None:
            return None, item.artifact.url, False, 'artifact has no local file_path'
        path = Path(item.file_path)
        try:
            return path.read_bytes(), item.artifact.url, False, None
        except OSError as exc:
            return None, item.artifact.url, False, f'cannot read artifact file: {exc}'
    assert isinstance(item, HttpEvidence)
    body = item.http.response.body
    assert body is not None
    return body.encode('utf-8'), item.http.request.url, item.http.response.body_note == 'truncated', None


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


class JsAnalysisCheck:
    """Passive check: deterministic tree-sitter analysis of JavaScript artifacts and responses."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return any(_is_js_evidence(item) for item in evidence)

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        drafts: list[FindingDraft] = []
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

            for key_or_kind, line in result.secrets:
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='medium',
                        subject=f'js:secret:{key_or_kind}',
                        title='Potential secret or credential embedded in JavaScript',
                        description=(
                            f'{url} line {line} assigns a non-empty value (<redacted>) to {key_or_kind!r}. '
                            'Client-side bundles are public to all users.'
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
                maps = ', '.join(f'{m} (line {ln})' for m, ln in result.sourcemaps)
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='low',
                        subject='js:sourcemap',
                        title='JavaScript sourceMappingURL exposed',
                        description=f'{url} declares sourceMappingURL: {maps}.',
                        evidence_ids=[item.id],
                        remediation='Restrict or omit source map references in production builds if original source should not be public.',
                    )
                )

            for sink_name, line in result.sinks:
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='low',
                        subject=f'js:sink:{sink_name}',
                        title=f'Risky DOM/JS sink ({sink_name}) in JavaScript',
                        description=(
                            f'{url} line {line} uses {sink_name} (low-confidence lead; verify whether '
                            'attacker-controlled input can reach this sink).'
                        ),
                        evidence_ids=[item.id],
                        remediation='Ensure untrusted input is sanitized or avoided before reaching DOM/JS execution sinks.',
                    )
                )

        return drafts


js_analysis_check = JsAnalysisCheck()
