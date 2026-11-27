"""Deterministic, operator-only target discovery rollup over the run store.

Pure aggregation and formatting over :class:`~partex.storage.RunReader` / :class:`~partex.storage.RunStore`:
no network, no model calls, and no ``pydantic_ai_pax`` imports. Every evidence record is passed through
:func:`partex.models.redact`, query/fragment parts are stripped from paths and redirect targets, and
C0/C1 terminal control sequences are neutralized before any string is returned.
"""

import html
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from .export import SEVERITY_RANK
from .models import (
    REDACTED,
    ArtifactEvidence,
    CoverageEntry,
    Evidence,
    Finding,
    HttpEvidence,
    Scope,
    Severity,
    get_header,
    redact,
)
from .scope import entry_url
from .storage import RunReader, RunRecord, RunStore, ToolCallRecord

type TargetStore = RunReader | RunStore
type TargetState = Literal['up', 'tls_error', 'unreachable', 'unprobed']
type OriginKey = tuple[str, str, int]

_TERMINAL_CONTROLS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')
_WHITESPACE = re.compile(r'[ \t\r\n]+')
_TITLE_RE = re.compile(r'<title\b[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
_GENERIC_TITLE_RE = re.compile(
    r'^(?:(?:http(?:\s+status)?|error)\s+)?(?:\d{3}\s*[-–—:/]?\s*)?'
    r'(?:moved permanently|moved temporarily|document moved|object moved|found|see other|'
    r'temporary redirect|permanent redirect|bad request|unauthorized|authorization required|'
    r'forbidden|access denied|not found|page not found|file not found|method not allowed|'
    r'request timeout|conflict|gone|too many requests|internal server error|not implemented|'
    r'bad gateway|service unavailable|gateway timeout|error)'
    r'(?:\s*[-–—:/]?\s*\d{3})?$',
    re.IGNORECASE,
)
_BANNER_HEADERS = ('server', 'x-powered-by', 'x-aspnet-version', 'x-generator')
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_STATUS_RANK = {'verified': 2, 'verification_failed': 1, 'reported': 0}
_SEVERITIES: tuple[Severity, ...] = tuple(sorted(SEVERITY_RANK, key=lambda s: -SEVERITY_RANK[s]))
_COVERAGE_GAP_OUTCOMES = frozenset({'not_applicable', 'needs_follow_up'})


def sanitize_text(text: str) -> str:
    """Collapse line/tab whitespace to spaces and neutralize C0/C1 terminal escapes."""
    collapsed = _WHITESPACE.sub(' ', text)
    neutralized = _TERMINAL_CONTROLS.sub(lambda match: f'\\x{ord(match.group()):02x}', collapsed)
    return neutralized.strip()


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + '…'


def canonical_origin(url: str) -> OriginKey | None:
    """Parse *url* into ``(scheme, host, port)``; returns ``None`` if host or scheme is missing/invalid."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return None
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == 'https' else 80
    return scheme, parts.hostname.lower(), port


def format_origin(scheme: str, host: str, port: int) -> str:
    """Format a canonical origin, bracketing IPv6 hosts and omitting scheme default ports."""
    display_host = f'[{host}]' if ':' in host and not host.startswith('[') else host
    if (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443):
        return f'{scheme}://{display_host}'
    return f'{scheme}://{display_host}:{port}'


def _extract_title(body: str | None, content_type: str | None) -> str | None:
    if not body:
        return None
    head = body[:4096].lower()
    is_html = content_type is None or 'html' in content_type.lower() or '<title' in head
    if not is_html:
        return None
    match = _TITLE_RE.search(body[:16_384])
    if match is None:
        return None
    cleaned = sanitize_text(html.unescape(match.group(1)))
    if not cleaned or _GENERIC_TITLE_RE.fullmatch(cleaned):
        return None
    return _truncate(cleaned, 48)


def _sanitize_redirect(location: str, origin_key: OriginKey) -> str | None:
    raw = location.strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    clean_path = sanitize_text(parts.path or '/')
    if not clean_path.startswith('/'):
        clean_path = '/' + clean_path if parts.scheme and parts.hostname else clean_path
    if parts.scheme and parts.hostname:
        target_origin = canonical_origin(raw)
        if target_origin == origin_key:
            display = clean_path
        elif target_origin is not None:
            origin_text = format_origin(*target_origin)
            display = f'{origin_text}{clean_path}' if clean_path != '/' else origin_text
        else:
            display = clean_path
    else:
        display = clean_path
    return _truncate(display, 48) or None


def _is_js_artifact(artifact: ArtifactEvidence) -> bool:
    path = urlsplit(artifact.artifact.url).path.lower()
    content_type = (artifact.artifact.content_type or '').lower()
    return path.endswith(('.js', '.mjs')) or 'javascript' in content_type


@dataclass(frozen=True, slots=True)
class TargetPath:
    """One normalized ``METHOD /path`` observed on a target."""

    method: str
    path: str
    statuses: tuple[int, ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TargetSummary:
    """Discovered state, surface, and findings aggregated for one canonical ``scheme://host:port``."""

    origin: str
    scheme: str
    host: str
    port: int
    state: TargetState
    state_note: str | None
    authorized: bool
    current: bool
    run_ids: tuple[str, ...]
    statuses: tuple[int, ...]
    redirects: tuple[str, ...]
    root_redirect: str | None
    banners: tuple[str, ...]
    title: str | None
    paths: tuple[TargetPath, ...]
    evidence_count: int
    artifact_count: int
    js_count: int
    openapi_count: int
    tls_unverified: bool
    findings: tuple[Finding, ...]
    coverage_gaps: tuple[CoverageEntry, ...]


@dataclass(frozen=True, slots=True)
class RunTargetInput:
    """One run's pre-loaded data handed to :func:`build_targets_rollup`."""

    run: RunRecord
    evidence: Sequence[Evidence]
    findings: Sequence[Finding]
    coverage: Sequence[CoverageEntry]
    tool_calls: Sequence[ToolCallRecord]
    scope: Scope | None = None
    is_current: bool = False
    tls_unverified_host: Callable[[str], bool] | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryRollup:
    """Aggregated discovery view across one run or the whole store."""

    scope_label: str
    run_count: int
    requests_spent: int
    targets: tuple[TargetSummary, ...]
    multi_run: bool = False

    @property
    def up_count(self) -> int:
        return sum(1 for t in self.targets if t.state == 'up')

    @property
    def tls_error_count(self) -> int:
        return sum(1 for t in self.targets if t.state == 'tls_error')

    @property
    def unreachable_count(self) -> int:
        return sum(1 for t in self.targets if t.state == 'unreachable')

    @property
    def unprobed_count(self) -> int:
        return sum(1 for t in self.targets if t.state == 'unprobed')

    @property
    def total_findings(self) -> int:
        return sum(len(t.findings) for t in self.targets)


@dataclass(slots=True)
class _TargetAccum:
    """Mutable per-origin builder inside :func:`build_targets_rollup`."""

    origin: str
    scheme: str
    host: str
    port: int
    order: int
    authorized: bool = False
    current: bool = False
    probed_tls_note: str | None = None
    probed_unreachable: bool = False
    probed_unreachable_note: str | None = None
    unprobed_note: str | None = None
    run_ids: list[str] = field(default_factory=list[str])
    statuses: list[int] = field(default_factory=list[int])
    redirects: list[str] = field(default_factory=list[str])
    root_redirects: list[str] = field(default_factory=list[str])
    has_plain_root_2xx: bool = False
    banners: list[str] = field(default_factory=list[str])
    _banner_seen: set[str] = field(default_factory=set[str])
    title_root_2xx: str | None = None
    title_2xx: str | None = None
    title_other: str | None = None
    paths: dict[tuple[str, str], tuple[list[int], list[str]]] = field(
        default_factory=dict[tuple[str, str], tuple[list[int], list[str]]]
    )
    evidence_count: int = 0
    artifact_count: int = 0
    js_count: int = 0
    openapi_count: int = 0
    tls_unverified: bool = False
    findings: dict[tuple[str, str, str, str], Finding] = field(default_factory=dict[tuple[str, str, str, str], Finding])
    coverage_gaps: list[CoverageEntry] = field(default_factory=list[CoverageEntry])
    _gap_seen: set[tuple[str, str, str, str]] = field(default_factory=set[tuple[str, str, str, str]])

    def note_run(self, run_id: str, *, is_current: bool) -> None:
        if run_id not in self.run_ids:
            self.run_ids.append(run_id)
        if is_current:
            self.current = True

    def add_banner(self, raw: str) -> None:
        cleaned = _truncate(sanitize_text(raw), 40)
        if not cleaned or cleaned == REDACTED:
            return
        norm = cleaned.lower()
        if norm not in self._banner_seen:
            self._banner_seen.add(norm)
            self.banners.append(cleaned)

    def add_finding(self, finding: Finding, *, artifact_path: str = '') -> None:
        key = (finding.check_id, finding.subject, finding.title, artifact_path)
        existing = self.findings.get(key)
        if existing is None or (_STATUS_RANK[finding.status], SEVERITY_RANK[finding.severity]) > (
            _STATUS_RANK[existing.status],
            SEVERITY_RANK[existing.severity],
        ):
            self.findings[key] = finding

    def add_coverage_gap(self, entry: CoverageEntry) -> None:
        key = (entry.surface, entry.risk_area, entry.outcome, entry.reason)
        if key not in self._gap_seen:
            self._gap_seen.add(key)
            self.coverage_gaps.append(entry)

    def freeze(self) -> TargetSummary:
        state: TargetState
        note: str | None = None
        if self.evidence_count > 0:
            state = 'up'
        elif self.probed_tls_note is not None:
            state = 'tls_error'
            note = self.probed_tls_note
        elif self.probed_unreachable:
            state = 'unreachable'
            note = self.probed_unreachable_note
        else:
            state = 'unprobed'
            note = self.unprobed_note
        sorted_findings = tuple(
            sorted(self.findings.values(), key=lambda f: (-SEVERITY_RANK[f.severity], f.check_id, f.id))
        )
        frozen_paths = tuple(
            TargetPath(method=method, path=path, statuses=tuple(statuses), evidence_ids=tuple(eids))
            for (method, path), (statuses, eids) in self.paths.items()
        )
        has_2xx = any(200 <= s < 300 for s in self.statuses)
        title = (
            self.title_root_2xx or self.title_2xx
            if has_2xx
            else (self.title_root_2xx or self.title_2xx or self.title_other)
        )
        return TargetSummary(
            origin=self.origin,
            scheme=self.scheme,
            host=self.host,
            port=self.port,
            state=state,
            state_note=note,
            authorized=self.authorized,
            current=self.current,
            run_ids=tuple(self.run_ids),
            statuses=tuple(self.statuses),
            redirects=tuple(self.redirects),
            root_redirect=None
            if self.has_plain_root_2xx
            else (self.root_redirects[0] if self.root_redirects else None),
            banners=tuple(self.banners),
            title=title,
            paths=frozen_paths,
            evidence_count=self.evidence_count,
            artifact_count=self.artifact_count,
            js_count=self.js_count,
            openapi_count=self.openapi_count,
            tls_unverified=self.tls_unverified,
            findings=sorted_findings,
            coverage_gaps=tuple(self.coverage_gaps),
        )


def _target_sort_key(summary: TargetSummary, order: int) -> tuple[int, int, int, int]:
    if summary.state == 'up':
        state_rank = 0 if summary.findings else 1
    elif summary.state == 'tls_error':
        state_rank = 2
    elif summary.state == 'unreachable':
        state_rank = 3
    else:
        state_rank = 4
    max_sev = max((SEVERITY_RANK[f.severity] for f in summary.findings), default=-1)
    return (state_rank, -max_sev, -len(summary.findings), order)


def build_targets_rollup(
    inputs: Sequence[RunTargetInput], *, scope_label: str, multi_run: bool = False
) -> DiscoveryRollup:
    """Aggregate pre-loaded runs into a deterministic, redacted :class:`DiscoveryRollup`."""
    accums: dict[OriginKey, _TargetAccum] = {}

    def ensure(
        key: OriginKey,
        *,
        run_id: str,
        is_current: bool,
        tls_check: Callable[[str], bool] | None,
    ) -> _TargetAccum:
        acc = accums.get(key)
        if acc is None:
            scheme, host, port = key
            acc = _TargetAccum(
                origin=format_origin(scheme, host, port),
                scheme=scheme,
                host=host,
                port=port,
                order=len(accums),
            )
            accums[key] = acc
        acc.note_run(run_id, is_current=is_current)
        if tls_check is not None and tls_check(acc.host):
            acc.tls_unverified = True
        return acc

    for item in inputs:
        run = item.run
        run_origins: list[OriginKey] = []
        effective_scope = item.scope if item.scope is not None else run.scope_snapshot
        if effective_scope is not None and effective_scope.urls:
            for entry in effective_scope.urls:
                if (key := canonical_origin(entry_url(entry))) is not None:
                    acc = ensure(key, run_id=run.id, is_current=item.is_current, tls_check=item.tls_unverified_host)
                    acc.authorized = True
                    if key not in run_origins:
                        run_origins.append(key)

        for call in item.tool_calls:
            raw_result: Any = call.result
            if call.tool != 'initial_probe' or not isinstance(raw_result, dict):
                continue
            outcomes = cast(dict[str, Any], raw_result).get('outcomes')
            if not isinstance(outcomes, dict):
                continue
            for raw_url, raw_outcome in cast(dict[Any, Any], outcomes).items():
                if not isinstance(raw_url, str) or not isinstance(raw_outcome, str):
                    continue
                if (key := canonical_origin(raw_url)) is None:
                    continue
                acc = ensure(key, run_id=run.id, is_current=item.is_current, tls_check=item.tls_unverified_host)
                if key not in run_origins:
                    run_origins.append(key)
                if raw_outcome == 'tls_verify_failed':
                    acc.probed_tls_note = 'cert verify failed — try -k'
                elif raw_outcome == 'tls_error':
                    if acc.probed_tls_note is None:
                        acc.probed_tls_note = 'handshake failed'
                elif raw_outcome == 'timeout':
                    acc.probed_unreachable = True
                    if acc.probed_unreachable_note is None:
                        acc.probed_unreachable_note = 'timeout'
                elif raw_outcome == 'unreachable':
                    acc.probed_unreachable = True
                elif raw_outcome == 'unprobed' and acc.unprobed_note is None:
                    acc.unprobed_note = 'request budget'

        evidence_origin: dict[str, OriginKey] = {}
        evidence_artifact_path: dict[str, str] = {}
        for ev in item.evidence:
            if isinstance(ev, HttpEvidence):
                redacted = cast(HttpEvidence, redact(ev))
                if (key := canonical_origin(redacted.http.request.url)) is None:
                    continue
                evidence_origin[ev.id] = key
                acc = ensure(key, run_id=run.id, is_current=item.is_current, tls_check=item.tls_unverified_host)
                if key not in run_origins:
                    run_origins.append(key)
                acc.evidence_count += 1
                if not ev.tls_verified:
                    acc.tls_unverified = True

                method = sanitize_text(redacted.http.request.method.upper()) or 'GET'
                req_parts = urlsplit(redacted.http.request.url)
                raw_path = req_parts.path or '/'
                clean_path = sanitize_text(raw_path) or '/'
                is_plain_root = raw_path == '/' and not req_parts.query
                status = redacted.http.response.status_code
                if status not in acc.statuses:
                    acc.statuses.append(status)
                if is_plain_root and 200 <= status < 300:
                    acc.has_plain_root_2xx = True
                if status in _REDIRECT_STATUSES:
                    location = get_header(redacted.http.response.headers, 'location')
                    if location and (redir := _sanitize_redirect(location, key)) is not None:
                        if redir not in acc.redirects:
                            acc.redirects.append(redir)
                        if is_plain_root and redir not in acc.root_redirects:
                            acc.root_redirects.append(redir)
                for header_name in _BANNER_HEADERS:
                    if header_val := get_header(redacted.http.response.headers, header_name):
                        acc.add_banner(header_val)
                title = _extract_title(
                    redacted.http.response.body, get_header(redacted.http.response.headers, 'content-type')
                )
                if title is not None:
                    if 200 <= status < 300:
                        if clean_path == '/' and acc.title_root_2xx is None:
                            acc.title_root_2xx = title
                        if acc.title_2xx is None:
                            acc.title_2xx = title
                    elif acc.title_other is None:
                        acc.title_other = title

                p_statuses, p_eids = acc.paths.setdefault((method, clean_path), ([], []))
                if status not in p_statuses:
                    p_statuses.append(status)
                if ev.id not in p_eids:
                    p_eids.append(ev.id)
            elif isinstance(ev, ArtifactEvidence):
                redacted_art = cast(ArtifactEvidence, redact(ev))
                if (key := canonical_origin(redacted_art.artifact.url)) is None:
                    continue
                evidence_origin[ev.id] = key
                art_path = sanitize_text(urlsplit(redacted_art.artifact.url).path or '/')
                if art_path:
                    evidence_artifact_path[ev.id] = art_path
                acc = ensure(key, run_id=run.id, is_current=item.is_current, tls_check=item.tls_unverified_host)
                if key not in run_origins:
                    run_origins.append(key)
                acc.evidence_count += 1
                acc.artifact_count += 1
                if _is_js_artifact(redacted_art):
                    acc.js_count += 1
                if not ev.tls_verified:
                    acc.tls_unverified = True
            else:
                cfg_key = canonical_origin(ev.config.path) if '://' in ev.config.path else None
                if cfg_key is None and '://' in ev.source:
                    cfg_key = canonical_origin(ev.source)
                if cfg_key is None and len(run_origins) == 1:
                    cfg_key = run_origins[0]
                if cfg_key is not None:
                    evidence_origin[ev.id] = cfg_key
                    acc = ensure(cfg_key, run_id=run.id, is_current=item.is_current, tls_check=item.tls_unverified_host)
                    acc.evidence_count += 1
                    if ev.config.format == 'openapi':
                        acc.openapi_count += 1

        single_origin = run_origins[0] if len(run_origins) == 1 else None
        for finding in item.findings:
            target_key = next((evidence_origin[eid] for eid in finding.evidence_ids if eid in evidence_origin), None)
            if target_key is None:
                target_key = single_origin
            if target_key is not None and target_key in accums:
                artifact_path = next(
                    (evidence_artifact_path[eid] for eid in finding.evidence_ids if eid in evidence_artifact_path),
                    '',
                )
                accums[target_key].add_finding(finding, artifact_path=artifact_path)

        for entry in item.coverage:
            if entry.outcome not in _COVERAGE_GAP_OUTCOMES:
                continue
            target_key = next((evidence_origin[eid] for eid in entry.evidence_ids if eid in evidence_origin), None)
            if target_key is None and '://' in entry.surface:
                target_key = canonical_origin(entry.surface)
            if target_key is None:
                target_key = single_origin
            if target_key is not None and target_key in accums:
                accums[target_key].add_coverage_gap(entry)

    frozen = [(acc.order, acc.freeze()) for acc in accums.values()]
    ordered = tuple(summary for _, summary in sorted(frozen, key=lambda pair: _target_sort_key(pair[1], pair[0])))
    return DiscoveryRollup(
        scope_label=scope_label,
        run_count=len(inputs),
        requests_spent=sum(item.run.requests_spent for item in inputs),
        targets=ordered,
        multi_run=multi_run,
    )


async def _load_run_input(
    store: TargetStore,
    run: RunRecord,
    *,
    is_current: bool = False,
    live_scope: Scope | None = None,
    live_tls_unverified: Callable[[str], bool] | None = None,
) -> RunTargetInput:
    evidence = await store.evidence(run.id)
    findings = await store.findings(run.id)
    coverage = await store.coverage(run.id)
    tool_calls = await store.tool_calls(run.id)
    return RunTargetInput(
        run=run,
        evidence=evidence,
        findings=findings,
        coverage=coverage,
        tool_calls=tool_calls,
        scope=live_scope,
        is_current=is_current,
        tls_unverified_host=live_tls_unverified,
    )


async def gather_run_targets(
    store: TargetStore,
    run_id: str,
    *,
    live_scope: Scope | None = None,
    live_tls_unverified: Callable[[str], bool] | None = None,
) -> DiscoveryRollup:
    """Build a :class:`DiscoveryRollup` for one run in *store*."""
    run = await store.get_run(run_id)
    loaded = await _load_run_input(
        store, run, is_current=True, live_scope=live_scope, live_tls_unverified=live_tls_unverified
    )
    return build_targets_rollup([loaded], scope_label='this run', multi_run=False)


async def gather_all_targets(
    store: TargetStore,
    *,
    current_run_id: str | None = None,
    live_scope: Scope | None = None,
    live_tls_unverified: Callable[[str], bool] | None = None,
) -> DiscoveryRollup:
    """Build a :class:`DiscoveryRollup` across all non-invalid runs in *store*."""
    runs = [run for run in await store.list_runs() if run.state != 'invalid']
    inputs: list[RunTargetInput] = []
    for run in runs:
        is_current = current_run_id is not None and run.id == current_run_id
        loaded = await _load_run_input(
            store,
            run,
            is_current=is_current,
            live_scope=live_scope if is_current else None,
            live_tls_unverified=live_tls_unverified if is_current else None,
        )
        if run.state == 'checks_failed' and not loaded.evidence and not loaded.tool_calls:
            continue
        inputs.append(loaded)
    run_word = 'run' if len(inputs) == 1 else 'runs'
    label = f'all runs ({len(inputs)} {run_word})' if inputs else 'all runs'
    return build_targets_rollup(inputs, scope_label=label, multi_run=len(inputs) > 1)


def match_targets(targets: Sequence[TargetSummary], query: str) -> list[TargetSummary]:
    """Match targets by tiered exact origin, ``host:port``, bare ``host``, or substring."""
    q = query.strip().lower()
    if not q:
        return list(targets)
    tiers = (
        [t for t in targets if t.origin.lower() == q],
        [t for t in targets if f'{t.host}:{t.port}'.lower() == q or f'[{t.host}]:{t.port}'.lower() == q],
        [t for t in targets if t.host.lower() == q],
        [t for t in targets if q in t.origin.lower()],
    )
    for matches in tiers:
        if matches:
            return matches
    return []


def _severity_summary(findings: Sequence[Finding]) -> str:
    counts: dict[Severity, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return ', '.join(f'{counts[sev]} {sev}' for sev in _SEVERITIES if sev in counts)


def render_targets_overview(rollup: DiscoveryRollup, *, findings_only: bool = False, show_all_hint: bool = True) -> str:
    """Render a compact multi-target overview suitable for the operator terminal."""
    if not rollup.targets:
        return 'No targets discovered yet.'
    shown = [t for t in rollup.targets if t.findings] if findings_only else list(rollup.targets)
    if findings_only and not shown:
        return f'No targets with findings ({len(rollup.targets)} target(s) in {rollup.scope_label}).'

    state_parts: list[str] = []
    if rollup.up_count:
        state_parts.append(f'{rollup.up_count} up')
    if rollup.tls_error_count:
        state_parts.append(f'{rollup.tls_error_count} tls error')
    if rollup.unreachable_count:
        state_parts.append(f'{rollup.unreachable_count} unreachable')
    if rollup.unprobed_count:
        state_parts.append(f'{rollup.unprobed_count} unprobed')
    state_text = ', '.join(state_parts) or '0 probed'
    finding_word = 'finding' if rollup.total_findings == 1 else 'findings'
    lines = [
        (
            f'Targets in {rollup.scope_label} ({len(rollup.targets)} total: {state_text} · '
            f'{rollup.total_findings} {finding_word}):'
        ),
        '',
    ]

    show_current_tag = (
        rollup.multi_run and any(t.current for t in rollup.targets) and any(not t.current for t in rollup.targets)
    )
    for target in shown:
        current_tag = ' [current]' if show_current_tag and target.current else ''
        tls_tag = ' (TLS unverified)' if target.tls_unverified else ''
        if target.state == 'up':
            if target.statuses:
                shown_statuses = ','.join(map(str, target.statuses[:3]))
                if len(target.statuses) > 3:
                    shown_statuses += f'+{len(target.statuses) - 3}'
            else:
                shown_statuses = 'up'
            if target.root_redirect is not None:
                shown_statuses += f' → {target.root_redirect}'

            meta: list[str] = []
            if target.title:
                meta.append(f'"{target.title}"')
            if target.banners:
                banner_text = ', '.join(target.banners[:2])
                if len(target.banners) > 2:
                    banner_text += f' (+{len(target.banners) - 2})'
                meta.append(banner_text)
            path_word = 'path' if len(target.paths) == 1 else 'paths'
            meta.append(f'{len(target.paths)} {path_word}')
            if target.js_count:
                meta.append(f'{target.js_count} JS')
            if target.openapi_count:
                meta.append(f'{target.openapi_count} OpenAPI')
            lines.append(f'  {target.origin}  {shown_statuses}  {" · ".join(meta)}{tls_tag}{current_tag}')
        else:
            state_label = 'tls error' if target.state == 'tls_error' else target.state
            note = f' ({target.state_note})' if target.state_note else ''
            lines.append(f'  {target.origin}  {state_label}{note}{tls_tag}{current_tag}')

        if target.findings:
            verified = sum(1 for f in target.findings if f.status == 'verified')
            verified_note = f' ({verified} verified)' if verified else ''
            unique_titles: list[str] = []
            for finding in target.findings:
                clean_title = _truncate(sanitize_text(finding.title), 56)
                if clean_title not in unique_titles:
                    unique_titles.append(clean_title)
            title_list = ', '.join(unique_titles[:2])
            if len(unique_titles) > 2:
                title_list += f', +{len(unique_titles) - 2} more'
            lines.append(f'    findings: {_severity_summary(target.findings)}{verified_note} — {title_list}')
        elif target.coverage_gaps:
            gap_word = 'coverage gap' if len(target.coverage_gaps) == 1 else 'coverage gaps'
            lines.append(f'    findings: none ({len(target.coverage_gaps)} {gap_word})')

    tips = ['/targets <host> for details', '/targets --findings to filter']
    if show_all_hint:
        tips.append('/targets --all for all runs')
    lines.extend(['', 'Tip: ' + ' · '.join(tips)])
    return '\n'.join(lines)


def render_target_detail(rollup: DiscoveryRollup, query: str) -> str:
    """Render full details (paths, banners, findings, coverage gaps) for targets matching *query*."""
    if not rollup.targets:
        return 'No targets discovered yet.'
    matches = match_targets(rollup.targets, query)
    if not matches:
        known = ', '.join(t.origin for t in rollup.targets)
        return f'No target matching {query!r}. Known targets: {known}'

    blocks: list[str] = []
    for target in matches:
        state_label = 'tls error' if target.state == 'tls_error' else target.state
        note = f' — {target.state_note}' if target.state_note else ''
        tls_tag = ' (TLS unverified)' if target.tls_unverified else ''
        lines = [f'{target.origin}  [{state_label}{note}]{tls_tag}']
        if target.run_ids:
            lines.append(f'  runs ({len(target.run_ids)}): {", ".join(target.run_ids)}')
        if target.title:
            lines.append(f'  title: {target.title}')
        if target.banners:
            lines.append(f'  banners: {", ".join(target.banners)}')
        if target.redirects:
            lines.append(f'  redirects: {", ".join(target.redirects)}')
        if target.artifact_count or target.openapi_count:
            art_word = 'artifact' if target.artifact_count == 1 else 'artifacts'
            spec_word = 'OpenAPI spec' if target.openapi_count == 1 else 'OpenAPI specs'
            lines.append(
                f'  assets: {target.artifact_count} {art_word} ({target.js_count} JS), '
                f'{target.openapi_count} {spec_word}'
            )
        if target.paths:
            lines.append(f'  paths ({len(target.paths)}):')
            for item in target.paths[:20]:
                statuses = ','.join(map(str, item.statuses))
                eids = ', '.join(item.evidence_ids[:3])
                if len(item.evidence_ids) > 3:
                    eids += ', …'
                lines.append(f'    {item.method} {item.path} -> {statuses} ({eids})')
            if len(target.paths) > 20:
                lines.append(f'    … +{len(target.paths) - 20} more')
        if target.findings:
            lines.append(f'  findings ({len(target.findings)}):')
            for finding in target.findings:
                title = sanitize_text(finding.title)
                subject = sanitize_text(finding.subject)
                eids = ', '.join(finding.evidence_ids)
                lines.append(
                    f'    [{finding.severity}] {title} — {subject} ({finding.id}, {finding.status}) evidence: {eids}'
                )
        else:
            lines.append('  findings: none')
        if target.coverage_gaps:
            lines.append(f'  coverage gaps ({len(target.coverage_gaps)}):')
            for entry in target.coverage_gaps:
                surface = sanitize_text(entry.surface)
                risk_area = sanitize_text(entry.risk_area)
                reason = f' ({sanitize_text(entry.reason)})' if entry.reason else ''
                lines.append(f'    {surface} / {risk_area}: {entry.outcome}{reason}')
        blocks.append('\n'.join(lines))
    return '\n\n'.join(blocks)


def format_status_badge(total: int, up: int, findings: int) -> str:
    """Format a pure-ASCII status-row badge (Pax replaces non-ASCII in the status bar)."""
    if total == 0:
        return ''
    base = f'targets: {up}/{total} up'
    if findings == 0:
        return base
    word = 'finding' if findings == 1 else 'findings'
    return f'{base}, {findings} {word}'
