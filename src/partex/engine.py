"""Run lifecycle — passive and live paths (PLAN §6, §6.1, §7.1).

``run_review`` turns an offline bundle into committed, evidence-backed findings::

    select checks ─▶ create run ─▶ load + validate bundle ─▶ run checks (bounded local workers)
                                     │ invalid                     │ a check raised / bad drafts
                                     ▼                             ▼
                                  invalid                     checks_failed (nothing published)
                                                                   │ ok
                                         validate drafts, assign IDs, one transaction
                                                                   ▼
                                                            checks_complete

The engine is the only writer: checks receive validated evidence and return drafts; they never see
the store. Results are assembled in selection order, so worker count and completion order never
change what is stored. The passive path makes no model, socket, or network call; the live path
opens sockets only through the scoped target client.
"""

import hashlib
import importlib.metadata
import os
import ssl
import sys
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import anyio
import anyio.to_thread
import httpx2
from pydantic import ValidationError

from .bundle import MAX_CONTENT_BYTES, load_bundle
from .checks import HeaderInput, PassiveCheck
from .engagement import MANIFEST_NAME, check_credentials_available, load_engagement
from .errors import BudgetExhausted, PartexError, ScopeViolation, ValidationFailed
from .ids import finding_id
from .models import (
    WRITE_METHODS,
    ArtifactEvidence,
    ConfigEvidence,
    CoverageEntry,
    Engagement,
    Evidence,
    Finding,
    FindingDraft,
    HttpEvidence,
    HttpPolicy,
    Scope,
    TlsPolicy,
    check_user_agent,
)
from .openapi_resolver import derive_openapi_config_evidence
from .probes import SeedPlan, plan_seed_probes
from .roles import RoleHandle, role_handles
from .scope import apply_urls, check_url, entry_url, extend_scope, parse_urls_file, validate_scope
from .storage import RunState, RunStore, SurfaceKind, SurfaceRel, run_artifact_dir, surface_node_id
from .target import DEFAULT_MAX_ASSET_BYTES, RequestBudget, ScopedHttpClient, tls_unverified

ENTRY_POINT_GROUP = 'partex.checks'
MAX_DRAFTS_PER_CHECK = 1000
DEFAULT_ACTIVE_CHECKS = ('version-disclosure',)
"""Active checks ``partex test`` runs when none are named."""
DISCOVERY_CHECKS = ('js-analysis', 'api-contract-conformance', 'openapi-spec-review')
"""Passive checks a live session re-runs by itself when static sources (downloaded assets, API specs) arrive (#185).
They only read captured evidence, so a pass sends no traffic and spends no budget."""
DEFAULT_AGENT_CHECKS = (*DEFAULT_ACTIVE_CHECKS, *DISCOVERY_CHECKS)
"""What ``partex agent`` runs before the chat opens when ``--checks`` is not given (#185)."""
_NOT_RUN = object()


class CheckSelectionError(PartexError):
    """The requested check selection is unusable (usage error, raised before any run row exists).

    ``rule_code`` is ``unknown-check``, ``not-passive``, or ``empty-selection``.
    """


class CheckFailed(PartexError):
    """A check raised or returned unusable output. Recorded on the run; never escapes ``run_review``."""

    def __init__(self, check_id: str, message: str) -> None:
        super().__init__(f'{check_id}: {message}', rule_code='check-failed')
        self.check_id = check_id


@dataclass(frozen=True, slots=True)
class ReviewResult:
    """Outcome of :func:`run_review`. ``findings`` is empty unless ``state == 'checks_complete'``."""

    run_id: str
    state: RunState
    selected_checks: tuple[str, ...]
    findings: tuple[Finding, ...] = ()
    evidence_count: int = 0
    warnings: tuple[str, ...] = ()
    error: str | None = None
    """Diagnostic for ``invalid`` (prefixed with the validation rule code) or ``checks_failed``."""
    rule_code: str | None = None
    failed_check: str | None = None
    skipped_checks: tuple[str, ...] = field(default=())
    """Selected checks whose ``applies_to`` returned ``False`` for this evidence."""
    coverage: tuple[CoverageEntry, ...] = field(default=())
    """``check_observed`` ledger entries emitted by passive checks."""


def engine_version() -> str:
    return importlib.metadata.version('partex')


def default_workers() -> int:
    return min(4, os.cpu_count() or 1)


# ── Check discovery (minimal; the full registry + skill join is M2, #25) ─────


def installed_checks() -> dict[str, Any]:
    """Load every ``partex.checks`` entry point, keyed by ``check_id``, in entry-point name order.

    Check code loads only from installed distributions — never from a path (PLAN §10).
    """
    checks: dict[str, Any] = {}
    for entry_point in sorted(importlib.metadata.entry_points(group=ENTRY_POINT_GROUP), key=lambda ep: ep.name):
        check = entry_point.load()
        checks[check.check_id] = check
    return checks


def select_passive_checks(registry: Mapping[str, Any], selection: Sequence[str]) -> list[PassiveCheck]:
    """Resolve *selection* (ordered, de-duplicated) to passive checks, or raise :class:`CheckSelectionError`."""
    ordered = list(dict.fromkeys(selection))
    if not ordered:
        raise CheckSelectionError('no checks selected', rule_code='empty-selection')
    unknown = [check_id for check_id in ordered if check_id not in registry]
    if unknown:
        available = ', '.join(sorted(registry)) or '(none installed)'
        raise CheckSelectionError(
            f'unknown check(s): {", ".join(unknown)}; available: {available}', rule_code='unknown-check'
        )
    not_passive = [check_id for check_id in ordered if not callable(getattr(registry[check_id], 'review', None))]
    if not_passive:
        raise CheckSelectionError(
            f'not passive check(s), cannot run on a bundle: {", ".join(not_passive)}', rule_code='not-passive'
        )
    return [registry[check_id] for check_id in ordered]


# ── Passive run ───────────────────────────────────────────────────────────────


async def run_review(
    bundle_path: str | Path,
    store: RunStore,
    checks: Sequence[str],
    *,
    registry: Mapping[str, Any] | None = None,
    workers: int | None = None,
) -> ReviewResult:
    """Review the bundle at *bundle_path* with *checks* (in order) and commit the results to *store*.

    Raises :class:`CheckSelectionError` for an unusable selection, before any run row is created.
    Every other outcome is recorded on the run and returned: ``invalid`` (bundle failed validation),
    ``checks_failed`` (a check raised or produced bad drafts; nothing is published), or
    ``checks_complete``.
    """
    registry = installed_checks() if registry is None else registry
    selected = select_passive_checks(registry, checks)
    selected_ids = tuple(check.check_id for check in selected)
    limit = default_workers() if workers is None else workers
    if limit < 1:
        raise CheckSelectionError(f'workers must be >= 1, got {limit}', rule_code='workers')

    try:
        loaded = await anyio.to_thread.run_sync(lambda: load_bundle(bundle_path, known_checks=registry.keys()))
    except ValidationFailed as exc:
        run_id = await store.create_run(
            input_kind='bundle',
            input_ref=str(bundle_path),
            input_sha256='',
            engine_version=engine_version(),
            selected_checks=selected_ids,
        )
        error = f'{exc.rule_code}: {exc}'
        await store.set_state(run_id, 'invalid', error=error)
        return ReviewResult(run_id, 'invalid', selected_ids, error=error, rule_code=exc.rule_code)

    run_id = await store.create_run(
        input_kind='bundle',
        input_ref=str(bundle_path),
        input_sha256=loaded.fingerprint,
        engine_version=engine_version(),
        selected_checks=selected_ids,
    )
    evidence = loaded.evidence

    try:
        drafts, skipped = await _run_checks(selected, evidence, limit)
        findings = _finalize(selected, drafts, evidence)
        skipped_set = set(skipped)
        coverage: list[CoverageEntry] = []
        surface_nodes: list[tuple[SurfaceKind, str, dict[str, Any], Sequence[str]]] = []
        surface_edges: list[tuple[str, str, SurfaceRel, str | None]] = []
        for check in selected:
            if check.check_id in skipped_set:
                continue
            coverage.extend(_collect_coverage(check, evidence))
            nodes, edges = _collect_surface(check, evidence)
            surface_nodes.extend(nodes)
            surface_edges.extend(edges)
    except CheckFailed as exc:
        await store.set_state(run_id, 'checks_failed', error=str(exc))
        return ReviewResult(
            run_id,
            'checks_failed',
            selected_ids,
            evidence_count=len(evidence),
            warnings=loaded.warnings,
            error=str(exc),
            rule_code=exc.rule_code,
            failed_check=exc.check_id,
        )

    await store.commit_passive(
        run_id,
        evidence,
        findings,
        coverage=coverage,
        surface_nodes=surface_nodes,
        surface_edges=surface_edges,
    )
    return ReviewResult(
        run_id,
        'checks_complete',
        selected_ids,
        findings=tuple(findings),
        evidence_count=len(evidence),
        warnings=loaded.warnings,
        skipped_checks=skipped,
        coverage=tuple(coverage),
    )


async def _run_checks(
    selected: Sequence[PassiveCheck], evidence: Sequence[Evidence], workers: int
) -> tuple[list[object], tuple[str, ...]]:
    """Run every check on a bounded pool. Returns drafts per check in selection order.

    On the first failure the remaining workers are cancelled; the failure reported is the earliest
    failing check in selection order, so the diagnostic doesn't depend on scheduling.
    """
    limiter = anyio.CapacityLimiter(workers)
    results: list[object] = [_NOT_RUN] * len(selected)
    applies: list[bool] = [True] * len(selected)
    failures: dict[int, CheckFailed] = {}

    async def worker(index: int, check: PassiveCheck) -> None:
        def call() -> tuple[bool, object]:
            if not check.applies_to(evidence):
                return False, ()
            return True, check.review(evidence)

        try:
            applies[index], results[index] = await anyio.to_thread.run_sync(call, limiter=limiter)
        except Exception as exc:  # noqa: BLE001 — any check crash becomes checks_failed, never escapes
            failures[index] = CheckFailed(check.check_id, f'raised {type(exc).__name__}: {exc}')
            tg.cancel_scope.cancel()

    async with anyio.create_task_group() as tg:
        for index, check in enumerate(selected):
            tg.start_soon(worker, index, check)

    if failures:
        raise failures[min(failures)]
    if any(result is _NOT_RUN for result in results):  # pragma: no cover — only reachable via external cancellation
        raise anyio.get_cancelled_exc_class()()
    skipped = tuple(check.check_id for check, applied in zip(selected, applies, strict=True) if not applied)
    return results, skipped


def _finalize(
    selected: Sequence[PassiveCheck], drafts_per_check: Sequence[object], evidence: Sequence[Evidence]
) -> list[Finding]:
    """Validate drafts (PLAN §5 contract rules) and assign final finding IDs, in selection order."""
    registered = {item.id for item in evidence}
    findings: dict[str, Finding] = {}
    for check, drafts in zip(selected, drafts_per_check, strict=True):
        if isinstance(drafts, (str, bytes)) or not isinstance(drafts, Sequence):
            raise CheckFailed(check.check_id, f'returned {type(drafts).__name__}, expected a sequence of drafts')
        drafts = cast(Sequence[object], drafts)
        if len(drafts) > MAX_DRAFTS_PER_CHECK:
            raise CheckFailed(check.check_id, f'returned {len(drafts)} drafts (limit {MAX_DRAFTS_PER_CHECK})')
        for position, raw in enumerate(drafts):
            draft = _validate_draft(check, position, raw)
            missing = sorted(set(draft.evidence_ids) - registered)
            if missing:
                raise CheckFailed(check.check_id, f'draft {position} cites unregistered evidence {missing}')
            fid = finding_id(draft.check_id, draft.subject, draft.title, draft.evidence_ids)
            # The same (check, subject, title, evidence) twice is one finding; keep the first.
            findings.setdefault(fid, Finding(id=fid, status='reported', **draft.model_dump()))
    return list(findings.values())


_SURFACE_KINDS: frozenset[str] = frozenset({'host', 'endpoint', 'parameter', 'role', 'tech_banner'})
_SURFACE_RELS: frozenset[str] = frozenset({'exposes_endpoint', 'accepts_param', 'authenticated_as', 'redirects_to'})


def _collect_coverage(check: Any, evidence: Sequence[Evidence]) -> list[CoverageEntry]:
    """Run a check's optional ``coverage(evidence)`` hook and validate its ``check_observed`` ledger entries."""
    hook = getattr(check, 'coverage', None)
    if not callable(hook):
        return []
    try:
        raw: list[Any] = list(cast('Iterable[Any]', hook(list(evidence))))
    except Exception as exc:
        raise CheckFailed(check.check_id, f'coverage raised {type(exc).__name__}: {exc}') from exc
    registered = {item.id for item in evidence}
    entries: list[CoverageEntry] = []
    for position, item in enumerate(raw):
        try:
            entry = CoverageEntry.model_validate(item.model_dump() if isinstance(item, CoverageEntry) else item)
        except ValidationError as exc:
            raise CheckFailed(
                check.check_id, f'coverage entry {position} is invalid: {exc.errors()[0]["msg"]}'
            ) from exc
        if entry.source != 'check_observed':
            raise CheckFailed(check.check_id, f'coverage entry {position} must have source check_observed')
        if missing := sorted(set(entry.evidence_ids) - registered):
            raise CheckFailed(check.check_id, f'coverage entry {position} cites unregistered evidence {missing}')
        entries.append(entry)
    return entries


async def _record_coverage(
    store: RunStore, run_id: str, check: Any, evidence: Sequence[Evidence]
) -> list[CoverageEntry]:
    """Run a check's optional ``coverage(evidence)`` hook and commit its ledger entries (``check_observed`` only)."""
    entries = _collect_coverage(check, evidence)
    if entries:
        await store.upsert_coverage(run_id, entries)
    return entries


def _collect_surface(
    check: Any, evidence: Sequence[Evidence]
) -> tuple[
    list[tuple[SurfaceKind, str, dict[str, Any], Sequence[str]]],
    list[tuple[str, str, SurfaceRel, str | None]],
]:
    """Run a check's optional ``surface(evidence)`` hook and validate its nodes and edges."""
    hook = getattr(check, 'surface', None)
    if not callable(hook):
        return [], []
    try:
        raw = hook(list(evidence))
    except Exception as exc:
        raise CheckFailed(check.check_id, f'surface raised {type(exc).__name__}: {exc}') from exc
    if not isinstance(raw, Mapping):
        raise CheckFailed(check.check_id, f'surface returned {type(raw).__name__}, expected a mapping')
    data = cast(Mapping[str, Any], raw)
    raw_nodes = data.get('nodes', ())
    raw_edges = data.get('edges', ())
    if not isinstance(raw_nodes, Sequence) or isinstance(raw_nodes, (str, bytes)):
        raise CheckFailed(check.check_id, 'surface nodes must be a sequence')
    if not isinstance(raw_edges, Sequence) or isinstance(raw_edges, (str, bytes)):
        raise CheckFailed(check.check_id, 'surface edges must be a sequence')

    registered = {item.id for item in evidence}
    nodes: list[tuple[SurfaceKind, str, dict[str, Any], Sequence[str]]] = []
    for position, node in enumerate(cast(Sequence[Any], raw_nodes)):
        if not isinstance(node, Mapping):
            raise CheckFailed(check.check_id, f'surface node {position} must be a mapping')
        nd = cast(Mapping[str, Any], node)
        kind = nd.get('kind')
        key = nd.get('key')
        meta = nd.get('metadata', {})
        ev_ids = nd.get('evidence_ids', ())
        if not isinstance(kind, str) or kind not in _SURFACE_KINDS or not isinstance(key, str) or not key:
            raise CheckFailed(check.check_id, f'surface node {position} has invalid kind/key')
        if not isinstance(meta, dict):
            raise CheckFailed(check.check_id, f'surface node {position} metadata must be a dict')
        if not isinstance(ev_ids, Sequence) or isinstance(ev_ids, (str, bytes)):
            raise CheckFailed(check.check_id, f'surface node {position} evidence_ids must be a sequence')
        ev_list = [str(eid) for eid in cast(Sequence[Any], ev_ids)]
        if missing := sorted(set(ev_list) - registered):
            raise CheckFailed(check.check_id, f'surface node {position} cites unregistered evidence {missing}')
        nodes.append((cast(SurfaceKind, kind), key, cast(dict[str, Any], meta), ev_list))

    edges: list[tuple[str, str, SurfaceRel, str | None]] = []
    for position, edge in enumerate(cast(Sequence[Any], raw_edges)):
        if not isinstance(edge, Mapping):
            raise CheckFailed(check.check_id, f'surface edge {position} must be a mapping')
        ed = cast(Mapping[str, Any], edge)
        src_kind = ed.get('src_kind')
        src_key = ed.get('src_key')
        dst_kind = ed.get('dst_kind')
        dst_key = ed.get('dst_key')
        rel = ed.get('rel')
        ev_id = ed.get('evidence_id')
        if (
            not isinstance(src_kind, str)
            or src_kind not in _SURFACE_KINDS
            or not isinstance(src_key, str)
            or not src_key
            or not isinstance(dst_kind, str)
            or dst_kind not in _SURFACE_KINDS
            or not isinstance(dst_key, str)
            or not dst_key
            or not isinstance(rel, str)
            or rel not in _SURFACE_RELS
        ):
            raise CheckFailed(check.check_id, f'surface edge {position} has invalid endpoints or rel')
        if ev_id is not None and (not isinstance(ev_id, str) or ev_id not in registered):
            raise CheckFailed(check.check_id, f'surface edge {position} cites unregistered evidence {ev_id!r}')
        src_id = surface_node_id(cast(SurfaceKind, src_kind), src_key)
        dst_id = surface_node_id(cast(SurfaceKind, dst_kind), dst_key)
        edges.append((src_id, dst_id, cast(SurfaceRel, rel), ev_id))
    return nodes, edges


async def _record_surface(store: RunStore, run_id: str, check: Any, evidence: Sequence[Evidence]) -> None:
    nodes, edges = _collect_surface(check, evidence)
    for kind, key, metadata, ev_ids in nodes:
        await store.upsert_surface_node(run_id, kind, key, metadata=metadata, evidence_ids=ev_ids)
    for src_id, dst_id, rel, ev_id in edges:
        await store.add_surface_edge(run_id, src_id, dst_id, rel, ev_id)


def _validate_draft(check: PassiveCheck, position: int, raw: Any) -> FindingDraft:
    try:
        draft = FindingDraft.model_validate(raw.model_dump() if isinstance(raw, FindingDraft) else raw)
    except ValidationError as exc:
        raise CheckFailed(check.check_id, f'draft {position} is invalid: {exc.errors()[0]["msg"]}') from exc
    if draft.check_id != check.check_id:
        raise CheckFailed(check.check_id, f'draft {position} claims check_id {draft.check_id!r}')
    if draft.check_version != check.version:
        raise CheckFailed(
            check.check_id, f'draft {position} claims check_version {draft.check_version!r}, check is {check.version!r}'
        )
    return draft


# ── Live run (issue #21; PLAN §6.1 live policy, §4.2 rule 5) ───────────────────


@dataclass(frozen=True, slots=True)
class TestResult:
    """Outcome of :func:`run_test`. ``findings`` is empty unless ``state == 'checks_complete'``."""

    run_id: str
    state: RunState
    selected_checks: tuple[str, ...]
    findings: tuple[Finding, ...] = ()
    requests_spent: int = 0
    authorized: bool = False
    evidence_count: int = 0
    error: str | None = None
    """Diagnostic for ``invalid`` (prefixed with the rule code) or ``checks_failed``."""
    rule_code: str | None = None
    failed_check: str | None = None
    skipped_checks: tuple[str, ...] = field(default=())
    """Selected checks that did not run: ``applies_to`` false, or cut short by budget."""
    budget_exhausted: bool = field(default=False)
    """True when ``max_requests`` ended active work cleanly (``checks_complete``, not failure)."""
    coverage: tuple[CoverageEntry, ...] = field(default=())
    """What the checks report they did or did not exercise (``check_observed`` ledger entries, #53)."""
    seeded_count: int = 0
    """Seeded bundle-surface probes actually sent (#76); ``0`` when no ``seed_bundle`` was given."""
    seed_plan: SeedPlan | None = None
    """The plan behind :attr:`seeded_count` — candidates plus every reported drop count."""
    seed_skipped: int = 0
    """Seeds refused by the scope gate at send time. Always 0: candidates are pre-filtered with
    the same gate, so a non-zero value means a logic bug, not a target condition."""


def is_active_check(check: Any) -> bool:
    """Active checks send probes (``probe``); every other registered check reviews captured evidence (``review``).

    A check that defines both is treated as active (its probe runs); no installed check does both today.
    """
    return callable(getattr(check, 'probe', None))


def select_live_checks(registry: Mapping[str, Any], selection: Sequence[str]) -> list[Any]:
    """Resolve *selection* (ordered, de-duplicated) to active and passive checks, or raise :class:`CheckSelectionError`.

    A live run can run both kinds: active checks probe the target, passive checks review every exchange the run
    captured (PLAN §6). The selection order is kept; :func:`order_for_live_run` decides what runs when.
    """
    ordered = list(dict.fromkeys(selection))
    if not ordered:
        raise CheckSelectionError('no checks selected', rule_code='empty-selection')
    unknown = [check_id for check_id in ordered if check_id not in registry]
    if unknown:
        available = ', '.join(sorted(registry)) or '(none installed)'
        raise CheckSelectionError(
            f'unknown check(s): {", ".join(unknown)}; available: {available}', rule_code='unknown-check'
        )
    unusable = [
        check_id
        for check_id in ordered
        if not is_active_check(registry[check_id]) and not callable(getattr(registry[check_id], 'review', None))
    ]
    if unusable:
        raise CheckSelectionError(
            f'check(s) with neither probe() nor review(): {", ".join(unusable)}', rule_code='not-runnable'
        )
    return [registry[check_id] for check_id in ordered]


def order_for_live_run(selected: Sequence[Any]) -> tuple[list[Any], list[Any]]:
    """Split *selected* into ``(active, passive)``, each in selection order.

    Active checks run first so passive checks also see the probe traffic; passive checks run last over every
    exchange the run captured.
    """
    return [c for c in selected if is_active_check(c)], [c for c in selected if not is_active_check(c)]


def default_live_checks(registry: Mapping[str, Any]) -> list[str]:
    """The ``partex test`` default: every installed passive check plus the default active set."""
    passive = [check_id for check_id, check in registry.items() if not is_active_check(check)]
    return [*passive, *(c for c in DEFAULT_ACTIVE_CHECKS if c in registry)]


def _manifest_fingerprint(engagement_path: str | Path) -> str:
    """sha256 over the engagement manifest file bytes (dir or file path both accepted)."""
    path = Path(engagement_path)
    if path.is_dir():
        path = path / MANIFEST_NAME
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _GateRefused(PartexError):
    """A live gate failed before any socket; the caller records the run as ``invalid``."""


def _apply_user_agent(engagement: Engagement, user_agent: str | None) -> Engagement:
    """``--user-agent`` replaces the engagement's ``http.user_agent`` for this run (#135); validated before any socket."""
    if user_agent is None:
        return engagement
    try:
        check_user_agent(user_agent)
    except ValueError as exc:
        raise _GateRefused(f'--user-agent: {exc}', rule_code='http-invalid') from exc
    return engagement.model_copy(update={'http': HttpPolicy(user_agent=user_agent)})


def _apply_write_flags(engagement: Engagement, allow_methods: Sequence[str], max_writes: int | None) -> Engagement:
    """``--allow-method`` / ``--max-writes`` extend the engagement's write authority for this run (#65, #119).

    Same E3 rules as the file: a write method needs a budget and a budget needs a write method. Never widens past
    the ceilings, and approval of each write still happens per action (§4.2).
    """
    if not allow_methods and max_writes is None:
        return engagement
    methods = list(engagement.scope.allowed_methods)
    for method in allow_methods:
        verb = method.strip().upper()
        if verb not in WRITE_METHODS:
            raise _GateRefused(
                f'--allow-method {method!r}: choose from {", ".join(sorted(WRITE_METHODS))}', rule_code='scope-invalid'
            )
        if verb not in methods:
            methods.append(verb)
    budget = engagement.scope.max_write_requests if max_writes is None else max_writes
    if max_writes is not None and max_writes < 0:
        raise _GateRefused('--max-writes must be 0 or more', rule_code='scope-invalid')
    scope = engagement.scope.model_copy(update={'allowed_methods': methods, 'max_write_requests': budget})
    problems = validate_scope(scope)
    if problems:
        raise _GateRefused('write flags: ' + '; '.join(problems), rule_code='scope-invalid')
    return engagement.model_copy(update={'scope': scope})


def _apply_insecure(engagement: Engagement, insecure: bool) -> Engagement:
    """``--insecure`` turns verification off for this run, keeping any ``insecure_hosts`` the file lists."""
    if not insecure or not engagement.tls.verify:
        return engagement
    return engagement.model_copy(update={'tls': TlsPolicy(verify=False, insecure_hosts=engagement.tls.insecure_hosts)})


async def _record_tls_policy(store: RunStore, run_id: str, engagement: Engagement) -> None:
    """Audit and announce a run that does not verify certificates; silent for the strict default (#71)."""
    tls = engagement.tls
    if tls.verify:
        return
    hosts = tls.insecure_hosts or list(engagement.scope.hosts)
    await store.record_tool_call(
        run_id,
        'tls_verify_disabled',
        {'hosts': hosts, 'all_in_scope_hosts': not tls.insecure_hosts},
        {'verified': False},
    )
    print(f'partex: warning: TLS certificate verification is DISABLED for {", ".join(hosts)}', file=sys.stderr)


def _apply_urls_file(engagement: Engagement, urls_file: str | Path, *, recursive: bool = False) -> Engagement:
    """``--urls-file`` restricts scope to the exact URLs listed; the target's ``base_url`` must be one of them (#121)."""
    try:
        urls = parse_urls_file(Path(urls_file).read_text(encoding='utf-8'), recursive=recursive)
        scope = apply_urls(engagement.scope, urls)
        check_url(scope, engagement.target.base_url)
    except OSError as exc:
        raise _GateRefused(f'cannot read URLs file {urls_file}: {exc}', rule_code='scope-invalid') from exc
    except ScopeViolation as exc:
        raise _GateRefused(f'URLs file {urls_file}: {exc}', rule_code='scope-invalid') from exc
    return engagement.model_copy(update={'scope': scope})


async def _check_live_gates(
    engagement_path: str | Path,
    *,
    authorized: bool,
    insecure: bool = False,
    urls_file: str | Path | None = None,
    recursive: bool = False,
    user_agent: str | None = None,
    allow_methods: Sequence[str] = (),
    max_writes: int | None = None,
) -> Engagement:
    """The live gates, all before any socket: ``--authorized`` (E2 CLI half), E1–E7, credentials present."""
    if not authorized:
        raise _GateRefused('--authorized is required for every live command', rule_code='unauthorized')
    try:
        engagement = await anyio.to_thread.run_sync(load_engagement, engagement_path)
    except ValidationFailed as exc:
        raise _GateRefused(str(exc), rule_code=exc.rule_code or 'engagement-invalid') from exc
    missing = check_credentials_available(engagement)
    if missing:
        raise _GateRefused(f'credential env vars not set: {", ".join(missing)}', rule_code='credential-missing')
    if urls_file is not None:
        engagement = await anyio.to_thread.run_sync(
            partial(_apply_urls_file, engagement, urls_file, recursive=recursive)
        )
    engagement = _apply_write_flags(engagement, allow_methods, max_writes)
    return _apply_user_agent(_apply_insecure(engagement, insecure), user_agent)


async def run_test(
    engagement_path: str | Path,
    store: RunStore,
    checks: Sequence[str],
    *,
    authorized: bool,
    insecure: bool = False,
    urls_file: str | Path | None = None,
    recursive: bool = False,
    user_agent: str | None = None,
    allow_methods: Sequence[str] = (),
    max_writes: int | None = None,
    registry: Mapping[str, Any] | None = None,
    seed_bundle: str | Path | None = None,
    max_seed: int | None = None,
) -> TestResult:
    """Run the live path against the engagement at *engagement_path*.

    Order of gates, all before any socket: check selection, the ``--authorized``
    flag (E2 CLI half), engagement validation (E1–E7), credential presence
    (E4/E7 run-start half), and — when *seed_bundle* is given — bundle validation and
    planning (candidates are method+URL only, scope-filtered against this engagement, #76).
    Then: baseline capture, seeded probes (in bundle registration order, so active checks'
    ``applies_to`` sees the seeded evidence), active checks in selection
    order, then passive checks over everything captured, evidence committed **at capture time** and findings **per check** —
    a crash or budget exhaustion keeps everything already paid for (§6.1).
    """
    registry = installed_checks() if registry is None else registry
    selected = select_live_checks(registry, checks)
    active, passive = order_for_live_run(selected)
    selected_ids = tuple(check.check_id for check in selected)

    async def invalid(rule_code: str, error: str) -> TestResult:
        run_id = await store.create_run(
            input_kind='engagement',
            input_ref=str(engagement_path),
            input_sha256='',
            engine_version=engine_version(),
            selected_checks=selected_ids,
        )
        message = f'{rule_code}: {error}'
        await store.set_state(run_id, 'invalid', error=message)
        return TestResult(run_id, 'invalid', selected_ids, error=message, rule_code=rule_code)

    try:
        engagement = await _check_live_gates(
            engagement_path,
            authorized=authorized,
            insecure=insecure,
            urls_file=urls_file,
            recursive=recursive,
            user_agent=user_agent,
            allow_methods=allow_methods,
            max_writes=max_writes,
        )
    except _GateRefused as exc:
        return await invalid(exc.rule_code or 'engagement-invalid', str(exc))

    seed_plan: SeedPlan | None = None
    if seed_bundle is not None:
        try:
            loaded_seed = await anyio.to_thread.run_sync(lambda: load_bundle(seed_bundle))
        except ValidationFailed as exc:
            return await invalid(exc.rule_code or 'bundle-invalid', f'seed bundle {seed_bundle}: {exc}')
        seed_plan = plan_seed_probes(loaded_seed, engagement, limit=max_seed)

    run_id = await store.create_run(
        input_kind='engagement',
        input_ref=str(engagement_path),
        input_sha256=_manifest_fingerprint(engagement_path),
        engine_version=engine_version(),
        selected_checks=selected_ids,
        authorized=True,
        scope_snapshot=engagement.scope,
    )
    await _record_tls_policy(store, run_id, engagement)

    captured: list[Evidence] = []
    findings: list[Finding] = []
    skipped: list[str] = []
    coverage: list[CoverageEntry] = []
    done: set[str] = set()
    budget_exhausted = False

    async def on_capture(evidence: HttpEvidence) -> None:
        # Capture-time commit: one small transaction per exchange (§6.1), so a
        # mid-run crash discards nothing already sent or received.
        await store.add_evidence(run_id, evidence, count_request=True)
        captured.append(evidence)
        await _maybe_register_openapi(store, run_id, captured, evidence)

    # One engagement-wide budget and DNS pin table shared by the primary client and any role
    # handles (#23/#27), so N roles never multiply ``max_requests``/``max_rps``.
    budget = RequestBudget(engagement.scope.max_requests, engagement.scope.max_rps)
    pins: dict[str, str] = {}
    client = ScopedHttpClient(engagement, source=f'capture:{run_id}', on_capture=on_capture, budget=budget, pins=pins)
    role_client_handles: dict[str, RoleHandle] = {}
    if engagement.roles and any(getattr(check, 'role_aware', False) for check in active):
        role_client_handles = role_handles(
            engagement, on_capture=on_capture, source=f'capture:{run_id}', budget=budget, pins=pins
        )
    seeded = 0
    seed_skipped = 0
    try:
        try:
            await client.request('GET', engagement.target.base_url)
            # #215 initial probe pass: one GET per active URL-list entry (the baseline target
            # itself is skipped), so checks review every imported host:port, not just base_url.
            if engagement.scope.urls:
                probe_outcomes: dict[str, str] = {}
                # Rule 5: a probe pass cut short by the budget ends it cleanly, like active work.
                budget_exhausted = (
                    budget_exhausted
                    or (
                        await probe_url_entries(
                            partial(client.request, 'GET'),
                            entries=engagement.scope.urls,
                            base_url=engagement.target.base_url,
                            outcomes=probe_outcomes,
                        )
                    )[2]
                    > 0
                )
                if probe_outcomes:
                    await store.record_tool_call(
                        run_id, 'initial_probe', {'total': len(probe_outcomes)}, {'outcomes': probe_outcomes}
                    )
            # Seeded bundle-surface probes (#76): right after the baseline so active checks see
            # the seeded evidence. Candidates are pre-filtered with the same scope gate, so a
            # refusal here is a logic bug — counted, never a run failure (the #80 lesson).
            if seed_plan is not None:
                for candidate in seed_plan.candidates:
                    try:
                        await client.request(candidate.method, candidate.url)
                        seeded += 1
                    except BudgetExhausted:
                        # Rule 5: exhaustion ends seeding cleanly, like active work.
                        budget_exhausted = True
                        break
                    except ScopeViolation:
                        seed_skipped += 1
            for check in active:
                if not check.applies_to(captured):
                    skipped.append(check.check_id)
                    done.add(check.check_id)
                    continue
                try:
                    if getattr(check, 'role_aware', False):
                        drafts = await check.probe(captured, client, roles=role_client_handles)
                    else:
                        drafts = await check.probe(captured, client)
                except BudgetExhausted:
                    # Rule 5: exhaustion ends active work cleanly, not as failure.
                    budget_exhausted = True
                    break
                except ScopeViolation as exc:
                    raise CheckFailed(check.check_id, f'probe left the engagement scope: {exc}') from exc
                except PartexError as exc:
                    raise CheckFailed(check.check_id, f'probe failed: {exc}') from exc
                except Exception as exc:
                    raise CheckFailed(check.check_id, f'raised {type(exc).__name__}: {exc}') from exc
                committed = _finalize([check], [drafts], captured)
                await store.commit_findings(run_id, committed)
                findings.extend(committed)
                coverage.extend(await _record_coverage(store, run_id, check, captured))
                await _record_surface(store, run_id, check, captured)
                done.add(check.check_id)
            # Passive checks run last, over every exchange captured so far (baseline and probe traffic), and need
            # no budget, so they still run after active work was cut short.
            for check in passive:
                if not check.applies_to(captured):
                    skipped.append(check.check_id)
                    done.add(check.check_id)
                    continue
                try:
                    drafts = await anyio.to_thread.run_sync(check.review, list(captured))
                except Exception as exc:
                    raise CheckFailed(check.check_id, f'raised {type(exc).__name__}: {exc}') from exc
                committed = _finalize([check], [drafts], captured)
                await store.commit_findings(run_id, committed)
                findings.extend(committed)
                coverage.extend(await _record_coverage(store, run_id, check, captured))
                await _record_surface(store, run_id, check, captured)
                done.add(check.check_id)
        except CheckFailed as exc:
            await store.set_state(run_id, 'checks_failed', error=str(exc))
            return TestResult(
                run_id,
                'checks_failed',
                selected_ids,
                findings=tuple(findings),
                requests_spent=client.requests_spent,
                authorized=True,
                evidence_count=len(captured),
                error=str(exc),
                rule_code=exc.rule_code,
                failed_check=exc.check_id,
                skipped_checks=tuple(skipped),
                coverage=tuple(coverage),
                seeded_count=seeded,
                seed_plan=seed_plan,
                seed_skipped=seed_skipped,
            )
        skipped.extend(check.check_id for check in selected if check.check_id not in done)
        await store.set_state(run_id, 'checks_complete')
        return TestResult(
            run_id,
            'checks_complete',
            selected_ids,
            findings=tuple(findings),
            requests_spent=client.requests_spent,
            authorized=True,
            evidence_count=len(captured),
            skipped_checks=tuple(skipped),
            budget_exhausted=budget_exhausted,
            coverage=tuple(coverage),
            seeded_count=seeded,
            seed_plan=seed_plan,
            seed_skipped=seed_skipped,
        )
    finally:
        for handle in role_client_handles.values():
            await handle.client.aclose()
        await client.aclose()


def _derive_openapi_from_artifact(item: ArtifactEvidence) -> ConfigEvidence | None:
    """Read a content-addressed ``2xx`` artifact within V4 bounds and derive ``ConfigEvidence`` if OpenAPI 3.x."""
    if not (200 <= item.artifact.status_code < 300):
        return None
    if item.artifact.size_bytes <= 0 or item.artifact.size_bytes > MAX_CONTENT_BYTES:
        return None
    if item.file_path is None:
        return None
    path = Path(item.file_path)
    digest = item.artifact.sha256
    in_artifacts = path.parent.name.endswith('.artifacts') or (
        path.parent.parent.name.endswith('.artifacts') and path.parent.name.startswith('run_')
    )
    if path.name != digest or not in_artifacts:
        return None
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONTENT_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > MAX_CONTENT_BYTES or hashlib.sha256(raw).hexdigest() != digest:
        return None
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return None
    return derive_openapi_config_evidence(text, origin_id=item.id, url=item.artifact.url)


async def _maybe_register_openapi(
    store: RunStore,
    run_id: str,
    captured: list[Evidence],
    item: HttpEvidence | ArtifactEvidence,
) -> None:
    """Register a derived ``ConfigEvidence(format='openapi')`` when *item* is a complete ``2xx`` OpenAPI 3.0/3.1 spec."""
    cfg_ev: ConfigEvidence | None = None
    if isinstance(item, HttpEvidence):
        resp = item.http.response
        if (
            200 <= resp.status_code < 300
            and resp.body is not None
            and resp.body_note is None
            and 'openapi' in resp.body
            and 'paths' in resp.body
        ):
            cfg_ev = await anyio.to_thread.run_sync(
                partial(derive_openapi_config_evidence, resp.body, origin_id=item.id, url=item.http.request.url)
            )
    elif 200 <= item.artifact.status_code < 300 and 0 < item.artifact.size_bytes <= MAX_CONTENT_BYTES:
        cfg_ev = await anyio.to_thread.run_sync(_derive_openapi_from_artifact, item)
    if cfg_ev is None:
        return
    if await store.add_evidence(run_id, cfg_ev):
        captured.append(cfg_ev)


# ── Live session (issue #54; PLAN §9 operator-in-the-loop) ─────────────────────


def _probe_key(url: str) -> tuple[str, str, int, str] | str:
    """Normalize a probe URL so ``http://host:80/*`` and ``http://host/`` collapse to one key."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return url
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError:
        return url
    if port is None:
        port = 443 if scheme == 'https' else 80
    return scheme, parts.hostname.lower(), port, parts.path or '/'


def _classify_probe_error(exc: PartexError) -> tuple[str, str]:
    """Classify a failed startup probe into ``(outcome_code, terminal_label)``."""
    chain: list[BaseException] = []
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack and len(chain) < 16:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        chain.append(current)
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None:
            stack.append(current.__context__)

    combined = ' '.join(str(item).lower() for item in chain)
    if any(isinstance(item, ssl.SSLCertVerificationError) for item in chain) or (
        'certificate_verify_failed' in combined or 'certificate verify failed' in combined
    ):
        return ('tls_verify_failed', 'tls error (cert verify failed — try -k)')
    if any(isinstance(item, ssl.SSLError) for item in chain) or '[ssl:' in combined:
        return ('tls_error', 'tls error (handshake failed)')
    if (
        any(isinstance(item, (httpx2.TimeoutException, TimeoutError)) for item in chain)
        or 'timed out' in combined
        or 'timeout' in combined
    ):
        return ('timeout', 'unreachable (timeout)')
    return ('unreachable', 'unreachable')


async def probe_url_entries(
    request: Callable[[str], Awaitable[object]],
    *,
    entries: Sequence[str],
    base_url: str,
    verbose: bool | None = None,
    outcomes: dict[str, str] | None = None,
) -> tuple[int, int, int]:
    """The #215 initial probe pass: one ``GET`` per active URL-list entry, before checks run.

    Only at startup (``partex test`` / ``partex agent``): an operator-confirmed import is the
    authorization, every probe is a safe method through the same scope gate and budget, and each
    capture commits at capture time — so the passive checks then review banner and error-page
    evidence from *every* imported host:port, not just the baseline target. ``request`` is a bound
    ``GET`` (``LiveSession.request`` or ``ScopedHttpClient.request``); *entries* is the active
    ``scope.urls``; *base_url* is skipped (the baseline capture already probed it), duplicates
    collapse. A dead host (:class:`PartexError` on connect) is counted and probed past, never a
    run failure; budget exhaustion stops the pass cleanly (PLAN §6). Returns
    ``(probed, failed, unprobed)`` and prints one summary line to stderr. With *verbose* (or on a
    TTY, the default) it also prints a live line per probe as it lands — the pass can take
    minutes at the engagement's rate limit, and a blank terminal reads as a hang. When *outcomes*
    is passed, it is populated with ``url -> 'ok' | 'tls_verify_failed' | 'tls_error' | 'timeout' |
    'unreachable' | 'unprobed'`` per probed URL.
    """
    show = sys.stderr.isatty() if verbose is None else verbose
    seen: set[tuple[str, str, int, str] | str] = {_probe_key(base_url)}
    urls: list[str] = []
    for entry in entries:
        url = entry_url(entry)
        key = _probe_key(url)
        if key not in seen:
            seen.add(key)
            urls.append(url)
    if show and urls:
        print(f'partex: probing {len(urls)} URL-list target(s) …', file=sys.stderr)
    probed = failed = tls_failed = 0
    for index, url in enumerate(urls, start=1):
        stopped = False
        try:
            await request(url)
            probed += 1
            outcome = 'ok'
            if outcomes is not None:
                outcomes[url] = 'ok'
        except BudgetExhausted:
            stopped = True
            outcome = 'stopped (request budget)'
            if outcomes is not None:
                for remaining in urls[index - 1 :]:
                    outcomes[remaining] = 'unprobed'
        except PartexError as exc:
            failed += 1
            code, outcome = _classify_probe_error(exc)
            if code in ('tls_verify_failed', 'tls_error'):
                tls_failed += 1
            if outcomes is not None:
                outcomes[url] = code
        if show:
            print(f'  [{index}/{len(urls)}] {url} — {outcome}', file=sys.stderr)
        if stopped:
            break
    unprobed = len(urls) - probed - failed
    if urls:
        tls_note = f' ({tls_failed} TLS — try -k)' if tls_failed else ''
        print(
            f'partex: initial probe of {len(urls) + 1} URL-list target(s): '
            f'{probed} probed, {failed} unreachable, {unprobed} unprobed (request budget){tls_note}',
            file=sys.stderr,
        )
    return probed, failed, unprobed


class LiveSessionRefused(PartexError):
    """A live gate failed before any socket. The run row is recorded ``invalid`` (``run_id``) for audit."""

    def __init__(self, message: str, *, rule_code: str | None, run_id: str) -> None:
        super().__init__(message, rule_code=rule_code)
        self.run_id = run_id


@dataclass(frozen=True, slots=True)
class DiscoveryUpdate:
    """What one automatic discovery pass produced (#185): which checks ran and what is new in the run."""

    checks: tuple[str, ...]
    new_findings: int
    new_surface_nodes: int
    surface_nodes: int
    failed: tuple[str, ...] = ()

    def note(self) -> str:
        """One line for the model: what discovery learned, and where to read it."""
        parts = [f'{self.surface_nodes} surface node(s) known ({self.new_surface_nodes} new)']
        if self.new_findings:
            parts.append(f'{self.new_findings} new finding(s)')
        if self.failed:
            parts.append(f'failed: {", ".join(self.failed)}')
        return (
            f'Discovery update (partex ran {", ".join(self.checks) or "no checks"} on newly captured sources; '
            f'no traffic sent): {"; ".join(parts)}. Read them with list_coverage and list_findings before guessing paths.'
        )


def _is_discovery_source(item: Evidence) -> bool:
    """Evidence that feeds the discovery checks: a downloaded asset, or a derived OpenAPI spec."""
    if isinstance(item, ArtifactEvidence):
        return True
    return isinstance(item, ConfigEvidence) and item.config.format.lower() == 'openapi'


class LiveSession:
    """One open live run that an operator (through an agent) extends with further requests and checks.

    The engine stays the only writer: requests go through the engagement-scoped client and commit their
    evidence at capture time; checks return drafts that the engine validates and commits. The run stays
    ``created`` while the session is open and is finalized when :func:`live_session` exits.
    """

    def __init__(self, *, run_id: str, engagement: Engagement, registry: Mapping[str, Any], store: RunStore) -> None:
        self.run_id = run_id
        self.engagement = engagement
        self.registry = registry
        self.captured: list[Evidence] = []
        self.findings: list[Finding] = []
        self._store = store
        self._discovery_cursor = 0
        self._discovery_lock = anyio.Lock()
        self.client = ScopedHttpClient(
            engagement,
            source=f'capture:{run_id}',
            on_capture=self._on_capture,
            on_artifact=self._on_artifact,
            on_failed_send=self._on_failed_send,
        )

    async def _on_capture(self, evidence: HttpEvidence) -> None:
        await self._store.add_evidence(self.run_id, evidence, count_request=True)
        self.captured.append(evidence)
        await _maybe_register_openapi(self._store, self.run_id, self.captured, evidence)

    async def _on_artifact(self, evidence: ArtifactEvidence) -> None:
        await self._store.add_evidence(self.run_id, evidence, count_request=True)
        self.captured.append(evidence)
        await _maybe_register_openapi(self._store, self.run_id, self.captured, evidence)

    async def _on_failed_send(self) -> None:
        await self._store.add_requests_spent(self.run_id, 1)

    @property
    def store(self) -> RunStore:
        """The run store this session writes to (for operator-only exports)."""
        return self._store

    @property
    def requests_spent(self) -> int:
        return self.client.requests_spent

    async def request(
        self, method: str, url: str, *, headers: HeaderInput | None = None, body: str | None = None
    ) -> HttpEvidence:
        """Send one request through the scope gate (raises ``ScopeViolation`` / ``BudgetExhausted`` / ``PartexError``)."""
        return await self.client.request(method, url, headers=headers, body=body)

    async def download_asset(
        self, url: str, *, headers: HeaderInput | None = None, max_bytes: int = DEFAULT_MAX_ASSET_BYTES
    ) -> ArtifactEvidence:
        """Stream a scoped GET-only asset to disk and register its ``ArtifactEvidence``."""
        return await self.client.download_asset(
            url, dest_dir=run_artifact_dir(self._store.path, self.run_id), headers=headers, max_bytes=max_bytes
        )

    def host_tls_unverified(self, host: str) -> bool:
        """Whether this session accepts invalid TLS certificates for *host* (``-k`` / engagement ``tls``, #101)."""
        return tls_unverified(self.engagement.tls, host)

    async def extend_scope(self, spec: str, *, confirmed_by: str) -> tuple[Scope, Scope]:
        """Add the host/port(s) in *spec* to this session's scope; returns ``(before, after)``.

        Only an operator-confirmed call may reach this (never a model tool). The scope only grows: paths,
        exclusions and budgets are unchanged, and the result must pass the E3 checks. The amendment is
        audited as a ``scope_amend`` tool call on the run and the run's scope snapshot is updated. The audit
        row records, per added host, whether its TLS certificates will be verified (#101).
        """
        before = self.engagement.scope
        after = extend_scope(before, spec)
        if after == before:
            return before, after
        added_hosts = [host for host in after.hosts if host not in before.hosts]
        # Persist the snapshot and the audit row together *before* the scope takes effect: if the write fails
        # the effective scope, the stored scope and the audit trail all still show the previous scope.
        try:
            await self._store.amend_scope(
                self.run_id,
                after,
                args={'spec': spec, 'confirmed_by': confirmed_by},
                result={
                    'hosts_before': before.hosts,
                    'hosts_after': after.hosts,
                    'ports_before': before.ports,
                    'ports_after': after.ports,
                    'tls_verified': {host: not self.host_tls_unverified(host) for host in added_hosts},
                },
            )
        except Exception as exc:
            raise PartexError(
                f'could not record the scope change, so the scope is unchanged: {exc}', rule_code='scope-persist'
            ) from exc
        self.client.set_scope(after)
        self.engagement = self.engagement.model_copy(update={'scope': after})
        return before, after

    async def import_urls(
        self, entries: Sequence[str], *, source: str, source_sha256: str | None, confirmed_by: str
    ) -> tuple[Scope, Scope]:
        """Add URL-list *entries* to this session's scope as one atomic amendment; ``(before, after)``.

        Only an operator-confirmed call may reach this (``/scope nmap``; never a model tool).
        The entries are #121 allowlist entries — host and port pinned per entry — so an import
        never widens scope to a host:port pair the scan did not show. Activating or extending a
        list narrows rule 3 for *every* request, so the caller keeps the engagement's
        ``base_url`` covered (:func:`partex.nmap.ensure_base_url_entry`). The amendment is audited
        as one ``scope_amend`` tool call recording the scan *source* and its sha256 (#215); the
        snapshot and the audit row commit together before the scope takes effect (the same
        ordering guarantee as :meth:`extend_scope`).
        """
        before = self.engagement.scope
        after = apply_urls(before, [*before.urls, *entries])
        problems = validate_scope(after)
        if problems:
            raise PartexError(f'imported scope is invalid: {"; ".join(problems)}', rule_code='scope-invalid')
        added_hosts = [host for host in after.hosts if host not in before.hosts]
        try:
            await self._store.amend_scope(
                self.run_id,
                after,
                args={
                    'action': 'import',
                    'specs': list(entries),
                    'source': source,
                    'source_sha256': source_sha256,
                    'confirmed_by': confirmed_by,
                },
                result={
                    'hosts_before': before.hosts,
                    'hosts_after': after.hosts,
                    'ports_before': before.ports,
                    'ports_after': after.ports,
                    'urls_before': len(before.urls),
                    'urls_after': len(after.urls),
                    'tls_verified': {host: not self.host_tls_unverified(host) for host in added_hosts},
                },
            )
        except Exception as exc:
            raise PartexError(
                f'could not record the scope change, so the scope is unchanged: {exc}', rule_code='scope-persist'
            ) from exc
        self.client.set_scope(after)
        self.engagement = self.engagement.model_copy(update={'scope': after})
        return before, after

    async def refresh_discovery(self) -> DiscoveryUpdate | None:
        """Run the passive discovery checks when static sources arrived since the last call (#185).

        Returns ``None`` when nothing new could change their output (the common case, and cheap). Otherwise runs
        each registered :data:`DISCOVERY_CHECKS` that applies, committing findings, coverage and surface exactly
        as an explicit ``run_check`` does; re-runs are idempotent (finding IDs, node upserts and edge inserts all
        dedupe). A check that fails is reported in the update, not raised, so a bad bundle cannot end the session.
        Sends no traffic.
        """
        async with self._discovery_lock:
            fresh = self.captured[self._discovery_cursor :]
            self._discovery_cursor = len(self.captured)
            if not any(_is_discovery_source(item) for item in fresh):
                return None
            nodes_before = len((await self._store.surface(self.run_id))[0])
            findings_before = len(self.findings)
            ran: list[str] = []
            failed: list[str] = []
            for check_id in DISCOVERY_CHECKS:
                check = self.registry.get(check_id)
                if check is None or not check.applies_to(self.captured):
                    continue
                try:
                    await self.run_check(check_id)
                except CheckFailed:
                    failed.append(check_id)
                else:
                    ran.append(check_id)
            nodes_after = len((await self._store.surface(self.run_id))[0])
            return DiscoveryUpdate(
                checks=tuple(ran),
                new_findings=len(self.findings) - findings_before,
                new_surface_nodes=nodes_after - nodes_before,
                surface_nodes=nodes_after,
                failed=tuple(failed),
            )

    async def run_check(self, check_id: str) -> list[Finding]:
        """Run one registered check over this session and commit its new findings; returns all of its findings.

        Active checks probe through the session's scoped client; passive checks review every exchange
        captured so far. Raises :class:`CheckSelectionError` for an unknown ID, ``BudgetExhausted`` when
        the budget runs out, and :class:`CheckFailed` when the check raises or returns invalid drafts.
        """
        check = self.registry.get(check_id)
        if check is None:
            available = ', '.join(sorted(self.registry)) or '(none installed)'
            raise CheckSelectionError(f'unknown check {check_id!r}; available: {available}', rule_code='unknown-check')
        evidence = list(self.captured)
        try:
            if callable(getattr(check, 'probe', None)):
                drafts = await check.probe(evidence, self.client)
            else:
                drafts = await anyio.to_thread.run_sync(check.review, evidence)
        except BudgetExhausted:
            raise
        except ScopeViolation as exc:
            raise CheckFailed(check_id, f'probe left the engagement scope: {exc}') from exc
        except Exception as exc:
            raise CheckFailed(check_id, f'raised {type(exc).__name__}: {exc}') from exc
        findings = _finalize([check], [drafts], self.captured)
        known = {finding.id for finding in self.findings}
        new = [finding for finding in findings if finding.id not in known]
        await self._store.commit_findings(self.run_id, new)
        self.findings.extend(new)
        await _record_coverage(self._store, self.run_id, check, self.captured)
        await _record_surface(self._store, self.run_id, check, self.captured)
        return findings


@asynccontextmanager
async def live_session(
    engagement_path: str | Path,
    store: RunStore,
    *,
    authorized: bool,
    insecure: bool = False,
    urls_file: str | Path | None = None,
    recursive: bool = False,
    user_agent: str | None = None,
    allow_methods: Sequence[str] = (),
    max_writes: int | None = None,
    checks: Sequence[str] = (),
    registry: Mapping[str, Any] | None = None,
) -> AsyncGenerator[LiveSession]:
    """Open a new live run, do the deterministic pass, and yield it for operator-directed work.

    Same gates as :func:`run_test`, before any socket (a refusal records an ``invalid`` run and raises
    :class:`LiveSessionRefused`). Then a baseline capture of ``target.base_url`` and the selected active
    *checks*, as ``partex test`` does. On exit the run becomes ``checks_complete``, or ``checks_failed``
    with the error if the block raised; finalizing is shielded from cancellation.
    """
    registry = installed_checks() if registry is None else registry
    selected = select_live_checks(registry, checks) if checks else []
    selected_ids = tuple(check.check_id for check in selected)
    try:
        engagement = await _check_live_gates(
            engagement_path,
            authorized=authorized,
            insecure=insecure,
            urls_file=urls_file,
            recursive=recursive,
            user_agent=user_agent,
            allow_methods=allow_methods,
            max_writes=max_writes,
        )
    except _GateRefused as exc:
        run_id = await store.create_run(
            input_kind='engagement',
            input_ref=str(engagement_path),
            input_sha256='',
            engine_version=engine_version(),
            selected_checks=selected_ids,
        )
        message = f'{exc.rule_code}: {exc}'
        await store.set_state(run_id, 'invalid', error=message)
        raise LiveSessionRefused(message, rule_code=exc.rule_code, run_id=run_id) from exc
    run_id = await store.create_run(
        input_kind='engagement',
        input_ref=str(engagement_path),
        input_sha256=_manifest_fingerprint(engagement_path),
        engine_version=engine_version(),
        selected_checks=selected_ids,
        authorized=True,
        scope_snapshot=engagement.scope,
    )
    await _record_tls_policy(store, run_id, engagement)
    session = LiveSession(run_id=run_id, engagement=engagement, registry=registry, store=store)
    try:
        await session.request('GET', engagement.target.base_url)
        # #215 initial probe pass: one GET per active URL-list entry, before the checks, so
        # passive review covers every imported host:port and active checks see all of it.
        if engagement.scope.urls:
            probe_outcomes: dict[str, str] = {}
            await probe_url_entries(
                partial(session.request, 'GET'),
                entries=engagement.scope.urls,
                base_url=engagement.target.base_url,
                outcomes=probe_outcomes,
            )
            if probe_outcomes:
                await store.record_tool_call(
                    run_id, 'initial_probe', {'total': len(probe_outcomes)}, {'outcomes': probe_outcomes}
                )
        active, passive = order_for_live_run(selected)
        for check in (*active, *passive):  # probes first, so passive checks also see their traffic
            if check.applies_to(session.captured):
                await session.run_check(check.check_id)
        await session.refresh_discovery()  # a baseline that is itself a spec or asset feeds discovery right away
        yield session
    except BaseException as exc:
        with anyio.CancelScope(shield=True):
            await store.set_state(run_id, 'checks_failed', error=f'{type(exc).__name__}: {exc}')
            await session.client.aclose()
        raise
    else:
        with anyio.CancelScope(shield=True):
            await store.set_state(run_id, 'checks_complete')
            await session.client.aclose()
