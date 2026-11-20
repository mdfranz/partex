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
from collections.abc import AsyncGenerator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import anyio
import anyio.to_thread
from pydantic import ValidationError

from .bundle import load_bundle
from .checks import HeaderInput, PassiveCheck
from .engagement import MANIFEST_NAME, check_credentials_available, load_engagement
from .errors import BudgetExhausted, PartexError, ScopeViolation, ValidationFailed
from .ids import finding_id
from .models import ArtifactEvidence, Engagement, Evidence, Finding, FindingDraft, HttpEvidence, Scope
from .scope import extend_scope
from .storage import RunState, RunStore, artifact_dir
from .target import DEFAULT_MAX_ASSET_BYTES, ScopedHttpClient

ENTRY_POINT_GROUP = 'partex.checks'
MAX_DRAFTS_PER_CHECK = 1000
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

    await store.commit_passive(run_id, evidence, findings)
    return ReviewResult(
        run_id,
        'checks_complete',
        selected_ids,
        findings=tuple(findings),
        evidence_count=len(evidence),
        warnings=loaded.warnings,
        skipped_checks=skipped,
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


def select_active_checks(registry: Mapping[str, Any], selection: Sequence[str]) -> list[Any]:
    """Resolve *selection* (ordered, de-duplicated) to active checks, or raise :class:`CheckSelectionError`."""
    ordered = list(dict.fromkeys(selection))
    if not ordered:
        raise CheckSelectionError('no checks selected', rule_code='empty-selection')
    unknown = [check_id for check_id in ordered if check_id not in registry]
    if unknown:
        available = ', '.join(sorted(registry)) or '(none installed)'
        raise CheckSelectionError(
            f'unknown check(s): {", ".join(unknown)}; available: {available}', rule_code='unknown-check'
        )
    not_active = [check_id for check_id in ordered if not callable(getattr(registry[check_id], 'probe', None))]
    if not_active:
        raise CheckSelectionError(
            f'not active check(s), cannot run on a live target: {", ".join(not_active)}', rule_code='not-active'
        )
    return [registry[check_id] for check_id in ordered]


def _manifest_fingerprint(engagement_path: str | Path) -> str:
    """sha256 over the engagement manifest file bytes (dir or file path both accepted)."""
    path = Path(engagement_path)
    if path.is_dir():
        path = path / MANIFEST_NAME
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _GateRefused(PartexError):
    """A live gate failed before any socket; the caller records the run as ``invalid``."""


async def _check_live_gates(engagement_path: str | Path, *, authorized: bool) -> Engagement:
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
    return engagement


async def run_test(
    engagement_path: str | Path,
    store: RunStore,
    checks: Sequence[str],
    *,
    authorized: bool,
    registry: Mapping[str, Any] | None = None,
) -> TestResult:
    """Run the live path against the engagement at *engagement_path*.

    Order of gates, all before any socket: check selection, the ``--authorized``
    flag (E2 CLI half), engagement validation (E1–E7), and credential presence
    (E4/E7 run-start half). Then: baseline capture, active checks in selection
    order, evidence committed **at capture time** and findings **per check** —
    a crash or budget exhaustion keeps everything already paid for (§6.1).
    """
    registry = installed_checks() if registry is None else registry
    selected = select_active_checks(registry, checks)
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
        engagement = await _check_live_gates(engagement_path, authorized=authorized)
    except _GateRefused as exc:
        return await invalid(exc.rule_code or 'engagement-invalid', str(exc))

    run_id = await store.create_run(
        input_kind='engagement',
        input_ref=str(engagement_path),
        input_sha256=_manifest_fingerprint(engagement_path),
        engine_version=engine_version(),
        selected_checks=selected_ids,
        authorized=True,
        scope_snapshot=engagement.scope,
    )

    captured: list[Evidence] = []
    findings: list[Finding] = []
    skipped: list[str] = []
    done: set[str] = set()
    budget_exhausted = False

    async def on_capture(evidence: HttpEvidence) -> None:
        # Capture-time commit: one small transaction per exchange (§6.1), so a
        # mid-run crash discards nothing already sent or received.
        await store.add_evidence(run_id, evidence)
        await store.add_requests_spent(run_id, 1)
        captured.append(evidence)

    client = ScopedHttpClient(engagement, source=f'capture:{run_id}', on_capture=on_capture)
    try:
        try:
            await client.request('GET', engagement.target.base_url)
            for check in selected:
                if not check.applies_to(captured):
                    skipped.append(check.check_id)
                    done.add(check.check_id)
                    continue
                try:
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
        )
    finally:
        await client.aclose()


# ── Live session (issue #54; PLAN §9 operator-in-the-loop) ─────────────────────


class LiveSessionRefused(PartexError):
    """A live gate failed before any socket. The run row is recorded ``invalid`` (``run_id``) for audit."""

    def __init__(self, message: str, *, rule_code: str | None, run_id: str) -> None:
        super().__init__(message, rule_code=rule_code)
        self.run_id = run_id


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
        self.client = ScopedHttpClient(
            engagement,
            source=f'capture:{run_id}',
            on_capture=self._on_capture,
            on_artifact=self._on_artifact,
            on_failed_send=self._on_failed_send,
        )

    async def _on_capture(self, evidence: HttpEvidence) -> None:
        await self._store.add_evidence(self.run_id, evidence)
        await self._store.add_requests_spent(self.run_id, 1)
        self.captured.append(evidence)

    async def _on_artifact(self, evidence: ArtifactEvidence) -> None:
        await self._store.add_evidence(self.run_id, evidence)
        await self._store.add_requests_spent(self.run_id, 1)
        self.captured.append(evidence)

    async def _on_failed_send(self) -> None:
        await self._store.add_requests_spent(self.run_id, 1)

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
            url, dest_dir=artifact_dir(self._store.path), headers=headers, max_bytes=max_bytes
        )

    async def extend_scope(self, spec: str, *, confirmed_by: str) -> tuple[Scope, Scope]:
        """Add the host/port(s) in *spec* to this session's scope; returns ``(before, after)``.

        Only an operator-confirmed call may reach this (never a model tool). The scope only grows: paths,
        exclusions and budgets are unchanged, and the result must pass the E3 checks. The amendment is
        audited as a ``scope_amend`` tool call on the run and the run's scope snapshot is updated.
        """
        before = self.engagement.scope
        after = extend_scope(before, spec)
        if after == before:
            return before, after
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
                },
            )
        except Exception as exc:
            raise PartexError(
                f'could not record the scope change, so the scope is unchanged: {exc}', rule_code='scope-persist'
            ) from exc
        self.client.set_scope(after)
        self.engagement = self.engagement.model_copy(update={'scope': after})
        return before, after

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
        return findings


@asynccontextmanager
async def live_session(
    engagement_path: str | Path,
    store: RunStore,
    *,
    authorized: bool,
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
    selected = select_active_checks(registry, checks) if checks else []
    selected_ids = tuple(check.check_id for check in selected)
    try:
        engagement = await _check_live_gates(engagement_path, authorized=authorized)
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
    session = LiveSession(run_id=run_id, engagement=engagement, registry=registry, store=store)
    try:
        await session.request('GET', engagement.target.base_url)
        for check in selected:
            if check.applies_to(session.captured):
                await session.run_check(check.check_id)
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
