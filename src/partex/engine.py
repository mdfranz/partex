"""Run lifecycle — passive path (PLAN §6, §6.1, §7.1).

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
change what is stored. No model, socket, or network call happens on this path.
"""

import importlib.metadata
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import anyio
import anyio.to_thread
from pydantic import ValidationError

from .bundle import load_bundle
from .checks import PassiveCheck
from .errors import PartexError, ValidationFailed
from .ids import finding_id
from .models import Evidence, Finding, FindingDraft
from .storage import RunState, RunStore

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
