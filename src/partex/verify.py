"""Verification runner — PLAN §8 ``verify``, §13.4; issue #22.

Replays a finding's ``verify_recipe`` against the live target and records the
verdict::

    load run + finding + cited evidence ─▶ build recipe ─▶ replay through the
                                           scope gate   scoped client   │
                                                                        ▼
              confirmed ←── check.verify_match ── response received ──┤
              not_reproduced ←────────────── no match ────────────────┤
              inconclusive ←─── transport error / budget spent ─────────┘

Verdict rules (``skills/version-disclosure/reference/verification-criteria.md``
§3, generalized): *confirmed* when the check's matcher says the replayed
response still exhibits the finding's class; *not_reproduced* when a response
arrived and it does not; *inconclusive* when no usable response arrived
(unreachable, rate-limited, budget exhausted) — recorded, but the finding keeps
its current status.  Verification never deletes a finding: both transitions
retain the original evidence and the replay evidence.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from .engine import installed_checks
from .errors import BudgetExhausted, PartexError, ScopeViolation, ValidationFailed
from .ids import verification_id
from .models import (
    Engagement,
    Evidence,
    Finding,
    HttpEvidence,
    Scope,
    Verification,
)
from .storage import RunStore
from .target import ScopedHttpClient


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of one verification replay."""

    run_id: str
    finding_id: str
    verification_id: str
    verdict: Literal['confirmed', 'not_reproduced', 'inconclusive']
    finding_status: str
    """The finding's status after the verdict (``inconclusive`` leaves it unchanged)."""
    requests_spent: int = 0
    replay_evidence_ids: tuple[str, ...] = ()
    detail: str = ''
    counterevidence: str = ''


def _engagement_from_snapshot(scope: Scope, origin: str, *, tls_unverified: bool = False) -> Engagement:
    """Rebuild a minimal engagement from the run's stored scope snapshot.

    Verification replays inside the scope the run was *authorized for*, even if
    the engagement file on disk has since changed (PLAN §12: verify re-tests
    the target under the recorded authorization).
    """
    return Engagement.model_validate(
        {
            'schema_version': 1,
            'target': {'name': 'verify-replay', 'base_url': origin},
            'scope': scope.model_dump(),
            # A replay reuses how the original exchange was made: certificates unverified only if they were.
            'tls': {
                'verify': not tls_unverified,
                'insecure_hosts': [urlsplit(origin).hostname] if tls_unverified else [],
            },
            'authorization': {
                'attestation': 'scope snapshot recorded by the run under verification',
                'operator': 'partex verify',
            },
        }
    )


def _origin_of(evidence: HttpEvidence) -> str:
    parts = urlsplit(evidence.http.request.url)
    return urlunsplit((parts.scheme, parts.netloc, '', '', ''))


def _absolute_replay_url(path: str, origin: str) -> str:
    """Recipe paths may be absolute URLs (the norm) or origin-relative paths."""
    scheme: str = urlsplit(path).scheme
    if scheme in ('http', 'https'):
        return path
    suffix = path if path.startswith('/') else f'/{path}'
    return f'{origin}{suffix}'


async def run_verification(
    run_id: str,
    finding_id: str,
    store: RunStore,
    *,
    authorized: bool,
    registry: Mapping[str, Any] | None = None,
) -> VerifyResult:
    """Replay the finding's recipe and record the verdict.

    Requires ``--authorized`` (E2, every live command); the recipe executes
    only inside the run's stored scope snapshot and its engagement budgets.
    """
    if not authorized:
        raise ValidationFailed('--authorized is required for every live command', rule_code='unauthorized')

    run = await store.get_run(run_id)
    if run.input_kind != 'engagement' or run.scope_snapshot is None:
        raise PartexError(
            f'run {run_id!r} is not a live run; verification replays against the target it recorded',
            rule_code='verify-not-live',
        )
    finding = await store.get_finding(run_id, finding_id)
    if finding is None:
        raise PartexError(f'finding {finding_id!r} not found in run {run_id!r}', rule_code='finding-not-found')
    original_evidence = [item for item in (await _load_cited(store, run_id, finding)) if isinstance(item, HttpEvidence)]
    if not original_evidence:
        raise PartexError(f'finding {finding_id!r} cites no http evidence to replay', rule_code='verify-no-evidence')
    original = original_evidence[0]

    checks = installed_checks() if registry is None else registry
    check = checks.get(finding.check_id)
    if check is None:
        raise PartexError(f'check {finding.check_id!r} is not registered', rule_code='unknown-check')
    recipe = check.verify_recipe(finding, original_evidence)
    if recipe is None:
        raise PartexError(
            f'check {finding.check_id!r} provides no replay recipe for this finding (reported-only)',
            rule_code='verify-no-recipe',
        )

    engagement = _engagement_from_snapshot(
        run.scope_snapshot, _origin_of(original), tls_unverified=not original.tls_verified
    )
    replays: list[Evidence] = []

    async def on_capture(evidence: HttpEvidence) -> None:
        # Capture-time commit (§6.1): the replay is paid for even if the rest fails.
        await store.add_evidence(run_id, evidence)
        await store.add_requests_spent(run_id, 1)
        replays.append(evidence)

    client = ScopedHttpClient(engagement, source=f'capture:{run_id}:verify', on_capture=on_capture)
    try:
        try:
            for request in recipe.requests:
                absolute = _absolute_replay_url(request.path, _origin_of(original))
                await client.request(request.method, absolute, headers=list(request.headers), body=request.body)
        except BudgetExhausted as exc:
            return await _record(
                store,
                run_id,
                finding,
                replays,
                verdict='inconclusive',
                replayable=False,
                detail=f'replay exhausted the engagement budget: {exc}',
                counterevidence='budget exhaustion is a local limit, not evidence about the target',
                requests_spent=client.requests_spent,
                transition=False,
            )
        except ScopeViolation as exc:
            raise PartexError(
                f'replay left the run scope (recipe or target drift): {exc}', rule_code='verify-scope'
            ) from exc
        except PartexError as exc:
            return await _record(
                store,
                run_id,
                finding,
                replays,
                verdict='inconclusive',
                replayable=False,
                detail=f'replay did not complete: {exc}',
                counterevidence='no response was captured; unreachability is not evidence of a fix',
                requests_spent=client.requests_spent,
                transition=False,
            )
    finally:
        await client.aclose()

    replay_exchange = next((item for item in replays if isinstance(item, HttpEvidence)), None)
    if replay_exchange is None:
        return await _record(
            store,
            run_id,
            finding,
            replays,
            verdict='inconclusive',
            replayable=False,
            detail='replay captured no http exchange',
            counterevidence='no response was captured; unreachability is not evidence of a fix',
            requests_spent=client.requests_spent,
            transition=False,
        )
    matched = bool(check.verify_match(finding, original, replay_exchange))
    status = replay_exchange.http.response.status_code
    if matched:
        return await _record(
            store,
            run_id,
            finding,
            replays,
            verdict='confirmed',
            replayable=True,
            detail=f'replay still exhibits the finding ({finding.subject}); response status {status}',
            counterevidence=f'the replay reached the target (HTTP {status}); scope, budget, and '
            'reachability preconditions all held',
            requests_spent=client.requests_spent,
            transition=True,
        )
    return await _record(
        store,
        run_id,
        finding,
        replays,
        verdict='not_reproduced',
        replayable=True,
        detail=f'replay no longer exhibits the finding ({finding.subject}); response status {status}',
        counterevidence=f'a clean response arrived (HTTP {status}), so absence is evidence of '
        'absence, not unreachability',
        requests_spent=client.requests_spent,
        transition=True,
    )


async def _load_cited(store: RunStore, run_id: str, finding: Finding) -> list[Evidence]:
    evidence: list[Evidence] = []
    for evidence_id in finding.evidence_ids:
        item = await store.get_evidence(run_id, evidence_id)
        if item is not None:
            evidence.append(item)
    return evidence


async def _record(
    store: RunStore,
    run_id: str,
    finding: Finding,
    replays: Sequence[Evidence],
    *,
    verdict: Literal['confirmed', 'not_reproduced', 'inconclusive'],
    replayable: bool,
    detail: str,
    counterevidence: str,
    requests_spent: int,
    transition: bool,
) -> VerifyResult:
    """Commit the ``vf_`` record (with replay evidence) and the status transition."""
    request_ids = [item.id for item in replays]
    verification = Verification(
        id=verification_id(finding.id, request_ids),
        finding_id=finding.id,
        check_id=finding.check_id,
        requests=request_ids,
        verdict=verdict,
        replayable=replayable,
        detail=detail,
        counterevidence=counterevidence,
    )
    await store.record_verification(run_id, verification, evidence=replays, transition=transition)
    updated = await store.get_finding(run_id, finding.id)
    return VerifyResult(
        run_id=run_id,
        finding_id=finding.id,
        verification_id=verification.id,
        verdict=verdict,
        finding_status=updated.status if updated is not None else finding.status,
        requests_spent=requests_spent,
        replay_evidence_ids=tuple(request_ids),
        detail=detail,
        counterevidence=counterevidence,
    )
