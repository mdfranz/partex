"""Check protocols and draft types — PLAN §5, §8, §10.

Checks are code; skills are data.  They are joined by ``check_id`` and stay
outside the engine.  Check code loads only from installed distributions via
the ``partex.checks`` entry point.
"""

from collections.abc import Mapping, Sequence
from typing import Protocol

from ..models import Evidence, Finding, FindingDraft, HttpEvidence, VerificationRecipe

type HeaderInput = Mapping[str, str] | Sequence[tuple[str, str]]
"""Request headers a caller may pass: a mapping, or ``(name, value)`` pairs (repeats allowed)."""

# ── Target client protocol ────────────────────────────────────────────────────


class TargetClient(Protocol):
    """What checks, the verification runner, and the agent see of the scoped client.

    The real implementation is :class:`partex.target.ScopedHttpClient` — the only engine module
    that opens sockets.  Every outbound request is scope-validated at send time (§4.2).  Checks
    receive this handle; they never construct their own HTTP stack.

    A request returns the captured exchange as evidence — checks need the ``ev_*`` id to cite
    in drafts — and the scope gate needs the full URL, not a bare path (#20, #39).
    """

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: HeaderInput | None = None,
        body: str | None = None,
    ) -> HttpEvidence:
        """Send a scoped request to absolute *url* and return the captured exchange as evidence.

        A check cites ``evidence.id`` in its drafts; ``secret_fields`` are already marked on the
        returned record.  Scope violation, budget exhaustion, and transport errors raise through
        the engine's error taxonomy (§9).
        """
        ...


# ── Check protocols ───────────────────────────────────────────────────────────


class PassiveCheck(Protocol):
    """Deterministic review of evidence — no I/O, network, model, or storage access."""

    check_id: str
    version: str
    title: str
    description: str

    def applies_to(self, evidence: Sequence[Evidence]) -> bool: ...

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]: ...


class ActiveCheck(Protocol):
    """Live probe check — sends traffic through the scoped ``TargetClient``.

    ``probe`` is async because the client is (anyio); the engine awaits it.
    Active checks produce findings that may carry a ``verify_recipe`` for later
    replayable verification.

    A check may set ``role_aware = True`` (class attribute).  The engine then
    binds ``engagement.roles`` to per-role :class:`~partex.target.ScopedHttpClient`
    handles (sharing the primary client's budget and DNS pins) and passes them as
    ``probe(evidence, client, roles=<name → partex.roles.RoleHandle>)`` so the
    check can compare scoped identities (#27).  Checks that don't set the flag
    keep the two-argument signature.
    """

    check_id: str
    version: str
    title: str
    description: str

    def applies_to(self, evidence: Sequence[Evidence]) -> bool: ...

    async def probe(
        self,
        evidence: Sequence[Evidence],
        client: TargetClient,
    ) -> Sequence[FindingDraft]: ...

    def verify_recipe(self, finding: Finding, evidence: Sequence[Evidence]) -> VerificationRecipe | None:
        """Build the minimal replay for *finding* from its own cited evidence.

        The runner (``verify.py``) loads the finding's cited evidence from the
        run store and passes it here — the check knows which exchange produced
        the finding and turns it into the exact ``(method, url)`` replay.
        Returns ``None`` for findings that cannot be replayed (reported-only).
        """
        raise NotImplementedError  # Protocol — only for static typing

    def verify_match(self, finding: Finding, original: HttpEvidence, replay: HttpEvidence) -> bool:
        """Return whether *replay* still exhibits what *original* did for *finding*.

        The check owns reproduction semantics: the runner executes the recipe,
        captures the replay exchange, and asks the check whether the finding's
        class is still present.  This is the confirmed/not_reproduced seam.
        """
        raise NotImplementedError  # Protocol — only for static typing
