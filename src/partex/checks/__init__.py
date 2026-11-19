"""Check protocols and draft types — PLAN §5, §8, §10.

Checks are code; skills are data.  They are joined by ``check_id`` and stay
outside the engine.  Check code loads only from installed distributions via
the ``partex.checks`` entry point.
"""

from collections.abc import Sequence
from typing import Protocol

from ..models import Evidence, Finding, FindingDraft, HttpEvidence, VerificationRecipe

# ── Target client protocol ────────────────────────────────────────────────────


class TargetClient(Protocol):
    """What checks, the verification runner, and the agent see of the scoped client.

    The real implementation is ``target.py`` — the only engine module that opens
    sockets.  Every outbound request is scope-validated at send time (§4.2).
    Checks receive this handle; they never construct their own HTTP stack.

    Aligned with the shipped client (issue #20): a request returns the
    captured exchange as evidence — checks need the ``ev_*`` id to cite in
    drafts — and the scope gate needs the full URL, not a bare path.
    """

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> HttpEvidence:
        """Send a scoped request and return the captured exchange as evidence.

        Scope violation, budget exhaustion, and transport errors raise through
        the engine's error taxonomy (§9); ``secret_fields`` are already marked
        on the returned record.
        """
        raise NotImplementedError  # Protocol — only for static typing


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

    def verify_recipe(self, finding: Finding) -> VerificationRecipe | None: ...
