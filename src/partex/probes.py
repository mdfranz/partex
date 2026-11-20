"""Bundle surface → live probe candidates — the capture→probe bridge (issue #76; PLAN §17.5 Q5).

``partex import-har`` (#28) made an operator capture into passive evidence; this module turns
that evidence into the candidate probe list a live engagement can execute. There is deliberately
**no replay transport**: candidates are method + path + query only, and they run through the
engine's scoped client under the engagement's own gates — never a byte-for-byte replay of
captured requests (PLAN §17.5 Q5: the scoped client stays the only engine-driven live-capture
door).

Locked design decisions (issue #76 comment):

- **No captured secrets leave the box.** ``Cookie``/``Authorization`` values stay in the
  bundle's ``secret_fields``; engagement roles supply credentials the normal way. Candidates
  never carry headers or bodies at all.
- **Methods:** GET/HEAD/OPTIONS only — state-changing requests need #65's operator-approval
  path; other observed methods are counted, not probed.
- **Scope, twice-filtered:** candidates are re-filtered against the **engagement's** scope with
  the same :func:`partex.scope.check_url` gate the client uses — the capture's origin scope is
  not the engagement's. Drops are counted, never silent.
- **Deterministic:** a pure function of (bundle, engagement): the same inputs produce the same
  ordered candidate list (registration order), so seeding is reproducible.
"""

from dataclasses import dataclass

from .bundle import LoadedBundle
from .engagement import Engagement
from .errors import ScopeViolation
from .models import HttpEvidence
from .scope import check_url

__all__ = [
    'SEED_METHODS',
    'ProbeCandidate',
    'SeedPlan',
    'plan_seed_probes',
    'seed_lines',
]

SEED_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})
"""Methods a seeded probe may use (state-changing methods need #65's approval path)."""


@dataclass(frozen=True, slots=True)
class ProbeCandidate:
    """One candidate probe derived from captured evidence: method + URL, nothing else."""

    method: str
    """Uppercase HTTP method, one of :data:`SEED_METHODS`."""

    url: str
    """The absolute captured URL: scheme + host + port + path + query, credentials excluded."""

    source_id: str
    """The bundle evidence ``ev_*`` this candidate was derived from (provenance for the audit)."""


@dataclass(frozen=True, slots=True)
class SeedPlan:
    """The planned candidates plus every reported drop count (never silent)."""

    candidates: tuple[ProbeCandidate, ...]
    dropped_out_of_scope: int
    """Outside the engagement's scope — the capture's origin scope is not the engagement's."""
    dropped_methods: int
    """Observed methods outside GET/HEAD/OPTIONS."""
    dropped_duplicates: int
    """Byte-identical (method, URL) pairs seen earlier in the bundle."""
    dropped_capped: int
    """Candidates beyond ``limit`` (``--max-seed``)."""

    @property
    def dropped_total(self) -> int:
        return self.dropped_out_of_scope + self.dropped_methods + self.dropped_duplicates + self.dropped_capped


def plan_seed_probes(bundle: LoadedBundle, engagement: Engagement, *, limit: int | None = None) -> SeedPlan:
    """Plan the seeded probes for *engagement* from *bundle*'s captured surface.

    One candidate per observed ``(method, URL)`` in bundle registration order, re-filtered
    against the engagement scope, de-duplicated, and capped at *limit*. Pure and deterministic:
    the same (bundle, engagement, limit) produce the same plan.
    """
    candidates: list[ProbeCandidate] = []
    seen: set[tuple[str, str]] = set()
    out_of_scope = methods = duplicates = capped = 0
    for item in bundle.evidence:
        if not isinstance(item, HttpEvidence):
            continue
        method = item.http.request.method.upper()
        if method not in SEED_METHODS:
            methods += 1
            continue
        url = item.http.request.url
        key = (method, url)
        if key in seen:
            duplicates += 1
            continue
        try:
            check_url(engagement.scope, url)
        except ScopeViolation:
            out_of_scope += 1
            continue
        if limit is not None and len(candidates) >= limit:
            capped += 1
            continue
        seen.add(key)
        candidates.append(ProbeCandidate(method=method, url=url, source_id=item.id))
    return SeedPlan(
        candidates=tuple(candidates),
        dropped_out_of_scope=out_of_scope,
        dropped_methods=methods,
        dropped_duplicates=duplicates,
        dropped_capped=capped,
    )


def seed_lines(plan: SeedPlan) -> tuple[str, ...]:
    """``"METHOD URL"`` per candidate — the read-only surface shown to operators and agents."""
    return tuple(f'{candidate.method} {candidate.url}' for candidate in plan.candidates)


def seed_summary(plan: SeedPlan, seeded: int, *, seed_skipped: int = 0) -> str:
    """One human line describing what a seeding did (used by the CLI and the audit record)."""
    parts = [f'{seeded}/{len(plan.candidates)} seeded']
    if seed_skipped:
        parts.append(f'{seed_skipped} refused at send time')
    if plan.dropped_out_of_scope:
        parts.append(f'{plan.dropped_out_of_scope} out of scope')
    if plan.dropped_methods:
        parts.append(f'{plan.dropped_methods} non-GET/HEAD/OPTIONS')
    if plan.dropped_duplicates:
        parts.append(f'{plan.dropped_duplicates} duplicates')
    if plan.dropped_capped:
        parts.append(f'{plan.dropped_capped} over --max-seed')
    return f'bundle surface: {", ".join(parts)}'


def plan_summary(plan: SeedPlan) -> str:
    """One human line describing a plan before anything is sent (``partex agent --bundle``)."""
    parts = [f'{len(plan.candidates)} in-scope candidates']
    if plan.dropped_out_of_scope:
        parts.append(f'{plan.dropped_out_of_scope} out of scope')
    if plan.dropped_methods:
        parts.append(f'{plan.dropped_methods} non-GET/HEAD/OPTIONS')
    if plan.dropped_duplicates:
        parts.append(f'{plan.dropped_duplicates} duplicates')
    if plan.dropped_capped:
        parts.append(f'{plan.dropped_capped} over the cap')
    return ', '.join(parts)
