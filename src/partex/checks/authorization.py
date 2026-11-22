"""authz-boundary — built-in active check for BOLA/IDOR/BFLA role-pair probing.

Issue #27 (Slice S2, PARTX_SKILL_PLAN §4 P1.2).  Guidance lives in
``skills/authorization-testing/`` (data, never executed).  The two-role rule is
absolute (skill §2): an access-control finding is never claimed from a single
response — it compares at least two role-scoped identities from
``engagement.roles`` and cites both exchanges.

v1 scope (issue comment): read-only cross-role probing only.  Safe-method
(``GET``/``HEAD``/``OPTIONS``) object reads and privileged reads are compared
across roles; every other method — ``POST``/``PUT``/``PATCH``/``DELETE`` and
anything else a target might accept — is recorded ``needs_follow_up``, never
sent, until the operator write-approval gate (#65) and the method-policy
schema (#119) land.

The first role declared in ``engagement.roles`` is the *baseline* (Role A in
``role-pair-probing.md``): the probe walks roles in declaration order and the
draft cites evidence baseline-first, so the verify runner's ``original`` is
the baseline exchange and the recipe leads with a cross-role replay.  (The
citation order is deliberate, never id-sorted — ``evidence_id`` is a content
hash, so sorting would make the recipe's lead a coin flip.)  Live sessions do
not bind role handles yet, so there the probe claims nothing and coverage
records ``needs_follow_up``.

Candidate operations are harvested from captured evidence (observed object
paths collapsed to ``{id}`` templates); a run with no object-scoped or
privileged traffic yields ``not_applicable`` (missing evidence), not findings.
Each role authenticates as ``Authorization: Bearer <role credential>`` (the
#23 convention); credentials are blanket-marked secret at capture, so they
never reach findings, coverage, or exports.

``role_aware = True`` tells the engine (``engine.run_test``) to bind
``engagement.roles`` to per-role client handles and pass them to ``probe``.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..ids import normalized_operation_key
from ..models import (
    CoverageEntry,
    Evidence,
    Finding,
    FindingDraft,
    HttpEvidence,
    Severity,
    VerificationRecipe,
    VerificationRequest,
    get_header,
)
from ..roles import RoleHandle
from . import TargetClient
from .api_inventory import collapse_path_ids

CHECK_ID = 'authz-boundary'
CHECK_VERSION = '1.0'
CHECK_TITLE = 'Authorization Boundary (BOLA / IDOR / BFLA)'
CHECK_DESCRIPTION = (
    'Compare object-scoped and privileged operations across engagement roles: cross-role replay '
    'of observed object identifiers (BOLA/IDOR) and lower-privilege access to privileged '
    'operations (BFLA), always citing at least two role-scoped exchanges.'
)

_SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})

# Numeric, UUID, and long-hex path segments are concrete object ids (mirrors api_inventory's collapse).
_ID_SEG = re.compile(r'\d+|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,}')
# `/admin`, `/api/admin`, `/v1/admin/...` — function-level (BFLA) surfaces.
_ADMIN_RE = re.compile(r'^/(?:[^/]+/)?(?:v\d+/)?admin(?:/|$)', re.IGNORECASE)
# A role capture's source cites its role as `...:role=<name>` (roles.py).
_ROLE_RE = re.compile(r':role=([^:]+)$')


@dataclass(frozen=True, slots=True)
class Candidate:
    """One operation worth cross-role probing, harvested from captured evidence."""

    method: str
    key: str
    concrete_url: str
    object_ids: tuple[str, ...]
    category: str  # 'bola' | 'bfla' | 'gated'
    evidence_id: str


def _path_segments(path: str) -> list[str]:
    return [seg for seg in path.strip('/').split('/') if seg]


def _concrete_ids(path: str) -> tuple[str, ...]:
    return tuple(seg for seg in _path_segments(path) if _ID_SEG.fullmatch(seg))


def _role_of(source: str) -> str | None:
    match = _ROLE_RE.search(source)
    return match.group(1) if match else None


def _names_id(body: str, object_ids: tuple[str, ...]) -> bool:
    """True when *body* carries one of *object_ids* as a standalone token.

    The id must sit on token boundaries — id ``'4'`` must not match ``{"count": 14}`` —
    so a match is never a substring of a longer numeric/hex run.
    """
    return any(re.search(rf'(?<![0-9A-Fa-f]){re.escape(oid)}(?![0-9A-Fa-f])', body) for oid in object_ids)


def harvest_candidates(evidence: Sequence[Evidence]) -> tuple[Candidate, ...]:
    """Object-scoped and privileged operations observed in *evidence*, one per normalized key.

    Only safe methods (``GET``/``HEAD``/``OPTIONS``) are probed; every other method classifies
    ``gated`` (never sent, #65).  Any object-id-bearing safe-method path classifies ``bola``;
    an ``/admin``-prefixed safe-method read classifies ``bfla``.  Deterministic: first exchange
    wins per key, keys sorted.
    """
    by_key: dict[str, Candidate] = {}
    for item in evidence:
        if not isinstance(item, HttpEvidence):
            continue
        method = item.http.request.method.upper()
        path = urlsplit(item.http.request.url).path
        object_ids = _concrete_ids(path)
        if method not in _SAFE_METHODS:
            category = 'gated'
        elif object_ids:
            category = 'bola'
        elif _ADMIN_RE.match(path):
            category = 'bfla'
        else:
            continue
        key = normalized_operation_key(method, collapse_path_ids(path))
        if key in by_key:
            continue
        by_key[key] = Candidate(
            method=method,
            key=key,
            concrete_url=item.http.request.url,
            object_ids=object_ids,
            category=category,
            evidence_id=item.id,
        )
    return tuple(by_key[key] for key in sorted(by_key))


def auth_headers(handle: RoleHandle) -> dict[str, str]:
    """The v1 role-auth header: the role credential as a Bearer token (issue #23 convention)."""
    return {'Authorization': f'Bearer {handle.credential}'}


def _origin_of(exchange: HttpEvidence) -> str:
    parts = urlsplit(exchange.http.request.url)
    return f'{parts.scheme}://{parts.netloc}'


class AuthzBoundaryCheck:
    """The active probe: cross-role replay of object-scoped and privileged reads."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION
    role_aware = True

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return any(isinstance(item, HttpEvidence) for item in evidence)

    async def probe(
        self,
        evidence: Sequence[Evidence],
        client: TargetClient,
        *,
        roles: Mapping[str, RoleHandle] | None = None,
    ) -> list[FindingDraft]:
        """Replay each candidate under every role; a finding needs at least two roles to succeed.

        ``client`` is the engagement's unauthenticated handle; role probing goes through the
        per-role handles the engine binds from ``engagement.roles``, walked in declaration
        order (the first declared role is the baseline).  With fewer than two role handles
        nothing is claimed — the coverage hook records ``needs_follow_up`` instead.
        """
        handles = dict(roles or {})  # declaration order preserved: baseline first
        drafts: list[FindingDraft] = []
        for candidate in harvest_candidates(evidence):
            drafts.extend(await self._probe_candidate(candidate, handles))
        return drafts

    async def _probe_candidate(self, candidate: Candidate, handles: Mapping[str, RoleHandle]) -> list[FindingDraft]:
        if candidate.category == 'gated' or len(handles) < 2:
            return []  # gated methods are never sent (#65); a single response can never found a finding
        accesses: list[tuple[str, HttpEvidence]] = []
        for role in handles:
            evidence = await handles[role].client.request(
                candidate.method, candidate.concrete_url, headers=auth_headers(handles[role])
            )
            if 200 <= evidence.http.response.status_code < 300 and self._exposes(candidate, evidence):
                accesses.append((role, evidence))
        if len(accesses) < 2:
            return []
        return [self._draft(candidate, accesses)]

    @staticmethod
    def _exposes(candidate: Candidate, exchange: HttpEvidence) -> bool:
        """A 2xx exposes the object when its body carries one of the harvested object ids as a token."""
        if candidate.category != 'bola':
            return True
        body = exchange.http.response.body or ''
        return bool(candidate.object_ids) and _names_id(body, candidate.object_ids)

    def _draft(self, candidate: Candidate, accesses: Sequence[tuple[str, HttpEvidence]]) -> FindingDraft:
        """Build the finding, citing evidence in probe order: baseline role first, cross-roles after.

        ``accesses`` arrive in engagement declaration order, so ``evidence_ids[0]`` is the
        baseline exchange (the verify runner's ``original``) and ``evidence_ids[-1]`` a
        cross-role one (the recipe's lead).  The order is deliberate, never id-sorted:
        ``evidence_id`` is a content hash, so sorting would make the recipe's lead a coin
        flip (#27 review).
        """
        roles = ', '.join(role for role, _ in accesses)
        evidence_ids = [exchange.id for _, exchange in accesses]
        if candidate.category == 'bola':
            severity: Severity = 'high'
            subject = f'bola:{candidate.key}'
            title = f'Missing object-level authorization on {candidate.key}'
            description = (
                f'{candidate.key} returned success to multiple engagement roles ({roles}) for the same '
                f'object(s) ({", ".join(candidate.object_ids)}), so per-object authorization is not '
                'enforced (OWASP API1:2023 Broken Object Level Authorization).'
            )
            remediation = (
                'Enforce per-object authorization server-side: verify the caller owns (or is entitled to) '
                'the requested object id on every request, before returning or mutating it.'
            )
        else:
            severity = 'high'
            subject = f'bfla:{candidate.key}'
            title = f'Missing function-level authorization on {candidate.key}'
            description = (
                f'{candidate.key} (a privileged operation) returned success to multiple engagement roles '
                f'({roles}); the lower-privilege role can invoke it (OWASP API5:2023 Broken Function '
                'Level Authorization).'
            )
            remediation = (
                'Enforce role/function-level authorization on privileged operations; deny lower-privilege '
                'roles by default and require explicit grants.'
            )
        return FindingDraft(
            check_id=CHECK_ID,
            check_version=CHECK_VERSION,
            severity=severity,
            subject=subject,
            title=title,
            description=description,
            evidence_ids=evidence_ids,
            remediation=remediation,
        )

    def coverage(self, evidence: Sequence[Evidence]) -> list[CoverageEntry]:
        """Ledger rows re-derived from evidence: reported / no_issue_found / needs_follow_up / not_applicable.

        Role-tagged captures (``source ...:role=<name>``) reveal which roles were granted access for
        each candidate, so this stays a pure function of evidence — no probe state leaks across runs.
        """
        candidates = harvest_candidates(evidence)
        exchanges = [item for item in evidence if isinstance(item, HttpEvidence)]
        if not candidates:
            if not exchanges:
                return []
            return [
                CoverageEntry(
                    surface=_origin_of(exchanges[0]),
                    risk_area=CHECK_ID,
                    outcome='not_applicable',
                    source='check_observed',
                    evidence_ids=[exchanges[0].id],
                    reason='no object-scoped or privileged operation observed (missing evidence)',
                )
            ]
        return [self._coverage_entry(candidate, exchanges) for candidate in candidates]

    def _coverage_entry(self, candidate: Candidate, exchanges: Sequence[HttpEvidence]) -> CoverageEntry:
        if candidate.category == 'gated':
            return CoverageEntry(
                surface=candidate.key,
                risk_area=CHECK_ID,
                outcome='needs_follow_up',
                source='check_observed',
                evidence_ids=[candidate.evidence_id],
                reason='non-safe method; probe gated behind the operator write-approval gate (#65); not sent',
            )
        hits: dict[str, list[HttpEvidence]] = {}
        for exchange in exchanges:
            role = _role_of(exchange.source)
            if role is None:
                continue
            key = normalized_operation_key(
                exchange.http.request.method.upper(), collapse_path_ids(urlsplit(exchange.http.request.url).path)
            )
            if key == candidate.key:
                hits.setdefault(role, []).append(exchange)
        granted = [
            role
            for role in sorted(hits)
            if any(200 <= exchange.http.response.status_code < 300 for exchange in hits[role])
        ]
        evidence_ids = sorted({exchange.id for role_exchanges in hits.values() for exchange in role_exchanges})
        if len(granted) >= 2:
            return CoverageEntry(
                surface=candidate.key,
                risk_area=CHECK_ID,
                outcome='reported',
                source='check_observed',
                evidence_ids=evidence_ids,
                reason=f'granted to multiple roles ({", ".join(granted)})',
            )
        if len(hits) >= 2 and len(granted) == 1:
            return CoverageEntry(
                surface=candidate.key,
                risk_area=CHECK_ID,
                outcome='no_issue_found',
                source='check_observed',
                evidence_ids=evidence_ids,
                reason=f'only role {granted[0]} was granted access; the cross-role replay was denied',
            )
        return CoverageEntry(
            surface=candidate.key,
            risk_area=CHECK_ID,
            outcome='needs_follow_up',
            source='check_observed',
            evidence_ids=[candidate.evidence_id],
            reason='not probed across roles (no second role handle, or the probe was cut short)',
        )

    def verify_recipe(self, finding: Finding, evidence: Sequence[Evidence]) -> VerificationRecipe | None:
        """The minimal re-verification: both cited exchanges, each re-sent with its own role credential.

        The draft cites evidence baseline-first (probe order), so the last cited exchange is a
        cross-role capture; the rotation leads with it so the verify runner's first-replay
        matcher re-tests the boundary crossing, not the authorized baseline.  (With more than
        two granted roles the verdict still rests on that one lead replay — the runner only
        matches the first; handing every replay to the matcher is the #176 follow-up.)
        Returns ``None`` (reported-only) when a cited exchange lacks its ``Authorization``
        header to replay.
        """
        exchanges = [item for item in evidence if isinstance(item, HttpEvidence)]
        if len(exchanges) < 2:
            return None
        requests: list[VerificationRequest] = []
        for exchange in exchanges:
            authorization = get_header(exchange.http.request.headers, 'authorization')
            if authorization is None:
                return None
            requests.append(
                VerificationRequest(
                    method=exchange.http.request.method,
                    path=exchange.http.request.url,
                    headers={'Authorization': authorization},
                )
            )
        # Lead with the last cited (cross-role) exchange; the baseline, cited first, stays second.
        requests = [requests[-1], *requests[:-1]]
        return VerificationRecipe(
            description=f'Replay {finding.subject} across roles and re-test the authorization boundary.',
            requests=requests,
        )

    def verify_match(self, finding: Finding, original: HttpEvidence, replay: HttpEvidence) -> bool:
        """Confirmed iff the cross-role replay still returns the object (BOLA) or 2xx (BFLA)."""
        if not 200 <= replay.http.response.status_code < 300:
            return False
        if finding.subject.startswith('bola:'):
            object_ids = _concrete_ids(urlsplit(original.http.request.url).path)
            body = replay.http.response.body or ''
            return bool(object_ids) and _names_id(body, object_ids)
        return finding.subject.startswith('bfla:')


authz_boundary_check = AuthzBoundaryCheck()
