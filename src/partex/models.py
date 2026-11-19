"""Pydantic data contracts — PLAN §5.

All models enforce `extra='forbid'`, use `Annotated` + `Field` / `StringConstraints` / `AfterValidator`
for field-level bounds, and express discriminated unions via `TypeAdapter`.
Python 3.14 syntax throughout: PEP 695 `type` aliases, no `from __future__ import annotations`.
"""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Discriminator, Field, TypeAdapter

Severity = Literal['info', 'low', 'medium', 'high', 'critical']

# ── Evidence shapes ──────────────────────────────────────────────────────────


class HttpRequest(BaseModel):
    """A captured HTTP request."""

    model_config = ConfigDict(extra='forbid')

    method: str
    url: str
    headers: dict[str, str]
    body: str | None = None


class HttpResponse(BaseModel):
    """A captured HTTP response."""

    model_config = ConfigDict(extra='forbid')

    status_code: int
    headers: dict[str, str]
    body: str | None = None


class HttpExchange(BaseModel):
    """An HTTP request / response pair."""

    model_config = ConfigDict(extra='forbid')

    request: HttpRequest
    response: HttpResponse


class ConfigExcerpt(BaseModel):
    """A captured configuration or contract document excerpt.

    `format` examples: ``openapi``, ``config``.
    ``revision`` is a git SHA or version string carried onto findings so the contract
    revision the check was run against is auditable.
    """

    model_config = ConfigDict(extra='forbid')

    path: str
    format: str
    content: str
    revision: str | None = None


# ── Evidence wrappers with discriminated union ────────────────────────────────


class HttpEvidence(BaseModel):
    """Evidence wrapping an HTTP exchange.

    ``id`` is derived from the canonical JSON of ``kind`` + ``http`` only (§12),
    so the same exchange hashes identically whether captured live or re-imported from a bundle.
    """

    model_config = ConfigDict(extra='forbid')

    id: str
    kind: Literal['http_exchange'] = 'http_exchange'
    source: str
    http: HttpExchange
    secret_fields: list[str] = Field(default_factory=list)


class ConfigEvidence(BaseModel):
    """Evidence wrapping a configuration excerpt."""

    model_config = ConfigDict(extra='forbid')

    id: str
    kind: Literal['config_excerpt'] = 'config_excerpt'
    source: str
    config: ConfigExcerpt
    secret_fields: list[str] = Field(default_factory=list)


type Evidence = HttpEvidence | ConfigEvidence

EvidenceType = Annotated[Evidence, Discriminator('kind')]

# Discriminated union adapter for storage round-trips and validation.
EvidenceAdapter: TypeAdapter[Evidence] = TypeAdapter(EvidenceType)


# ── Findings, verification, coverage ──────────────────────────────────────────


class FindingDraft(BaseModel):
    """A finding produced by a check — before the engine assigns final IDs.

    The engine validates drafts (known check_id, valid severity, evidence_ids resolve)
    and then persists them as ``Finding`` records with final IDs assigned.
    """

    model_config = ConfigDict(extra='forbid')

    check_id: str
    check_version: str
    severity: Severity
    title: str
    description: str
    evidence_ids: Annotated[list[str], Field(min_length=1)]
    remediation: str


class Finding(BaseModel):
    """A persisted finding with engine-assigned IDs."""

    model_config = ConfigDict(extra='forbid')

    id: str
    check_id: str
    check_version: str
    severity: Severity
    title: str
    description: str
    evidence_ids: Annotated[list[str], Field(min_length=1)]
    remediation: str
    status: Literal['reported', 'verified', 'verification_failed']
    verification_id: str | None = None


class VerificationRequest(BaseModel):
    """A single request in a verification recipe."""

    model_config = ConfigDict(extra='forbid')

    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class VerificationRecipe(BaseModel):
    """The minimal request set that confirms a finding (returned by ``verify_recipe``)."""

    model_config = ConfigDict(extra='forbid')

    description: str
    requests: list[VerificationRequest]


class Verification(BaseModel):
    """A verification record attached to a finding."""

    model_config = ConfigDict(extra='forbid')

    id: str
    finding_id: str
    check_id: str
    requests: list[str]
    verdict: Literal['confirmed', 'not_reproduced', 'inconclusive']
    replayable: bool
    detail: str
    counterevidence: str


class CoverageEntry(BaseModel):
    """Coverage ledger entry tracking what was tested on a given surface."""

    model_config = ConfigDict(extra='forbid')

    surface: str
    risk_area: str
    outcome: Literal['reported', 'no_issue_found', 'ruled_out', 'not_applicable', 'needs_follow_up']
    source: Literal['check_observed', 'agent_reported']
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str = ''
    goal_attempts: int = 0


class ReviewSummary(BaseModel):
    """A model-generated narrative summary of a run's findings."""

    model_config = ConfigDict(extra='forbid')

    narrative: str
    finding_ids: list[str] = Field(default_factory=list)


# ── Scope and engagement ──────────────────────────────────────────────────────


class Scope(BaseModel):
    """Engagement scope — defines the attack surface boundary (§4.2)."""

    model_config = ConfigDict(extra='forbid')

    hosts: list[str] = Field(min_length=1)
    path_prefixes: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    ports: Annotated[list[int], Field(default_factory=list)]
    max_rps: Annotated[int, Field(gt=0)] = 5
    max_requests: Annotated[int, Field(gt=0)] = 2000


class EngagementTarget(BaseModel):
    """Target application descriptor inside an engagement."""

    model_config = ConfigDict(extra='forbid')

    name: str
    base_url: str


class Authorization(BaseModel):
    """Authorization attestation — required before any live traffic."""

    model_config = ConfigDict(extra='forbid')

    attestation: str
    operator: str


class Engagement(BaseModel):
    """An engagement manifest declaring a live target and the authority to test it (§4.1)."""

    model_config = ConfigDict(extra='forbid')

    schema_version: int = 1
    target: EngagementTarget
    scope: Scope
    authorization: Authorization
    credentials: dict[str, str] = Field(default_factory=dict)
    roles: dict[str, str] = Field(default_factory=dict)
    suggested_checks: list[str] = Field(default_factory=list)


# ── Redaction ──────────────────────────────────────────────────────────────────


def _set_at_path(data: dict[str, Any], path_parts: list[str], value: Any) -> None:
    """Walk *data* by *path_parts* and replace the leaf with *value*."""
    current: dict[str, Any] | list[Any] = data  # type: ignore[assignment]
    for key in path_parts[:-1]:
        if isinstance(current, list):
            idx = int(key)
            current = current[idx]  # type: ignore[list-item]
        else:
            current = current[key]  # type: ignore[index]
    final = path_parts[-1]
    if isinstance(current, list):
        current[int(final)] = value
    else:
        current[final] = value  # type: ignore[literal-required]


def redact(evidence: Evidence) -> Evidence:
    """Return a copy of *evidence* with every ``secret_field`` replaced by ``<redacted>``.

    ``secret_fields`` are JSON-path-like strings (e.g. ``$.http.request.headers.Authorization``)
    that navigate the serialised model.  The leading ``$.`` is stripped before traversal.
    """
    if not evidence.secret_fields:
        return evidence

    serialised = evidence.model_dump(mode='json')
    for sf in evidence.secret_fields:
        path = sf.removeprefix('$').lstrip('.')
        parts = path.split('.') if path else []
        if parts:
            try:
                _set_at_path(serialised, parts, '<redacted>')
            except KeyError, IndexError, ValueError, TypeError:
                # Path does not resolve — skip silently (field may not exist in this evidence).
                pass

    return EvidenceAdapter.validate_python(serialised)
