"""Pydantic data contracts — PLAN §5.

All models enforce `extra='forbid'`, use `Annotated` + `Field` / `StringConstraints` / `AfterValidator`
for field-level bounds, and express discriminated unions via `TypeAdapter`.
Python 3.14 syntax throughout: PEP 695 `type` aliases, no `from __future__ import annotations`.
"""

import re
from collections.abc import Sequence
from typing import Annotated, Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Discriminator, Field, TypeAdapter, field_validator, model_validator

Severity = Literal['info', 'low', 'medium', 'high', 'critical']

# ── Headers ──────────────────────────────────────────────────────────────────

type Headers = list[tuple[str, str]]
"""HTTP headers as ``(name, value)`` pairs in wire order, original casing, repeats preserved.

Serialized as a JSON array of two-element arrays: ``[["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]]``.
Look headers up with :func:`get_header` / :func:`get_all` (case-insensitive), never by position.
"""


def get_header(headers: Sequence[tuple[str, str]], name: str) -> str | None:
    """Return the first value of header *name* (case-insensitive), or ``None``."""
    wanted = name.lower()
    for key, value in headers:
        if key.lower() == wanted:
            return value
    return None


def get_all(headers: Sequence[tuple[str, str]], name: str) -> list[str]:
    """Return every value of header *name* (case-insensitive), in wire order."""
    wanted = name.lower()
    return [value for key, value in headers if key.lower() == wanted]


# ── Evidence shapes ──────────────────────────────────────────────────────────


class HttpRequest(BaseModel):
    """A captured HTTP request."""

    model_config = ConfigDict(extra='forbid')

    method: str
    url: str
    headers: Headers
    body: str | None = None


class HttpResponse(BaseModel):
    """A captured HTTP response."""

    model_config = ConfigDict(extra='forbid')

    status_code: int
    headers: Headers
    body: str | None = None
    body_note: Literal['truncated', 'refused'] | None = Field(default=None, exclude_if=lambda note: note is None)
    """Why ``body`` is not the full response body: ``truncated`` (cut at the capture cap) or ``refused``
    (binary or not UTF-8, so not stored). Omitted from serialization when unset, so evidence IDs of
    complete bodies are unchanged (§12)."""


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
    tls_verified: bool = Field(default=True, exclude_if=lambda verified: verified)
    """``False`` when the certificate was not verified for this exchange (operator-accepted invalid TLS, #71).
    Left out of dumps and exports while ``True`` (so strict runs are unchanged), and excluded from the evidence
    ID, like ``source``, so the same exchange hashes the same either way."""

    @model_validator(mode='after')
    def _secret_fields_resolve(self) -> Self:
        _validate_secret_fields(self)
        return self


class ConfigEvidence(BaseModel):
    """Evidence wrapping a configuration excerpt."""

    model_config = ConfigDict(extra='forbid')

    id: str
    kind: Literal['config_excerpt'] = 'config_excerpt'
    source: str
    config: ConfigExcerpt
    secret_fields: list[str] = Field(default_factory=list)

    @model_validator(mode='after')
    def _secret_fields_resolve(self) -> Self:
        _validate_secret_fields(self)
        return self


class ArtifactAsset(BaseModel):
    """Metadata for a downloaded full-body asset (e.g. a JavaScript bundle) stored on disk."""

    model_config = ConfigDict(extra='forbid')

    url: str
    status_code: int
    headers: Headers
    content_type: str | None = None
    sha256: str
    size_bytes: int


class ArtifactEvidence(BaseModel):
    """Evidence referencing a locally stored full-body asset (mode 0600, content-addressed).

    ``id`` is derived from ``kind`` + ``artifact`` only (§12), excluding ``file_path`` so the
    ID is machine-independent.
    """

    model_config = ConfigDict(extra='forbid')

    id: str
    kind: Literal['artifact'] = 'artifact'
    source: str
    artifact: ArtifactAsset
    file_path: str | None = None
    secret_fields: list[str] = Field(default_factory=list)
    tls_verified: bool = Field(default=True, exclude_if=lambda verified: verified)
    """``False`` when the download did not verify the certificate (#71); see :class:`HttpEvidence`."""

    @model_validator(mode='after')
    def _secret_fields_resolve(self) -> Self:
        _validate_secret_fields(self)
        return self


type Evidence = HttpEvidence | ConfigEvidence | ArtifactEvidence

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
    subject: Annotated[str, Field(min_length=1)]
    """What the finding is about, distinguishing findings that share a title and evidence.

    Examples: ``cookie:sessionid``, ``header:strict-transport-security``, ``op:GET /api/users/{id}``.
    Part of the finding ID (§12).
    """
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
    subject: Annotated[str, Field(min_length=1)]
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
    urls: list[str] = Field(default_factory=list, exclude_if=lambda urls: not urls)
    """Exact URL allowlist (#121); empty means no URL-level restriction. Left out of dumps while empty."""
    ports: Annotated[list[int], Field(default_factory=list)]
    max_rps: Annotated[int, Field(gt=0)] = 5
    max_requests: Annotated[int, Field(gt=0)] = 2000


class EngagementTarget(BaseModel):
    """Target application descriptor inside an engagement."""

    model_config = ConfigDict(extra='forbid')

    name: str
    base_url: str


class TlsPolicy(BaseModel):
    """TLS verification for the target client (#71). Strict by default; relaxed only by the operator.

    ``verify: false`` accepts invalid certificates (self-signed, private CA, expired, hostname mismatch) for
    ``insecure_hosts``, or for every in-scope host when that list is empty. Never set from a model.
    """

    model_config = ConfigDict(extra='forbid')

    verify: bool = True
    insecure_hosts: list[str] = Field(default_factory=list)


USER_AGENT_MAX_CHARS = 512
_USER_AGENT_CHARS = re.compile(r'[\x20-\x7e]+')


def check_user_agent(value: str) -> str:
    """Validate a configured User-Agent (#135): one line of printable ASCII, not blank, at most 512 characters.

    Printable ASCII rules out CR/LF (header injection), every other control or format character, and values
    an HTTP/1.1 header cannot carry. Raises :class:`ValueError`; returns *value* unchanged.
    """
    if not value.strip():
        raise ValueError('user_agent must not be empty')
    if len(value) > USER_AGENT_MAX_CHARS:
        raise ValueError(f'user_agent exceeds {USER_AGENT_MAX_CHARS} characters ({len(value)} given)')
    if not _USER_AGENT_CHARS.fullmatch(value):
        raise ValueError('user_agent must be a single line of printable ASCII (no control or format characters)')
    return value


class HttpPolicy(BaseModel):
    """HTTP presentation for the target client (#135), symmetric with :class:`TlsPolicy`.

    ``user_agent`` is sent on every request this engagement makes unless a request sets its own. Unset means
    ``partex/<engine version>``, never the HTTP library's own default (which would disclose the tool stack).
    Not a secret: it is captured in evidence like any other request header.
    """

    model_config = ConfigDict(extra='forbid')

    user_agent: str | None = None

    @field_validator('user_agent')
    @classmethod
    def _valid_user_agent(cls, value: str | None) -> str | None:
        return None if value is None else check_user_agent(value)


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
    tls: TlsPolicy = Field(default_factory=TlsPolicy)
    http: HttpPolicy = Field(default_factory=HttpPolicy)
    authorization: Authorization
    credentials: dict[str, str] = Field(default_factory=dict)
    roles: dict[str, str] = Field(default_factory=dict)
    suggested_checks: list[str] = Field(default_factory=list)


# ── Secret paths and redaction ───────────────────────────────────────────────

REDACTED = '<redacted>'

_PATH_TOKEN = re.compile(r'\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]')

type _PathPart = str | int


def parse_secret_path(path: str) -> tuple[_PathPart, ...]:
    """Parse a ``secret_fields`` path into keys and indexes.

    Grammar: ``$`` followed by ``.name`` (object key) and ``[n]`` (array index) steps, e.g.
    ``$.http.request.headers[2][1]`` (the value of request header 2) or ``$.http.request.body``.
    Header names never appear in paths, so casing and dots in names cannot break redaction.
    Raises :class:`ValueError` on anything else.
    """
    if not path.startswith('$'):
        raise ValueError(f'secret path {path!r} must start with "$"')
    parts: list[_PathPart] = []
    position = 1
    while position < len(path):
        match = _PATH_TOKEN.match(path, position)
        if match is None:
            raise ValueError(f'secret path {path!r} is malformed at offset {position}')
        key, index = match.groups()
        parts.append(key if key is not None else int(index))
        position = match.end()
    if not parts:
        raise ValueError(f'secret path {path!r} names no field')
    return tuple(parts)


def _resolve_parent(data: Any, parts: tuple[_PathPart, ...]) -> tuple[Any, _PathPart]:
    """Walk to the container of the leaf; raise :class:`ValueError` unless it is a string leaf."""
    current = data
    for part in parts[:-1]:
        current = _step(current, part)
    leaf = parts[-1]
    if not isinstance(_step(current, leaf), str):
        # ValueError, not TypeError: pydantic only turns ValueError into a ValidationError.
        raise ValueError('does not name a string value')  # noqa: TRY004
    return current, leaf


def _step(container: Any, part: _PathPart) -> Any:
    if isinstance(part, int):
        if isinstance(container, list) and 0 <= part < len(cast(list[Any], container)):
            return cast(list[Any], container)[part]
    elif isinstance(container, dict) and part in container:
        return cast(dict[str, Any], container)[part]
    raise ValueError(f'step {part!r} does not resolve')


def _validate_secret_fields(evidence: HttpEvidence | ConfigEvidence | ArtifactEvidence) -> None:
    """Every ``secret_fields`` path must parse and name a string value of this evidence.

    Checked at construction so :func:`redact` can never meet a path it cannot apply: a secret
    marking that does not resolve is an input error, not something to skip at the export boundary.
    """
    if not evidence.secret_fields:
        return
    data = evidence.model_dump(mode='json')
    if isinstance(evidence, HttpEvidence):
        payload = 'http'
    elif isinstance(evidence, ConfigEvidence):
        payload = 'config'
    else:
        payload = 'artifact'
    for path in evidence.secret_fields:
        try:
            parts = parse_secret_path(path)
            if parts[0] != payload:  # never id/kind/source: redacting those would corrupt the record
                raise ValueError(f'must point inside ${payload}')
            _resolve_parent(data, parts)
        except ValueError as exc:
            raise ValueError(f'secret_fields entry {path!r}: {exc}') from None


def _redact_set_cookie(value: str) -> str:
    """``sid=abc; Path=/; Secure`` → ``sid=<redacted>; Path=/; Secure``: the value goes, attributes stay."""
    pair, sep, attributes = value.partition(';')
    name, has_value, _ = pair.partition('=')
    if not has_value:
        return REDACTED
    return f'{name.strip()}={REDACTED}{sep}{attributes}'


def _redact_cookie_header(value: str) -> str:
    """``a=1; b=2`` → ``a=<redacted>; b=<redacted>``: which cookies were sent stays visible."""
    return '; '.join(
        f'{name.strip()}={REDACTED}' if has_value else REDACTED
        for name, has_value, _ in (pair.partition('=') for pair in value.split(';'))
    )


def _redacted_value(container: Any, leaf: _PathPart) -> str:
    """The replacement for one secret value; cookie headers keep their structure (PLAN §5, value-only)."""
    if leaf == 1 and isinstance(container, list) and len(cast(list[Any], container)) == 2:
        name, value = cast(list[str], container)
        match name.lower():
            case 'set-cookie':
                return _redact_set_cookie(value)
            case 'cookie':
                return _redact_cookie_header(value)
            case _:
                pass
    return REDACTED


def redact(evidence: Evidence) -> Evidence:
    """Return a copy of *evidence* with every ``secret_fields`` value replaced by ``<redacted>``.

    Paths were validated when *evidence* was constructed, so every one resolves. For a header only
    the value is replaced (``headers[i][1]``) and the name stays visible; for cookie headers only
    the cookie values are (``Set-Cookie: sid=<redacted>; Path=/; Secure``, ``Cookie: a=<redacted>``),
    so cookie attributes stay reviewable after redaction.
    """
    if not evidence.secret_fields:
        return evidence
    data = evidence.model_dump(mode='json')
    for path in evidence.secret_fields:
        parent, leaf = _resolve_parent(data, parse_secret_path(path))
        parent[leaf] = _redacted_value(parent, leaf)
    return EvidenceAdapter.validate_python(data)
