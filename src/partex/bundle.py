"""Offline evidence bundle load and validation — PLAN §4.3.

A bundle is a directory with a ``bundle.json`` manifest and one evidence record per file::

    bundle/
      bundle.json            # schema_version, target, evidence_files, suggested_checks
      evidence/0001.json     # {"kind": "http_exchange", "http": {...}} or
                             # {"kind": "config_excerpt", "config": {...}}

Evidence files never carry ``id`` or ``source``: the engine derives the ID from content (§12) and the
source is the bundle-relative path. Every failure raises :class:`~partex.errors.ValidationFailed` with
a rule code before any check, model, or network call runs:

========  ===================================================  ======================
Rule      Requirement                                          Failure
========  ===================================================  ======================
V1        manifest exists, parses, ``schema_version == 1``     ``bundle-parse`` /
                                                               ``bundle-version``
V2        every evidence file is inside the bundle, exists,    ``evidence-invalid``
          is UTF-8 JSON, and passes its model
V3        evidence is deduplicated by content-derived ID       warning, not failure
V4        size caps (see constants below)                      ``evidence-too-large``
V6        unregistered ``suggested_checks`` are dropped        warning, not failure
========  ===================================================  ======================

``<redacted>`` markers are accepted wherever a producer sanitized a value; they are not required.
"""

import json
from collections.abc import Collection
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Discriminator, Field, TypeAdapter, ValidationError

from .errors import ValidationFailed
from .ids import canonical_json, evidence_id, sha256_hex
from .models import ConfigEvidence, ConfigExcerpt, Evidence, HttpEvidence, HttpExchange

MANIFEST_NAME = 'bundle.json'
SCHEMA_VERSION = 1

# V4 caps.
MAX_EVIDENCE_FILES = 500
MAX_CONTENT_BYTES = 256 * 1024  # per request/response body or config excerpt, UTF-8 encoded
MAX_HEADERS = 100  # per request or response
MAX_URL_BYTES = 64 * 1024
# Raw read caps: refuse oversized files before parsing them. JSON escaping can inflate a body that
# is within MAX_CONTENT_BYTES, so the per-file read cap is deliberately generous.
MAX_EVIDENCE_FILE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024


# ── On-disk shapes ────────────────────────────────────────────────────────────


class BundleTarget(BaseModel):
    """The application a bundle's evidence was captured from."""

    model_config = ConfigDict(extra='forbid')

    name: str
    base_url: str
    notes: str | None = None


class BundleManifest(BaseModel):
    """``bundle.json``."""

    model_config = ConfigDict(extra='forbid')

    schema_version: Literal[1]
    target: BundleTarget
    evidence_files: list[str]
    suggested_checks: list[str] = Field(default_factory=list[str])


class _HttpRecord(BaseModel):
    model_config = ConfigDict(extra='forbid')

    kind: Literal['http_exchange']
    http: HttpExchange
    secret_fields: list[str] = Field(default_factory=list[str])


class _ConfigRecord(BaseModel):
    model_config = ConfigDict(extra='forbid')

    kind: Literal['config_excerpt']
    config: ConfigExcerpt
    secret_fields: list[str] = Field(default_factory=list[str])


type _EvidenceRecord = Annotated[_HttpRecord | _ConfigRecord, Discriminator('kind')]

_record_adapter: TypeAdapter[_HttpRecord | _ConfigRecord] = TypeAdapter(_EvidenceRecord)


# ── Result ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class LoadedBundle:
    """A validated bundle, ready for evidence registration.

    ``evidence`` is in registration order: manifest order with later duplicates removed (V3).
    """

    root: Path
    manifest: BundleManifest
    evidence: tuple[Evidence, ...]
    fingerprint: str
    """``sha256`` over the sorted ``(file, sha256(file))`` pairs of the manifest and every evidence file."""
    suggested_checks: tuple[str, ...]
    """``manifest.suggested_checks`` minus unregistered IDs (V6)."""
    warnings: tuple[str, ...] = field(default=())


# ── Loading ───────────────────────────────────────────────────────────────────


def load_bundle(path: str | Path, *, known_checks: Collection[str] | None = None) -> LoadedBundle:
    """Load and validate the bundle directory at *path*.

    ``known_checks`` is the set of registered check IDs used for V6; when ``None`` (no registry
    available) every suggested check is kept.

    Raises:
        ValidationFailed: the bundle violates V1, V2, or V4; ``rule_code`` names the rule.
    """
    root = Path(path)
    manifest_bytes = _read_manifest(root)
    manifest = _parse_manifest(manifest_bytes)

    if len(manifest.evidence_files) > MAX_EVIDENCE_FILES:
        raise ValidationFailed(
            f'{MANIFEST_NAME}: {len(manifest.evidence_files)} evidence files exceeds the cap of {MAX_EVIDENCE_FILES}',
            rule_code='evidence-too-large',
        )

    warnings: list[str] = []
    file_hashes: dict[str, str] = {MANIFEST_NAME: sha256_hex(manifest_bytes)}
    evidence: list[Evidence] = []
    seen: dict[str, str] = {}
    for name in manifest.evidence_files:
        relative, raw = _read_evidence_file(root, name)
        file_hashes[relative] = sha256_hex(raw)
        item = _parse_evidence(relative, raw)
        if item.id in seen:
            warnings.append(f'{relative}: duplicate of {seen[item.id]} ({item.id}); skipped')
            continue
        seen[item.id] = relative
        evidence.append(item)

    suggested = tuple(manifest.suggested_checks)
    if known_checks is not None:
        unknown = [check for check in suggested if check not in known_checks]
        warnings.extend(f'{MANIFEST_NAME}: suggested check {check!r} is not registered; dropped' for check in unknown)
        suggested = tuple(check for check in suggested if check in known_checks)

    return LoadedBundle(
        root=root,
        manifest=manifest,
        evidence=tuple(evidence),
        fingerprint=sha256_hex(canonical_json(sorted(file_hashes.items()))),
        suggested_checks=suggested,
        warnings=tuple(warnings),
    )


def _read_manifest(root: Path) -> bytes:
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ValidationFailed(f'{manifest_path}: manifest not found', rule_code='bundle-parse')
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValidationFailed(
            f'{MANIFEST_NAME}: larger than {MAX_MANIFEST_BYTES} bytes', rule_code='evidence-too-large'
        )
    return manifest_path.read_bytes()


def _parse_manifest(raw: bytes) -> BundleManifest:
    decoded = _decode_json(MANIFEST_NAME, raw, rule_code='bundle-parse')
    if not isinstance(decoded, dict):
        raise ValidationFailed(f'{MANIFEST_NAME}: expected a JSON object', rule_code='bundle-parse')
    data = cast(dict[str, Any], decoded)
    version = data.get('schema_version')
    # bool is an int subclass; `true` must not pass as version 1.
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValidationFailed(
            f'{MANIFEST_NAME}: schema_version must be {SCHEMA_VERSION}, got {version!r}', rule_code='bundle-version'
        )
    try:
        return BundleManifest.model_validate(data)
    except ValidationError as exc:
        raise ValidationFailed(f'{MANIFEST_NAME}: {_first_error(exc)}', rule_code='bundle-parse') from exc


def _read_evidence_file(root: Path, name: str) -> tuple[str, bytes]:
    """Resolve *name* inside *root* and return ``(normalized relative path, bytes)``."""
    pure = PurePosixPath(name)
    if not name or '\\' in name or pure.is_absolute() or '..' in pure.parts:
        raise ValidationFailed(
            f'{name!r}: evidence path must be relative and inside the bundle', rule_code='evidence-invalid'
        )
    relative = pure.as_posix()
    candidate = root / pure
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValidationFailed(f'{relative}: evidence file not found', rule_code='evidence-invalid') from exc
    if not resolved.is_relative_to(root.resolve()):
        raise ValidationFailed(f'{relative}: resolves outside the bundle', rule_code='evidence-invalid')
    if not resolved.is_file():
        raise ValidationFailed(f'{relative}: not a regular file', rule_code='evidence-invalid')
    if resolved.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
        raise ValidationFailed(
            f'{relative}: larger than {MAX_EVIDENCE_FILE_BYTES} bytes', rule_code='evidence-too-large'
        )
    return relative, resolved.read_bytes()


def _parse_evidence(relative: str, raw: bytes) -> Evidence:
    data = _decode_json(relative, raw, rule_code='evidence-invalid')
    try:
        record = _record_adapter.validate_python(data)
    except ValidationError as exc:
        raise ValidationFailed(f'{relative}: {_first_error(exc)}', rule_code='evidence-invalid') from exc

    item: Evidence
    if isinstance(record, _HttpRecord):
        _check_http_caps(relative, record.http)
        item = HttpEvidence(id='', source=relative, http=record.http, secret_fields=record.secret_fields)
    else:
        _check_content_cap(relative, 'config.content', record.config.content)
        item = ConfigEvidence(id='', source=relative, config=record.config, secret_fields=record.secret_fields)
    return item.model_copy(update={'id': evidence_id(item)})


def _check_http_caps(relative: str, http: HttpExchange) -> None:
    if len(http.request.url.encode()) > MAX_URL_BYTES:
        raise ValidationFailed(f'{relative}: request URL exceeds {MAX_URL_BYTES} bytes', rule_code='evidence-too-large')
    for side, headers, body in (
        ('request', http.request.headers, http.request.body),
        ('response', http.response.headers, http.response.body),
    ):
        if len(headers) > MAX_HEADERS:
            raise ValidationFailed(
                f'{relative}: {side} has {len(headers)} headers, cap is {MAX_HEADERS}', rule_code='evidence-too-large'
            )
        if body is not None:
            _check_content_cap(relative, f'{side}.body', body)


def _check_content_cap(relative: str, label: str, content: str) -> None:
    size = len(content.encode())
    if size > MAX_CONTENT_BYTES:
        raise ValidationFailed(
            f'{relative}: {label} is {size} bytes, cap is {MAX_CONTENT_BYTES}', rule_code='evidence-too-large'
        )


def _decode_json(label: str, raw: bytes, *, rule_code: str) -> Any:
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValidationFailed(f'{label}: not UTF-8 text (binary content is refused)', rule_code=rule_code) from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationFailed(f'{label}: invalid JSON: {exc}', rule_code=rule_code) from exc


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    location = '.'.join(str(part) for part in error['loc'])
    return f'{location}: {error["msg"]}' if location else error['msg']
