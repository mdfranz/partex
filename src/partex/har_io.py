"""HAR import and bundle export — the MITM-free capture round-trip (PLAN §8, §17.5 Q5; DEPS.md §3.6).

Two directions around the passive bundle format (:mod:`partex.bundle`):

- :func:`import_har`: an operator-exported HAR file → a passive-reviewable bundle directory.
  Entries outside the declared target origin are filtered with a reported drop count and a
  per-host histogram (DEPS.md §3.6); an import with zero in-scope entries is an operator error.
- :func:`export_bundle`: a run's stored captures → a bundle directory, so ``partex review`` can
  re-run the passive checks over them. ``secret_fields`` values are redacted by default;
  ``include_secrets=True`` opts back in (and warns).

Both are pure functions of their inputs: the same HAR (and target) or the same stored evidence
produce byte-identical bundles (PLAN §12) — files are written with the single canonical JSON
encoding and evidence IDs are content-derived. Import and export never open a socket and never
read the engagement file back: everything is derived from the run's stored evidence and scope
snapshot (a live run's engagement path may already be gone, e.g. a script's temp dir).
"""

import base64
import binascii
import json
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast
from warnings import warn

from .bundle import MANIFEST_NAME, MAX_CONTENT_BYTES, MAX_EVIDENCE_FILES, MAX_HEADERS, MAX_URL_BYTES
from .errors import ValidationFailed
from .export import ExportStore, IncludeSecretsWarning
from .ids import canonical_json, evidence_id
from .models import Headers, HttpEvidence, HttpExchange, HttpRequest, HttpResponse, redact
from .storage import RunRecord

__all__ = [
    'ExportResult',
    'ImportResult',
    'export_bundle',
    'import_har',
]

MAX_HAR_BYTES = 64 * 1024 * 1024
"""Refuse to read a HAR larger than this before parsing (an operator capture of one app stays far below)."""

_EVIDENCE_DIR = 'evidence'

# Request headers whose values are always credentials in an operator capture, mirroring the live
# client's blanket marking (target.py `_CREDENTIAL_REQUEST_HEADERS`); response Set-Cookie values too.
_CREDENTIAL_REQUEST_HEADERS = frozenset({'authorization', 'proxy-authorization', 'cookie'})


# ── Result types ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ImportResult:
    """What one ``import-har`` did."""

    root: Path
    base_url: str
    target_name: str
    evidence_count: int
    dropped_out_of_scope: int
    """Entries outside the declared target origin, with a per-host histogram in ``dropped_hosts``."""
    dropped_hosts: dict[str, int]
    dropped_oversize: int
    """Entries skipped for exceeding a bundle cap (URL or header count) before any file was written."""
    duplicates: int
    """Entries skipped as byte-identical to an earlier one (the loader would dedup them anyway)."""


@dataclass(frozen=True, slots=True)
class ExportResult:
    """What one ``export-bundle`` did."""

    root: Path
    run_id: str
    base_url: str
    target_name: str
    evidence_count: int
    redacted: bool


# ── HAR import ───────────────────────────────────────────────────────────────


def _origin(url: str) -> str | None:
    """The comparable origin of *url* (scheme, normalized host, effective port), or ``None``.

    Default ports fold away (``https://h:443`` == ``https://h``); hosts are lowercased; only
    ``http``/``https`` are origins here — a HAR's ``data:``/``chrome-extension://`` entries are
    never capture material for a web-app engagement.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return None
    port = parsed.port
    default = 443 if parsed.scheme == 'https' else 80
    if port is None or port == default:
        return f'{parsed.scheme}://{parsed.hostname.lower()}'
    return f'{parsed.scheme}://{parsed.hostname.lower()}:{port}'


def _target_host(base_url: str) -> str:
    host = urllib.parse.urlsplit(base_url).hostname or base_url
    return host.lower()


def _read_har(path: str | Path) -> list[dict[str, Any]]:
    """Read and structurally validate the HAR at *path*; return its entries.

    Only the shape partex consumes is required: a top-level ``log`` object with an ``entries``
    list. Everything else in the spec (``log.version``, ``creator``, page/timing data) is
    ignored, and unknown per-entry fields are left alone rather than guessed at.
    """
    har_path = Path(path)
    if not har_path.is_file():
        raise ValidationFailed(f'{har_path}: HAR file not found', rule_code='har-parse')
    if har_path.stat().st_size > MAX_HAR_BYTES:
        raise ValidationFailed(f'{har_path.name}: larger than {MAX_HAR_BYTES} bytes', rule_code='har-too-large')
    try:
        data: Any = json.loads(har_path.read_text(encoding='utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationFailed(f'{har_path.name}: invalid HAR: {exc}', rule_code='har-parse') from exc
    if not isinstance(data, dict):
        raise ValidationFailed(f'{har_path.name}: invalid HAR: expected a JSON object', rule_code='har-parse')
    top = cast(dict[str, Any], data)
    log = top.get('log')
    if not isinstance(log, dict):
        raise ValidationFailed(f'{har_path.name}: invalid HAR: log must be an object', rule_code='har-parse')
    log_record = cast(dict[str, Any], log)
    entries = log_record.get('entries')
    if not isinstance(entries, list):
        raise ValidationFailed(f'{har_path.name}: invalid HAR: log.entries must be a list', rule_code='har-parse')
    typed: list[dict[str, Any]] = []
    for index, entry in enumerate(cast(list[Any], entries)):
        if not isinstance(entry, dict):
            raise ValidationFailed(
                f'{har_path.name}: entry {index} must be an object with request and response objects',
                rule_code='har-parse',
            )
        record = cast(dict[str, Any], entry)
        if not isinstance(record.get('request'), dict) or not isinstance(record.get('response'), dict):
            raise ValidationFailed(
                f'{har_path.name}: entry {index} must be an object with request and response objects',
                rule_code='har-parse',
            )
        typed.append(record)
    return typed


def _har_headers(raw: Any) -> Headers | None:
    """HAR ``headers`` (a list of ``{name, value}``) → wire-order pairs; ``None`` when malformed."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        return None
    pairs: Headers = []
    for header in cast(list[Any], raw):
        if not isinstance(header, dict):
            return None
        record = cast(dict[str, Any], header)
        name = record.get('name')
        value = record.get('value')
        if not isinstance(name, str) or not isinstance(value, str):
            return None
        pairs.append((name, value))
    return pairs


def _capped_text(text: str) -> str:
    """Truncate *text* to at most :data:`~partex.bundle.MAX_CONTENT_BYTES` encoded bytes.

    The cut may land inside a multi-byte character; the incomplete tail is dropped rather than
    storing a broken encoding (same policy as the live capture's ``_decode_body``).
    """
    encoded = text.encode()
    if len(encoded) <= MAX_CONTENT_BYTES:
        return text
    return encoded[:MAX_CONTENT_BYTES].decode(errors='ignore')


def _har_body(content: Any) -> tuple[str | None, Literal['truncated', 'refused'] | None]:
    """HAR response ``content`` → ``(body, body_note)``; ``(None, None)`` when there is no body.

    ``encoding: base64`` is decoded first; non-UTF-8 bytes are refused (``body_note='refused'``,
    the live capture's term for “binary, not stored”). Plain text over the bundle cap is
    truncated with ``body_note='truncated'``.
    """
    if not isinstance(content, dict):
        return None, None
    record = cast(dict[str, Any], content)
    text = record.get('text')
    if not isinstance(text, str):
        return None, None
    if record.get('encoding') == 'base64':
        try:
            decoded = base64.b64decode(text, validate=True)
        except binascii.Error, ValueError:
            return None, 'refused'
        try:
            text = decoded.decode('utf-8')
        except UnicodeDecodeError:
            return None, 'refused'
    if len(text.encode()) > MAX_CONTENT_BYTES:
        return _capped_text(text), 'truncated'
    return text, None


def _secret_fields(exchange: HttpExchange) -> list[str]:
    """Blanket-mark credential header values, mirroring the live client's policy.

    An operator capture carries whatever the browser sent and the target issued: request
    ``Cookie``/``Authorization``/``Proxy-Authorization`` values and every response ``Set-Cookie``
    value are secrets until proven otherwise, so export/show redaction works unchanged.
    """
    paths: list[str] = []
    for index, (name, _) in enumerate(exchange.request.headers):
        if name.lower() in _CREDENTIAL_REQUEST_HEADERS:
            paths.append(f'$.http.request.headers[{index}][1]')
    for index, (name, _) in enumerate(exchange.response.headers):
        if name.lower() == 'set-cookie':
            paths.append(f'$.http.response.headers[{index}][1]')
    return paths


def _entry_to_exchange(entry: dict[str, Any]) -> HttpExchange | None:
    """Build the :class:`~partex.models.HttpExchange` for one HAR entry; ``None`` when unusable.

    ``None`` means the entry exceeds a bundle cap (oversize URL or header count) — importing it
    would produce evidence the loader must refuse, so it is dropped with a reported count
    instead. Malformed structure inside the entry was already rejected by :func:`_read_har`'s
    looser pass only for the outer shape; field-level problems (non-string method, non-int
    status) are treated the same way: dropped, not fatal — a real browser HAR never has them,
    and one bad entry should not cost the operator the whole capture.
    """
    request = entry['request']
    response = entry['response']
    method = request.get('method')
    url = request.get('url')
    if not isinstance(method, str) or not isinstance(url, str) or not isinstance(response.get('status'), int):
        return None
    if _origin(url) is None or len(url.encode()) > MAX_URL_BYTES:
        return None
    request_headers = _har_headers(request.get('headers'))
    response_headers = _har_headers(response.get('headers'))
    if request_headers is None or response_headers is None:
        return None
    if len(request_headers) > MAX_HEADERS or len(response_headers) > MAX_HEADERS:
        return None
    request_body = request.get('postData')
    body: str | None = None
    if isinstance(request_body, dict):
        post = cast(dict[str, Any], request_body)
        text = post.get('text')
        if isinstance(text, str):
            body = _capped_text(text)
    response_body, body_note = _har_body(response.get('content'))
    return HttpExchange(
        request=HttpRequest(method=method, url=url, headers=request_headers, body=body),
        response=HttpResponse(
            status_code=response['status'], headers=response_headers, body=response_body, body_note=body_note
        ),
    )


def _default_target(entries: list[dict[str, Any]]) -> str | None:
    """The most frequent request origin in the HAR; ties break by first appearance.

    A capture of one app is dominated by that app's origin, so analytics/CDN hosts lose without
    the operator having to name anything. ``None`` when no entry has a usable origin.
    """
    counts: Counter[str] = Counter()
    for entry in entries:
        url = entry['request'].get('url')
        origin = _origin(url) if isinstance(url, str) else None
        if origin is not None:
            counts[origin] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def import_har(
    har_path: str | Path,
    out_dir: str | Path,
    *,
    target: str | None = None,
) -> ImportResult:
    """Import the HAR at *har_path* into a passive-reviewable bundle at *out_dir*.

    *target* declares the capture's target origin (scheme + host [+ port]); when omitted it is
    inferred as the most frequent request origin. Entries whose origin does not match exactly
    are dropped with a reported count and per-host histogram; zero in-scope entries is an
    operator error (:class:`~partex.errors.ValidationFailed`, ``rule_code='har-empty'``).
    Pure: the same (HAR, target) produce a byte-identical bundle.
    """
    entries = _read_har(har_path)
    base_url = target if target is not None else _default_target(entries)
    normalized = _origin(base_url) if base_url is not None else None
    if base_url is None or normalized is None:
        raise ValidationFailed(f'no usable target: {base_url!r}', rule_code='har-target')

    kept: list[HttpExchange] = []
    dropped_hosts: Counter[str] = Counter()
    dropped_oversize = 0
    duplicates = 0
    seen: set[str] = set()
    for entry in entries:
        url = entry['request'].get('url')
        entry_origin = _origin(url) if isinstance(url, str) else None
        if entry_origin != normalized:
            host = '<no host>'
            if isinstance(url, str):
                host = urllib.parse.urlsplit(url).hostname or '<no host>'
            dropped_hosts[host.lower()] += 1
            continue
        exchange = _entry_to_exchange(entry)
        if exchange is None:
            dropped_oversize += 1
            continue
        probe = HttpEvidence(id='', source='', http=exchange)
        content_id = evidence_id(probe)
        if content_id in seen:
            duplicates += 1
            continue
        seen.add(content_id)
        kept.append(exchange)

    if not kept:
        histogram = ', '.join(f'{host} {count}' for host, count in sorted(dropped_hosts.items()))
        detail = f' ({histogram})' if histogram else ''
        raise ValidationFailed(f'no in-scope HAR entries for target {base_url}{detail}', rule_code='har-empty')
    if len(kept) > MAX_EVIDENCE_FILES:
        raise ValidationFailed(
            f'{len(kept)} in-scope entries exceeds the bundle cap of {MAX_EVIDENCE_FILES}', rule_code='har-too-large'
        )

    dropped = sum(dropped_hosts.values())
    notes = f'imported from {Path(har_path).name}'
    drops: list[str] = []
    if dropped:
        histogram = ', '.join(f'{host} {count}' for host, count in sorted(dropped_hosts.items()))
        drops.append(f'{dropped} out-of-scope (hosts: {histogram})')
    if dropped_oversize:
        drops.append(f'{dropped_oversize} oversize')
    if duplicates:
        drops.append(f'{duplicates} duplicates')
    if drops:
        notes += '; dropped ' + ', '.join(drops)

    root = Path(out_dir)
    evidence_dir = root / _EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_files: list[str] = []
    for index, exchange in enumerate(kept, start=1):
        name = f'{_EVIDENCE_DIR}/{index:04d}.json'
        record = {
            'kind': 'http_exchange',
            'http': exchange.model_dump(mode='json'),
            'secret_fields': _secret_fields(exchange),
        }
        (root / name).write_bytes(canonical_json(record) + b'\n')
        evidence_files.append(name)
    manifest: dict[str, Any] = {
        'schema_version': 1,
        'target': {
            'name': _target_host(base_url),
            'base_url': base_url,
            'notes': notes,
        },
        'evidence_files': evidence_files,
        'suggested_checks': [],
    }
    (root / MANIFEST_NAME).write_bytes(canonical_json(manifest) + b'\n')
    return ImportResult(
        root=root,
        base_url=base_url,
        target_name=cast(str, manifest['target']['name']),
        evidence_count=len(kept),
        dropped_out_of_scope=dropped,
        dropped_hosts=dict(sorted(dropped_hosts.items())),
        dropped_oversize=dropped_oversize,
        duplicates=duplicates,
    )


# ── Bundle export ─────────────────────────────────────────────────────────────


async def export_bundle(
    store: ExportStore,
    run_id: str,
    out_dir: str | Path,
    *,
    include_secrets: bool = False,
) -> ExportResult:
    """Write the captures of *run_id* to a passive-reviewable bundle at *out_dir*.

    The target is derived only from stored data (the engagement file may be gone): ``base_url``
    is the origin of the run's first HTTP exchange, ``name`` the first scope-snapshot host.
    ``secret_fields`` values are redacted unless ``include_secrets=True`` (which warns). The
    secret markers themselves are kept either way, so the exported bundle stays redact-on-export.
    """
    run: RunRecord = await store.get_run(run_id)
    evidence = await store.evidence(run_id)
    if not evidence:
        raise ValidationFailed(f'run {run_id} has no evidence to export', rule_code='export-empty')
    if len(evidence) > MAX_EVIDENCE_FILES:
        raise ValidationFailed(
            f'run {run_id} has {len(evidence)} evidence items, over the bundle cap of {MAX_EVIDENCE_FILES}',
            rule_code='evidence-too-large',
        )

    first_url = next((item.http.request.url for item in evidence if isinstance(item, HttpEvidence)), None)
    origin = _origin(first_url) if first_url is not None else None
    if origin is None:
        raise ValidationFailed(
            f'run {run_id} has no HTTP evidence to derive a target from', rule_code='export-no-target'
        )
    hosts = [] if run.scope_snapshot is None else run.scope_snapshot.hosts
    name = (hosts[0] if hosts else urllib.parse.urlsplit(origin).hostname or 'target').lower()

    if include_secrets:
        warn(
            f'Exporting run {run_id} with include_secrets=True; output may contain unredacted secrets.',
            IncludeSecretsWarning,
            stacklevel=2,
        )

    root = Path(out_dir)
    evidence_dir = root / _EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_files: list[str] = []
    for index, item in enumerate(evidence, start=1):
        record = (item if include_secrets else redact(item)).model_dump(mode='json', exclude={'id', 'source'})
        name_path = f'{_EVIDENCE_DIR}/{index:04d}.json'
        (root / name_path).write_bytes(canonical_json(record) + b'\n')
        evidence_files.append(name_path)
    manifest: dict[str, Any] = {
        'schema_version': 1,
        'target': {
            'name': name,
            'base_url': origin,
            'notes': f'exported from run {run_id}',
        },
        'evidence_files': evidence_files,
        'suggested_checks': [],
    }
    (root / MANIFEST_NAME).write_bytes(canonical_json(manifest) + b'\n')
    return ExportResult(
        root=root,
        run_id=run_id,
        base_url=origin,
        target_name=name,
        evidence_count=len(evidence),
        redacted=not include_secrets,
    )
