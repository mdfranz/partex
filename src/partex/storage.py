"""SQLite ``RunStore`` — PLAN §7, §7.1.

One file, stdlib ``sqlite3``, WAL. The engine owns the single writer (:class:`RunStore`); everything
else reads through :class:`RunReader`, which opens the database ``mode=ro``. Both expose an async API:
blocking SQLite calls run in worker threads via :func:`anyio.to_thread.run_sync`, serialized on one
connection per object.

Every model is re-validated on read, so schema drift between engine versions surfaces as a
``store-load`` error instead of silently wrong data. A database whose ``PRAGMA user_version`` is not
:data:`SCHEMA_VERSION` is refused (``store-version``); it is never migrated in place.

Schema version 2 adds ``findings.subject`` (#39); a version-1 store is refused like any unknown version.

Deviations from the PLAN §7 DDL, both required by existing contracts:

- ``evidence.seq`` records registration order (export lists evidence "by registration order").
- ``findings.verification_id`` persists ``Finding.verification_id``.
"""

import json
import os
import re
import sqlite3
import stat
import threading
import uuid
from collections.abc import Callable, Generator, Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Literal, Self

import anyio.to_thread
from pydantic import TypeAdapter, ValidationError

from .errors import PartexError
from .ids import canonical_json, engagement_id, sha256_hex
from .models import (
    CoverageEntry,
    Engagement,
    Evidence,
    EvidenceAdapter,
    Finding,
    ReviewSummary,
    Scope,
    Verification,
)
from .paths import mkdir_private

SCHEMA_VERSION = 2  # 2: findings.subject (#39)
DEFAULT_BUSY_TIMEOUT_MS = 5000

type RunState = Literal['created', 'invalid', 'checks_complete', 'checks_failed', 'complete']
type InputKind = Literal['bundle', 'engagement']
type FindingStatus = Literal['reported', 'verified', 'verification_failed']
type SurfaceKind = Literal['host', 'endpoint', 'parameter', 'role', 'tech_banner']
type SurfaceRel = Literal['exposes_endpoint', 'accepts_param', 'authenticated_as', 'redirects_to']
type LlmRole = Literal['tester', 'verifier', 'summarizer', 'reviewer', 'judge', 'search']

# Run states only move forward (§6). ``checks_complete -> complete`` happens when a summary lands.
_TRANSITIONS: dict[str, frozenset[str]] = {
    'created': frozenset({'invalid', 'checks_complete', 'checks_failed'}),
    'checks_complete': frozenset({'complete'}),
    'invalid': frozenset(),
    'checks_failed': frozenset(),
    'complete': frozenset(),
}

_SCHEMA = """
CREATE TABLE engagements (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  scope TEXT NOT NULL,
  attestation TEXT NOT NULL,
  operator TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  state TEXT NOT NULL,
  input_kind TEXT NOT NULL,
  input_ref TEXT NOT NULL,
  input_sha256 TEXT NOT NULL,
  engine_version TEXT NOT NULL,
  selected_checks TEXT NOT NULL,
  authorized_flag INTEGER NOT NULL DEFAULT 0,
  model TEXT,
  requests_spent INTEGER NOT NULL DEFAULT 0,
  scope_snapshot TEXT,
  error TEXT,
  summary_error TEXT
);
CREATE TABLE evidence (
  run_id TEXT NOT NULL REFERENCES runs,
  evidence_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL,
  content TEXT NOT NULL,
  PRIMARY KEY (run_id, evidence_id),
  UNIQUE (run_id, seq)
);
CREATE TABLE findings (
  run_id TEXT NOT NULL REFERENCES runs,
  finding_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  check_version TEXT NOT NULL,
  severity TEXT NOT NULL,
  subject TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence_ids TEXT NOT NULL,
  remediation TEXT NOT NULL,
  status TEXT NOT NULL,
  verification_id TEXT,
  PRIMARY KEY (run_id, finding_id)
);
CREATE TABLE verifications (
  run_id TEXT NOT NULL REFERENCES runs,
  verification_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  verdict TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, verification_id)
);
CREATE TABLE tool_calls (
  run_id TEXT NOT NULL REFERENCES runs,
  call_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  args TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, call_id)
);
CREATE TABLE summaries (
  run_id TEXT PRIMARY KEY REFERENCES runs,
  content TEXT NOT NULL,
  model TEXT NOT NULL,
  generated_at TEXT NOT NULL
);
CREATE TABLE surface_nodes (
  run_id TEXT NOT NULL REFERENCES runs,
  node_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  metadata TEXT NOT NULL,
  evidence_ids TEXT NOT NULL,
  PRIMARY KEY (run_id, node_id)
);
CREATE TABLE surface_edges (
  run_id TEXT NOT NULL REFERENCES runs,
  src_id TEXT NOT NULL,
  dst_id TEXT NOT NULL,
  rel TEXT NOT NULL,
  evidence_id TEXT,
  PRIMARY KEY (run_id, src_id, dst_id, rel)
);
CREATE TABLE coverage_entries (
  run_id TEXT NOT NULL REFERENCES runs,
  surface TEXT NOT NULL,
  risk_area TEXT NOT NULL,
  outcome TEXT NOT NULL,
  source TEXT NOT NULL,
  evidence_ids TEXT NOT NULL,
  reason TEXT NOT NULL,
  goal_attempts INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (run_id, surface, risk_area)
);
CREATE TABLE llm_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES runs,
  role TEXT NOT NULL,
  model TEXT NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cache_read_tokens INTEGER NOT NULL DEFAULT 0,
  cache_write_tokens INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""

_string_list = TypeAdapter(list[str])


class StoreError(PartexError):
    """A storage failure. ``rule_code`` is one of:

    - ``store-version``: unknown or foreign schema (``PRAGMA user_version``)
    - ``store-missing``: a reader was pointed at a database that does not exist
    - ``store-locked``: another writer held the lock past ``busy_timeout``
    - ``store-load``: a stored row no longer validates against its model
    - ``run-not-found`` / ``finding-not-found``: unknown ID for this store
    - ``run-state``: an illegal run state transition
    - ``dangling-evidence``: a finding or verification references evidence the run doesn't have
    """


# ── Row shapes ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RunRecord:
    """One ``runs`` row."""

    id: str
    created_at: str
    state: RunState
    input_kind: InputKind
    input_ref: str
    input_sha256: str
    engine_version: str
    selected_checks: tuple[str, ...]
    authorized: bool
    model: str | None
    requests_spent: int
    scope_snapshot: Scope | None
    error: str | None
    summary_error: str | None
    findings_count: int


@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    """One ``tool_calls`` row; ``args`` and ``result`` are already redacted by the caller."""

    call_id: str
    tool: str
    args: Any
    result: Any
    created_at: str


@dataclass(frozen=True, slots=True)
class LlmUsageRecord:
    """One ``llm_usage`` row: a single model turn's role, model, token counts, latency, and status."""

    role: str
    model: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    latency_ms: int
    status: str
    created_at: str


@dataclass(frozen=True, slots=True)
class SurfaceNode:
    """One ``surface_nodes`` row."""

    node_id: str
    kind: SurfaceKind
    key: str
    metadata: dict[str, Any]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SurfaceEdge:
    """One ``surface_edges`` row."""

    src_id: str
    dst_id: str
    rel: SurfaceRel
    evidence_id: str | None


def surface_node_id(kind: SurfaceKind, key: str) -> str:
    """Deterministic node ID: ``sn_`` + sha256 over ``kind`` and normalized ``key``."""
    return 'sn_' + sha256_hex(f'{kind}\0{key}'.encode())[:16]


def artifact_dir(db_path: Path) -> Path:
    """Directory beside *db_path* where full-body downloaded artifacts are stored (mode 0700, files 0600)."""
    return db_path.parent / f'{db_path.name}.artifacts'


def run_artifact_dir(db_path: Path, run_id: str) -> Path:
    """This run's own artifact directory, ``<db>.artifacts/<run_id>/``: what a ``run_code`` sandbox may read (#83).

    The database-wide directory also holds earlier runs' downloads, possibly from other targets.
    """
    return artifact_dir(db_path) / run_id


def run_reports_dir(db_path: Path, run_id: str) -> Path:
    """This run's own report directory, ``<db>.reports/<run_id>/`` (mode 0700): where ``save_report`` writes (#104).

    Kept apart from ``<db>.artifacts`` so model-written text never sits beside, or overwrites, captured evidence.
    """
    return db_path.parent / f'{db_path.name}.reports' / run_id


REPORT_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
"""A report name: a plain file stem, no path separators, no leading dot, at most 64 characters."""
MAX_REPORT_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class ReportRecord:
    run_id: str
    name: str
    size_bytes: int
    mtime: str
    sha256: str


@contextmanager
def _open_reports_dir(db_path: Path, run_id: str) -> Generator[int]:
    if re.fullmatch(r'run_[0-9a-f]{32}', run_id) is None:
        raise StoreError('invalid report run ID', rule_code='report-invalid')
    directory = run_reports_dir(db_path, run_id)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(directory.parent, flags)
    try:
        run_fd = os.open(directory.name, flags, dir_fd=root_fd)
        try:
            yield run_fd
        finally:
            os.close(run_fd)
    finally:
        os.close(root_fd)


def _load_report(directory: int, name: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(f'{name}.md', flags, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise StoreError('report must be a regular file', rule_code='report-invalid')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_REPORT_BYTES:
        raise StoreError(f'report exceeds the {MAX_REPORT_BYTES}-byte limit', rule_code='report-too-large')
    return data, info


def list_reports(db_path: Path, run_id: str) -> list[ReportRecord]:
    """List readable Markdown report files for a run, ordered by name."""
    reports: list[ReportRecord] = []
    try:
        with _open_reports_dir(db_path, run_id) as directory:
            for filename in sorted(os.listdir(directory)):
                name = filename.removesuffix('.md')
                if filename == name or REPORT_NAME.fullmatch(name) is None:
                    continue
                try:
                    data, info = _load_report(directory, name)
                    data.decode('utf-8')
                except OSError, StoreError, UnicodeError:
                    continue
                mtime = datetime.fromtimestamp(info.st_mtime, UTC).isoformat()
                reports.append(ReportRecord(run_id, name, len(data), mtime, sha256_hex(data)))
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise StoreError('could not open the report directory', rule_code='report-read') from exc
    return reports


def read_report(db_path: Path, run_id: str, name: str) -> str:
    """Read a saved UTF-8 Markdown report by its stem."""
    if REPORT_NAME.fullmatch(name) is None:
        raise StoreError('invalid report name', rule_code='report-invalid')
    try:
        with _open_reports_dir(db_path, run_id) as directory:
            data, _ = _load_report(directory, name)
            return data.decode('utf-8')
    except FileNotFoundError as exc:
        raise StoreError('report does not exist in this run', rule_code='report-not-found') from exc
    except (OSError, UnicodeError) as exc:
        raise StoreError('could not read the report', rule_code='report-read') from exc


def write_report(directory: Path, name: str, content: str) -> Path:
    """Write ``<directory>/<name>.md`` (file ``0600``, directory ``0700``), refusing to overwrite; return the path.

    Raises ``ValueError`` for a bad name or oversize content and ``FileExistsError`` for a same-name report.
    """
    if REPORT_NAME.fullmatch(name) is None:
        raise ValueError('report name must be 1-64 characters of letters, digits, dot, underscore or hyphen')
    data = content.encode()
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError(f'report is {len(data)} bytes; the limit is {MAX_REPORT_BYTES}')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory.parent, 0o700)
    os.chmod(directory, 0o700)
    path = directory / f'{name}.md'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    return path


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec='microseconds')


def _json(value: Any) -> str:
    return canonical_json(value).decode()


# ── Connection plumbing ──────────────────────────────────────────────────────


class _Connection:
    """One sqlite3 connection, used from worker threads one call at a time."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.Lock()

    async def run[T](self, fn: Callable[[sqlite3.Connection], T]) -> T:
        def call() -> T:
            with self._lock:
                try:
                    return fn(self._conn)
                except sqlite3.OperationalError as exc:
                    if 'locked' in str(exc) or 'busy' in str(exc):
                        raise StoreError(
                            'database is locked by another writer; retry when it finishes', rule_code='store-locked'
                        ) from exc
                    raise

        return await anyio.to_thread.run_sync(call)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _transaction[T](conn: sqlite3.Connection, fn: Callable[[sqlite3.Connection], T]) -> T:
    """Run *fn* inside ``BEGIN IMMEDIATE`` … ``COMMIT``, rolling back on any error."""
    conn.execute('BEGIN IMMEDIATE')
    try:
        result = fn(conn)
    except BaseException:
        conn.execute('ROLLBACK')
        raise
    conn.execute('COMMIT')
    return result


def _apply_pragmas(conn: sqlite3.Connection, busy_timeout_ms: int) -> None:
    conn.execute(f'PRAGMA busy_timeout = {int(busy_timeout_ms)}')
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA synchronous = NORMAL')


def _check_version(conn: sqlite3.Connection, path: Path) -> None:
    (version,) = conn.execute('PRAGMA user_version').fetchone()
    if version != SCHEMA_VERSION:
        raise StoreError(
            f'{path}: schema version {version} is not supported (expected {SCHEMA_VERSION}); refusing to open',
            rule_code='store-version',
        )


# ── Reads (shared by reader and writer) ───────────────────────────────────────


class _Reads:
    _db: _Connection

    async def list_runs(self) -> list[RunRecord]:
        """All runs, oldest first."""
        return await self._db.run(
            lambda conn: [_run_from_row(r) for r in conn.execute(_RUN_SELECT + ' ORDER BY r.created_at, r.id')]
        )

    async def get_run(self, run_id: str) -> RunRecord:
        return await self._db.run(lambda conn: _get_run(conn, run_id))

    async def evidence(self, run_id: str) -> list[Evidence]:
        """The run's evidence in registration order."""

        def read(conn: sqlite3.Connection) -> list[Evidence]:
            _get_run(conn, run_id)
            rows = conn.execute('SELECT content FROM evidence WHERE run_id = ? ORDER BY seq', (run_id,))
            return [_load(EvidenceAdapter.validate_json, content) for (content,) in rows]

        return await self._db.run(read)

    async def get_evidence(self, run_id: str, evidence_id: str) -> Evidence | None:
        """One evidence item of *run_id*, or ``None`` (cross-run IDs never resolve)."""

        def read(conn: sqlite3.Connection) -> Evidence | None:
            row = conn.execute(
                'SELECT content FROM evidence WHERE run_id = ? AND evidence_id = ?', (run_id, evidence_id)
            ).fetchone()
            return None if row is None else _load(EvidenceAdapter.validate_json, row[0])

        return await self._db.run(read)

    async def findings(self, run_id: str) -> list[Finding]:
        """The run's findings in commit order."""

        def read(conn: sqlite3.Connection) -> list[Finding]:
            _get_run(conn, run_id)
            rows = conn.execute(_FINDING_SELECT + ' WHERE run_id = ? ORDER BY rowid', (run_id,))
            return [_finding_from_row(row) for row in rows]

        return await self._db.run(read)

    async def get_finding(self, run_id: str, finding_id: str) -> Finding | None:
        def read(conn: sqlite3.Connection) -> Finding | None:
            row = conn.execute(
                _FINDING_SELECT + ' WHERE run_id = ? AND finding_id = ?', (run_id, finding_id)
            ).fetchone()
            return None if row is None else _finding_from_row(row)

        return await self._db.run(read)

    async def verifications(self, run_id: str) -> list[Verification]:
        def read(conn: sqlite3.Connection) -> list[Verification]:
            _get_run(conn, run_id)
            rows = conn.execute('SELECT content FROM verifications WHERE run_id = ? ORDER BY rowid', (run_id,))
            return [_load(Verification.model_validate_json, content) for (content,) in rows]

        return await self._db.run(read)

    async def summary(self, run_id: str) -> ReviewSummary | None:
        def read(conn: sqlite3.Connection) -> ReviewSummary | None:
            _get_run(conn, run_id)
            row = conn.execute('SELECT content FROM summaries WHERE run_id = ?', (run_id,)).fetchone()
            return None if row is None else _load(ReviewSummary.model_validate_json, row[0])

        return await self._db.run(read)

    async def coverage(self, run_id: str) -> list[CoverageEntry]:
        def read(conn: sqlite3.Connection) -> list[CoverageEntry]:
            _get_run(conn, run_id)
            rows = conn.execute(
                'SELECT surface, risk_area, outcome, source, evidence_ids, reason, goal_attempts '
                'FROM coverage_entries WHERE run_id = ? ORDER BY surface, risk_area',
                (run_id,),
            )
            return [
                _load(
                    CoverageEntry.model_validate,
                    {
                        'surface': s,
                        'risk_area': r,
                        'outcome': o,
                        'source': src,
                        'evidence_ids': json.loads(ev),
                        'reason': reason,
                        'goal_attempts': g,
                    },
                )
                for s, r, o, src, ev, reason, g in rows
            ]

        return await self._db.run(read)

    async def tool_calls(self, run_id: str) -> list[ToolCallRecord]:
        def read(conn: sqlite3.Connection) -> list[ToolCallRecord]:
            _get_run(conn, run_id)
            rows = conn.execute(
                'SELECT call_id, tool, args, result, created_at FROM tool_calls WHERE run_id = ? ORDER BY rowid',
                (run_id,),
            )
            return [ToolCallRecord(c, t, json.loads(a), json.loads(r), at) for c, t, a, r, at in rows]

        return await self._db.run(read)

    async def llm_usage(self, run_id: str) -> list[LlmUsageRecord]:
        """The run's recorded model turns, in the order they were recorded."""

        def read(conn: sqlite3.Connection) -> list[LlmUsageRecord]:
            _get_run(conn, run_id)
            rows = conn.execute(
                'SELECT role, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, '
                'latency_ms, status, created_at FROM llm_usage WHERE run_id = ? ORDER BY id',
                (run_id,),
            )
            return [LlmUsageRecord(*row) for row in rows]

        return await self._db.run(read)

    async def surface(self, run_id: str) -> tuple[list[SurfaceNode], list[SurfaceEdge]]:
        def read(conn: sqlite3.Connection) -> tuple[list[SurfaceNode], list[SurfaceEdge]]:
            _get_run(conn, run_id)
            nodes = [
                SurfaceNode(n, k, key, json.loads(meta), tuple(json.loads(ev)))  # pyright: ignore[reportArgumentType]
                for n, k, key, meta, ev in conn.execute(
                    'SELECT node_id, kind, key, metadata, evidence_ids FROM surface_nodes WHERE run_id = ? '
                    'ORDER BY kind, key',
                    (run_id,),
                )
            ]
            edges = [
                SurfaceEdge(s, d, rel, ev)  # pyright: ignore[reportArgumentType]
                for s, d, rel, ev in conn.execute(
                    'SELECT src_id, dst_id, rel, evidence_id FROM surface_edges WHERE run_id = ? '
                    'ORDER BY src_id, dst_id, rel',
                    (run_id,),
                )
            ]
            return nodes, edges

        return await self._db.run(read)


_RUN_SELECT = (
    'SELECT r.id, r.created_at, r.state, r.input_kind, r.input_ref, r.input_sha256, r.engine_version, '
    'r.selected_checks, r.authorized_flag, r.model, r.requests_spent, r.scope_snapshot, r.error, r.summary_error, '
    '(SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id) FROM runs r'
)
_FINDING_SELECT = (
    'SELECT finding_id, check_id, check_version, severity, subject, title, description, evidence_ids, remediation, status, '
    'verification_id FROM findings'
)


def _load[T](validate: Callable[[Any], T], raw: Any) -> T:
    try:
        return validate(raw)
    except ValidationError as exc:
        raise StoreError(f'stored record no longer validates: {exc}', rule_code='store-load') from exc


def _get_run(conn: sqlite3.Connection, run_id: str) -> RunRecord:
    row = conn.execute(_RUN_SELECT + ' WHERE r.id = ?', (run_id,)).fetchone()
    if row is None:
        raise StoreError(f'run {run_id!r} not found', rule_code='run-not-found')
    return _run_from_row(row)


def _run_from_row(row: tuple[Any, ...]) -> RunRecord:
    (
        rid,
        created,
        state,
        kind,
        ref,
        sha,
        engine,
        checks,
        authorized,
        model,
        spent,
        scope,
        error,
        summary_error,
        count,
    ) = row
    return RunRecord(
        id=rid,
        created_at=created,
        state=state,
        input_kind=kind,
        input_ref=ref,
        input_sha256=sha,
        engine_version=engine,
        selected_checks=tuple(_load(_string_list.validate_json, checks)),
        authorized=bool(authorized),
        model=model,
        requests_spent=spent,
        scope_snapshot=None if scope is None else _load(Scope.model_validate_json, scope),
        error=error,
        summary_error=summary_error,
        findings_count=count,
    )


def _finding_from_row(row: tuple[Any, ...]) -> Finding:
    fid, check_id, version, severity, subject, title, description, evidence_ids, remediation, status, vid = row
    return _load(
        Finding.model_validate,
        {
            'id': fid,
            'check_id': check_id,
            'check_version': version,
            'severity': severity,
            'subject': subject,
            'title': title,
            'description': description,
            'evidence_ids': json.loads(evidence_ids),
            'remediation': remediation,
            'status': status,
            'verification_id': vid,
        },
    )


# ── Reader ────────────────────────────────────────────────────────────────────


class RunReader(_Reads):
    """Read-only view of a store (``mode=ro``); safe to use while a run is writing."""

    def __init__(self, db: _Connection, path: Path) -> None:
        self._db = db
        self.path = path

    @classmethod
    async def open(cls, path: str | Path, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> Self:
        db_path = Path(path)

        def connect() -> sqlite3.Connection:
            if not db_path.is_file():
                raise StoreError(f'{db_path}: no partex database here', rule_code='store-missing')
            conn = sqlite3.connect(
                f'{db_path.resolve().as_uri()}?mode=ro', uri=True, isolation_level=None, check_same_thread=False
            )
            try:
                _apply_pragmas(conn, busy_timeout_ms)
                _check_version(conn, db_path)
            except BaseException:
                conn.close()
                raise
            return conn

        return cls(_Connection(await anyio.to_thread.run_sync(connect)), db_path)

    async def aclose(self) -> None:
        await anyio.to_thread.run_sync(self._db.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


# ── Writer ────────────────────────────────────────────────────────────────────


class RunStore(_Reads):
    """The single writer. Only the engine holds one; checks and workers never do (§7.1)."""

    def __init__(self, db: _Connection, path: Path) -> None:
        self._db = db
        self.path = path

    @classmethod
    async def open(cls, path: str | Path, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> Self:
        """Open (creating if needed) the store at *path*."""
        db_path = Path(path)

        def connect() -> sqlite3.Connection:
            mkdir_private(db_path.parent)
            conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
            try:
                _apply_pragmas(conn, busy_timeout_ms)
                conn.execute('PRAGMA journal_mode = WAL')
                _initialize(conn, db_path)
            except BaseException:
                conn.close()
                raise
            return conn

        db = _Connection(await anyio.to_thread.run_sync(connect))
        return cls(db, db_path)

    async def aclose(self) -> None:
        await anyio.to_thread.run_sync(self._db.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.aclose()

    # ── runs ──

    async def create_run(
        self,
        *,
        input_kind: InputKind,
        input_ref: str,
        input_sha256: str,
        engine_version: str,
        selected_checks: Sequence[str],
        authorized: bool = False,
        model: str | None = None,
        scope_snapshot: Scope | None = None,
    ) -> str:
        """Open a run row in state ``created`` and return its ID (``run_`` + uuid4)."""
        run_id = 'run_' + uuid.uuid4().hex
        scope = None if scope_snapshot is None else scope_snapshot.model_dump_json()

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                'INSERT INTO runs (id, created_at, state, input_kind, input_ref, input_sha256, engine_version, '
                'selected_checks, authorized_flag, model, scope_snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    run_id,
                    _now(),
                    'created',
                    input_kind,
                    input_ref,
                    input_sha256,
                    engine_version,
                    _json(list(selected_checks)),
                    int(authorized),
                    model,
                    scope,
                ),
            )

        await self._db.run(lambda conn: _transaction(conn, write))
        return run_id

    async def set_state(self, run_id: str, state: RunState, *, error: str | None = None) -> None:
        """Move *run_id* to *state* (forward only), optionally recording an error diagnostic."""
        await self._db.run(lambda conn: _transaction(conn, lambda c: _set_state(c, run_id, state, error)))

    async def add_requests_spent(self, run_id: str, count: int = 1) -> None:
        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            conn.execute('UPDATE runs SET requests_spent = requests_spent + ? WHERE id = ?', (count, run_id))

        await self._db.run(lambda conn: _transaction(conn, write))

    async def amend_scope(self, run_id: str, scope: Scope, *, args: Any, result: Any) -> str:
        """Replace the run's scope snapshot and append its ``scope_amend`` audit row in one transaction.

        Either both land or neither does, so the stored scope and the audit trail cannot disagree.
        Callers redact secrets first. Returns the audit row's call ID.
        """
        call_id = 'tc_' + uuid.uuid4().hex

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            conn.execute('UPDATE runs SET scope_snapshot = ? WHERE id = ?', (scope.model_dump_json(), run_id))
            conn.execute(
                'INSERT INTO tool_calls (run_id, call_id, tool, args, result, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (run_id, call_id, 'scope_amend', _json(args), _json(result), _now()),
            )

        await self._db.run(lambda conn: _transaction(conn, write))
        return call_id

    # ── passive: one transaction at the end (§6.1) ──

    async def commit_passive(self, run_id: str, evidence: Sequence[Evidence], findings: Sequence[Finding]) -> None:
        """Persist a passive run's evidence and findings and mark it ``checks_complete`` atomically.

        Either everything lands or nothing does: a failure leaves the run ``created`` with no rows.
        """

        def write(conn: sqlite3.Connection) -> None:
            _require_state(conn, run_id, {'created'})
            for item in evidence:
                _insert_evidence(conn, run_id, item)
            _insert_findings(conn, run_id, findings)
            _set_state(conn, run_id, 'checks_complete', None)

        await self._db.run(lambda conn: _transaction(conn, write))

    # ── live: per-capture evidence, per-check findings (§6.1) ──

    async def add_evidence(self, run_id: str, item: Evidence) -> bool:
        """Persist one captured exchange in its own transaction. Returns ``False`` if already stored."""
        return await self._db.run(lambda conn: _transaction(conn, lambda c: _insert_evidence(c, run_id, item)))

    async def commit_findings(self, run_id: str, findings: Sequence[Finding]) -> None:
        """Persist one check's findings; every referenced evidence ID must already be stored."""
        await self._db.run(lambda conn: _transaction(conn, lambda c: _insert_findings(c, run_id, findings)))

    async def record_verification(
        self,
        run_id: str,
        verification: Verification,
        evidence: Sequence[Evidence] = (),
        *,
        transition: bool = True,
    ) -> None:
        """Store *verification* with its PoC evidence and transition the finding's status, atomically.

        ``confirmed`` → ``verified``; ``not_reproduced`` → ``verification_failed``;
        with ``transition=False`` (the runner's ``inconclusive`` path) the finding
        keeps its current status — the skill's replay table keeps inconclusive
        findings ``reported``. The finding is never deleted.
        """

        def write(conn: sqlite3.Connection) -> None:
            _require_state(conn, run_id, {'created', 'checks_complete', 'complete', 'checks_failed'})
            if (
                conn.execute(
                    'SELECT 1 FROM findings WHERE run_id = ? AND finding_id = ?', (run_id, verification.finding_id)
                ).fetchone()
                is None
            ):
                raise StoreError(
                    f'finding {verification.finding_id!r} not in run {run_id!r}', rule_code='finding-not-found'
                )
            for item in evidence:
                _insert_evidence(conn, run_id, item)
            _require_evidence(conn, run_id, verification.requests, f'verification {verification.id}')
            conn.execute(
                'INSERT OR REPLACE INTO verifications (run_id, verification_id, finding_id, verdict, content, created_at) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (
                    run_id,
                    verification.id,
                    verification.finding_id,
                    verification.verdict,
                    verification.model_dump_json(),
                    _now(),
                ),
            )
            status: FindingStatus = 'verified' if verification.verdict == 'confirmed' else 'verification_failed'
            if transition:
                conn.execute(
                    'UPDATE findings SET status = ?, verification_id = ? WHERE run_id = ? AND finding_id = ?',
                    (status, verification.id, run_id, verification.finding_id),
                )

        await self._db.run(lambda conn: _transaction(conn, write))

    # ── summaries ──

    async def save_summary(self, run_id: str, summary: ReviewSummary, model: str) -> None:
        """Store (or replace) the summary and mark the run ``complete``; clears ``summary_error``."""

        def write(conn: sqlite3.Connection) -> None:
            run = _require_state(conn, run_id, {'checks_complete', 'complete'})
            conn.execute(
                'INSERT OR REPLACE INTO summaries (run_id, content, model, generated_at) VALUES (?, ?, ?, ?)',
                (run_id, summary.model_dump_json(), model, _now()),
            )
            conn.execute('UPDATE runs SET summary_error = NULL WHERE id = ?', (run_id,))
            if run.state != 'complete':
                _set_state(conn, run_id, 'complete', None)

        await self._db.run(lambda conn: _transaction(conn, write))

    async def set_summary_error(self, run_id: str, error: str) -> None:
        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            conn.execute('UPDATE runs SET summary_error = ? WHERE id = ?', (error, run_id))

        await self._db.run(lambda conn: _transaction(conn, write))

    # ── engagements, audit, coverage, surface ──

    async def record_engagement(self, engagement: Engagement) -> str:
        """Store *engagement* (idempotent) and return its ``eng_`` ID."""
        eng_id = engagement_id(engagement)

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                'INSERT OR IGNORE INTO engagements (id, name, base_url, scope, attestation, operator, created_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (
                    eng_id,
                    engagement.target.name,
                    engagement.target.base_url,
                    engagement.scope.model_dump_json(),
                    engagement.authorization.attestation,
                    engagement.authorization.operator,
                    _now(),
                ),
            )

        await self._db.run(lambda conn: _transaction(conn, write))
        return eng_id

    async def record_tool_call(self, run_id: str, tool: str, args: Any, result: Any) -> str:
        """Append a tool invocation to the audit log. Callers redact secrets first."""
        call_id = 'tc_' + uuid.uuid4().hex

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            conn.execute(
                'INSERT INTO tool_calls (run_id, call_id, tool, args, result, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (run_id, call_id, tool, _json(args), _json(result), _now()),
            )

        await self._db.run(lambda conn: _transaction(conn, write))
        return call_id

    async def record_llm_usage(
        self,
        run_id: str,
        *,
        role: LlmRole,
        model: str,
        status: Literal['ok', 'error'],
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        latency_ms: int = 0,
    ) -> None:
        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            conn.execute(
                'INSERT INTO llm_usage (run_id, role, model, input_tokens, output_tokens, cache_read_tokens, '
                'cache_write_tokens, latency_ms, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    run_id,
                    role,
                    model,
                    input_tokens,
                    output_tokens,
                    cache_read_tokens,
                    cache_write_tokens,
                    latency_ms,
                    status,
                    _now(),
                ),
            )

        await self._db.run(lambda conn: _transaction(conn, write))

    async def llm_usage_totals(self, run_id: str) -> dict[str, int]:
        """Summed token counts and call count for *run_id*."""

        def read(conn: sqlite3.Connection) -> dict[str, int]:
            row = conn.execute(
                'SELECT COUNT(*), COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0) '
                'FROM llm_usage WHERE run_id = ?',
                (run_id,),
            ).fetchone()
            return {'calls': row[0], 'input_tokens': row[1], 'output_tokens': row[2]}

        return await self._db.run(read)

    async def upsert_coverage(self, run_id: str, entries: Iterable[CoverageEntry]) -> None:
        """Insert or replace coverage entries keyed by ``(surface, risk_area)``."""
        rows = list(entries)

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            for entry in rows:
                if entry.evidence_ids:
                    _require_evidence(conn, run_id, entry.evidence_ids, f'coverage {entry.surface} / {entry.risk_area}')
                conn.execute(
                    'INSERT OR REPLACE INTO coverage_entries (run_id, surface, risk_area, outcome, source, evidence_ids, '
                    'reason, goal_attempts, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        run_id,
                        entry.surface,
                        entry.risk_area,
                        entry.outcome,
                        entry.source,
                        _json(entry.evidence_ids),
                        entry.reason,
                        entry.goal_attempts,
                        _now(),
                    ),
                )

        await self._db.run(lambda conn: _transaction(conn, write))

    async def upsert_surface_node(
        self,
        run_id: str,
        kind: SurfaceKind,
        key: str,
        *,
        metadata: dict[str, Any] | None = None,
        evidence_ids: Sequence[str] = (),
    ) -> str:
        """Insert a surface node or merge *evidence_ids* / *metadata* into the existing one. Returns its ID."""
        node_id = surface_node_id(kind, key)

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            if evidence_ids:
                _require_evidence(conn, run_id, evidence_ids, f'surface node {kind} {key}')
            row = conn.execute(
                'SELECT metadata, evidence_ids FROM surface_nodes WHERE run_id = ? AND node_id = ?', (run_id, node_id)
            ).fetchone()
            merged_meta: dict[str, Any] = {} if row is None else json.loads(row[0])
            merged_meta.update(metadata or {})
            existing: list[str] = [] if row is None else _string_list.validate_json(row[1])
            merged_ev = sorted({*existing, *evidence_ids})
            conn.execute(
                'INSERT OR REPLACE INTO surface_nodes (run_id, node_id, kind, key, metadata, evidence_ids) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (run_id, node_id, kind, key, _json(merged_meta), _json(merged_ev)),
            )

        await self._db.run(lambda conn: _transaction(conn, write))
        return node_id

    async def add_surface_edge(
        self, run_id: str, src_id: str, dst_id: str, rel: SurfaceRel, evidence_id: str | None = None
    ) -> None:
        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            if evidence_id is not None:
                _require_evidence(conn, run_id, [evidence_id], f'surface edge {rel}')
            conn.execute(
                'INSERT OR IGNORE INTO surface_edges (run_id, src_id, dst_id, rel, evidence_id) VALUES (?, ?, ?, ?, ?)',
                (run_id, src_id, dst_id, rel, evidence_id),
            )

        await self._db.run(lambda conn: _transaction(conn, write))


# ── Write helpers (run inside a transaction) ──────────────────────────────────


def _initialize(conn: sqlite3.Connection, path: Path) -> None:
    (version,) = conn.execute('PRAGMA user_version').fetchone()
    if version == 0:
        (tables,) = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()
        if tables:
            raise StoreError(
                f'{path}: not a partex database (unversioned with existing tables)', rule_code='store-version'
            )

        def create(c: sqlite3.Connection) -> None:
            # Not executescript(): it issues its own COMMIT, which would split the schema across transactions.
            for statement in _SCHEMA.split(';'):
                if statement.strip():
                    c.execute(statement)
            c.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')

        _transaction(conn, create)
        return
    _check_version(conn, path)


def _require_state(conn: sqlite3.Connection, run_id: str, allowed: set[str]) -> RunRecord:
    run = _get_run(conn, run_id)
    if run.state not in allowed:
        raise StoreError(f'run {run_id} is {run.state}; expected one of {sorted(allowed)}', rule_code='run-state')
    return run


def _set_state(conn: sqlite3.Connection, run_id: str, state: RunState, error: str | None) -> None:
    run = _get_run(conn, run_id)
    if state not in _TRANSITIONS[run.state]:
        raise StoreError(f'run {run_id}: cannot move from {run.state} to {state}', rule_code='run-state')
    conn.execute('UPDATE runs SET state = ?, error = COALESCE(?, error) WHERE id = ?', (state, error, run_id))


def _insert_evidence(conn: sqlite3.Connection, run_id: str, item: Evidence) -> bool:
    _get_run(conn, run_id)
    (next_seq,) = conn.execute('SELECT COALESCE(MAX(seq), -1) + 1 FROM evidence WHERE run_id = ?', (run_id,)).fetchone()
    cursor = conn.execute(
        'INSERT OR IGNORE INTO evidence (run_id, evidence_id, seq, kind, content) VALUES (?, ?, ?, ?, ?)',
        (run_id, item.id, next_seq, item.kind, EvidenceAdapter.dump_json(item).decode()),
    )
    return cursor.rowcount == 1


def _require_evidence(conn: sqlite3.Connection, run_id: str, evidence_ids: Iterable[str], owner: str) -> None:
    wanted = set(evidence_ids)
    placeholders = ','.join('?' * len(wanted))
    found = {
        eid
        for (eid,) in conn.execute(
            f'SELECT evidence_id FROM evidence WHERE run_id = ? AND evidence_id IN ({placeholders})',
            (run_id, *wanted),
        )
    }
    missing = sorted(wanted - found)
    if missing:
        raise StoreError(f'{owner} references evidence not in run {run_id}: {missing}', rule_code='dangling-evidence')


def _insert_findings(conn: sqlite3.Connection, run_id: str, findings: Sequence[Finding]) -> None:
    _get_run(conn, run_id)
    for finding in findings:
        _require_evidence(conn, run_id, finding.evidence_ids, f'finding {finding.id}')
        conn.execute(
            'INSERT INTO findings (run_id, finding_id, check_id, check_version, severity, subject, title, '
            'description, evidence_ids, remediation, status, verification_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                run_id,
                finding.id,
                finding.check_id,
                finding.check_version,
                finding.severity,
                finding.subject,
                finding.title,
                finding.description,
                _json(finding.evidence_ids),
                finding.remediation,
                finding.status,
                finding.verification_id,
            ),
        )
