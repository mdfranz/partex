"""SQLite ``RunStore`` — PLAN §7, §7.1.

One file, stdlib ``sqlite3``, WAL. The engine owns the single writer (:class:`RunStore`); everything
else reads through :class:`RunReader`, which opens the database ``mode=ro``. Both expose an async API:
blocking SQLite calls run in worker threads via :func:`anyio.to_thread.run_sync`, serialized on one
connection per object.

Every model is re-validated on read, so schema drift between engine versions surfaces as a
``store-load`` error instead of silently wrong data. Before 1.0 there are no migrations (PLAN §7, #245):
a database whose ``PRAGMA user_version`` is not :data:`SCHEMA_VERSION` is refused (``store-version``)
with a message pointing at ``partex export-bundle`` / ``partex show --format json`` and
``scripts/clean-state.sh`` (#242).
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
from .ids import canonical_json, engagement_id, finding_key, sha256_hex
from .models import (
    SAFE_METHODS,
    CoverageEntry,
    Engagement,
    Evidence,
    EvidenceAdapter,
    Finding,
    HttpEvidence,
    Scope,
    Verification,
)
from .paths import mkdir_private

SCHEMA_VERSION = 5  # v5 (#245): engagement record only, no migrations before 1.0
DEFAULT_BUSY_TIMEOUT_MS = 5000

type RunState = Literal['created', 'invalid', 'checks_complete', 'checks_failed', 'complete']
type InputKind = Literal['bundle', 'engagement']
type FindingStatus = Literal['reported', 'verified', 'verification_failed']
type LlmRole = Literal['tester', 'verifier', 'summarizer', 'reviewer', 'judge', 'search', 'decision']

# Run states only move forward (§6). ``checks_complete -> complete`` is reserved for M4 summarization.
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
  ended_at TEXT,
  state TEXT NOT NULL,
  input_kind TEXT NOT NULL,
  input_ref TEXT NOT NULL,
  input_sha256 TEXT NOT NULL,
  engagement_id TEXT REFERENCES engagements,
  engine_version TEXT NOT NULL,
  selected_checks TEXT NOT NULL,
  authorized_flag INTEGER NOT NULL DEFAULT 0,
  model TEXT,
  model_calls INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  requests_spent INTEGER NOT NULL DEFAULT 0,
  write_requests_spent INTEGER NOT NULL DEFAULT 0,
  scope_snapshot TEXT,
  error TEXT
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
  finding_key TEXT NOT NULL,
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
CREATE INDEX idx_findings_finding_key ON findings (finding_key);
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
CREATE TABLE web_research (
  run_id TEXT NOT NULL REFERENCES runs,
  research_id TEXT NOT NULL,
  call_id TEXT,
  query TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  auth_mode TEXT NOT NULL,
  answer TEXT NOT NULL,
  sources TEXT NOT NULL,
  truncated INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, research_id)
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
    - ``store-integrity``: a write violated a database constraint (for example a duplicate finding ID)
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
    findings_count: int
    ended_at: str | None = None
    engagement_id: str | None = None
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    write_requests_spent: int = 0
    """State-changing sends this run made (``max_write_requests``, #65)."""


@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    """One ``tool_calls`` row; ``args`` and ``result`` are already redacted by the caller."""

    call_id: str
    tool: str
    args: Any
    result: Any
    created_at: str


@dataclass(frozen=True, slots=True)
class WebResearchRecord:
    """One ``web_research`` row (#113): a persisted ``web_search`` answer. Third-party content, never evidence."""

    id: str
    call_id: str | None
    query: str
    provider: str
    model: str
    auth_mode: str
    answer: str
    sources: tuple[dict[str, Any], ...]
    """``{"url": ..., "title": ...}`` per source; ``title`` may be ``None``."""
    truncated: bool
    created_at: str


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
    """Run *fn* inside ``BEGIN IMMEDIATE`` … ``COMMIT``, rolling back on any error.

    A constraint violation surfaces as :class:`StoreError` (``store-integrity``), not a raw
    ``sqlite3.IntegrityError``. If ``ROLLBACK`` itself fails, the original error is still the one raised (#40).
    """
    conn.execute('BEGIN IMMEDIATE')
    try:
        result = fn(conn)
    except sqlite3.IntegrityError as exc:
        _rollback(conn, exc)
        raise StoreError(f'write violated a database constraint: {exc}', rule_code='store-integrity') from exc
    except BaseException as exc:
        _rollback(conn, exc)
        raise
    conn.execute('COMMIT')
    return result


def _rollback(conn: sqlite3.Connection, original: BaseException) -> None:
    """Roll back, keeping *original* as the error that propagates; a rollback failure is attached as a note."""
    try:
        conn.execute('ROLLBACK')
    except sqlite3.Error as rollback_exc:
        original.add_note(f'ROLLBACK also failed: {rollback_exc!r}')


def _apply_pragmas(conn: sqlite3.Connection, busy_timeout_ms: int) -> None:
    conn.execute(f'PRAGMA busy_timeout = {int(busy_timeout_ms)}')
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA synchronous = NORMAL')


def _check_version(conn: sqlite3.Connection, path: Path) -> None:
    (version,) = conn.execute('PRAGMA user_version').fetchone()
    if version != SCHEMA_VERSION:
        raise StoreError(
            f'{path}: schema version {version} is not supported (expected {SCHEMA_VERSION}); '
            'before 1.0 there are no migrations — export with partex export-bundle / partex show --format json '
            'or remove old stores with scripts/clean-state.sh',
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

    async def web_research(self, run_id: str) -> list[WebResearchRecord]:
        """The run's persisted web research, in the order it was saved."""

        def read(conn: sqlite3.Connection) -> list[WebResearchRecord]:
            _get_run(conn, run_id)
            rows = conn.execute(_RESEARCH_SELECT + ' WHERE run_id = ? ORDER BY rowid', (run_id,))
            return [_research_from_row(row) for row in rows]

        return await self._db.run(read)

    async def get_web_research(self, run_id: str, research_id: str) -> WebResearchRecord | None:
        """One web research entry of *run_id*, or ``None`` (cross-run IDs never resolve)."""

        def read(conn: sqlite3.Connection) -> WebResearchRecord | None:
            row = conn.execute(
                _RESEARCH_SELECT + ' WHERE run_id = ? AND research_id = ?', (run_id, research_id)
            ).fetchone()
            return None if row is None else _research_from_row(row)

        return await self._db.run(read)


_RUN_SELECT = (
    'SELECT r.id, r.created_at, r.ended_at, r.state, r.input_kind, r.input_ref, r.input_sha256, r.engagement_id, '
    'r.engine_version, r.selected_checks, r.authorized_flag, r.model, r.model_calls, r.input_tokens, r.output_tokens, '
    'r.requests_spent, r.write_requests_spent, r.scope_snapshot, r.error, '
    '(SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id) FROM runs r'
)

_FINDING_SELECT = (
    'SELECT finding_id, check_id, check_version, severity, subject, title, description, evidence_ids, remediation, status, '
    'verification_id FROM findings'
)
_RESEARCH_SELECT = (
    'SELECT research_id, call_id, query, provider, model, auth_mode, answer, sources, truncated, created_at '
    'FROM web_research'
)


def _research_from_row(row: tuple[Any, ...]) -> WebResearchRecord:
    rid, call_id, query, provider, model, auth_mode, answer, sources, truncated, created_at = row
    return WebResearchRecord(
        id=rid,
        call_id=call_id,
        query=query,
        provider=provider,
        model=model,
        auth_mode=auth_mode,
        answer=answer,
        sources=tuple(json.loads(sources)),
        truncated=bool(truncated),
        created_at=created_at,
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
        ended,
        state,
        kind,
        ref,
        sha,
        eng_id,
        engine,
        checks,
        authorized,
        model,
        model_calls,
        in_tok,
        out_tok,
        spent,
        writes,
        scope,
        error,
        count,
    ) = row
    return RunRecord(
        id=rid,
        created_at=created,
        ended_at=ended,
        state=state,
        input_kind=kind,
        input_ref=ref,
        input_sha256=sha,
        engagement_id=eng_id,
        engine_version=engine,
        selected_checks=tuple(_load(_string_list.validate_json, checks)),
        authorized=bool(authorized),
        model=model,
        model_calls=model_calls,
        input_tokens=in_tok,
        output_tokens=out_tok,
        requests_spent=spent,
        write_requests_spent=writes,
        scope_snapshot=None if scope is None else _load(Scope.model_validate_json, scope),
        error=error,
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
        engagement: Engagement | None = None,
        engagement_id_val: str | None = None,
    ) -> str:
        """Open a run row in state ``created`` and return its ID (``run_`` + uuid4).

        When *engagement* is supplied, its ``engagements`` row is recorded in the same transaction and
        linked via ``runs.engagement_id``.
        """
        run_id = 'run_' + uuid.uuid4().hex
        scope = None if scope_snapshot is None else scope_snapshot.model_dump_json()
        eng_id = engagement_id(engagement) if engagement is not None else engagement_id_val

        def write(conn: sqlite3.Connection) -> None:
            now = _now()
            if engagement is not None and eng_id is not None:
                _insert_engagement_row(conn, eng_id, engagement, now)
            conn.execute(
                'INSERT INTO runs (id, created_at, state, input_kind, input_ref, input_sha256, engagement_id, '
                'engine_version, selected_checks, authorized_flag, model, scope_snapshot) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    run_id,
                    now,
                    'created',
                    input_kind,
                    input_ref,
                    input_sha256,
                    eng_id,
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

    async def set_model(self, run_id: str, model: str) -> None:
        """Set ``runs.model`` on *run_id*."""

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            conn.execute('UPDATE runs SET model = ? WHERE id = ?', (model, run_id))

        await self._db.run(lambda conn: _transaction(conn, write))

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

    async def commit_passive(
        self,
        run_id: str,
        evidence: Sequence[Evidence],
        findings: Sequence[Finding],
        *,
        coverage: Sequence[CoverageEntry] = (),
    ) -> None:
        """Persist a passive run's evidence, findings, and coverage atomically.

        Either everything lands or nothing does: a failure leaves the run ``created`` with no rows.
        """

        def write(conn: sqlite3.Connection) -> None:
            _require_state(conn, run_id, {'created'})
            for item in evidence:
                _insert_evidence(conn, run_id, item)
            _insert_findings(conn, run_id, findings)
            if coverage:
                _upsert_coverage_rows(conn, run_id, coverage)
            _set_state(conn, run_id, 'checks_complete', None)

        await self._db.run(lambda conn: _transaction(conn, write))

    # ── live: per-capture evidence, per-check findings (§6.1) ──

    async def add_evidence(self, run_id: str, item: Evidence, *, count_request: bool = False) -> bool:
        """Persist one captured exchange in its own transaction. Returns ``False`` if already stored.

        With *count_request*, the request that produced it is added to ``requests_spent`` in the **same**
        transaction, so a crash can never leave a stored exchange uncounted or a counted one unstored (#40).
        The request counts even when the exchange was already stored (content-addressed): it was still sent.
        """

        def write(conn: sqlite3.Connection) -> bool:
            inserted = _insert_evidence(conn, run_id, item)
            if count_request:
                # A state-changing exchange also counts against max_write_requests (#65), in the same transaction.
                writes = int(isinstance(item, HttpEvidence) and item.http.request.method.upper() not in SAFE_METHODS)
                conn.execute(
                    'UPDATE runs SET requests_spent = requests_spent + 1, write_requests_spent = write_requests_spent + ? '
                    'WHERE id = ?',
                    (writes, run_id),
                )
            return inserted

        return await self._db.run(lambda conn: _transaction(conn, write))

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

    # ── engagements, audit, coverage, model usage totals ──

    async def record_engagement(self, engagement: Engagement) -> str:
        """Store *engagement* (idempotent) and return its ``eng_`` ID."""
        eng_id = engagement_id(engagement)

        def write(conn: sqlite3.Connection) -> None:
            _insert_engagement_row(conn, eng_id, engagement, _now())

        await self._db.run(lambda conn: _transaction(conn, write))
        return eng_id

    async def record_tool_call(self, run_id: str, tool: str, args: Any, result: Any) -> str:
        """Append an action tool invocation to the audit log. Callers redact secrets first."""
        call_id = 'tc_' + uuid.uuid4().hex

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            conn.execute(
                'INSERT INTO tool_calls (run_id, call_id, tool, args, result, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (run_id, call_id, tool, _json(args), _json(result), _now()),
            )

        await self._db.run(lambda conn: _transaction(conn, write))
        return call_id

    async def add_web_research(
        self,
        run_id: str,
        *,
        query: str,
        provider: str,
        model: str,
        auth_mode: str,
        answer: str,
        sources: Sequence[dict[str, Any]],
        truncated: bool,
        audit_args: Any,
        sources_total: int | None = None,
    ) -> str:
        """Persist one successful ``web_search`` and its ``tool_calls`` audit row in one transaction (#113).

        The research row keeps the capped answer and sources; the audit row keeps metadata only (query,
        provider, source URLs, truncated) plus the ``research_id``, never the answer. Returns the ``wr_`` ID.
        *sources_total*, when the caller capped *sources*, is the uncapped count and goes in the audit row (#146).
        """
        research_id = 'wr_' + uuid.uuid4().hex[:16]
        call_id = 'tc_' + uuid.uuid4().hex
        source_list = [dict(source) for source in sources]
        audit_result: dict[str, Any] = {
            'research_id': research_id,
            'sources': [source.get('url') for source in source_list],
            'truncated': truncated,
        }
        if sources_total is not None:
            audit_result['sources_total'] = sources_total

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            now = _now()
            conn.execute(
                'INSERT INTO tool_calls (run_id, call_id, tool, args, result, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (run_id, call_id, 'web_search', _json(audit_args), _json(audit_result), now),
            )
            conn.execute(
                'INSERT INTO web_research (run_id, research_id, call_id, query, provider, model, auth_mode, answer, '
                'sources, truncated, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    run_id,
                    research_id,
                    call_id,
                    query,
                    provider,
                    model,
                    auth_mode,
                    answer,
                    _json(source_list),
                    int(truncated),
                    now,
                ),
            )

        await self._db.run(lambda conn: _transaction(conn, write))
        return research_id

    async def record_model_usage(
        self,
        run_id: str,
        *,
        model: str | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        calls: int = 1,
    ) -> None:
        """Accumulate model call and token totals onto ``runs`` (and set ``runs.model`` if still unset)."""

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            conn.execute(
                'UPDATE runs SET model_calls = model_calls + ?, input_tokens = input_tokens + ?, '
                'output_tokens = output_tokens + ?, model = COALESCE(model, ?) WHERE id = ?',
                (calls, input_tokens, output_tokens, model, run_id),
            )

        await self._db.run(lambda conn: _transaction(conn, write))

    async def upsert_coverage(self, run_id: str, entries: Iterable[CoverageEntry]) -> None:
        """Insert or replace coverage entries keyed by ``(surface, risk_area)``."""
        rows = list(entries)

        def write(conn: sqlite3.Connection) -> None:
            _get_run(conn, run_id)
            _upsert_coverage_rows(conn, run_id, rows)

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


def _insert_engagement_row(conn: sqlite3.Connection, eng_id: str, engagement: Engagement, now: str) -> None:
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
            now,
        ),
    )


def _require_state(conn: sqlite3.Connection, run_id: str, allowed: set[str]) -> RunRecord:
    run = _get_run(conn, run_id)
    if run.state not in allowed:
        raise StoreError(f'run {run_id} is {run.state}; expected one of {sorted(allowed)}', rule_code='run-state')
    return run


def _set_state(conn: sqlite3.Connection, run_id: str, state: RunState, error: str | None) -> None:
    run = _get_run(conn, run_id)
    if state not in _TRANSITIONS[run.state]:
        raise StoreError(f'run {run_id}: cannot move from {run.state} to {state}', rule_code='run-state')
    conn.execute(
        'UPDATE runs SET state = ?, ended_at = COALESCE(ended_at, ?), error = COALESCE(?, error) WHERE id = ?',
        (state, _now(), error, run_id),
    )


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
        fkey = finding_key(finding.check_id, finding.subject, finding.title)
        conn.execute(
            'INSERT INTO findings (run_id, finding_id, finding_key, check_id, check_version, severity, subject, title, '
            'description, evidence_ids, remediation, status, verification_id) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                run_id,
                finding.id,
                fkey,
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


def _upsert_coverage_rows(conn: sqlite3.Connection, run_id: str, rows: Sequence[CoverageEntry]) -> None:
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
