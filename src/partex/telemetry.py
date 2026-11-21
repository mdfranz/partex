"""Default local trace log — PLAN §11.1.

Commands that send traffic or call a model write every span (model turns, tool calls and their
failures, including scope refusals) to a JSONL file by default, so a session can be reviewed offline
without a Logfire account. The file never leaves the machine: ``send_to_logfire`` stays off unless the
operator passes ``--logfire``. It is created ``0600`` because spans carry model prompts and tool results
(already secret-redacted by the tools, but still engagement data).

``--log-file PATH`` picks the file, ``--log-file off`` (or ``PARTEX_LOG_FILE=off``) disables it, and the
default is ``$XDG_STATE_HOME/partex/logs/<command>-<UTC time>-<pid>.jsonl``.
"""

import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult

LOG_FILE_ENV = 'PARTEX_LOG_FILE'
LOGGED_COMMANDS = frozenset({'review', 'test', 'verify', 'chat', 'agent'})
"""Commands that log to a file by default; the read-only listing/export commands do not."""


def resolve_log_path(command: str, cli_value: str | None, env: Mapping[str, str] | None = None) -> Path | None:
    """``--log-file`` > ``$PARTEX_LOG_FILE`` > a new file under the user state dir; ``None`` when disabled.

    Pure: never creates anything (the exporter creates the directory on first write).
    """
    environ = os.environ if env is None else env
    value = cli_value or environ.get(LOG_FILE_ENV)
    if value:
        return None if value.lower() in {'off', 'none', '0', 'false'} else Path(value)
    if command not in LOGGED_COMMANDS:
        return None
    state_home = environ.get('XDG_STATE_HOME') or str(Path.home() / '.local' / 'state')
    stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
    return Path(state_home) / 'partex' / 'logs' / f'{command}-{stamp}-{os.getpid()}.jsonl'


def _iso(nanos: int | None) -> str | None:
    return None if nanos is None else datetime.fromtimestamp(nanos / 1e9, UTC).isoformat()


def span_record(span: ReadableSpan) -> dict[str, Any]:
    """One finished span as a JSON-able dict (ids as hex, attributes as given)."""
    context = span.context
    parent = span.parent
    return {
        'name': span.name,
        'trace_id': None if context is None else f'{context.trace_id:032x}',
        'span_id': None if context is None else f'{context.span_id:016x}',
        'parent_span_id': None if parent is None else f'{parent.span_id:016x}',
        'start': _iso(span.start_time),
        'end': _iso(span.end_time),
        'status': span.status.status_code.name,
        'status_description': span.status.description,
        'attributes': dict(span.attributes or {}),
        'events': [
            {'name': event.name, 'time': _iso(event.timestamp), 'attributes': dict(event.attributes or {})}
            for event in span.events
        ],
    }


class JsonlSpanExporter(SpanExporter):
    """Append each finished span to *path* as one JSON line (flushed per export, file mode ``0600``).

    The file is created on the first span, so a command that exits before doing any work (a usage
    error, a gate refusal) leaves no empty log behind (#126).
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._file: TextIO | None = None

    def _open(self) -> TextIO:
        if self._file is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            self._file = os.fdopen(fd, 'a', encoding='utf-8')
        return self._file

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            file = self._open()
            for span in spans:
                file.write(json.dumps(span_record(span), default=str) + '\n')
            file.flush()
        except OSError, ValueError:  # a full disk or closed file must never break a probe session
            return SpanExportResult.FAILURE
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        if self._file is not None:
            self._file.close()


def configure_telemetry(*, log_path: Path | None, remote: bool, service_version: str) -> None:
    """Configure Logfire once for the process: the local JSONL log, and remote export only if *remote*.

    Never ``instrument_httpx()``: the target client carries engagement credentials.
    """
    import logfire

    processors = [] if log_path is None else [SimpleSpanProcessor(JsonlSpanExporter(log_path))]
    logfire.configure(
        service_name='partex',
        service_version=service_version,
        send_to_logfire='if-token-present' if remote else False,
        console=False,
        additional_span_processors=processors,
    )
    logfire.instrument_pydantic_ai()


def announce(path: Path | None) -> None:
    """Tell the operator where the log is (stderr, once, before any terminal UI takes over)."""
    if path is not None:
        print(f'partex: logging to {path}', file=sys.stderr)
