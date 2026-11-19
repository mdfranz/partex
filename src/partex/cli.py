"""Partex CLI — PLAN §6 (exit codes), §8 (surface), §11.1 (Logfire).

One function per subcommand (``_cmd_<name>``) so later milestones add commands in isolated hunks.

Exit codes (§6): ``0`` completed with no findings, ``3`` completed with findings, ``2`` usage error
(argparse, empty check selection), ``1`` fatal (invalid input, unknown check, unauthorized, storage
error including a lock timeout, check crash), ``130`` interrupted.

Output is JSON when stdout is not a TTY (or with ``--json`` / ``--format json``), human text otherwise.
"""

import argparse
import json
import os
import sys
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import anyio

from . import engine
from .engine import CheckSelectionError
from .errors import PartexError
from .export import IncludeSecretsWarning, export_run_data, write_run_export
from .ids import canonical_json
from .storage import RunReader, RunRecord, RunStore

DB_ENV = 'PARTEX_DB'
LOGFIRE_ENV = 'PARTEX_LOGFIRE'

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_USAGE = 2
EXIT_FINDINGS = 3
EXIT_INTERRUPTED = 130

# Selection problems that are bad input (exit 1, PLAN §8) rather than a malformed invocation (exit 2).
_FATAL_SELECTION_CODES = frozenset({'unknown-check', 'not-passive', 'not-active'})


# ── Shared plumbing ───────────────────────────────────────────────────────────


def resolve_db_path(cli_value: str | None, env: dict[str, str] | None = None) -> Path:
    """``--db`` > ``$PARTEX_DB`` > ``$XDG_DATA_HOME/partex/partex.db`` > ``~/.local/share/partex/partex.db``.

    Pure: never creates directories (the writer creates the parent on open; readers must not).
    """
    environ = os.environ if env is None else env
    if cli_value:
        return Path(cli_value)
    if environ.get(DB_ENV):
        return Path(environ[DB_ENV])
    data_home = environ.get('XDG_DATA_HOME') or str(Path.home() / '.local' / 'share')
    return Path(data_home) / 'partex' / 'partex.db'


def _wants_json(explicit: bool = False) -> bool:
    return explicit or not sys.stdout.isatty()


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _split_checks(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(',') if item.strip()]


def _configure_logfire() -> None:
    """Enable Logfire for this process (§11.1): ``configure`` once, strictly before instrumentation.

    Never ``instrument_httpx()``: the target client carries engagement credentials.
    """
    import logfire

    logfire.configure(service_name='partex', service_version=engine.engine_version())
    logfire.instrument_pydantic_ai()


def _finding_rows(findings: Sequence[Any]) -> list[dict[str, Any]]:
    return [
        {
            'id': finding.id,
            'check_id': finding.check_id,
            'severity': finding.severity,
            'status': finding.status,
            'subject': finding.subject,
            'title': finding.title,
        }
        for finding in findings
    ]


def _print_findings_text(findings: Sequence[Any]) -> None:
    if not findings:
        print('no findings')
        return
    for finding in findings:
        print(f'  [{finding.severity}] {finding.title} — {finding.subject} ({finding.id}, {finding.status})')


def _run_exit_code(state: str, has_findings: bool) -> int:
    if state not in ('checks_complete', 'complete'):
        return EXIT_FATAL
    return EXIT_FINDINGS if has_findings else EXIT_OK


async def _write_export(store: RunStore, run_id: str, out: str | None) -> None:
    if out:
        await write_run_export(store, run_id, out)


# ── Parser ────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """The argparse surface (PLAN §8). Every subcommand accepts ``--logfire``; store commands ``--db``."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--logfire', action='store_true', help=f'enable Logfire observability (or set {LOGFIRE_ENV}=1)')
    with_db = argparse.ArgumentParser(add_help=False, parents=[common])
    with_db.add_argument('--db', default=None, help=f'database path (default: ${DB_ENV} or the user data dir)')

    parser = argparse.ArgumentParser(prog='partex', description='Evidence-backed web application security testing.')
    parser.add_argument('--version', action='version', version=f'partex {engine.engine_version()}')
    subparsers = parser.add_subparsers(dest='command', required=True, metavar='COMMAND')

    review = subparsers.add_parser('review', parents=[with_db], help='passive review of an offline bundle')
    review.add_argument('bundle', help='bundle directory (containing bundle.json)')
    selection = review.add_mutually_exclusive_group(required=True)
    selection.add_argument('--checks', help='comma-separated check ids, run in this order (duplicates dropped)')
    selection.add_argument('--all', action='store_true', help='run every installed passive check, registration order')
    review.add_argument(
        '--workers', type=_positive_int, default=None, help='local worker count (default: min(4, CPUs))'
    )
    review.add_argument('--no-summary', action='store_true', help='skip the model-backed summary (M4)')
    review.add_argument('--out', default=None, help='also write the canonical JSON export to this file')
    review.set_defaults(handler=_cmd_review)

    test = subparsers.add_parser(
        'test', parents=[with_db], help='live run: capture, active checks (requires --authorized)'
    )
    test.add_argument('engagement', help='engagement directory or engagement.json path')
    test.add_argument('--authorized', action='store_true', help='required: attests authorization to test')
    test.add_argument(
        '--checks', default='version-disclosure', help='comma-separated, ordered check ids (default: %(default)s)'
    )
    test.add_argument('--no-summary', action='store_true', help='skip the model-backed summary (M4)')
    test.add_argument('--out', default=None, help='also write the canonical JSON export to this file')
    test.set_defaults(handler=_cmd_test)

    runs = subparsers.add_parser('runs', parents=[with_db], help='list runs')
    runs.add_argument('--json', action='store_true', help='JSON output even on a TTY')
    runs.set_defaults(handler=_cmd_runs)

    show = subparsers.add_parser('show', parents=[with_db], help='export a run (secrets redacted by default)')
    show.add_argument('run_id', help='run id (run_…)')
    show.add_argument('--format', choices=('json', 'text'), default=None, help='default: text on a TTY, json otherwise')
    show.add_argument('--include-secrets', action='store_true', help='emit secret_fields unredacted (warns)')
    show.add_argument('--out', default=None, help='write to this file instead of stdout')
    show.set_defaults(handler=_cmd_show)

    checks = subparsers.add_parser('checks', parents=[common], help='list installed checks')
    checks.add_argument('--json', action='store_true', help='JSON output even on a TTY')
    checks.set_defaults(handler=_cmd_checks)
    return parser


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f'expected a positive integer, got {value!r}') from None
    if number < 1:
        raise argparse.ArgumentTypeError(f'expected a positive integer, got {number}')
    return number


# ── review ────────────────────────────────────────────────────────────────────


def _passive_check_ids(registry: dict[str, Any]) -> list[str]:
    return [check_id for check_id, check in registry.items() if callable(getattr(check, 'review', None))]


def _cmd_review(args: argparse.Namespace) -> int:
    registry = engine.installed_checks()
    selection = _passive_check_ids(registry) if args.all else _split_checks(args.checks)
    engine.select_passive_checks(registry, selection)  # a bad selection fails before any store is opened
    db_path = resolve_db_path(args.db)

    async def go() -> engine.ReviewResult:
        async with await RunStore.open(db_path) as store:
            result = await engine.run_review(args.bundle, store, selection, registry=registry, workers=args.workers)
            await _write_export(store, result.run_id, args.out)
            return result

    result = anyio.run(go)
    if _wants_json():
        _print_json(
            {
                'run_id': result.run_id,
                'state': result.state,
                'checks': list(result.selected_checks),
                'evidence_count': result.evidence_count,
                'findings': _finding_rows(result.findings),
                'warnings': list(result.warnings),
                'skipped_checks': list(result.skipped_checks),
                'error': result.error,
                'rule_code': result.rule_code,
                'failed_check': result.failed_check,
            }
        )
    else:
        print(f'run {result.run_id}: {result.state}')
        print(f'evidence: {result.evidence_count}  checks: {", ".join(result.selected_checks)}')
        for warning in result.warnings:
            print(f'warning: {warning}', file=sys.stderr)
        if result.skipped_checks:
            print(f'skipped (not applicable): {", ".join(result.skipped_checks)}')
        if result.error:
            print(f'error: {result.error}', file=sys.stderr)
        else:
            _print_findings_text(result.findings)
    return _run_exit_code(result.state, bool(result.findings))


# ── test ──────────────────────────────────────────────────────────────────────


def _cmd_test(args: argparse.Namespace) -> int:
    checks = _split_checks(args.checks)
    engine.select_active_checks(engine.installed_checks(), checks)  # fail before any store is opened
    db_path = resolve_db_path(args.db)

    async def go() -> engine.TestResult:
        async with await RunStore.open(db_path) as store:
            result = await engine.run_test(args.engagement, store, checks, authorized=bool(args.authorized))
            await _write_export(store, result.run_id, args.out)
            return result

    result = anyio.run(go)
    if _wants_json():
        _print_json(
            {
                'run_id': result.run_id,
                'state': result.state,
                'checks': list(result.selected_checks),
                'requests_spent': result.requests_spent,
                'authorized': result.authorized,
                'evidence_count': result.evidence_count,
                'budget_exhausted': result.budget_exhausted,
                'findings': _finding_rows(result.findings),
                'error': result.error,
                'rule_code': result.rule_code,
                'failed_check': result.failed_check,
                'skipped_checks': list(result.skipped_checks),
            }
        )
    else:
        print(f'run {result.run_id}: {result.state}')
        print(f'requests spent: {result.requests_spent}  checks: {", ".join(result.selected_checks)}')
        if result.budget_exhausted:
            print('budget exhausted: active work ended cleanly')
        if result.skipped_checks:
            print(f'skipped: {", ".join(result.skipped_checks)}')
        if result.error:
            print(f'error: {result.error}', file=sys.stderr)
        _print_findings_text(result.findings)
    return _run_exit_code(result.state, bool(result.findings))


# ── runs ──────────────────────────────────────────────────────────────────────


def _run_row(run: RunRecord) -> dict[str, Any]:
    return {
        'id': run.id,
        'created_at': run.created_at,
        'state': run.state,
        'input_kind': run.input_kind,
        'input_ref': run.input_ref,
        'findings_count': run.findings_count,
    }


def _cmd_runs(args: argparse.Namespace) -> int:
    db_path = resolve_db_path(args.db)

    async def go() -> list[RunRecord]:
        async with await RunReader.open(db_path) as reader:
            return await reader.list_runs()

    runs = anyio.run(go)
    if _wants_json(args.json):
        _print_json([_run_row(run) for run in runs])
    elif not runs:
        print('no runs')
    else:
        for run in runs:
            print(
                f'{run.id}  {run.created_at}  {run.state:<15}  {run.findings_count:>4} findings  '
                f'{run.input_kind}:{run.input_ref}'
            )
    return EXIT_OK


# ── show ──────────────────────────────────────────────────────────────────────


def _render_text(payload: dict[str, Any], run_id: str) -> str:
    """Human view built from the export payload, so text output gets the same redaction as JSON."""
    run = payload['run']
    lines = [
        f'run {run_id}: {run["state"]}',
        f'input: {run["input_kind"]}:{run["input_ref"]}  engine: {run["engine_version"]}',
        f'checks: {", ".join(run["selected_checks"])}  evidence: {len(payload["evidence"])}',
    ]
    if run['input_kind'] == 'engagement':
        lines.append(f'requests spent: {run["requests_spent"]}  authorized: {run["authorized"]}')
    if run['error']:
        lines.append(f'error: {run["error"]}')
    findings: list[dict[str, Any]] = payload['findings']
    lines.append(f'findings: {len(findings)}')
    for finding in findings:
        lines.append(f'  [{finding["severity"]}] {finding["title"]} — {finding["subject"]} ({finding["status"]})')
        lines.append(f'      {finding["id"]}  evidence: {", ".join(finding["evidence_ids"])}')
    for verification in payload['verifications']:
        lines.append(f'verification {verification["id"]}: {verification["verdict"]} for {verification["finding_id"]}')
    if payload['summary'] is not None:
        lines.append('summary:')
        lines.append(f'  {payload["summary"]["narrative"]}')
    return '\n'.join(lines) + '\n'


def _cmd_show(args: argparse.Namespace) -> int:
    db_path = resolve_db_path(args.db)
    output_format = args.format or ('json' if args.out or _wants_json() else 'text')

    async def go() -> dict[str, Any]:
        async with await RunReader.open(db_path) as reader:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', IncludeSecretsWarning)  # surfaced once below, on stderr
                return await export_run_data(reader, args.run_id, include_secrets=args.include_secrets)

    payload = anyio.run(go)
    if args.include_secrets:
        print('warning: export includes unredacted secrets (--include-secrets)', file=sys.stderr)
    if output_format == 'json':
        rendered = canonical_json(payload).decode() + '\n'
    else:
        rendered = _render_text(payload, args.run_id)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding='utf-8')
    else:
        sys.stdout.write(rendered)
    return EXIT_OK


# ── checks ────────────────────────────────────────────────────────────────────


def _check_kind(check: Any) -> str:
    passive = callable(getattr(check, 'review', None))
    active = callable(getattr(check, 'probe', None))
    return 'passive+active' if passive and active else 'passive' if passive else 'active' if active else 'unknown'


def _cmd_checks(args: argparse.Namespace) -> int:
    registry = engine.installed_checks()
    rows = [
        {
            'check_id': check_id,
            'kind': _check_kind(check),
            'version': str(getattr(check, 'version', '')),
            'title': str(getattr(check, 'title', '')),
        }
        for check_id, check in registry.items()
    ]
    if _wants_json(args.json):
        _print_json(rows)
    elif not rows:
        print('no checks installed')
    else:
        for row in rows:
            print(f'{row["check_id"]:<24} {row["kind"]:<15} {row["version"]:<8} {row["title"]}')
    return EXIT_OK


# ── Entry point ───────────────────────────────────────────────────────────────


def main(argv: Sequence[str] | None = None) -> int:
    """Parse and dispatch; returns the process exit code (§6)."""
    # argparse exits itself: SystemExit(2) on usage errors, SystemExit(0) for --help / --version.
    args = build_parser().parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        if args.logfire or os.environ.get(LOGFIRE_ENV) == '1':
            _configure_logfire()
        return handler(args)
    except CheckSelectionError as exc:
        print(f'partex: {exc.rule_code}: {exc}', file=sys.stderr)
        return EXIT_FATAL if exc.rule_code in _FATAL_SELECTION_CODES else EXIT_USAGE
    except PartexError as exc:
        print(f'partex: {exc.rule_code or "error"}: {exc}', file=sys.stderr)
        return EXIT_FATAL
    except KeyboardInterrupt:
        print('partex: interrupted', file=sys.stderr)
        return EXIT_INTERRUPTED
