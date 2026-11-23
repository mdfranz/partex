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
import re
import sys
import warnings
from collections.abc import Callable, Sequence
from dataclasses import asdict
from functools import partial
from pathlib import Path
from typing import Any

import anyio

from . import engine
from .engine import CheckSelectionError
from .errors import PartexError
from .export import IncludeSecretsWarning, export_run_data, write_run_export
from .har_io import export_bundle, import_har
from .ids import canonical_json
from .nmap import convert_nmap
from .paths import STATE_DIR_ENV, state_dir
from .probes import seed_summary
from .registry import build_registry
from .report import gather_report_payload, render_report_text
from .sandboxes import detect_sandboxes, sandboxes_as_dicts
from .storage import RunReader, RunRecord, RunStore, list_reports, read_report
from .telemetry import LOG_FILE_ENV, announce, configure_telemetry, resolve_log_path

DB_ENV = 'PARTEX_DB'
LOGFIRE_ENV = 'PARTEX_LOGFIRE'
LOGFIRE_CONTENT_ENV = 'PARTEX_LOGFIRE_CONTENT'
SKILL_DIR_ARGS: dict[str, Any] = {
    'action': 'append',
    'default': [],
    'metavar': 'DIR',
    'help': 'extra skill root offered to the model as on-demand playbooks (data only; repeatable)',
}
RECURSIVE_HELP = 'with --urls-file: treat every listed URL as a path prefix (http://foo/ allows everything under it)'
URLS_FILE_HELP = (
    'file of authorized URLs, one per line (# comments; a trailing /* allows a path prefix). Only these URLs can be '
    'requested, and target.base_url must be listed (#121)'
)
INSECURE_HELP = (
    'accept invalid TLS certificates (self-signed, expired, hostname mismatch) for this run; also '
    'engagement tls.verify=false. Recorded on the run, never available to the model'
)
USER_AGENT_HELP = 'User-Agent for this run, overriding the engagement http.user_agent (default partex/<version>)'

ALLOW_METHOD_HELP = (
    'also authorize this state-changing method (POST, PUT, PATCH or DELETE) for this run; repeatable, needs '
    '--max-writes (or the engagement max_write_requests). Each write still waits for operator approval; headless '
    'runs deny them'
)
MAX_WRITES_HELP = 'budget of state-changing requests for this run (ceiling 1000); overrides max_write_requests'

REQUEST_LIMIT_HELP = (
    'most model turns one prompt may take before the turn stops (default {default}); a long investigation that '
    'chains many tool calls may need more'
)

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_USAGE = 2
EXIT_FINDINGS = 3
EXIT_INTERRUPTED = 130

# Selection problems that are bad input (exit 1, PLAN §8) rather than a malformed invocation (exit 2).
_FATAL_SELECTION_CODES = frozenset({'unknown-check', 'not-passive', 'not-active', 'not-runnable'})


# ── Shared plumbing ───────────────────────────────────────────────────────────


def resolve_db_path(cli_value: str | None, env: dict[str, str] | None = None) -> Path:
    """``--db`` > ``$PARTEX_DB`` > ``partex.db`` within the Partex state directory.

    Pure: never creates directories (the writer creates the parent on open; readers must not).
    """
    environ = os.environ if env is None else env
    if cli_value:
        return Path(cli_value)
    if environ.get(DB_ENV):
        return Path(environ[DB_ENV])
    return state_dir(environ) / 'partex.db'


def _wants_json(explicit: bool = False) -> bool:
    return explicit or not sys.stdout.isatty()


_TERMINAL_CONTROLS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]')


def neutralize_controls(text: str) -> str:
    """Show C0/C1 control characters (except newline and tab) as visible ``\\xNN`` escapes (#141).

    Reports are model-authored from untrusted target data, so they may carry ANSI/OSC sequences (screen clears,
    cursor moves, OSC 8 links, title changes) that a terminal would act on instead of display.
    """
    return _TERMINAL_CONTROLS.sub(lambda match: f'\\x{ord(match.group()):02x}', text)


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _split_checks(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(',') if item.strip()]


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


def _coverage_gaps(entries: Sequence[dict[str, Any]]) -> list[str]:
    """Ledger entries the operator should not read as a clean result: not exercised, or needing follow-up."""
    return [
        f'  not exercised: {entry["surface"]} / {entry["risk_area"]} ({entry["outcome"]}): {entry["reason"]}'
        for entry in entries
        if entry['outcome'] in ('not_applicable', 'needs_follow_up')
    ]


def _print_coverage_gaps(entries: Sequence[dict[str, Any]]) -> None:
    for line in _coverage_gaps(entries):
        print(line)


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


THINKING_LEVELS = ('minimal', 'low', 'medium', 'high', 'xhigh', 'max')


def _request_limit_help() -> str:
    from .agent_adapter import DEFAULT_REQUEST_LIMIT

    return REQUEST_LIMIT_HELP.format(default=DEFAULT_REQUEST_LIMIT)


def build_parser() -> argparse.ArgumentParser:
    """The argparse surface (PLAN §8). Every subcommand accepts ``--logfire``; store commands ``--db``."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        '--logfire', action='store_true', help=f'also send telemetry to Logfire (or set {LOGFIRE_ENV}=1)'
    )
    common.add_argument(
        '--logfire-content',
        action='store_true',
        help=f'keep model and tool content out of the default secret scrubber in traces (or set {LOGFIRE_CONTENT_ENV}=1)',
    )
    common.add_argument(
        '--log-file',
        default=None,
        help=f'JSONL trace log (default for review/test/verify/chat/agent: a new file in the user state dir; '
        f"'off' disables; or set {LOG_FILE_ENV})",
    )
    with_db = argparse.ArgumentParser(add_help=False, parents=[common])
    with_db.add_argument('--db', default=None, help=f'database path (default: ${DB_ENV} or partex.db in the state dir)')

    parser = argparse.ArgumentParser(
        prog='partex',
        description='Evidence-backed web application security testing.',
        epilog=f'Set {STATE_DIR_ENV} to override the directory for local Partex state.',
    )
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
        'test', parents=[with_db], help='live run: capture, active and passive checks (requires --authorized)'
    )
    test.add_argument('engagement', help='engagement directory or engagement.json path')
    test.add_argument('--authorized', action='store_true', help='required: attests authorization to test')
    test.add_argument('--insecure', action='store_true', help=INSECURE_HELP)
    test.add_argument('--user-agent', default=None, help=USER_AGENT_HELP)
    test.add_argument('--urls-file', default=None, help=URLS_FILE_HELP)
    test.add_argument('--recursive', action='store_true', help=RECURSIVE_HELP)
    test.add_argument('--allow-method', action='append', default=[], metavar='METHOD', help=ALLOW_METHOD_HELP)
    test.add_argument('--max-writes', type=int, default=None, metavar='N', help=MAX_WRITES_HELP)
    test_selection = test.add_mutually_exclusive_group()
    test_selection.add_argument(
        '--checks',
        default=None,
        help='comma-separated check ids, active and/or passive, de-duplicated '
        '(default: every installed passive check plus version-disclosure)',
    )
    test_selection.add_argument('--all', action='store_true', help='run every installed check, active and passive')
    test.add_argument('--no-summary', action='store_true', help='skip the model-backed summary (M4)')
    test.add_argument('--out', default=None, help='also write the canonical JSON export to this file')
    test.add_argument(
        '--bundle',
        default=None,
        help="seed the run with an imported bundle's captured surface (import-har or export-bundle output, #76)",
    )
    test.add_argument(
        '--max-seed',
        type=_positive_int,
        default=None,
        help='cap on seeded probes from --bundle (drops are reported, not silent)',
    )
    test.set_defaults(handler=_cmd_test)

    runs = subparsers.add_parser('runs', parents=[with_db], help='list runs')
    runs.add_argument('--json', action='store_true', help='JSON output even on a TTY')
    runs.set_defaults(handler=_cmd_runs)

    report = subparsers.add_parser(
        'report', parents=[with_db], help='cross-run rollup of findings, model spend, and tool calls'
    )
    report.add_argument('--json', action='store_true', help='JSON output even on a TTY')
    report.set_defaults(handler=_cmd_report)

    show = subparsers.add_parser('show', parents=[with_db], help='export a run (secrets redacted by default)')
    show.add_argument('run_id', help='run id (run_…)')
    show.add_argument('--format', choices=('json', 'text'), default=None, help='default: text on a TTY, json otherwise')
    show.add_argument('--include-secrets', action='store_true', help='emit secret_fields unredacted (warns)')
    show.add_argument('--out', default=None, help='write to this file instead of stdout')
    show.set_defaults(handler=_cmd_show)

    reports = subparsers.add_parser('reports', parents=[with_db], help='list or read a run’s saved Markdown reports')
    reports.add_argument('run_id', help='run id (run_…)')
    reports.add_argument('name', nargs='?', help='report name from the listing')
    reports.add_argument('--json', action='store_true', help='output structured JSON')
    reports.set_defaults(handler=_cmd_reports)

    import_har_cmd = subparsers.add_parser(
        'import-har', parents=[common], help='build a passive-reviewable bundle from an operator-exported HAR'
    )
    import_har_cmd.add_argument('har', help='HAR file (operator capture; the MITM-free input path)')
    import_har_cmd.add_argument('--out', required=True, help='bundle directory to write (bundle.json + evidence/)')
    import_har_cmd.add_argument(
        '--target', default=None, help='target origin entries must match (default: the most frequent request origin)'
    )
    import_har_cmd.set_defaults(handler=_cmd_import_har)

    export_bundle_cmd = subparsers.add_parser(
        'export-bundle', parents=[with_db], help="write a run's captures as a passive-reviewable bundle"
    )
    export_bundle_cmd.add_argument('run_id', help='run id (run_…)')
    export_bundle_cmd.add_argument('--out', required=True, help='bundle directory to write (bundle.json + evidence/)')
    export_bundle_cmd.add_argument(
        '--include-secrets', action='store_true', help='emit secret_fields unredacted (warns)'
    )
    export_bundle_cmd.set_defaults(handler=_cmd_export_bundle)

    nmap_cmd = subparsers.add_parser(
        'nmap',
        parents=[common],
        help='convert nmap -oX scan output into authorized-URL-list entries (pure conversion; review before use)',
    )
    nmap_cmd.add_argument(
        'files', nargs='+', metavar='XML', help='nmap -oX scan file(s); several merge (a sweep plus a -sV pass)'
    )
    nmap_cmd.add_argument(
        '--use-hostnames',
        action='store_true',
        help='entry hosts from the scan PTR hostnames instead of the scanned IPs (reverse DNS can be stale)',
    )
    nmap_cmd.add_argument(
        '--out', default=None, metavar='PATH', help='write the entries to this --urls-file instead of stdout'
    )
    nmap_cmd.add_argument('--json', action='store_true', help='JSON output even on a TTY')
    nmap_cmd.set_defaults(handler=_cmd_nmap)

    checks = subparsers.add_parser('checks', parents=[common], help='list installed checks')
    checks.add_argument('--json', action='store_true', help='JSON output even on a TTY')
    checks.add_argument(
        '--skill-dir', action='append', default=[], metavar='DIR', help='extra skill root (data only; repeatable)'
    )
    checks.set_defaults(handler=_cmd_checks)

    verify = subparsers.add_parser(
        'verify', parents=[with_db], help='(re)run the verification replay for one finding (requires --authorized)'
    )
    verify.add_argument('run_id', help='the run holding the finding')
    verify.add_argument('finding_id', help='the finding to re-verify')
    verify.add_argument('--authorized', action='store_true', help='required: attests authorization to test')
    verify.add_argument(
        '--user-agent',
        default=None,
        help='User-Agent for the replay (default: the one the original request used)',
    )
    verify.add_argument('--json', action='store_true', help='JSON output even on a TTY')
    verify.set_defaults(handler=_cmd_verify)

    chat = subparsers.add_parser(
        'chat', parents=[with_db], help='read-only review chat over a saved run (CLAI2 terminal)'
    )
    chat.add_argument('run_id', help='run id (run_…)')
    chat.add_argument(
        '--model',
        required=True,
        help='pydantic-ai model string (e.g. gateway/anthropic:claude-sonnet-5-5), or a bare model name with '
        '--gateway-route',
    )
    chat.add_argument(
        '--gateway-route',
        default=None,
        help='Pydantic AI Gateway route serving a bare --model, e.g. doubleword for zai-org/GLM-5.3',
    )
    chat.add_argument(
        '--no-briefing', action='store_true', help='open the chat without the opening model summary of the run'
    )
    chat.add_argument('--skill-dir', **SKILL_DIR_ARGS)
    chat.add_argument('--request-limit', type=_positive_int, default=None, metavar='N', help=_request_limit_help())
    chat.set_defaults(handler=_cmd_chat)

    agent = subparsers.add_parser(
        'agent',
        parents=[with_db],
        help='live session: direct further probes from the CLAI2 terminal (requires --authorized)',
    )
    agent.add_argument('engagement', help='engagement directory or engagement.json path')
    agent.add_argument('--authorized', action='store_true', help='required: attests authorization to test')
    agent.add_argument('--insecure', action='store_true', help=INSECURE_HELP)
    agent.add_argument('--user-agent', default=None, help=USER_AGENT_HELP)
    agent.add_argument('--urls-file', default=None, help=URLS_FILE_HELP)
    agent.add_argument('--recursive', action='store_true', help=RECURSIVE_HELP)
    agent.add_argument('--allow-method', action='append', default=[], metavar='METHOD', help=ALLOW_METHOD_HELP)
    agent.add_argument('--max-writes', type=int, default=None, metavar='N', help=MAX_WRITES_HELP)
    agent.add_argument(
        '--model', required=True, help='as for chat: a model string, or a bare name with --gateway-route'
    )
    agent.add_argument('--gateway-route', default=None, help='Pydantic AI Gateway route serving a bare --model')
    agent.add_argument(
        '--search-model',
        default=None,
        help='optional separate model for web_search (anthropic:, google:, google-cloud:, or openai:<name>)',
    )
    agent.add_argument(
        '--checks',
        default=','.join(engine.DEFAULT_AGENT_CHECKS),
        help='checks run before the chat opens (comma-separated; default: %(default)s). The passive discovery '
        'checks also re-run by themselves when assets or specs are captured (#185)',
    )
    agent.add_argument('--from', dest='from_run', default=None, help='earlier run the agent may read (run_…)')
    agent.add_argument(
        '--bundle',
        default=None,
        help="expose an imported bundle's surface to the session read-only (nothing is sent automatically, #76)",
    )
    agent.add_argument('--no-briefing', action='store_true', help='open the chat without the opening summary')
    agent.add_argument('--request-limit', type=_positive_int, default=None, metavar='N', help=_request_limit_help())
    agent.add_argument(
        '--thinking',
        choices=THINKING_LEVELS,
        default=None,
        help="tester model's reasoning effort (default: the provider's); lower is faster and cheaper",
    )
    agent.add_argument('--skill-dir', **SKILL_DIR_ARGS)
    agent.set_defaults(handler=_cmd_agent)

    sandboxes = subparsers.add_parser(
        'sandboxes', parents=[common], help='detect which sandboxes (monty, docker, podman, bubblewrap) are usable'
    )
    sandboxes.add_argument('--json', action='store_true', help='output JSON')
    sandboxes.set_defaults(handler=_cmd_sandboxes)
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
    registry = engine.installed_checks()
    if args.all:
        checks = list(registry)
    elif args.checks is None:
        checks = engine.default_live_checks(registry)
    else:
        checks = _split_checks(args.checks)
    engine.select_live_checks(registry, checks)  # fail before any store is opened
    if args.max_seed is not None and args.bundle is None:
        print('partex: usage: --max-seed requires --bundle', file=sys.stderr)
        return EXIT_USAGE
    if args.recursive and args.urls_file is None:
        print('partex: usage: --recursive requires --urls-file', file=sys.stderr)
        return EXIT_USAGE
    db_path = resolve_db_path(args.db)

    async def go() -> engine.TestResult:
        async with await RunStore.open(db_path) as store:
            result = await engine.run_test(
                args.engagement,
                store,
                checks,
                authorized=bool(args.authorized),
                insecure=bool(args.insecure),
                urls_file=args.urls_file,
                recursive=bool(args.recursive),
                user_agent=args.user_agent,
                allow_methods=args.allow_method,
                max_writes=args.max_writes,
                seed_bundle=args.bundle,
                max_seed=args.max_seed,
            )
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
                'seeded_count': result.seeded_count,
                'seed_plan': None
                if result.seed_plan is None
                else {
                    'candidates': len(result.seed_plan.candidates),
                    'dropped_out_of_scope': result.seed_plan.dropped_out_of_scope,
                    'dropped_methods': result.seed_plan.dropped_methods,
                    'dropped_duplicates': result.seed_plan.dropped_duplicates,
                    'dropped_capped': result.seed_plan.dropped_capped,
                },
                'seed_skipped': result.seed_skipped,
                'findings': _finding_rows(result.findings),
                'error': result.error,
                'rule_code': result.rule_code,
                'failed_check': result.failed_check,
                'skipped_checks': list(result.skipped_checks),
                'coverage': [entry.model_dump(mode='json') for entry in result.coverage],
            }
        )
    else:
        print(f'run {result.run_id}: {result.state}')
        print(f'requests spent: {result.requests_spent}  checks: {", ".join(result.selected_checks)}')
        if result.seed_plan is not None:
            print(seed_summary(result.seed_plan, result.seeded_count, seed_skipped=result.seed_skipped))
        if result.budget_exhausted:
            print('budget exhausted: active work ended cleanly')
        if result.skipped_checks:
            print(f'skipped: {", ".join(result.skipped_checks)}')
        if result.error:
            print(f'error: {result.error}', file=sys.stderr)
        _print_coverage_gaps([entry.model_dump(mode='json') for entry in result.coverage])
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
        'requests_spent': run.requests_spent,
        'model': run.model,
        'hosts': [] if run.scope_snapshot is None else run.scope_snapshot.hosts,
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


def _cmd_report(args: argparse.Namespace) -> int:
    db_path = resolve_db_path(args.db)

    async def go() -> dict[str, Any]:
        async with await RunReader.open(db_path) as reader:
            return await gather_report_payload(reader)

    payload = anyio.run(go)
    if _wants_json(args.json):
        _print_json(payload)
    else:
        sys.stdout.write(render_report_text(payload))
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
    model_calls: int = run.get('model_calls', 0)
    in_tok: int = run.get('input_tokens', 0)
    out_tok: int = run.get('output_tokens', 0)
    if model_calls or in_tok or out_tok:
        lines.append(f'model calls: {model_calls}  tokens in/out: {in_tok}/{out_tok}')
    findings: list[dict[str, Any]] = payload['findings']
    lines.append(f'findings: {len(findings)}')
    for finding in findings:
        lines.append(f'  [{finding["severity"]}] {finding["title"]} — {finding["subject"]} ({finding["status"]})')
        lines.append(f'      {finding["id"]}  evidence: {", ".join(finding["evidence_ids"])}')
    lines.extend(_coverage_gaps(payload.get('coverage', [])))
    for verification in payload['verifications']:
        lines.append(f'verification {verification["id"]}: {verification["verdict"]} for {verification["finding_id"]}')
    research: list[dict[str, Any]] = payload.get('web_research', [])
    if research:
        lines.append(f'web research: {len(research)}')
        for entry in research:
            truncated = ', truncated' if entry['truncated'] else ''
            lines.append(f'  {entry["query"]} ({entry["provider"]}, {len(entry["sources"])} sources{truncated})')
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


def _cmd_reports(args: argparse.Namespace) -> int:
    db_path = resolve_db_path(args.db)

    async def check_run() -> None:
        async with await RunReader.open(db_path) as reader:
            await reader.get_run(args.run_id)

    anyio.run(check_run)
    if args.name is not None:
        content = read_report(db_path, args.run_id, args.name)
        if args.json:
            _print_json({'run_id': args.run_id, 'name': args.name, 'content': content})
        elif sys.stdout.isatty():
            sys.stdout.write(neutralize_controls(content))  # a terminal would act on escapes; show them
        else:
            sys.stdout.write(content)  # piped or redirected: the saved bytes, unchanged
    else:
        reports = list_reports(db_path, args.run_id)
        if _wants_json(args.json):
            _print_json([asdict(report) for report in reports])
        elif reports:
            for report in reports:
                print(f'{report.name}\t{report.size_bytes} bytes\t{report.mtime}\t{report.sha256}')
        else:
            print('No saved reports.')
    return EXIT_OK


# ── nmap (issue #215) ──────────────────────────────────────────────────────────


def _cmd_nmap(args: argparse.Namespace) -> int:
    imported = convert_nmap(args.files, use_hostnames=args.use_hostnames)
    lines = imported.as_lines()
    if args.out:
        Path(args.out).write_text('\n'.join(lines) + '\n', encoding='utf-8')
    if _wants_json(args.json):
        _print_json(
            {
                'entries': imported.entries,
                'hosts': imported.hosts,
                'skipped': imported.skipped,
                'sources': [{'path': s.path, 'sha256': s.sha256} for s in imported.sources],
                'out': args.out,
            }
        )
    else:
        print('\n'.join(lines))
        where = f'written to {args.out}' if args.out else 'printed above'
        print(f'{len(imported.entries)} URL entries across {len(imported.hosts)} host(s), {where}')
        print('pass it to a session with: partex.sh -u <file> (or partex test|agent --urls-file <file>)')
    return EXIT_OK


# ── import-har / export-bundle (issue #28; DEPS.md §3.6) ─────────────────────


def _cmd_import_har(args: argparse.Namespace) -> int:
    result = import_har(args.har, args.out, target=args.target)
    if _wants_json():
        _print_json(
            {
                'root': str(result.root),
                'base_url': result.base_url,
                'target_name': result.target_name,
                'evidence_count': result.evidence_count,
                'dropped_out_of_scope': result.dropped_out_of_scope,
                'dropped_hosts': result.dropped_hosts,
                'dropped_oversize': result.dropped_oversize,
                'duplicates': result.duplicates,
            }
        )
    else:
        print(f'imported {result.evidence_count} entries into {result.root} (target {result.base_url})')
        drops: list[str] = []
        if result.dropped_out_of_scope:
            histogram = ', '.join(f'{host} {count}' for host, count in result.dropped_hosts.items())
            drops.append(f'{result.dropped_out_of_scope} out-of-scope ({histogram})')
        if result.dropped_oversize:
            drops.append(f'{result.dropped_oversize} oversize')
        if result.duplicates:
            drops.append(f'{result.duplicates} duplicates')
        if drops:
            print(f'dropped: {", ".join(drops)}')
        print(f'review it with: partex review {result.root} --checks header-security')
    return EXIT_OK


def _cmd_export_bundle(args: argparse.Namespace) -> int:
    db_path = resolve_db_path(args.db)

    async def go():
        async with await RunReader.open(db_path) as reader:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', IncludeSecretsWarning)  # surfaced once below, on stderr
                return await export_bundle(reader, args.run_id, args.out, include_secrets=args.include_secrets)

    result = anyio.run(go)
    if args.include_secrets:
        print('warning: bundle includes unredacted secrets (--include-secrets)', file=sys.stderr)
    if _wants_json():
        _print_json(
            {
                'root': str(result.root),
                'run_id': result.run_id,
                'base_url': result.base_url,
                'target_name': result.target_name,
                'evidence_count': result.evidence_count,
                'redacted': result.redacted,
            }
        )
    else:
        state = 'secrets redacted' if result.redacted else 'secrets included (--include-secrets)'
        print(f'exported {result.evidence_count} evidence items from {result.run_id} into {result.root} ({state})')
        print(f'review it with: partex review {result.root} --checks header-security')
    return EXIT_OK


# ── checks ────────────────────────────────────────────────────────────────────


def _check_kind(check: Any) -> str:
    passive = callable(getattr(check, 'review', None))
    active = callable(getattr(check, 'probe', None))
    return 'passive+active' if passive and active else 'passive' if passive else 'active' if active else 'unknown'


def _cmd_checks(args: argparse.Namespace) -> int:
    registry = build_registry(args.skill_dir)
    rows = [
        {
            'check_id': check_id,
            'kind': _check_kind(check),
            'version': str(getattr(check, 'version', '')),
            'title': str(getattr(check, 'title', '')),
            'skills': registry.skills_for(check_id),
        }
        for check_id, check in registry.checks.items()
    ]
    if _wants_json(args.json):
        _print_json(rows)
    elif not rows:
        print('no checks installed')
    else:
        for row in rows:
            skills = ','.join(row['skills']) or '-'
            print(f'{row["check_id"]:<24} {row["kind"]:<15} {row["version"]:<8} {row["title"]}  [skills: {skills}]')
    for diagnostic in registry.diagnostics:
        print(f'partex: {diagnostic.render()}', file=sys.stderr)
    return EXIT_FATAL if registry.errors else EXIT_OK


# ── chat ──────────────────────────────────────────────────────────────────────


def _session_skills(args: argparse.Namespace) -> list[Any]:
    """Skills for a model session as deferred capabilities (#59): installed-check playbooks plus ``--skill-dir``.

    Lint errors are reported on stderr; a skill that fails them is simply not offered.
    """
    from .agent_adapter.skills import skill_capabilities, usable_skills

    registry = build_registry(args.skill_dir)
    for diagnostic in registry.errors:
        print(f'partex: warning: {diagnostic.render()}', file=sys.stderr)
    return skill_capabilities(usable_skills(registry.skills, registry.checks))


def _request_limit_kwargs(args: argparse.Namespace) -> dict[str, int]:
    return {} if args.request_limit is None else {'request_limit': args.request_limit}


def _cmd_chat(args: argparse.Namespace) -> int:
    from .agent_adapter import run_chat
    from .models_config import resolve_model

    db_path = resolve_db_path(args.db)

    async def check_run() -> None:
        async with await RunReader.open(db_path) as reader:
            await reader.get_run(args.run_id)

    anyio.run(check_run)  # unknown store or run: exit 1 before a model is built or the terminal opens
    model = resolve_model(args.model, gateway_route=args.gateway_route)
    skills = _session_skills(args)
    anyio.run(
        partial(
            run_chat,
            args.run_id,
            db_path,
            model,
            briefing=not args.no_briefing,
            skills=skills,
            **_request_limit_kwargs(args),
        )
    )
    return EXIT_OK


# ── agent ─────────────────────────────────────────────────────────────────────


def _cmd_agent(args: argparse.Namespace) -> int:
    from .agent_adapter import run_agent
    from .models_config import resolve_model, resolve_search_model

    if args.recursive and args.urls_file is None:
        print('partex: usage: --recursive requires --urls-file', file=sys.stderr)
        return EXIT_USAGE
    db_path = resolve_db_path(args.db)
    checks = tuple(_split_checks(args.checks))
    if args.from_run is not None:

        async def check_from() -> None:
            async with await RunReader.open(db_path) as reader:
                await reader.get_run(args.from_run)

        anyio.run(check_from)  # unknown store or run: exit 1 before a model, a run row, or a socket
    model = resolve_model(args.model, gateway_route=args.gateway_route)
    search_model = resolve_search_model(args.search_model) if args.search_model is not None else None
    bundle = Path(args.bundle) if args.bundle is not None else None
    run_id = anyio.run(
        partial(
            run_agent,
            Path(args.engagement),
            db_path,
            model,
            authorized=bool(args.authorized),
            insecure=bool(args.insecure),
            urls_file=Path(args.urls_file) if args.urls_file is not None else None,
            recursive=bool(args.recursive),
            user_agent=args.user_agent,
            allow_methods=args.allow_method,
            max_writes=args.max_writes,
            checks=checks,
            from_run=args.from_run,
            bundle=bundle,
            briefing=not args.no_briefing,
            skills=_session_skills(args),
            search_model=search_model,
            thinking=args.thinking,
            **_request_limit_kwargs(args),
        )
    )
    print(f'session run {run_id} saved; review it with: partex show {run_id} --db {db_path}', file=sys.stderr)
    return EXIT_OK


# ── Entry point ───────────────────────────────────────────────────────────────


def _cmd_verify(args: argparse.Namespace) -> int:
    from .verify import VerifyResult, run_verification

    db_path = resolve_db_path(args.db)

    async def go() -> VerifyResult:
        async with await RunStore.open(db_path) as store:
            return await run_verification(
                args.run_id, args.finding_id, store, authorized=bool(args.authorized), user_agent=args.user_agent
            )

    result = anyio.run(go)  # PartexError → main() prints `partex: <rule>: <msg>` and exits 1
    if _wants_json(args.json):
        _print_json(
            {
                'run_id': result.run_id,
                'finding_id': result.finding_id,
                'verification_id': result.verification_id,
                'verdict': result.verdict,
                'finding_status': result.finding_status,
                'requests_spent': result.requests_spent,
                'replay_evidence_ids': list(result.replay_evidence_ids),
                'detail': result.detail,
                'counterevidence': result.counterevidence,
            }
        )
    else:
        print(f'finding {result.finding_id}: {result.verdict} (now {result.finding_status})')
        print(f'detail: {result.detail}')
        print(f'counterevidence: {result.counterevidence}')
    # A recorded verdict is a completed command (§6): confirmed, not_reproduced and inconclusive all exit 0.
    return EXIT_OK


def _cmd_sandboxes(args: argparse.Namespace) -> int:
    statuses = detect_sandboxes()
    if _wants_json(args.json):
        _print_json(sandboxes_as_dicts(statuses))
    else:
        for status in statuses:
            mark = 'available' if status.available else 'unavailable'
            print(f'{status.name:<12} {mark:<12} {status.detail}')
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Parse and dispatch; returns the process exit code (§6)."""
    # argparse exits itself: SystemExit(2) on usage errors, SystemExit(0) for --help / --version.
    args = build_parser().parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        remote = args.logfire or os.environ.get(LOGFIRE_ENV) == '1'
        log_path = resolve_log_path(args.command, args.log_file)
        if remote or log_path is not None:
            content = args.logfire_content or os.environ.get(LOGFIRE_CONTENT_ENV) == '1'
            configure_telemetry(
                log_path=log_path, remote=remote, service_version=engine.engine_version(), content=content
            )
            if args.command in {'chat', 'agent'}:
                announce(log_path)
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
