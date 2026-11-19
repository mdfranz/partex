"""Partex CLI — PLAN §8 (thin slice: ``test``; review/runs/show/checks land with #9).

Exit codes (§6): ``0`` completed with no findings, ``3`` completed with
findings, ``2`` usage error (argparse), ``1`` fatal (invalid input,
unauthorized, check crash), ``130`` interrupted.
"""

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import anyio

from . import engine
from .engine import CheckSelectionError
from .errors import PartexError
from .storage import RunStore

DB_ENV = 'PARTEX_DB'


def _default_db() -> Path:
    """``$PARTEX_DB`` or the single-operator default under the user data dir."""
    env = os.environ.get(DB_ENV)
    if env:
        return Path(env)
    data_home = os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
    path = Path(data_home) / 'partex' / 'partex.db'
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def build_parser() -> argparse.ArgumentParser:
    """The argparse surface (``partex [--version] test <engagement> ...``)."""
    parser = argparse.ArgumentParser(prog='partex')
    parser.add_argument('--version', action='version', version=f'partex {engine.engine_version()}')
    subparsers = parser.add_subparsers(dest='command', required=True)

    test_parser = subparsers.add_parser('test', help='live run: capture, active checks (requires --authorized)')
    test_parser.add_argument('engagement', help='engagement directory or engagement.json path')
    test_parser.add_argument('--authorized', action='store_true', help='required: attests authorization to test')
    test_parser.add_argument(
        '--checks', default='version-disclosure', help='comma-separated, ordered check ids (default: %(default)s)'
    )
    test_parser.add_argument('--db', default=None, help='database path (default: $PARTEX_DB or user data dir)')
    test_parser.add_argument(
        '--no-summary',
        action='store_true',
        help='skip the model-backed summary (summaries land with M4; nothing summarizes without a model anyway)',
    )

    verify_parser = subparsers.add_parser(
        'verify', help='(re)run the verification replay for one finding (requires --authorized)'
    )
    verify_parser.add_argument('run_id', help='the run holding the finding')
    verify_parser.add_argument('finding_id', help='the finding to re-verify')
    verify_parser.add_argument('--authorized', action='store_true', help='required: attests authorization to test')
    verify_parser.add_argument('--db', default=None, help='database path (default: $PARTEX_DB or user data dir)')
    return parser


def _run_test(args: argparse.Namespace) -> int:
    checks = [item.strip() for item in str(args.checks).split(',') if item.strip()]
    db_path = Path(args.db) if args.db else _default_db()

    async def go() -> engine.TestResult:
        store = await RunStore.open(db_path)
        try:
            return await engine.run_test(args.engagement, store, checks, authorized=bool(args.authorized))
        finally:
            await store.aclose()

    result = anyio.run(go)
    summary = {
        'run_id': result.run_id,
        'state': result.state,
        'checks': list(result.selected_checks),
        'requests_spent': result.requests_spent,
        'authorized': result.authorized,
        'evidence_count': result.evidence_count,
        'budget_exhausted': result.budget_exhausted,
        'findings': [
            {
                'id': finding.id,
                'check_id': finding.check_id,
                'severity': finding.severity,
                'status': finding.status,
                'title': finding.title,
            }
            for finding in result.findings
        ],
        'error': result.error,
        'rule_code': result.rule_code,
        'failed_check': result.failed_check,
        'skipped_checks': list(result.skipped_checks),
    }
    if sys.stdout.isatty():
        print(f'run {result.run_id}: {result.state}')
        print(f'requests spent: {result.requests_spent}  checks: {", ".join(result.selected_checks)}')
        if result.budget_exhausted:
            print('budget exhausted: active work ended cleanly')
        if result.skipped_checks:
            print(f'skipped: {", ".join(result.skipped_checks)}')
        if result.error:
            print(f'error: {result.error}', file=sys.stderr)
        if result.findings:
            for finding in result.findings:
                print(f'  [{finding.severity}] {finding.title} ({finding.id}, {finding.status})')
        else:
            print('no findings')
    else:
        print(json.dumps(summary, indent=2))
    if result.state != 'checks_complete':
        return 1
    return 3 if result.findings else 0


def _run_verify(args: argparse.Namespace) -> int:
    from .verify import VerifyResult, run_verification

    db_path = Path(args.db) if args.db else _default_db()

    async def go() -> VerifyResult:
        store = await RunStore.open(db_path)
        try:
            return await run_verification(args.run_id, args.finding_id, store, authorized=bool(args.authorized))
        finally:
            await store.aclose()

    try:
        result = anyio.run(go)
    except PartexError as exc:
        print(f'{exc.rule_code or "error"}: {exc}', file=sys.stderr)
        return 1
    summary = {
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
    if sys.stdout.isatty():
        print(f'finding {result.finding_id}: {result.verdict} (now {result.finding_status})')
        print(f'detail: {result.detail}')
        print(f'counterevidence: {result.counterevidence}')
    else:
        print(json.dumps(summary, indent=2))
    # A recorded verdict is a completed command (§6): confirmed, not_reproduced,
    # and inconclusive all exit 0; the finding is never deleted either way.
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Parse and dispatch; returns the process exit code (§6)."""
    args = build_parser().parse_args(argv)
    try:
        if args.command == 'test':
            return _run_test(args)
        if args.command == 'verify':
            return _run_verify(args)
    except CheckSelectionError as exc:
        print(f'{exc.rule_code}: {exc}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 2
