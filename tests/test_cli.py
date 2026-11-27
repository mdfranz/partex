"""CLI surface — PLAN §6 exit codes, §8 commands, §11.1 Logfire opt-in (issue #9).

Every test drives :func:`partex.cli.main` in-process against a temporary store; no network, no
model. ``capsys`` makes stdout a non-TTY, so output is JSON unless a test forces TTY mode.
"""

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import anyio
import pytest

from partex import cli, engine
from partex.bundle import load_bundle
from partex.models import Evidence, FindingDraft
from partex.storage import MAX_REPORT_BYTES, RunStore, run_reports_dir, write_report

FIXTURES = Path(__file__).parent.parent / 'fixtures'
VALID_BUNDLE = FIXTURES / 'bundles' / 'valid'
SERVER_ERROR_BUNDLE = FIXTURES / 'bundles' / 'server-error'
JS_INERT_BUNDLE = FIXTURES / 'bundles' / 'js-inert'
CLEAN_OPENAPI_BUNDLE = FIXTURES / 'bundles' / 'clean-openapi'
CLEAN_HEADERS_BUNDLE = FIXTURES / 'bundles' / 'clean-headers'
MALFORMED_BUNDLE = FIXTURES / 'bundles' / 'malformed' / 'bundle-version--version-2'
SECRET = 'Bearer cli-test-secret-token'


# ── helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / 'store' / 'partex.db'


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    """Run the CLI as the console script would: argparse's own ``SystemExit`` becomes the exit code."""
    try:
        code = cli.main(list(argv))
    except SystemExit as exc:
        assert isinstance(exc.code, int)
        code = exc.code
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def as_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: True)


def write_bundle(root: Path, records: list[dict[str, Any]]) -> Path:
    (root / 'evidence').mkdir(parents=True)
    names: list[str] = []
    for index, record in enumerate(records):
        name = f'evidence/{index:04d}.json'
        (root / name).write_text(json.dumps(record))
        names.append(name)
    manifest = {
        'schema_version': 1,
        'target': {'name': 'cli-fixture', 'base_url': 'https://app.example.test/'},
        'evidence_files': names,
    }
    (root / 'bundle.json').write_text(json.dumps(manifest))
    return root


def secret_bundle(root: Path) -> Path:
    """One exchange whose Authorization value is a real (marked) secret, plus a weak-header response."""
    return write_bundle(
        root,
        [
            {
                'kind': 'http_exchange',
                'http': {
                    'request': {
                        'method': 'GET',
                        'url': 'https://app.example.test/',
                        'headers': [['Authorization', SECRET]],
                    },
                    'response': {'status_code': 200, 'headers': [['Content-Type', 'text/html']], 'body': 'hi'},
                },
                'secret_fields': ['$.http.request.headers[0][1]'],
            }
        ],
    )


def config_only_bundle(root: Path) -> Path:
    """header-security does not apply to config excerpts, so the run completes with no findings."""
    return write_bundle(
        root,
        [{'kind': 'config_excerpt', 'config': {'path': 'app.ini', 'format': 'config', 'content': 'debug=false'}}],
    )


def review_run_id(capsys: pytest.CaptureFixture[str], db: Path, bundle: Path) -> str:
    code, out, _ = run(capsys, 'review', str(bundle), '--checks', 'header-security', '--db', str(db))
    assert code in (cli.EXIT_OK, cli.EXIT_FINDINGS)
    return json.loads(out)['run_id']


def test_reports_cli(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    run_id = review_run_id(capsys, db, config_only_bundle(tmp_path / 'bundle'))
    args = ('reports', run_id, '--db', str(db))
    assert run(capsys, *args) == (0, '[]\n', '')

    directory = run_reports_dir(db, run_id)
    content = '# Saved report\n'
    report = write_report(directory, 'summary', content)
    (directory / 'link.md').symlink_to(report)
    (directory / 'oversize.md').write_bytes(b'a' * (MAX_REPORT_BYTES + 1))
    (directory / 'ignore.txt').write_text('not a report')

    code, out, err = run(capsys, *args)
    assert (code, err) == (0, '')
    [row] = json.loads(out)
    assert (row['run_id'], row['name'], row['size_bytes']) == (run_id, 'summary', len(content))
    assert run(capsys, 'reports', run_id, 'summary', '--db', str(db)) == (0, content, '')
    code, out, err = run(capsys, 'reports', run_id, 'summary', '--db', str(db), '--json')
    assert (code, err) == (0, '')
    assert json.loads(out) == {'run_id': run_id, 'name': 'summary', 'content': content}

    for name in ('absent', '../summary', 'link', 'oversize'):
        code, out, err = run(capsys, 'reports', run_id, name, '--db', str(db))
        assert (code, out) == (1, '')
        assert 'report-' in err

    moved = directory.with_name('moved')
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)
    code, out, err = run(capsys, *args)
    assert (code, out) == (1, '')
    assert 'report-read' in err


# ── DB path resolution ────────────────────────────────────────────────────────


def test_db_flag_wins(tmp_path: Path) -> None:
    env = {'PARTEX_DB': '/env/db', 'PARTEX_STATE_DIR': '/custom-state', 'XDG_STATE_HOME': '/xdg'}
    assert cli.resolve_db_path(str(tmp_path / 'flag.db'), env) == tmp_path / 'flag.db'


def test_db_env_beats_state_override() -> None:
    env = {'PARTEX_DB': '/env/db', 'PARTEX_STATE_DIR': '/custom-state', 'XDG_STATE_HOME': '/xdg'}
    assert cli.resolve_db_path(None, env) == Path('/env/db')


def test_db_xdg_state_home() -> None:
    env = {'XDG_STATE_HOME': '/state', 'XDG_DATA_HOME': '/old-data'}
    assert cli.resolve_db_path(None, env) == Path('/state/partex/partex.db')


@pytest.mark.parametrize('env', [{}, {'XDG_STATE_HOME': ''}, {'XDG_STATE_HOME': 'relative'}])
def test_db_home_fallback_creates_nothing(env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    assert cli.resolve_db_path(None, env) == tmp_path / '.local' / 'state' / 'partex' / 'partex.db'
    assert not (tmp_path / '.local').exists()


def test_db_env_used_by_commands(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_path = tmp_path / 'env.db'
    monkeypatch.setenv('PARTEX_DB', str(db_path))
    code, _, _ = run(capsys, 'review', str(VALID_BUNDLE), '--all')
    assert code == cli.EXIT_FINDINGS
    assert db_path.is_file()


@pytest.mark.parametrize('override', [False, True])
def test_state_db_is_shared_by_cli_readers_and_writers(
    override: bool, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv('PARTEX_DB', raising=False)
    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path / 'xdg'))
    if override:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv('PARTEX_STATE_DIR', 'custom state')
        state = tmp_path / 'custom state'
    else:
        monkeypatch.delenv('PARTEX_STATE_DIR', raising=False)
        state = tmp_path / 'xdg' / 'partex'
    db = state / 'partex.db'

    code, out, _ = run(capsys, 'review', str(VALID_BUNDLE), '--all')
    assert code == cli.EXIT_FINDINGS
    run_id = json.loads(out)['run_id']
    assert db.is_file()

    code, out, _ = run(capsys, 'runs')
    assert code == cli.EXIT_OK
    assert [row['id'] for row in json.loads(out)] == [run_id]

    write_report(run_reports_dir(db, run_id), 'summary', '# Summary\n')
    code, out, _ = run(capsys, 'reports', run_id, 'summary')
    assert code == cli.EXIT_OK
    assert out == '# Summary\n'


# ── review ────────────────────────────────────────────────────────────────────


def test_review_with_findings_exits_3(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    code, out, _ = run(capsys, 'review', str(VALID_BUNDLE), '--all', '--db', str(db))
    assert code == cli.EXIT_FINDINGS
    payload = json.loads(out)
    assert payload['state'] == 'checks_complete'
    assert payload['checks'] == [
        'api-contract-conformance',
        'header-security',
        'js-analysis',
        'openapi-spec-review',
        'privacy-signals',
        'server-error',
    ]  # --all: installed passive checks only
    assert 'js-analysis' in payload['skipped_checks']
    subjects = {finding['subject'] for finding in payload['findings']}
    assert {'cookie:session', 'cookie:remember_token'} <= subjects


def test_review_without_findings_exits_0(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    bundle = config_only_bundle(tmp_path / 'bundle')
    code, out, _ = run(capsys, 'review', str(bundle), '--checks', 'header-security', '--db', str(db))
    assert code == cli.EXIT_OK
    payload = json.loads(out)
    assert (payload['findings'], payload['skipped_checks']) == ([], ['header-security'])


def test_review_invalid_bundle_exits_1(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    code, out, _ = run(capsys, 'review', str(MALFORMED_BUNDLE), '--checks', 'header-security', '--db', str(db))
    assert code == cli.EXIT_FATAL
    payload = json.loads(out)
    assert payload['state'] == 'invalid'
    assert payload['rule_code'] == 'bundle-version'


def test_review_checks_are_ordered_and_deduplicated(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    code, out, _ = run(
        capsys, 'review', str(VALID_BUNDLE), '--checks', 'header-security, header-security', '--db', str(db)
    )
    assert code == cli.EXIT_FINDINGS
    assert json.loads(out)['checks'] == ['header-security']


def test_unknown_check_exits_1_listing_available(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    code, out, err = run(capsys, 'review', str(VALID_BUNDLE), '--checks', 'nope', '--db', str(db))
    assert code == cli.EXIT_FATAL
    assert out == ''
    assert 'unknown-check' in err
    assert 'header-security' in err and 'version-disclosure' in err
    assert not db.exists()  # rejected before any run row (or store) is created


def test_active_check_on_bundle_exits_1(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    code, _, err = run(capsys, 'review', str(VALID_BUNDLE), '--checks', 'version-disclosure', '--db', str(db))
    assert code == cli.EXIT_FATAL
    assert 'not-passive' in err


# ── offline-review outcomes over saved bundles (issue #178) ─────────────────────


async def _review_rows(db: Path, run_id: str) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """Read one review run's findings (with citations) and coverage rows back from the store."""
    async with await RunStore.open(db) as store:
        findings = {finding.id: list(finding.evidence_ids) for finding in await store.findings(run_id)}
        coverage = [entry.model_dump(mode='json') for entry in await store.coverage(run_id)]
    return findings, coverage


def test_review_server_error_bundle_produces_cited_finding(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    """The saved 5xx bundle: server-error applies, finds the route, and cites the saved exchange."""
    code, out, _ = run(capsys, 'review', str(SERVER_ERROR_BUNDLE), '--checks', 'server-error', '--db', str(db))
    assert code == cli.EXIT_FINDINGS
    payload = json.loads(out)
    assert payload['state'] == 'checks_complete'
    assert payload['checks'] == ['server-error']
    assert payload['skipped_checks'] == []  # applies: a 5xx response is present
    (finding,) = payload['findings']
    assert finding['check_id'] == 'server-error'
    assert finding['severity'] == 'low'  # ordinary 500, no stack-trace/debug disclosure

    # The finding cites the saved evidence: the citation resolves to the bundle's one exchange.
    findings, _ = anyio.run(_review_rows, db, payload['run_id'])
    (cited,) = findings[finding['id']]
    (evidence,) = load_bundle(SERVER_ERROR_BUNDLE).evidence
    assert cited == evidence.id


def test_review_js_inert_bundle_is_checked_clean_and_skipped_distinguishable(
    capsys: pytest.CaptureFixture[str], db: Path
) -> None:
    """The inert-JS bundle: js-analysis runs and is clean; server-error is skipped (no 5xx) — not clean-but-skipped."""
    code, out, _ = run(capsys, 'review', str(JS_INERT_BUNDLE), '--checks', 'server-error,js-analysis', '--db', str(db))
    assert code == cli.EXIT_OK
    payload = json.loads(out)
    assert payload['checks'] == ['server-error', 'js-analysis']
    assert payload['findings'] == []  # inert JavaScript: nothing to find
    assert payload['skipped_checks'] == ['server-error']  # no 5xx in the bundle


def test_review_clean_openapi_bundle_is_clean_with_a_coverage_lead(
    capsys: pytest.CaptureFixture[str], db: Path
) -> None:
    """The clean-spec bundle: openapi-spec-review runs, finds nothing, and persists its coverage lead."""
    code, out, _ = run(capsys, 'review', str(CLEAN_OPENAPI_BUNDLE), '--checks', 'openapi-spec-review', '--db', str(db))
    assert code == cli.EXIT_OK
    payload = json.loads(out)
    assert payload['checks'] == ['openapi-spec-review']
    assert payload['skipped_checks'] == []  # applies: a format=openapi config excerpt is present
    assert payload['findings'] == []  # secured spec: no spec findings

    # The coverage lead persists: the callback_url parameter is a follow-up, never a finding.
    _, coverage = anyio.run(_review_rows, db, payload['run_id'])
    (entry,) = coverage
    assert entry['surface'] == 'GET /api/widgets'
    assert entry['risk_area'] == 'ssrf-or-open-redirect'
    assert entry['outcome'] == 'needs_follow_up'
    assert entry['source'] == 'check_observed'
    assert 'callback_url' in entry['reason']
    (spec,) = load_bundle(CLEAN_OPENAPI_BUNDLE).evidence
    assert entry['evidence_ids'] == [spec.id]


def test_review_clean_headers_bundle_is_clean(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    """The hardened-response bundle: header-security runs and produces zero findings."""
    code, out, _ = run(capsys, 'review', str(CLEAN_HEADERS_BUNDLE), '--checks', 'header-security', '--db', str(db))
    assert code == cli.EXIT_OK
    payload = json.loads(out)
    assert payload['checks'] == ['header-security']
    assert payload['skipped_checks'] == []  # applies: an HTTP exchange is present
    assert payload['findings'] == []


@pytest.mark.parametrize(
    'argv',
    [
        pytest.param(['--checks', ' , '], id='empty-selection'),
        pytest.param([], id='no-selection'),
        pytest.param(['--checks', 'header-security', '--all'], id='checks-and-all'),
        pytest.param(['--all', '--workers', '0'], id='zero-workers'),
        pytest.param(['--all', '--workers', 'many'], id='non-int-workers'),
    ],
)
def test_review_usage_errors_exit_2(capsys: pytest.CaptureFixture[str], db: Path, argv: list[str]) -> None:
    code, out, _ = run(capsys, 'review', str(VALID_BUNDLE), *argv, '--db', str(db))
    assert code == cli.EXIT_USAGE
    assert out == ''


def test_no_command_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys)[0] == cli.EXIT_USAGE


def test_version_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, '--version')
    assert code == cli.EXIT_OK
    assert out.startswith('partex ')


class _CrashingCheck:
    check_id = 'boom'
    version = '1'
    title = 'Crashes'
    description = 'raises from review'

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return True

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        raise RuntimeError('check exploded')


def test_check_crash_exits_1(capsys: pytest.CaptureFixture[str], db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, 'installed_checks', lambda: {'boom': _CrashingCheck()})
    code, out, _ = run(capsys, 'review', str(VALID_BUNDLE), '--checks', 'boom', '--db', str(db))
    assert code == cli.EXIT_FATAL
    payload = json.loads(out)
    assert (payload['state'], payload['failed_check']) == ('checks_failed', 'boom')


def test_interrupt_exits_130(capsys: pytest.CaptureFixture[str], db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted() -> dict[str, Any]:
        raise KeyboardInterrupt

    monkeypatch.setattr(engine, 'installed_checks', interrupted)
    code, _, err = run(capsys, 'review', str(VALID_BUNDLE), '--all', '--db', str(db))
    assert code == cli.EXIT_INTERRUPTED
    assert 'interrupted' in err


def test_review_text_output_on_tty(
    capsys: pytest.CaptureFixture[str], db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    as_tty(monkeypatch)
    code, out, _ = run(capsys, 'review', str(VALID_BUNDLE), '--all', '--db', str(db))
    assert code == cli.EXIT_FINDINGS
    assert out.startswith('run run_')
    assert 'checks_complete' in out
    assert 'cookie:remember_token' in out


def test_review_out_writes_the_canonical_export(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    out_file = tmp_path / 'exports' / 'run.json'
    code, out, _ = run(capsys, 'review', str(VALID_BUNDLE), '--all', '--db', str(db), '--out', str(out_file))
    assert code == cli.EXIT_FINDINGS
    run_id = json.loads(out)['run_id']
    _, shown, _ = run(capsys, 'show', run_id, '--db', str(db), '--format', 'json')
    assert out_file.read_text() == shown


# ── runs ──────────────────────────────────────────────────────────────────────


def test_runs_lists_runs_as_json(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    first = review_run_id(capsys, db, VALID_BUNDLE)
    second = review_run_id(capsys, db, config_only_bundle(tmp_path / 'b'))
    code, out, _ = run(capsys, 'runs', '--db', str(db))
    assert code == cli.EXIT_OK
    rows = json.loads(out)
    assert [row['id'] for row in rows] == [first, second]
    assert rows[0]['state'] == 'checks_complete'
    assert rows[0]['findings_count'] > 0 and rows[1]['findings_count'] == 0
    assert {'requests_spent', 'model', 'hosts'} <= rows[0].keys()  # extra columns for partex.sh list


def test_runs_text_output(capsys: pytest.CaptureFixture[str], db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_id = review_run_id(capsys, db, VALID_BUNDLE)
    as_tty(monkeypatch)
    code, out, _ = run(capsys, 'runs', '--db', str(db))
    assert code == cli.EXIT_OK
    assert run_id in out and 'checks_complete' in out


def test_runs_json_flag_on_tty(capsys: pytest.CaptureFixture[str], db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    review_run_id(capsys, db, VALID_BUNDLE)
    as_tty(monkeypatch)
    code, out, _ = run(capsys, 'runs', '--db', str(db), '--json')
    assert code == cli.EXIT_OK
    assert len(json.loads(out)) == 1


def test_runs_empty_store(capsys: pytest.CaptureFixture[str], db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def create() -> None:
        async with await RunStore.open(db):
            pass

    anyio.run(create)
    as_tty(monkeypatch)
    assert run(capsys, 'runs', '--db', str(db)) == (cli.EXIT_OK, 'no runs\n', '')


def test_runs_missing_store_exits_1_and_creates_nothing(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing = tmp_path / 'nowhere' / 'partex.db'
    code, out, err = run(capsys, 'runs', '--db', str(missing))
    assert code == cli.EXIT_FATAL
    assert out == ''
    assert 'store-missing' in err
    assert not missing.parent.exists()


# ── show ──────────────────────────────────────────────────────────────────────


def test_show_json_redacts_by_default(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    run_id = review_run_id(capsys, db, secret_bundle(tmp_path / 'bundle'))
    code, out, err = run(capsys, 'show', run_id, '--db', str(db))
    assert code == cli.EXIT_OK
    assert err == ''
    assert SECRET not in out
    payload = json.loads(out)
    assert payload['evidence'][0]['http']['request']['headers'] == [['Authorization', '<redacted>']]
    assert run_id not in out  # canonical export omits run IDs (§7)


def test_show_include_secrets_warns(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    run_id = review_run_id(capsys, db, secret_bundle(tmp_path / 'bundle'))
    code, out, err = run(capsys, 'show', run_id, '--db', str(db), '--include-secrets')
    assert code == cli.EXIT_OK
    assert SECRET in out
    assert 'unredacted secrets' in err


def test_show_text_is_redacted_and_names_subjects(
    capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = review_run_id(capsys, db, secret_bundle(tmp_path / 'bundle'))
    as_tty(monkeypatch)
    code, out, _ = run(capsys, 'show', run_id, '--db', str(db))
    assert code == cli.EXIT_OK
    assert out.startswith(f'run {run_id}: checks_complete')
    assert 'header:content-security-policy' in out
    assert SECRET not in out


def test_show_out_writes_file(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    run_id = review_run_id(capsys, db, VALID_BUNDLE)
    target = tmp_path / 'out' / 'show.txt'
    code, out, _ = run(capsys, 'show', run_id, '--db', str(db), '--format', 'text', '--out', str(target))
    assert (code, out) == (cli.EXIT_OK, '')
    assert target.read_text().startswith(f'run {run_id}:')


def test_show_unknown_run_exits_1(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    review_run_id(capsys, db, VALID_BUNDLE)
    code, out, err = run(capsys, 'show', 'run_missing', '--db', str(db))
    assert code == cli.EXIT_FATAL
    assert out == ''
    assert 'run-not-found' in err


def test_show_text_includes_error_verifications_and_model_usage() -> None:
    payload: dict[str, Any] = {
        'run': {
            'state': 'checks_complete',
            'input_kind': 'engagement',
            'input_ref': 'eng_x',
            'engine_version': '0.1.0',
            'selected_checks': ['version-disclosure'],
            'requests_spent': 3,
            'authorized': True,
            'error': 'earlier diagnostic',
            'model_calls': 2,
            'input_tokens': 100,
            'output_tokens': 25,
        },
        'evidence': [],
        'findings': [],
        'verifications': [{'id': 'vf_1', 'verdict': 'confirmed', 'finding_id': 'fn_1'}],
    }
    text = cli._render_text(payload, 'run_x')  # pyright: ignore[reportPrivateUsage]
    assert 'requests spent: 3  authorized: True' in text
    assert 'error: earlier diagnostic' in text
    assert 'model calls: 2  tokens in/out: 100/25' in text
    assert 'verification vf_1: confirmed for fn_1' in text


# ── checks ────────────────────────────────────────────────────────────────────


def test_checks_json(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, 'checks')
    assert code == cli.EXIT_OK
    kinds = {row['check_id']: row['kind'] for row in json.loads(out)}
    assert kinds == {
        'api-contract-conformance': 'passive',
        'authz-boundary': 'active',
        'header-security': 'passive',
        'js-analysis': 'passive',
        'openapi-spec-review': 'passive',
        'privacy-signals': 'passive',
        'server-error': 'passive',
        'version-disclosure': 'active',
    }


def test_checks_text(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    as_tty(monkeypatch)
    code, out, _ = run(capsys, 'checks')
    assert code == cli.EXIT_OK
    assert out.splitlines()[0].startswith('api-contract-conformance')
    assert 'header-security' in out


def test_checks_none_installed(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, 'installed_checks', dict)
    as_tty(monkeypatch)
    code, out, err = run(capsys, 'checks')  # skills naming now-unregistered checks warn on stderr (#25)
    assert (code, out) == (cli.EXIT_OK, 'no checks installed\n')
    assert 'warning: header-review: unknown-check' in err


def test_check_kind_labels() -> None:
    class Both:
        def review(self) -> None: ...
        def probe(self) -> None: ...

    assert cli._check_kind(Both()) == 'passive+active'  # pyright: ignore[reportPrivateUsage]
    assert cli._check_kind(object()) == 'unknown'  # pyright: ignore[reportPrivateUsage]


# ── test (live) — only the gates that need no target ─────────────────────────


def test_live_test_without_authorized_exits_1(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    engagement = FIXTURES / 'engagements' / 'valid'
    code, out, _ = run(capsys, 'test', str(engagement), '--db', str(db))
    assert code == cli.EXIT_FATAL
    assert json.loads(out)['rule_code'] == 'unauthorized'


def test_live_test_text_output(capsys: pytest.CaptureFixture[str], db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    as_tty(monkeypatch)
    code, out, err = run(capsys, 'test', str(FIXTURES / 'engagements' / 'valid'), '--db', str(db))
    assert code == cli.EXIT_FATAL
    assert 'invalid' in out and 'no findings' in out
    assert 'unauthorized' in err


def test_live_test_checks_and_all_are_mutually_exclusive_and_unknown_ids_fail(
    capsys: pytest.CaptureFixture[str], db: Path
) -> None:
    engagement = str(FIXTURES / 'engagements' / 'valid')
    code, _, err = run(capsys, 'test', engagement, '--all', '--checks', 'header-security', '--db', str(db))
    assert code == cli.EXIT_USAGE and 'not allowed with' in err
    code, _, err = run(capsys, 'test', engagement, '--authorized', '--checks', 'nope', '--db', str(db))
    assert code == cli.EXIT_FATAL and 'unknown check' in err and 'available:' in err
    assert (
        run(capsys, 'test', engagement, '--checks', 'header-security', '--db', str(db))[0] == cli.EXIT_FATAL
    )  # passive IDs now accepted, then the gate refuses


# ── Logfire opt-in (§11.1) ────────────────────────────────────────────────────


@pytest.fixture
def logfire_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    import logfire

    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(logfire, 'configure', lambda **kw: calls.append(('configure', kw)))  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    monkeypatch.setattr(logfire, 'instrument_pydantic_ai', lambda **kw: calls.append(('instrument_pydantic_ai', kw)))  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    monkeypatch.delenv('PARTEX_LOGFIRE', raising=False)
    return calls


def test_logfire_off_by_default(capsys: pytest.CaptureFixture[str], logfire_calls: list[Any]) -> None:
    run(capsys, 'checks')
    assert logfire_calls == []


def test_logfire_flag_configures_before_instrumenting(
    capsys: pytest.CaptureFixture[str], logfire_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    assert run(capsys, 'checks', '--logfire')[0] == cli.EXIT_OK
    assert [name for name, _ in logfire_calls] == ['configure', 'instrument_pydantic_ai']
    config = logfire_calls[0][1]
    assert config['service_name'] == 'partex' and config['service_version'] == engine.engine_version()
    assert config['send_to_logfire'] == 'if-token-present' and config['additional_span_processors'] == []


def test_logfire_env_var(
    capsys: pytest.CaptureFixture[str], logfire_calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('PARTEX_LOGFIRE', '1')
    run(capsys, 'checks')
    assert [name for name, _ in logfire_calls] == ['configure', 'instrument_pydantic_ai']


def test_log_file_is_local_only_and_on_for_live_commands(
    capsys: pytest.CaptureFixture[str], logfire_calls: list[tuple[str, dict[str, Any]]], tmp_path: Path, db: Path
) -> None:
    log = tmp_path / 'trace.jsonl'
    run(capsys, 'test', str(VALID_BUNDLE), '--db', str(db), '--log-file', str(log))  # no --logfire
    assert [name for name, _ in logfire_calls] == ['configure', 'instrument_pydantic_ai']
    config = logfire_calls[0][1]
    assert config['send_to_logfire'] is False and len(config['additional_span_processors']) == 1
    assert not log.exists()  # created lazily on the first span; this run exits before emitting one (#126)


def test_log_file_off_and_read_only_commands_do_not_configure(
    capsys: pytest.CaptureFixture[str], logfire_calls: list[Any], tmp_path: Path, db: Path
) -> None:
    run(capsys, 'runs', '--db', str(db))
    run(capsys, 'checks', '--log-file', 'off')
    assert logfire_calls == []


def test_cli_never_instruments_httpx(capsys: pytest.CaptureFixture[str], logfire_calls: list[Any]) -> None:
    """§11.1: the target client carries engagement credentials; global httpx instrumentation is forbidden."""
    source = Path(cli.__file__).read_text()
    assert 'instrument_httpx' not in source.replace('Never ``instrument_httpx()``', '')


def test_review_workers_flag(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    code, _, _ = run(capsys, 'review', str(VALID_BUNDLE), '--all', '--workers', '2', '--db', str(db))
    assert code == cli.EXIT_FINDINGS


def test_review_text_reports_warnings_and_skips(
    capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = config_only_bundle(tmp_path / 'bundle')
    manifest = json.loads((bundle / 'bundle.json').read_text())
    manifest['evidence_files'] *= 2  # duplicate evidence → V3 warning
    (bundle / 'bundle.json').write_text(json.dumps(manifest))
    as_tty(monkeypatch)
    code, out, err = run(capsys, 'review', str(bundle), '--checks', 'header-security', '--db', str(db))
    assert code == cli.EXIT_OK
    assert 'skipped (not applicable): header-security' in out
    assert 'warning:' in err and 'duplicate' in err


def test_review_text_reports_invalid_bundle(
    capsys: pytest.CaptureFixture[str], db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    as_tty(monkeypatch)
    code, out, err = run(capsys, 'review', str(MALFORMED_BUNDLE), '--checks', 'header-security', '--db', str(db))
    assert code == cli.EXIT_FATAL
    assert ': invalid' in out
    assert err.startswith('error: ')


# ── chat (#49) — the Pax terminal is replaced; nothing interactive starts ───


briefings: list[bool] = []
offered: list[list[str]] = []


@pytest.fixture
def chat_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Path, object]]:
    import partex.agent_adapter

    briefings.clear()
    offered.clear()

    calls: list[tuple[str, Path, object]] = []

    async def fake_run_chat(
        run_id: str, db_path: Path, model: object, *, briefing: bool, skills: Sequence[Any] = ()
    ) -> None:
        calls.append((run_id, db_path, model))
        briefings.append(briefing)
        offered.append(sorted(str(getattr(skill, 'id', '')) for skill in skills))

    monkeypatch.setattr(partex.agent_adapter, 'run_chat', fake_run_chat)
    return calls


def test_chat_opens_the_run_with_the_resolved_model(
    capsys: pytest.CaptureFixture[str], db: Path, chat_calls: list[tuple[str, Path, object]]
) -> None:
    run_id = review_run_id(capsys, db, VALID_BUNDLE)
    code, _, err = run(capsys, 'chat', run_id, '--model', 'test', '--db', str(db))
    assert (code, err) == (cli.EXIT_OK, '')
    assert chat_calls == [(run_id, db, 'test')]
    assert briefings == [True]


def test_chat_no_briefing_flag(
    capsys: pytest.CaptureFixture[str], db: Path, chat_calls: list[tuple[str, Path, object]]
) -> None:
    run_id = review_run_id(capsys, db, VALID_BUNDLE)
    assert run(capsys, 'chat', run_id, '--model', 'test', '--db', str(db), '--no-briefing')[0] == cli.EXIT_OK
    assert briefings == [False]


def test_chat_routes_a_bare_model_through_the_gateway(
    capsys: pytest.CaptureFixture[str],
    db: Path,
    chat_calls: list[tuple[str, Path, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pydantic_ai.models.openai import OpenAIChatModel

    monkeypatch.setenv('PYDANTIC_AI_GATEWAY_API_KEY', 'pylf_v2_eu_dummyKeyForTests')
    monkeypatch.setenv('PYDANTIC_AI_GATEWAY_BASE_URL', 'https://gateway-eu.pydantic.dev/proxy/doubleword')
    run_id = review_run_id(capsys, db, VALID_BUNDLE)
    code, _, _ = run(
        capsys, 'chat', run_id, '--model', 'zai-org/GLM-5.3', '--gateway-route', 'doubleword', '--db', str(db)
    )
    assert code == cli.EXIT_OK
    ((_, _, model),) = chat_calls
    assert isinstance(model, OpenAIChatModel)
    assert str(model.client.base_url) == 'https://gateway-eu.pydantic.dev/proxy/doubleword/'


def test_chat_unknown_run_exits_1_before_resolving_a_model(
    capsys: pytest.CaptureFixture[str],
    db: Path,
    chat_calls: list[tuple[str, Path, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import partex.models_config

    def must_not_resolve(*args: object, **kwargs: object) -> object:
        raise AssertionError('model resolved for an unknown run')

    monkeypatch.setattr(partex.models_config, 'resolve_model', must_not_resolve)
    review_run_id(capsys, db, VALID_BUNDLE)
    code, out, err = run(capsys, 'chat', 'run_missing', '--model', 'test', '--db', str(db))
    assert (code, out) == (cli.EXIT_FATAL, '')
    assert 'run-not-found' in err
    assert chat_calls == []


def test_chat_missing_store_exits_1(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, 'chat', 'run_x', '--model', 'test', '--db', str(tmp_path / 'none.db'))
    assert code == cli.EXIT_FATAL
    assert 'store-missing' in err


def test_chat_bare_model_without_route_exits_1(
    capsys: pytest.CaptureFixture[str], db: Path, chat_calls: list[tuple[str, Path, object]]
) -> None:
    run_id = review_run_id(capsys, db, VALID_BUNDLE)
    code, _, err = run(capsys, 'chat', run_id, '--model', 'zai-org/GLM-5.3', '--db', str(db))
    assert code == cli.EXIT_FATAL
    assert 'model-config' in err and '--gateway-route' in err
    assert chat_calls == []


def test_chat_requires_model(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    assert run(capsys, 'chat', 'run_x', '--db', str(db))[0] == cli.EXIT_USAGE


# ── agent (#54) — the live session and terminal are replaced ──────────────────


@pytest.fixture
def agent_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    import partex.agent_adapter

    calls: list[dict[str, object]] = []

    async def fake_run_agent(engagement: Path, db_path: Path, model: object, **kwargs: object) -> str:
        calls.append({'engagement': engagement, 'db': db_path, 'model': model, **kwargs})
        return 'run_session'

    monkeypatch.setattr(partex.agent_adapter, 'run_agent', fake_run_agent)
    return calls


def test_agent_passes_options_through(
    capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path, agent_calls: list[dict[str, object]]
) -> None:
    run_id = review_run_id(capsys, db, VALID_BUNDLE)
    code, _, err = run(
        capsys,
        'agent',
        str(tmp_path / 'eng'),
        '--authorized',
        '--model',
        'test',
        '--checks',
        'version-disclosure, x',
        '--from',
        run_id,
        '--no-briefing',
        '--db',
        str(db),
    )
    assert code == cli.EXIT_OK
    (call,) = agent_calls
    assert call['authorized'] is True and call['briefing'] is False
    assert call['checks'] == ('version-disclosure', 'x') and call['from_run'] == run_id
    assert call['model'] == 'test' and call['db'] == db
    assert 'run_session' in err


def test_agent_unknown_from_run_exits_1_before_the_model(
    capsys: pytest.CaptureFixture[str],
    db: Path,
    tmp_path: Path,
    agent_calls: list[dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import partex.models_config

    monkeypatch.setattr(partex.models_config, 'resolve_model', lambda *a, **k: pytest.fail('model resolved'))
    review_run_id(capsys, db, VALID_BUNDLE)
    code, _, err = run(
        capsys, 'agent', str(tmp_path / 'eng'), '--authorized', '--model', 'test', '--from', 'run_nope', '--db', str(db)
    )
    assert code == cli.EXIT_FATAL and 'run-not-found' in err
    assert agent_calls == []


def test_agent_refused_session_exits_1(
    capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import partex.agent_adapter
    from partex.engine import LiveSessionRefused

    async def refused(*args: object, **kwargs: object) -> str:
        raise LiveSessionRefused('unauthorized: --authorized is required', rule_code='unauthorized', run_id='run_x')

    monkeypatch.setattr(partex.agent_adapter, 'run_agent', refused)
    code, _, err = run(capsys, 'agent', str(tmp_path / 'eng'), '--model', 'test', '--db', str(db))
    assert code == cli.EXIT_FATAL and 'unauthorized' in err


def test_agent_requires_model(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert run(capsys, 'agent', str(tmp_path / 'eng'), '--authorized')[0] == cli.EXIT_USAGE


def test_report_empty_store_exits_ok(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    async def create() -> None:
        async with await RunStore.open(db):
            pass

    anyio.run(create)
    code, out, _ = run(capsys, 'report', '--db', str(db))
    assert code == cli.EXIT_OK
    payload = json.loads(out)
    assert payload['runs']['total'] == 0
    assert payload['findings']['total'] == 0


def test_report_rolls_up_a_reviewed_run(capsys: pytest.CaptureFixture[str], db: Path) -> None:
    assert review_run_id(capsys, db, VALID_BUNDLE)  # seed one reviewed run
    code, out, _ = run(capsys, 'report', '--db', str(db))
    assert code == cli.EXIT_OK
    payload = json.loads(out)
    assert payload['runs']['total'] == 1
    assert payload['findings']['total'] >= 1
    assert any(check['check_id'] == 'header-security' for check in payload['findings']['by_check'])


def test_show_text_and_test_text_flag_areas_that_were_not_exercised() -> None:
    gap = {
        'surface': 'http://a.test',
        'risk_area': 'error-page-disclosure',
        'outcome': 'not_applicable',
        'reason': 'catch-all route',
    }
    fine = {**gap, 'risk_area': 'cors', 'outcome': 'no_issue_found', 'reason': 'ok'}
    assert cli._coverage_gaps([gap, fine]) == [  # pyright: ignore[reportPrivateUsage]
        '  not exercised: http://a.test / error-page-disclosure (not_applicable): catch-all route'
    ]


def test_chat_offers_installed_check_skills_and_extra_skill_dirs(
    capsys: pytest.CaptureFixture[str], db: Path, chat_calls: list[Any], tmp_path: Path
) -> None:
    run_id = review_run_id(capsys, db, VALID_BUNDLE)
    extra = tmp_path / 'skills' / 'my-playbook'
    extra.mkdir(parents=True)
    (extra / 'SKILL.md').write_text(
        '---\nname: my-playbook\ndescription: Use for local notes\nmodes: [passive]\n---\n# Notes\nbody\n'
    )
    assert (
        run(capsys, 'chat', run_id, '--model', 'test', '--db', str(db), '--skill-dir', str(tmp_path / 'skills'))[0] == 0
    )
    (names,) = offered
    # Playbooks for installed checks are offered; drafts whose checks are not installed are not.
    assert {
        'api-inventory',
        'authorization-testing',
        'header-review',
        'version-disclosure',
        'js-analysis',
        'my-playbook',
    } <= set(names)
    # auth-session-controls is still a staged draft: its checks (session-cookie-config, token-weakness) are not installed.
    assert 'auth-session-controls' not in set(names)


HOSTILE_REPORT = '# Report\n\x1b[2Jcleared \x1b]8;;https://evil.test\x07link\x1b]8;;\x07 \x1b]0;title\x07\x9b31m\tok\n'


def test_reports_cli_neutralizes_terminal_controls_on_a_tty(
    capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#141: on a terminal, escape sequences in a saved report are shown, not executed."""
    run_id = review_run_id(capsys, db, config_only_bundle(tmp_path / 'bundle'))
    write_report(run_reports_dir(db, run_id), 'hostile', HOSTILE_REPORT)
    args = ('reports', run_id, 'hostile', '--db', str(db))

    monkeypatch.setattr(sys.stdout, 'isatty', lambda: True)
    code, out, _ = run(capsys, *args)
    assert code == 0
    assert '\x1b' not in out and '\x07' not in out and '\x9b' not in out
    assert out == (
        '# Report\n\\x1b[2Jcleared \\x1b]8;;https://evil.test\\x07link\\x1b]8;;\\x07 \\x1b]0;title\\x07\\x9b31m\tok\n'
    )
    code, out, _ = run(capsys, *args, '--json')
    assert json.loads(out)['content'] == HOSTILE_REPORT  # --json is unchanged (escaped by JSON itself)


def test_reports_cli_keeps_raw_bytes_when_piped(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    run_id = review_run_id(capsys, db, config_only_bundle(tmp_path / 'bundle'))
    write_report(run_reports_dir(db, run_id), 'hostile', HOSTILE_REPORT)
    assert run(capsys, 'reports', run_id, 'hostile', '--db', str(db)) == (0, HOSTILE_REPORT, '')
