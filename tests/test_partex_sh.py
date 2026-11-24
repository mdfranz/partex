"""``partex.sh`` regression checks that need no model, target or network (issue #73)."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
SCRIPT = REPO / 'partex.sh'

pytestmark = pytest.mark.skipif(shutil.which('bash') is None, reason='bash not available')


def _run_list(cwd: Path, script: str, stub_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    stub = stub_dir / 'uv'  # `uv run partex runs --json` -> a canned run list; nothing real is executed
    stub.write_text(
        '#!/bin/sh\n'
        'if [ "$4" = runs ]; then printf "state dir: %s\\n" "${PARTEX_STATE_DIR:-}" >&2; fi\n'
        'echo \'[{"id":"run_' + 'a' * 32 + '","created_at":"2026-11-19T01:02:03+00:00","state":"checks_complete",'
        '"input_kind":"engagement","input_ref":"/tmp/e","findings_count":2,"requests_spent":5,'
        '"model":null,"hosts":["app.test"]}]\'\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, 'PATH': f'{stub_dir}{os.pathsep}{os.environ["PATH"]}'}
    return subprocess.run(
        ['bash', script, 'list', *args],
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize('how', ['absolute', 'from-repo-root', 'relative-from-parent', 'relative-from-elsewhere'])
def test_list_finds_its_helper_however_it_is_invoked(how: str, tmp_path: Path) -> None:
    db = tmp_path / 'existing.db'
    db.write_bytes(b'')
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()
    cwd, script = {
        'absolute': (elsewhere, str(SCRIPT)),
        'from-repo-root': (REPO, './partex.sh'),
        'relative-from-parent': (REPO.parent, os.path.relpath(SCRIPT, REPO.parent)),
        'relative-from-elsewhere': (elsewhere, os.path.relpath(SCRIPT, elsewhere)),
    }[how]
    result = _run_list(cwd, script, stubs, '-d', str(db))
    assert result.returncode == 0, result.stderr
    assert 'run_' + 'a' * 32 in result.stdout and 'app.test' in result.stdout


@pytest.mark.parametrize('state_home', ['absolute', 'relative', 'unset'])
def test_list_uses_the_state_database_by_default(
    state_home: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv('PARTEX_DB', raising=False)
    monkeypatch.delenv('PARTEX_STATE_DIR', raising=False)
    monkeypatch.setenv('HOME', str(tmp_path))
    state_root = tmp_path / '.local' / 'state'
    if state_home == 'absolute':
        state_root = tmp_path / 'xdg state'
        monkeypatch.setenv('XDG_STATE_HOME', str(state_root))
    elif state_home == 'relative':
        monkeypatch.setenv('XDG_STATE_HOME', 'relative-state')
    else:
        monkeypatch.delenv('XDG_STATE_HOME', raising=False)
    db = state_root / 'partex' / 'partex.db'
    db.parent.mkdir(parents=True)
    db.touch()
    stubs = tmp_path / 'stubs'
    stubs.mkdir()

    result = _run_list(tmp_path, str(SCRIPT), stubs)

    assert result.returncode == 0, result.stderr
    assert f'1 saved run(s) in {db}' in result.stdout


def test_list_passes_a_relative_state_override_to_partex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('PARTEX_DB', raising=False)
    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setenv('PARTEX_STATE_DIR', 'custom state')
    state = tmp_path.resolve() / 'custom state'
    state.mkdir()
    db = state / 'partex.db'
    db.touch()
    stubs = tmp_path / 'stubs'
    stubs.mkdir()

    result = _run_list(tmp_path, str(SCRIPT), stubs)

    assert result.returncode == 0, result.stderr
    assert f'1 saved run(s) in {db}' in result.stdout
    assert result.stderr.strip() == f'state dir: {state}'


def test_urls_file_must_exist_before_any_traffic(tmp_path: Path) -> None:
    result = subprocess.run(
        ['bash', str(SCRIPT), '-a', 'test attestation', '-u', str(tmp_path / 'missing.txt'), 'http://127.0.0.1:9/'],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert 'URLs file not found' in result.stderr


def test_nmap_file_must_exist_before_any_traffic(tmp_path: Path) -> None:
    result = subprocess.run(
        ['bash', str(SCRIPT), '-a', 'test attestation', '-N', str(tmp_path / 'missing.xml')],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert 'nmap scan file not found' in result.stderr


def _run_urls(tmp_path: Path, content: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / 'urls.txt').write_text(content)
    return subprocess.run(  # relative -u path from outside the repo; port 9 on loopback refuses, so no real traffic
        ['bash', str(SCRIPT), '-a', 'test attestation', '-u', 'urls.txt', '--no-tui', '-d', str(tmp_path / 't.db')],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_urls_file_alone_supplies_the_target_from_its_first_url(tmp_path: Path) -> None:
    result = _run_urls(tmp_path, '# header\n\n  http://127.0.0.1:9/app/*  \nhttp://127.0.0.1:9/other\n')
    assert 'target: http://127.0.0.1:9/app/ (first URL in' in result.stdout
    assert 'URLs file not found' not in result.stderr  # the relative path resolved against the caller's cwd


def test_urls_file_without_any_url_is_refused(tmp_path: Path) -> None:
    result = _run_urls(tmp_path, '# nothing here\n\n')
    assert result.returncode == 1
    assert 'no URLs in' in result.stderr


RESUME_RUN = 'run_' + 'b' * 32
RESUME_SCOPE = (
    '{"hosts":["app.test"],"path_prefixes":["/"],"exclusions":[],"ports":[443],"max_rps":2,"max_requests":50}'
)


def _resume_db(tmp_path: Path) -> Path:
    import json
    import sqlite3

    db = tmp_path / 'resume.db'
    with sqlite3.connect(db) as conn:
        conn.execute(
            'CREATE TABLE engagements (id TEXT, name TEXT, base_url TEXT, scope TEXT, attestation TEXT, operator TEXT)'
        )
        conn.execute('CREATE TABLE runs (id TEXT, engagement_id TEXT)')
        conn.execute(
            'INSERT INTO engagements VALUES (?, ?, ?, ?, ?, ?)',
            ('eng_1', 'app.test', 'https://app.test', RESUME_SCOPE, 'I own app.test', 'op'),
        )
        conn.execute('INSERT INTO runs VALUES (?, ?)', (RESUME_RUN, 'eng_1'))
        conn.execute('INSERT INTO runs VALUES (?, ?)', ('run_' + 'c' * 32, None))
    assert json.loads(RESUME_SCOPE)
    return db


def test_resume_rebuilds_the_engagement_and_continues_from_the_run(tmp_path: Path) -> None:
    """--resume starts a new agent session on the run's stored engagement; -n and -k override it (#253)."""
    db = _resume_db(tmp_path)
    stub = tmp_path / 'uv'  # record the agent call and the engagement it was handed
    log = tmp_path / 'agent.log'
    stub.write_text(f'#!/bin/sh\nif [ "$4" = agent ]; then echo "$@" > {log}; cat "$5/engagement.json" >> {log}; fi\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, 'PATH': f'{tmp_path}{os.pathsep}{os.environ["PATH"]}', 'PYDANTIC_AI_GATEWAY_API_KEY': 'k'}
    result = subprocess.run(
        ['bash', str(SCRIPT), '-d', str(db), '--resume', RESUME_RUN, '-k', '-n', '0'],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    recorded = log.read_text()
    assert f'--from {RESUME_RUN}' in recorded and '--authorized' in recorded
    assert '"base_url": "https://app.test"' in recorded and '"attestation": "I own app.test"' in recorded
    assert '"max_requests": 0' in recorded and '"verify": false' in recorded


def test_resume_refuses_a_run_without_a_stored_engagement(tmp_path: Path) -> None:
    db = _resume_db(tmp_path)
    result = subprocess.run(
        ['bash', str(SCRIPT), '-d', str(db), '--resume', 'run_' + 'c' * 32],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert '--read-only' in result.stderr
