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


def _run_list(cwd: Path, script: str, db: Path, stub_dir: Path) -> subprocess.CompletedProcess[str]:
    stub = stub_dir / 'uv'  # `uv run partex runs --json` -> a canned run list; nothing real is executed
    stub.write_text(
        '#!/bin/sh\n'
        'echo \'[{"id":"run_' + 'a' * 32 + '","created_at":"2026-11-19T01:02:03+00:00","state":"checks_complete",'
        '"input_kind":"engagement","input_ref":"/tmp/e","findings_count":2,"requests_spent":5,'
        '"model":null,"hosts":["app.test"]}]\'\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, 'PATH': f'{stub_dir}{os.pathsep}{os.environ["PATH"]}'}
    return subprocess.run(
        ['bash', script, 'list', '-d', str(db)],
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
    result = _run_list(cwd, script, db, stubs)
    assert result.returncode == 0, result.stderr
    assert 'run_' + 'a' * 32 in result.stdout and 'app.test' in result.stdout


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
