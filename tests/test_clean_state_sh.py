"""``scripts/clean-state.sh``: per-item confirmation, unit removal of databases, filters (issue #242).

The script must read every answer from a terminal, so these tests give it a pty as stdin and type the answers.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / 'scripts' / 'clean-state.sh'
DAY = 86_400

pytestmark = pytest.mark.skipif(shutil.which('bash') is None or os.name != 'posix', reason='needs bash and a pty')


def run(state: Path, *args: str, answers: str | None = '') -> subprocess.CompletedProcess[str]:
    """Run the script on *state*; *answers* are typed at a pty, ``None`` gives it a non-terminal stdin."""
    cmd = ['bash', str(SCRIPT), '-s', str(state), *args]
    if answers is None:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False)
    controller, terminal = os.openpty()
    try:
        os.write(controller, answers.encode())
        return subprocess.run(cmd, stdin=terminal, capture_output=True, text=True, timeout=30, check=False)
    finally:
        os.close(terminal)
        os.close(controller)


def touch(path: Path, *, days_old: float = 0, content: str = 'x') -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    stamp = time.time() - days_old * DAY
    os.utime(path, (stamp, stamp))
    return path


def make_db(state: Path, name: str = 'partex.db', *, days_old: float = 0) -> Path:
    db = touch(state / name, days_old=days_old)
    touch(state / f'{name}-wal', days_old=days_old)
    touch(state / f'{name}-shm', days_old=days_old)
    touch(state / f'{name}.artifacts' / 'run_1' / 'bundle.js', days_old=days_old)
    touch(state / f'{name}.reports' / 'run_1' / 'report.md', days_old=days_old)
    return db


def test_refuses_a_non_terminal_stdin_and_deletes_nothing(tmp_path: Path) -> None:
    log = touch(tmp_path / 'logs' / 'agent-1.jsonl')
    result = run(tmp_path, answers=None)
    assert result.returncode == 2
    assert 'not a terminal' in result.stderr
    assert log.exists()


def test_each_log_needs_its_own_yes_oldest_first(tmp_path: Path) -> None:
    older = touch(tmp_path / 'logs' / 'agent-old.jsonl', days_old=3)
    newer = touch(tmp_path / 'logs' / 'agent-new.jsonl', days_old=1)
    result = run(tmp_path, '--logs-only', answers='y\nn\n')
    assert result.returncode == 0, result.stderr
    assert not older.exists()
    assert newer.exists()
    assert result.stdout.index('agent-old') < result.stdout.index('agent-new')
    assert 'removed 1 item(s)' in result.stdout


def test_enter_keeps_and_q_stops(tmp_path: Path) -> None:
    first = touch(tmp_path / 'logs' / 'a.jsonl', days_old=3)
    second = touch(tmp_path / 'logs' / 'b.jsonl', days_old=2)
    third = touch(tmp_path / 'logs' / 'c.jsonl', days_old=1)
    result = run(tmp_path, '--logs-only', answers='\nq\ny\n')
    assert result.returncode == 0, result.stderr
    assert first.exists() and second.exists() and third.exists()
    assert 'removed 0 item(s)' in result.stdout


def test_a_database_is_removed_with_its_wal_files_and_sibling_directories(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    unrelated = touch(tmp_path / 'notes.txt')
    result = run(tmp_path, '--db-only', answers='y\n')
    assert result.returncode == 0, result.stderr
    leftovers = sorted(p.name for p in tmp_path.iterdir())
    assert leftovers == ['notes.txt']
    assert unrelated.exists() and not db.exists()


def test_declining_a_database_keeps_every_part_of_it(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    result = run(tmp_path, '--db-only', answers='n\n')
    assert result.returncode == 0, result.stderr
    for part in (db, Path(f'{db}-wal'), Path(f'{db}-shm'), Path(f'{db}.artifacts'), Path(f'{db}.reports')):
        assert part.exists(), part


def test_a_database_with_a_symlinked_sibling_is_skipped(tmp_path: Path) -> None:
    state = tmp_path / 'state'
    db = touch(state / 'partex.db')
    outside = touch(tmp_path / 'outside' / 'keep.js').parent
    (state / 'partex.db.artifacts').symlink_to(outside, target_is_directory=True)
    result = run(state, '--db-only', answers='y\n')
    assert result.returncode == 0, result.stderr
    assert 'symlink' in result.stdout
    assert db.exists() and (outside / 'keep.js').exists()


def test_an_extra_database_outside_the_state_dir_is_offered(tmp_path: Path) -> None:
    state = tmp_path / 'state'
    state.mkdir()
    probe = make_db(tmp_path / 'repo', 'partex-probe.db')
    result = run(state, '--db-only', '-d', str(probe), answers='y\n')
    assert result.returncode == 0, result.stderr
    assert not probe.exists() and not Path(f'{probe}.artifacts').exists()


def test_older_than_only_offers_items_untouched_for_that_long(tmp_path: Path) -> None:
    stale = touch(tmp_path / 'logs' / 'stale.jsonl', days_old=10)
    fresh = touch(tmp_path / 'logs' / 'fresh.jsonl', days_old=1)
    db = make_db(tmp_path, days_old=1)
    result = run(tmp_path, '--older-than', '5', answers='y\ny\n')
    assert result.returncode == 0, result.stderr
    assert not stale.exists()
    assert fresh.exists() and db.exists()
    assert 'fresh.jsonl' not in result.stdout


def test_logs_only_and_db_only_restrict_what_is_offered(tmp_path: Path) -> None:
    make_db(tmp_path)
    touch(tmp_path / 'logs' / 'a.jsonl')
    logs_only = run(tmp_path, '--logs-only', '--dry-run', answers=None)
    db_only = run(tmp_path, '--db-only', '--dry-run', answers=None)
    assert '[db]' not in logs_only.stdout and '[log]' in logs_only.stdout
    assert '[db]' in db_only.stdout and '[log]' not in db_only.stdout


def test_dry_run_lists_without_a_terminal_and_deletes_nothing(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    log = touch(tmp_path / 'logs' / 'a.jsonl')
    result = run(tmp_path, '--dry-run', answers=None)
    assert result.returncode == 0, result.stderr
    assert 'nothing deleted' in result.stdout
    assert db.exists() and log.exists()


@pytest.mark.parametrize('bad', [['--older-than', 'soon'], ['--db-only', '--logs-only'], ['--bogus']])
def test_usage_errors_exit_2(tmp_path: Path, bad: list[str]) -> None:
    result = run(tmp_path, *bad, answers='')
    assert result.returncode == 2
