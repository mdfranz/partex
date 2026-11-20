"""Sandbox detection (issue #84): every probe reports a reason and never raises or hangs."""

import json
import subprocess
from typing import Any

import pytest

from partex import cli, sandboxes
from partex.sandboxes import SandboxStatus, check_bubblewrap, check_container_runtime, check_monty, detect_sandboxes


def _completed(returncode: int = 0, stdout: str = '', stderr: str = '') -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _patch(monkeypatch: pytest.MonkeyPatch, *, on_path: set[str], result: Any = None, system: str = 'Linux') -> None:
    monkeypatch.setattr(sandboxes.shutil, 'which', lambda name: f'/usr/bin/{name}' if name in on_path else None)
    monkeypatch.setattr(sandboxes.platform, 'system', lambda: system)
    monkeypatch.setattr(sandboxes.subprocess, 'run', lambda argv, **kwargs: result)  # pyright: ignore[reportUnknownLambdaType]


def test_monty_is_available_here() -> None:
    status = check_monty()
    assert status.available and 'pydantic-monty' in status.detail


def test_container_runtime_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, on_path=set())
    assert check_container_runtime('docker') == SandboxStatus('docker', False, '`docker` not found on PATH')


def test_container_runtime_installed_but_daemon_down(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, on_path={'docker'}, result=_completed(1, stderr='Cannot connect to the Docker daemon'))
    status = check_container_runtime('docker')
    assert not status.available and 'daemon' in status.detail and 'Cannot connect' in status.detail


def test_container_runtime_running(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, on_path={'docker'}, result=_completed(0, stdout='27.1.2\n'))
    assert check_container_runtime('docker') == SandboxStatus('docker', True, 'daemon running, server 27.1.2')


def test_probe_timeout_and_os_error_are_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    def hang(argv: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(argv, 5)

    def broken(argv: list[str], **kwargs: Any) -> Any:
        raise PermissionError('denied')

    monkeypatch.setattr(sandboxes.shutil, 'which', lambda name: f'/usr/bin/{name}')
    monkeypatch.setattr(sandboxes.subprocess, 'run', hang)
    assert 'timed out' in check_container_runtime('podman').detail
    monkeypatch.setattr(sandboxes.subprocess, 'run', broken)
    assert 'denied' in check_container_runtime('podman').detail


def test_bubblewrap_only_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, on_path={'bwrap'}, result=_completed(0), system='Darwin')
    status = check_bubblewrap()
    assert not status.available and 'Linux only' in status.detail and 'Darwin' in status.detail


def test_bubblewrap_cases_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, on_path=set())
    assert 'not found' in check_bubblewrap().detail
    _patch(monkeypatch, on_path={'bwrap'}, result=_completed(1, stderr='bwrap: No permissions to create new namespace'))
    status = check_bubblewrap()
    assert not status.available and 'user namespaces' in status.detail
    _patch(monkeypatch, on_path={'bwrap'}, result=_completed(0))
    assert check_bubblewrap().available


def test_detect_returns_all_four_in_order() -> None:
    assert [s.name for s in detect_sandboxes()] == ['monty', 'docker', 'podman', 'bubblewrap']


def test_cli_sandboxes_json_and_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['sandboxes', '--json']) == cli.EXIT_OK  # exit 0 whatever is available
    rows = json.loads(capsys.readouterr().out)
    assert {row['name'] for row in rows} == {'monty', 'docker', 'podman', 'bubblewrap'}
    assert all(set(row) == {'name', 'available', 'detail'} for row in rows)
