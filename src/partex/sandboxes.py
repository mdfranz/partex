"""Which sandboxes this host can run — a read-only, hermetic-friendly detector (issue #84).

Monty ships with partex. Docker or Podman need the CLI *and* a running daemon. bubblewrap exists only
on Linux, with ``bwrap`` installed and user namespaces allowed. Every probe runs an argument list (never a
shell) with a short timeout and never raises: a failure is reported as "unavailable" with the reason.
"""

import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass

PROBE_TIMEOUT = 5.0
"""Seconds any single probe may take before the sandbox is reported unavailable."""


@dataclass(frozen=True, slots=True)
class SandboxStatus:
    name: str
    available: bool
    detail: str


def _run(argv: list[str]) -> subprocess.CompletedProcess[str] | str:
    """Run *argv*; return the completed process, or a short failure reason (timeout, missing, OS error)."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=PROBE_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return f'timed out after {PROBE_TIMEOUT:g}s'
    except OSError as exc:
        return str(exc)


def check_monty() -> SandboxStatus:
    try:
        import pydantic_monty
    except ImportError as exc:
        return SandboxStatus('monty', False, f'pydantic-monty is not importable: {exc}')
    version = getattr(pydantic_monty, '__version__', None)
    return SandboxStatus('monty', True, f'in-process Python sandbox{f" (pydantic-monty {version})" if version else ""}')


def check_container_runtime(name: str) -> SandboxStatus:
    """Docker or Podman: the CLI is on PATH and its daemon (or socket) answers a ``version`` query."""
    if shutil.which(name) is None:
        return SandboxStatus(name, False, f'`{name}` not found on PATH')
    result = _run([name, 'version', '--format', '{{.Server.Version}}'])
    if isinstance(result, str):
        return SandboxStatus(name, False, f'`{name} version` failed: {result}')
    if result.returncode != 0:
        reason = (result.stderr.strip().splitlines() or ['no output'])[-1][:200]
        return SandboxStatus(name, False, f'installed but not usable (is the daemon running?): {reason}')
    version = result.stdout.strip() or 'unknown version'
    return SandboxStatus(name, True, f'daemon running, server {version}')


def check_bubblewrap() -> SandboxStatus:
    """Linux only: ``bwrap`` is installed and can start a minimal sandbox (user namespaces allowed)."""
    if platform.system() != 'Linux':
        return SandboxStatus('bubblewrap', False, f'Linux only (this host is {platform.system() or "unknown"})')
    if shutil.which('bwrap') is None:
        return SandboxStatus('bubblewrap', False, '`bwrap` not found on PATH (install the bubblewrap package)')
    result = _run(['bwrap', '--ro-bind', '/', '/', '--unshare-all', '--die-with-parent', 'true'])
    if isinstance(result, str):
        return SandboxStatus('bubblewrap', False, f'`bwrap` failed to start a sandbox: {result}')
    if result.returncode != 0:
        reason = (result.stderr.strip().splitlines() or ['no output'])[-1][:200]
        return SandboxStatus('bubblewrap', False, f'installed but cannot start a sandbox (user namespaces?): {reason}')
    return SandboxStatus('bubblewrap', True, 'bwrap can start a sandbox')


def detect_sandboxes() -> list[SandboxStatus]:
    """All sandbox statuses for this host, in a stable order."""
    return [check_monty(), check_container_runtime('docker'), check_container_runtime('podman'), check_bubblewrap()]


def sandboxes_as_dicts(statuses: list[SandboxStatus]) -> list[dict[str, object]]:
    return [asdict(status) for status in statuses]
