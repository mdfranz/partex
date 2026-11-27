"""Greenfield dependency check (PLAN.md §13.1, first half).

Builds the wheel and installs it with its full locked dependency set into a fresh
environment, asserting the supply-chain posture of PLAN.md §3.1:

- every locked requirement is a hash-pinned PyPI release: no local path, VCS, or URL source;
- the distributions the Pydantic AI / Monty stack provides are present in the fresh environment;
- no `artex` or `strix` distribution appears anywhere;
- the built-in skills ship as `partex/skills/` and no fixture or test does;
- a Monty worker starts and evaluates a constant expression from the fresh environment.

Issue #10 extends this to run `partex review` from the same kind of environment.
"""

import json
import os
import re
import subprocess
import sys
from contextlib import redirect_stdout
from importlib.metadata import version
from io import StringIO
from pathlib import Path, PurePosixPath
from runpy import run_module
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zipfile import ZipFile

import pytest

from partex.__main__ import main as cli_main

ROOT = Path(__file__).resolve().parents[1]

# Distributions of the Pydantic AI / Monty stack (PLAN.md §3.1): they resolve from PyPI like
# every other dependency, pinned and hash-checked by `uv.lock`.
STACK_DISTRIBUTIONS = (
    'pydantic-ai-slim',
    'pydantic-graph',
    'pydantic-ai-harness',
    'pydantic-ai-pax',
    'pydantic-monty',
    'pydantic-monty-client',
    'pydantic-monty-runtime',
)

FORBIDDEN_PREFIXES = ('artex', 'strix')

MONTY_SMOKE_SCRIPT = """
from pydantic_monty import Monty

# RUNTIME.md M0: version resolution and worker startup, outside both checkouts.
with Monty() as pool:
    with pool.checkout() as session:
        assert session.feed_run('1 + 2') == 3
"""


def assert_wheel_contents(wheel: Path) -> None:
    """Built-in skills ship as `partex/skills/`; fixtures and tests never do."""
    with ZipFile(wheel) as archive:
        names = archive.namelist()
    skills = [name for name in names if PurePosixPath(name).parts[:2] == ('partex', 'skills')]
    if not any(name.endswith('/SKILL.md') for name in skills):
        raise ValueError(f'built-in skills must ship as partex/skills/, found: {skills}')
    for name in names:
        parts = PurePosixPath(name).parts[:-1]
        if {'fixtures', 'tests'} & set(parts):
            raise ValueError(f'unexpected wheel member: {name}')


def export_requirements(scratch: Path) -> Path:
    """Export the locked runtime dependency set (the project itself excluded), with hashes."""
    requirements = scratch / 'requirements.txt'
    subprocess.run(
        [
            'uv',
            'export',
            '--frozen',
            '--no-dev',
            '--no-emit-project',
            '--output-file',
            str(requirements),
        ],
        check=True,
        cwd=ROOT,
    )
    return requirements


def assert_locked_requirements(requirements: Path) -> None:
    """Every requirement is a pinned, hash-checked registry release; nothing forbidden."""
    text = requirements.read_text()
    # Continuation lines (`--hash=...`) belong to the requirement above them.
    entries = [entry for entry in re.split(r'\n(?=\S)', text) if entry and not entry.startswith('#')]
    names: set[str] = set()
    for entry in entries:
        line = entry.splitlines()[0]
        if line.startswith(('-e ', '.', '/')) or ' @ ' in line or 'git+' in line:
            raise ValueError(f'non-registry dependency source: {line}')
        if '==' not in line or '--hash=sha256:' not in entry:
            raise ValueError(f'dependency is not pinned with a hash: {line}')
        name = re.split(r'[<>=!~\[; ]', line, maxsplit=1)[0].lower()
        if name.startswith(FORBIDDEN_PREFIXES):
            raise ValueError(f'forbidden distribution in the dependency set: {line}')
        names.add(name)
    if missing := sorted(set(STACK_DISTRIBUTIONS) - names):
        raise ValueError(f'stack distributions missing from the lock: {missing}')


def assert_fresh_environment(python: Path, scratch: Path) -> None:
    """The fresh environment holds no forbidden distribution and all stack distributions."""
    listing = subprocess.run(
        ['uv', '--offline', 'pip', 'list', '--python', str(python), '--format', 'json'],
        check=True,
        capture_output=True,
        text=True,
        cwd=scratch,
    ).stdout
    names = {distribution['name'].lower() for distribution in json.loads(listing)}
    forbidden = sorted(name for name in names if name.startswith(FORBIDDEN_PREFIXES))
    if forbidden:
        raise ValueError(f'forbidden distributions in the fresh environment: {forbidden}')
    missing = sorted(set(STACK_DISTRIBUTIONS) - names)
    if missing:
        raise ValueError(f'stack distributions missing from the fresh environment: {missing}')


def assert_cli(environment: Path, scratch: Path) -> None:
    expected = f'partex {version("partex")}'
    for command in (
        [str(environment / 'bin/partex'), '--version'],
        [str(environment / 'bin/python'), '-m', 'partex', '--version'],
    ):
        result = subprocess.run(command, check=True, capture_output=True, text=True, cwd=scratch)
        if result.stdout.strip() != expected:
            raise ValueError(f'expected {expected!r}, got {result.stdout.strip()!r}')


def assert_monty_smoke(python: Path, scratch: Path) -> None:
    subprocess.run([str(python), '-c', MONTY_SMOKE_SCRIPT], check=True, capture_output=True, text=True, cwd=scratch)


def main() -> None:
    with TemporaryDirectory(prefix='partex-greenfield-') as temporary_directory:
        scratch = Path(temporary_directory)
        wheels = scratch / 'wheels'
        wheels.mkdir()
        subprocess.run(
            ['uv', '--offline', 'build', '--wheel', '--out-dir', str(wheels), str(ROOT)], check=True, cwd=scratch
        )
        (wheel,) = wheels.glob('*.whl')
        assert_wheel_contents(wheel)

        # The exported requirement set is asserted for provenance; the fresh environment
        # is installed from the same lock, so no dependency is ever re-resolved.
        requirements = export_requirements(scratch)
        assert_locked_requirements(requirements)

        environment = scratch / '.venv'
        subprocess.run(
            ['uv', '--offline', 'sync', '--frozen', '--no-dev', '--no-install-project', '--project', str(ROOT)],
            check=True,
            cwd=scratch,
            env={**os.environ, 'UV_PROJECT_ENVIRONMENT': str(environment)},
        )
        python = environment / 'bin/python'
        subprocess.run(
            ['uv', '--offline', 'pip', 'install', '--python', str(python), str(wheel)], check=True, cwd=scratch
        )
        assert_fresh_environment(python, scratch)
        assert_cli(environment, scratch)
        assert_monty_smoke(python, scratch)
        print('greenfield environment verified')


def test_cli_version() -> None:
    output = StringIO()
    with patch.object(sys, 'argv', ['partex', '--version']), redirect_stdout(output):
        try:
            cli_main()
        except SystemExit as exc:
            assert exc.code == 0
        else:
            raise AssertionError('--version must exit')
    assert output.getvalue().strip() == f'partex {version("partex")}'


def test_module_entry_point() -> None:
    # The console script imports partex.__main__ as a package module; exercise
    # exactly that path (a loose script run cannot express the CLI delegation).
    sys.modules.pop('partex.__main__', None)  # let run_module execute it fresh
    with patch.object(sys, 'argv', ['partex', '--version']), pytest.raises(SystemExit) as excinfo:
        run_module('partex.__main__', run_name='__main__')
    assert excinfo.value.code == 0


def test_greenfield_install() -> None:
    main()


if __name__ == '__main__':
    main()
