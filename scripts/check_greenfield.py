"""Greenfield dependency check (PLAN.md §13.1, first half).

Builds the wheel and installs it with its full locked dependency set into a fresh
environment outside both checkouts, asserting the supply-chain posture of PLAN.md §3.1:

- the sibling checkouts are at the revisions pinned in DEPS.md §4.1, with clean trees;
- the distributions the checkouts provide resolve from those local paths, never PyPI;
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
from runpy import run_path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlparse
from zipfile import ZipFile

from partex.__main__ import main as cli_main

ROOT = Path(__file__).resolve().parents[1]

# Distributions provided by the audited sibling checkouts (PLAN.md §3.1, DEPS.md §4.1):
# each must resolve from its local path, never PyPI. `pydantic`, `pydantic-core`, and
# `pydantic-settings` are upstream PyPI releases the checkout stack itself depends on
# (like `httpx2`); they are audited via the lockfile instead.
CHECKOUT_DISTRIBUTIONS = {
    'pydantic-ai-slim': ('pydantic-ai', 'pydantic_ai_slim'),
    'pydantic-graph': ('pydantic-ai', 'pydantic_graph'),
    'pydantic-ai-harness': ('pydantic-ai', 'src/pydantic_ai_harness'),
    'pydantic-clai2': ('pydantic-ai', 'src/pydantic_clai2'),
    'pydantic-monty': ('monty', 'packages/pydantic-monty'),
    'pydantic-monty-client': ('monty', 'crates/monty-python'),
    'pydantic-monty-runtime': ('monty', 'crates/monty-runtime'),
}

FORBIDDEN_PREFIXES = ('artex', 'strix')

# DEPS.md §4.1 is the source of truth for pin bumps; CI clones the same rows.
PIN_ROW = re.compile(r'^\| *`\.\./(pydantic-ai|monty)` *\| *`([0-9a-f]{40})` *\|', re.MULTILINE)

PROVENANCE_SCRIPT = f"""
import json
from importlib.metadata import distribution

names = {json.dumps(sorted(CHECKOUT_DISTRIBUTIONS))}
report = {{}}
for name in names:
    direct_url = distribution(name).read_text('direct_url.json')
    report[name] = json.loads(direct_url)['url'] if direct_url else None
print(json.dumps(report))
"""

MONTY_SMOKE_SCRIPT = """
from pydantic_monty import Monty

# RUNTIME.md M0: version resolution and worker startup, outside both checkouts.
with Monty() as pool:
    with pool.checkout() as session:
        assert session.feed_run('1 + 2') == 3
"""


def pinned_revisions() -> dict[str, str]:
    """The audited sibling-checkout revisions pinned in DEPS.md §4.1."""
    pins = dict(PIN_ROW.findall((ROOT / 'DEPS.md').read_text()))
    if sorted(pins) != ['monty', 'pydantic-ai']:
        raise ValueError(f'DEPS.md §4.1 must pin exactly ../pydantic-ai and ../monty, found: {sorted(pins)}')
    return pins


def check_pinned_checkouts() -> None:
    """Fail when a sibling checkout is not at its pinned revision or has a dirty tree."""

    def git(checkout: Path, *arguments: str) -> str:
        return subprocess.run(
            ['git', '-C', str(checkout), *arguments], check=True, capture_output=True, text=True
        ).stdout.strip()

    for name, sha in sorted(pinned_revisions().items()):
        checkout = ROOT.parent / name
        actual = git(checkout, 'rev-parse', 'HEAD')
        if actual != sha:
            raise ValueError(
                f'../{name} is at {actual} but DEPS.md pins {sha}. '
                f'Run: git -C ../{name} fetch && git -C ../{name} checkout {sha}'
            )
        if dirty := git(checkout, 'status', '--porcelain'):
            raise ValueError(f'../{name} has a dirty tree: {dirty.splitlines()[0]}')


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
    """Export the locked runtime dependency set (the project itself excluded).

    `uv export` spells editable sources relative to the repository; they are rewritten
    to absolute paths so the fresh-environment install does not depend on the cwd.
    """
    requirements = scratch / 'requirements.txt'
    subprocess.run(
        [
            'uv',
            'export',
            '--frozen',
            '--no-dev',
            '--no-emit-project',
            '--no-emit-workspace',
            '--output-file',
            str(requirements),
        ],
        check=True,
        cwd=ROOT,
    )
    lines = requirements.read_text().splitlines()
    rewritten = [line if not line.startswith('-e ') else f'-e {(ROOT / line[3:].strip()).resolve()}' for line in lines]
    requirements.write_text('\n'.join(rewritten) + '\n')
    return requirements


def assert_local_requirements(requirements: Path) -> None:
    """Checkout-provided distributions appear only as editable local sources."""
    expected = {(ROOT.parent / checkout / suffix).resolve() for checkout, suffix in CHECKOUT_DISTRIBUTIONS.values()}
    editables: set[Path] = set()
    for line in requirements.read_text().splitlines():
        if line.startswith('-e '):
            editables.add(Path(line[3:].strip()).resolve())
        elif line and not line.startswith(('#', ' ')):
            name = re.split(r'[<>=!~\[; ]', line, maxsplit=1)[0].lower()
            if name.startswith(FORBIDDEN_PREFIXES):
                raise ValueError(f'forbidden distribution in the dependency set: {line}')
            if name in CHECKOUT_DISTRIBUTIONS:
                raise ValueError(f'{name} must resolve from the local checkout, not PyPI: {line}')
    if editables != expected:
        raise ValueError(
            f'editable local sources differ from the checkout set: {sorted(str(path) for path in editables ^ expected)}'
        )


def assert_fresh_environment(python: Path, scratch: Path) -> None:
    """The fresh environment holds no forbidden distribution, and every
    checkout-provided distribution in it points back at the audited paths."""
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
    missing = sorted(set(CHECKOUT_DISTRIBUTIONS) - names)
    if missing:
        raise ValueError(f'checkout distributions missing from the fresh environment: {missing}')

    report = json.loads(
        subprocess.run(
            [str(python), '-c', PROVENANCE_SCRIPT], check=True, capture_output=True, text=True, cwd=scratch
        ).stdout
    )
    for name, url in report.items():
        if url is None:
            raise ValueError(f'{name} has no direct_url.json; expected the editable local install')
        checkout, suffix = CHECKOUT_DISTRIBUTIONS[name]
        resolved = Path(urlparse(str(url)).path).resolve()
        if resolved != (ROOT.parent / checkout / suffix).resolve():
            raise ValueError(f'{name} resolved from {url}, expected the audited checkout path')


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
    check_pinned_checkouts()
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
        assert_local_requirements(requirements)

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


def test_pinned_checkouts() -> None:
    check_pinned_checkouts()


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
    with patch.object(sys, 'argv', ['partex']):
        run_path(str(ROOT / 'src/partex/__main__.py'), run_name='__main__')


def test_greenfield_install() -> None:
    main()


if __name__ == '__main__':
    main()
