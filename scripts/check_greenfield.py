"""Build and install the wheel in a fresh environment outside the checkout."""

import json
import subprocess
import sys
from contextlib import redirect_stdout
from importlib.metadata import version
from io import StringIO
from pathlib import Path, PurePosixPath
from runpy import run_path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zipfile import ZipFile

from partex.__main__ import main as cli_main

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with TemporaryDirectory(prefix='partex-greenfield-') as temporary_directory:
        scratch = Path(temporary_directory)
        subprocess.run(
            ['uv', '--offline', 'build', '--wheel', '--out-dir', str(scratch), str(ROOT)], check=True, cwd=scratch
        )
        (wheel,) = scratch.glob('*.whl')
        with ZipFile(wheel) as archive:
            for name in archive.namelist():
                if {'fixtures', 'tests'}.intersection(PurePosixPath(name).parts[:-1]):
                    raise ValueError(f'Unexpected wheel member: {name}')

        environment = scratch / '.venv'
        subprocess.run(
            ['uv', '--offline', 'venv', '--python', sys.executable, str(environment)], check=True, cwd=scratch
        )
        subprocess.run(
            ['uv', '--offline', 'pip', 'install', '--python', str(environment / 'bin/python'), str(wheel)],
            check=True,
            cwd=scratch,
        )
        installed = subprocess.run(
            ['uv', '--offline', 'pip', 'list', '--python', str(environment / 'bin/python'), '--format', 'json'],
            check=True,
            cwd=scratch,
            capture_output=True,
            text=True,
        )
        distributions: list[dict[str, str]] = json.loads(installed.stdout)
        names = {distribution['name'] for distribution in distributions}
        if names != {'partex'}:
            raise ValueError(f'Expected only partex in the fresh environment, found {sorted(names)}')

        commands = (
            [str(environment / 'bin/partex'), '--version'],
            [str(environment / 'bin/python'), '-m', 'partex', '--version'],
        )
        expected = f'partex {version("partex")}'
        for command in commands:
            result = subprocess.run(command, check=True, cwd=scratch, capture_output=True, text=True)
            if result.stdout.strip() != expected:
                raise ValueError(f'Expected {expected!r}, got {result.stdout.strip()!r}')
        print(expected)


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
