"""``--urls-file`` authorized-URL allowlist through the live gates (issue #121); loopback fixture only."""

import json
from pathlib import Path
from typing import Any

import pytest

from partex.engine import run_test
from partex.storage import RunStore

pytest_plugins = ['plugins.target_server']


def engagement_dir(tmp_path: Path, server: Any) -> Path:
    directory = tmp_path / 'engagement'
    directory.mkdir()
    (directory / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'fixture', 'base_url': server.base_url},
                'scope': {
                    'hosts': ['127.0.0.1'],
                    'path_prefixes': ['/'],
                    'ports': [server.port],
                    'max_rps': 64,
                    'max_requests': 100,
                },
                'authorization': {'attestation': 'local fixture on loopback', 'operator': 'test'},
            }
        )
    )
    return directory


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / 'urls.txt'
    path.write_text(text, encoding='utf-8')
    return path


async def test_listing_the_whole_site_runs_normally(target_server: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    base = target_server.base_url
    directory = engagement_dir(tmp_path, target_server)
    urls = _write(tmp_path, f'# everything on the fixture\n{base}/*\n')
    result = await run_test(directory, tmp_store, ['version-disclosure'], authorized=True, urls_file=urls)
    assert result.state == 'checks_complete'
    assert target_server.requests


@pytest.mark.parametrize(
    ('content', 'detail'),
    [
        ('', 'no URLs'),
        ('ftp://127.0.0.1/x\n', 'line 1'),
        ('http://127.0.0.1:1/never\n', 'base_url'),  # the target's base_url is not listed
    ],
)
async def test_bad_urls_file_fails_before_any_socket(
    content: str, detail: str, target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    directory = engagement_dir(tmp_path, target_server)
    result = await run_test(
        directory, tmp_store, ['version-disclosure'], authorized=True, urls_file=_write(tmp_path, content)
    )
    assert result.state == 'invalid'
    assert result.rule_code == 'scope-invalid'
    assert target_server.requests == []


async def test_missing_urls_file_fails_before_any_socket(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    directory = engagement_dir(tmp_path, target_server)
    result = await run_test(
        directory, tmp_store, ['version-disclosure'], authorized=True, urls_file=tmp_path / 'nope.txt'
    )
    assert result.state == 'invalid'
    assert result.rule_code == 'scope-invalid'
    assert target_server.requests == []


async def test_unlisted_paths_are_refused_on_the_wire(target_server: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    """Only the listed base URL is requested; the check's other probes (/robots.txt, ...) are refused by scope."""
    base = target_server.base_url
    directory = engagement_dir(tmp_path, target_server)
    result = await run_test(
        directory, tmp_store, ['version-disclosure'], authorized=True, urls_file=_write(tmp_path, f'{base}/\n')
    )
    paths = [request['path'] for request in target_server.requests]
    assert set(paths) <= {'/'}, (result.state, paths)
