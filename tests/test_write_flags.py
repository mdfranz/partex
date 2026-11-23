"""``--allow-method`` / ``--max-writes`` extend write authority through the live gates (#65, #119); loopback only."""

from pathlib import Path
from typing import Any

import pytest
from test_urls_file import engagement_dir

from partex.engagement import load_engagement
from partex.engine import (
    _apply_write_flags,  # pyright: ignore[reportPrivateUsage]
    run_test,
)
from partex.storage import RunStore

pytest_plugins = ['plugins.target_server']


def test_flags_authorize_post_with_a_budget(target_server: Any, tmp_path: Path) -> None:
    engagement = load_engagement(engagement_dir(tmp_path, target_server))
    updated = _apply_write_flags(engagement, ['post', 'POST'], 5)
    assert updated.scope.allowed_methods == ['GET', 'HEAD', 'OPTIONS', 'POST']
    assert updated.scope.max_write_requests == 5


def test_no_flags_changes_nothing(target_server: Any, tmp_path: Path) -> None:
    engagement = load_engagement(engagement_dir(tmp_path, target_server))
    assert _apply_write_flags(engagement, [], None) is engagement


@pytest.mark.parametrize(
    ('methods', 'budget'),
    [(['POST'], None), ([], 3), (['GET'], 3), (['TRACE'], 3), (['POST'], 1001), (['POST'], -1)],
)
async def test_bad_write_flags_fail_before_any_socket(
    methods: list[str], budget: int | None, target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    directory = engagement_dir(tmp_path, target_server)
    result = await run_test(
        directory, tmp_store, ['version-disclosure'], authorized=True, allow_methods=methods, max_writes=budget
    )
    assert result.state == 'invalid'
    assert result.rule_code == 'scope-invalid'
    assert target_server.requests == []


async def test_valid_write_flags_run_normally(target_server: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    directory = engagement_dir(tmp_path, target_server)
    result = await run_test(
        directory, tmp_store, ['version-disclosure'], authorized=True, allow_methods=['POST'], max_writes=2
    )
    assert result.state == 'checks_complete'
