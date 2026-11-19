"""``tmp_store``: a fresh writer ``RunStore`` on a temporary path, one per test (PLAN §14)."""

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from partex.storage import RunStore


@pytest.fixture
def tmp_store_path(tmp_path: Path) -> Path:
    return tmp_path / 'partex.db'


@pytest.fixture
async def tmp_store(tmp_store_path: Path) -> AsyncIterator[RunStore]:
    store = await RunStore.open(tmp_store_path)
    try:
        yield store
    finally:
        await store.aclose()
