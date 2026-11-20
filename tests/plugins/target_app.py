"""``target_app``: the deliberately vulnerable fixture app on an ephemeral loopback port.

Shared by live-path tests (registered in the root conftest's ``pytest_plugins``; PLAN §14).
The suite's non-loopback socket block stays armed — the app binds ``127.0.0.1`` only.
"""

import importlib.util
from collections.abc import Iterator
from pathlib import Path

import pytest

_TARGET_APP = Path(__file__).parent.parent.parent / 'fixtures' / 'target_app' / 'app.py'


@pytest.fixture
def target_app() -> Iterator[object]:
    """The fixture target app on an ephemeral localhost port; every received request is logged."""
    spec = importlib.util.spec_from_file_location('partex_fixture_target_app', _TARGET_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.make_server()  # pyright: ignore[reportUnknownMemberType]
    thread = module.serve_thread(server)  # pyright: ignore[reportUnknownMemberType]
    try:
        yield server
    finally:
        server.shutdown()  # pyright: ignore[reportUnknownMemberType]
        server.server_close()  # pyright: ignore[reportUnknownMemberType]
        thread.join(timeout=5)
