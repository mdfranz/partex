"""Default locations for Partex's persistent local state."""

import os
from collections.abc import Mapping
from pathlib import Path

STATE_DIR_ENV = 'PARTEX_STATE_DIR'


def state_dir(env: Mapping[str, str] | None = None) -> Path:
    """Return Partex's state directory without creating it."""
    environ = os.environ if env is None else env
    override = environ.get(STATE_DIR_ENV)
    if override:
        return Path(override).absolute()
    root = Path(environ.get('XDG_STATE_HOME', ''))
    if not root.is_absolute():
        root = Path.home() / '.local' / 'state'
    return root / 'partex'
