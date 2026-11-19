"""Built-in checks — entry-point targets.

Each built-in check is registered under ``partex.checks`` via ``pyproject.toml``.
Third-party checks register via the same entry-point group.
"""

from .header_security import header_security_check

__all__ = ['header_security_check']
