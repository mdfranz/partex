"""Built-in checks — entry-point targets.

Each built-in check is registered under ``partex.checks`` via ``pyproject.toml``.
Third-party checks register via the same entry-point group.
"""

from .api_inventory import api_contract_conformance_check
from .header_security import header_security_check
from .js_analysis import js_analysis_check
from .openapi_spec_review import openapi_spec_review_check
from .privacy_signals import privacy_signals_check
from .server_error import server_error_check

__all__ = [
    'api_contract_conformance_check',
    'header_security_check',
    'js_analysis_check',
    'openapi_spec_review_check',
    'privacy_signals_check',
    'server_error_check',
]
