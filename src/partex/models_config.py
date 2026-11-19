"""Model resolution for model-backed stages — PLAN §9 (role-based routing lands later).

``resolve_model`` turns the CLI's ``--model`` / ``--gateway-route`` into what ``Agent`` accepts:

- a full pydantic-ai model string (``gateway/anthropic:claude-sonnet-5-5``, ``openai:gpt-6-sol``,
  ``test``) passes through unchanged;
- a bare model name with a gateway route (``zai-org/GLM-5.3`` via ``doubleword``) becomes an
  OpenAI-chat-format model on that Pydantic AI Gateway route.

Credentials stay in the environment: pydantic-ai reads ``PYDANTIC_AI_GATEWAY_API_KEY`` and
``PYDANTIC_AI_GATEWAY_BASE_URL`` itself, and nothing here logs or stores them.
"""

import os
from collections.abc import MutableMapping

from pydantic_ai.models import Model

from .errors import PartexError

GATEWAY_BASE_URL_ENV = 'PYDANTIC_AI_GATEWAY_BASE_URL'


class ModelConfigError(PartexError):
    """``--model`` / ``--gateway-route`` cannot be resolved (rule code ``model-config``)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, rule_code='model-config')


def is_model_string(model: str) -> bool:
    """A provider-qualified pydantic-ai model string (``provider:name``) or the built-in ``test`` model."""
    return ':' in model or model == 'test'


def normalize_gateway_base_url(route: str, env: MutableMapping[str, str] | None = None) -> None:
    """Strip a trailing ``/<route>`` from ``$PYDANTIC_AI_GATEWAY_BASE_URL`` in *env* (``os.environ`` by default).

    The Gateway "Connect" page hands out base URLs that already end in the route
    (``…/proxy/doubleword``); pydantic-ai appends the route itself, which would send requests to
    ``…/doubleword/doubleword/chat/completions`` (a 404).
    """
    environ = os.environ if env is None else env
    base_url = environ.get(GATEWAY_BASE_URL_ENV)
    if not base_url:
        return
    normalized = base_url.rstrip('/').removesuffix(f'/{route}')
    if normalized != base_url:
        environ[GATEWAY_BASE_URL_ENV] = normalized


def resolve_model(model: str, *, gateway_route: str | None = None) -> Model | str:
    """Resolve ``--model`` (and optional ``--gateway-route``) to a pydantic-ai model or model string.

    Nothing here contacts a provider; a missing gateway key surfaces when the model first runs
    (agents use ``defer_model_check=True``), except for a routed model, whose provider is built now
    and reports a missing ``PYDANTIC_AI_GATEWAY_API_KEY`` as :class:`ModelConfigError`.
    """
    model = model.strip()
    if not model:
        raise ModelConfigError('--model is empty')
    if gateway_route is None:
        if not is_model_string(model):
            raise ModelConfigError(
                f'model {model!r} has no provider prefix; use e.g. gateway/anthropic:<name>, '
                'or pass --gateway-route for a model served on a gateway route (e.g. zai-org/GLM-5.3 '
                'with --gateway-route doubleword)'
            )
        return model
    route = gateway_route.strip().strip('/')
    if not route or '/' in route:
        raise ModelConfigError(f'--gateway-route must be a single route name, got {gateway_route!r}')
    if is_model_string(model):
        raise ModelConfigError(f'--gateway-route takes a bare model name, not the model string {model!r}')

    from pydantic_ai.exceptions import UserError
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.gateway import gateway_provider  # pyright: ignore[reportUnknownVariableType]

    normalize_gateway_base_url(route)
    try:
        provider = gateway_provider('openai', route=route)
    except UserError as exc:  # missing key, or a key whose region cannot be inferred
        raise ModelConfigError(str(exc)) from exc
    return OpenAIChatModel(model, provider=provider)
