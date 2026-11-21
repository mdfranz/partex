"""Model resolution for model-backed stages — PLAN §9.

``resolve_model`` turns the CLI's ``--model`` / ``--gateway-route`` into what ``Agent`` accepts:

- a full pydantic-ai model string (``gateway/anthropic:claude-sonnet-5-5``, ``openai:gpt-6-sol``,
  ``test``) passes through unchanged;
- a bare model name with a gateway route (``zai-org/GLM-5.3`` via ``doubleword``) becomes an
  OpenAI-chat-format model on that Pydantic AI Gateway route.

``resolve_search_model`` resolves the optional ``--search-model`` role (#111) to a provider with
native web search (``anthropic:``, ``google:``, or ``google-cloud:``). Search never goes through
the Pydantic AI Gateway and fails fast at startup if the prefix or credentials/ADC are invalid.

Credentials stay in the environment: pydantic-ai reads ``PYDANTIC_AI_GATEWAY_API_KEY``,
``PYDANTIC_AI_GATEWAY_BASE_URL``, ``ANTHROPIC_API_KEY``, ``GOOGLE_API_KEY`` / ``GEMINI_API_KEY``,
and Google ADC itself, and nothing here logs or stores them.
"""

import os
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Any, Literal

from pydantic_ai.models import Model

from .errors import PartexError

GATEWAY_BASE_URL_ENV = 'PYDANTIC_AI_GATEWAY_BASE_URL'
DEFAULT_GOOGLE_CLOUD_LOCATION = 'global'
"""Vertex location for ``google-cloud:`` search. Newer Gemini models (3.x and later) are served from
``global`` only; ``us-central1`` returns 404 for them (live-verified, #111). Override with ``GOOGLE_CLOUD_LOCATION``."""

type SearchProvider = Literal['anthropic', 'google', 'google-cloud']
type SearchAuthMode = Literal['api_key', 'adc']
type AdcLoader = Callable[[], tuple[Any, str | None]]

SEARCH_MODEL_PREFIXES: tuple[SearchProvider, ...] = ('anthropic', 'google', 'google-cloud')
"""Providers accepted by ``--search-model`` (native server-side web search only, never Gateway)."""


class ModelConfigError(PartexError):
    """``--model`` / ``--gateway-route`` / ``--search-model`` cannot be resolved (rule code ``model-config``)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, rule_code='model-config')


@dataclass(frozen=True, slots=True)
class SearchModelConfig:
    """Validated ``--search-model`` configuration ready for the dedicated search agent (#111)."""

    spec: str
    provider: SearchProvider
    model_name: str
    auth_mode: SearchAuthMode
    model: Model | str
    project: str | None = None
    location: str | None = None

    def startup_summary(self) -> str:
        """Operator-facing startup line (model, auth mode, project ID only — never credentials)."""
        if self.auth_mode == 'adc' and self.project:
            return f'{self.spec} (auth: adc, project: {self.project}; queries leave this machine)'
        return f'{self.spec} (auth: {self.auth_mode}; queries leave this machine)'


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


def _default_adc_loader() -> tuple[Any, str | None]:
    import google.auth  # pyright: ignore[reportMissingTypeStubs]

    return google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]


def resolve_search_model(
    model: str,
    *,
    env: Mapping[str, str] | None = None,
    adc_loader: AdcLoader | None = None,
) -> SearchModelConfig:
    """Validate and resolve ``--search-model`` (native search only: ``anthropic:``, ``google:``, ``google-cloud:``).

    Fails fast with :class:`ModelConfigError` on unsupported prefixes (including ``gateway/...`` and
    bare model names) or missing credentials/ADC. Error messages never include credential values,
    tokens, or key file contents.
    """
    accepted = ', '.join(f'{prefix}:<model>' for prefix in SEARCH_MODEL_PREFIXES)
    spec = model.strip()
    if not spec:
        raise ModelConfigError(f'--search-model is empty; accepted prefixes: {accepted}')
    if spec.startswith('gateway/') or ':' not in spec:
        raise ModelConfigError(
            f'--search-model {spec!r} is not supported (gateway models and bare names are not allowed); '
            f'accepted prefixes: {accepted}'
        )
    raw_prefix, _, raw_name = spec.partition(':')
    model_name = raw_name.strip()
    if raw_prefix not in SEARCH_MODEL_PREFIXES:
        raise ModelConfigError(
            f'--search-model provider {raw_prefix!r} is not supported; accepted prefixes: {accepted}'
        )
    if not model_name:
        raise ModelConfigError(f'--search-model {spec!r} is missing a model name after {raw_prefix!r}:')

    environ = os.environ if env is None else env
    normalized = f'{raw_prefix}:{model_name}'

    if raw_prefix == 'anthropic':
        if not (environ.get('ANTHROPIC_API_KEY') or '').strip():
            raise ModelConfigError(f'ANTHROPIC_API_KEY is required for --search-model {normalized!r}')
        return SearchModelConfig(
            spec=normalized,
            provider='anthropic',
            model_name=model_name,
            auth_mode='api_key',
            model=normalized,
        )

    if raw_prefix == 'google':
        if not ((environ.get('GOOGLE_API_KEY') or '').strip() or (environ.get('GEMINI_API_KEY') or '').strip()):
            raise ModelConfigError(f'GOOGLE_API_KEY (or GEMINI_API_KEY) is required for --search-model {normalized!r}')
        return SearchModelConfig(
            spec=normalized,
            provider='google',
            model_name=model_name,
            auth_mode='api_key',
            model=normalized,
        )

    # google-cloud: Vertex AI with Application Default Credentials (ADC), no API key.
    project = (environ.get('GOOGLE_CLOUD_PROJECT') or '').strip()
    if not project:
        raise ModelConfigError(
            f'GOOGLE_CLOUD_PROJECT is required for --search-model {normalized!r} '
            '(uses Google Application Default Credentials, no API key)'
        )
    from google.auth.exceptions import GoogleAuthError  # pyright: ignore[reportMissingTypeStubs]

    location = (environ.get('GOOGLE_CLOUD_LOCATION') or '').strip() or DEFAULT_GOOGLE_CLOUD_LOCATION
    loader = _default_adc_loader if adc_loader is None else adc_loader
    try:
        credentials, _ = loader()
    except GoogleAuthError, OSError, ValueError, KeyError, RuntimeError:
        # Never forward the underlying exception text: a malformed credentials file or auth error
        # could echo credential, token, or key-file contents into stderr or logs.
        raise ModelConfigError(
            f'Google Application Default Credentials (ADC) could not be resolved for --search-model {normalized!r}; '
            'run "gcloud auth application-default login" or set GOOGLE_APPLICATION_CREDENTIALS'
        ) from None
    if credentials is None:
        raise ModelConfigError(
            f'Google Application Default Credentials (ADC) returned no credentials for --search-model {normalized!r}'
        )

    from pydantic_ai.models.google import GoogleModel
    from pydantic_ai.providers.google_cloud import GoogleCloudProvider

    try:
        provider = GoogleCloudProvider(credentials=credentials, project=project, location=location)
    except GoogleAuthError, OSError, ValueError, TypeError, RuntimeError:
        raise ModelConfigError(
            f'could not initialize Google Cloud provider for --search-model {normalized!r} '
            f'(project {project!r}, location {location!r})'
        ) from None
    return SearchModelConfig(
        spec=normalized,
        provider='google-cloud',
        model_name=model_name,
        auth_mode='adc',
        model=GoogleModel(model_name, provider=provider),
        project=project,
        location=location,
    )
