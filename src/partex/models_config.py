"""Model resolution for model-backed stages — PLAN §9.

``resolve_model`` turns the CLI's ``--model`` / ``--gateway-route`` into what ``Agent`` accepts:

- a full pydantic-ai model string (``gateway/anthropic:claude-sonnet-5-5``, ``openai:gpt-6-sol``,
  ``test``) passes through unchanged;
- a bare model name with a gateway route (``zai-org/GLM-5.3`` via ``doubleword``) becomes an
  OpenAI-chat-format model on that Pydantic AI Gateway route.

``resolve_search_model`` resolves the optional ``--search-model`` role (#111) to a provider with
native web search (``anthropic:``, ``google:``, ``google-cloud:``, or ``openai:``). Search never goes through
the Pydantic AI Gateway and fails fast at startup if the prefix or credentials/ADC are invalid.

``resolve_decision_model`` resolves the optional ``--decision-model`` / ``-D`` role (#256) to
``google-decisions:``, ``openai-decisions:`` (calibrated single-pass Decisions endpoints), or
degraded uncalibrated ``anthropic:`` (``NativeOutput``, ``calibrated=False``, ``top_p=None``).
Gateway routes, bare names, and ``google-cloud-decisions:`` (no Vertex ADC endpoint in pydantic-ai)
are rejected at startup; missing credentials fail fast without echoing any secret.

Credentials stay in the environment: pydantic-ai reads ``PYDANTIC_AI_GATEWAY_API_KEY``,
``PYDANTIC_AI_GATEWAY_BASE_URL``, ``ANTHROPIC_API_KEY``, ``GOOGLE_API_KEY`` / ``GEMINI_API_KEY``,
``OPENAI_API_KEY``, and Google ADC itself, and nothing here logs or stores them.
"""

import json
import os
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Any, Literal, cast

from pydantic_ai.models import Model
from pydantic_ai.settings import ModelSettings

from .errors import PartexError

GATEWAY_BASE_URL_ENV = 'PYDANTIC_AI_GATEWAY_BASE_URL'
DEFAULT_GOOGLE_CLOUD_LOCATION = 'global'
"""Vertex location for ``google-cloud:`` search. Newer Gemini models (3.x and later) are served from
``global`` only; ``us-central1`` returns 404 for them (live-verified, #111). Override with ``GOOGLE_CLOUD_LOCATION``."""

GOOGLE_SAFETY_ENV = 'PARTEX_GOOGLE_SAFETY_SETTINGS'
"""Gemini configurable content-filter thresholds (#218). Default **off** for ``google:`` /
``google-cloud:`` model roles (:data:`GOOGLE_SAFETY_DEFAULT_PRESET`); this variable overrides
with a preset (``high``, ``off``) or a JSON
``[{"category": "HARM_CATEGORY_…", "threshold": "BLOCK_…"}]`` list. Startup prints the effective
thresholds. The provider's non-configurable CSAM and PII/SPII filters stay on whatever this sets."""

GOOGLE_SAFETY_DEFAULT_PRESET = 'off'
"""partex's default for ``google:`` / ``google-cloud:`` model roles (#218, operator-directed):
the provider's configurable content filters are disabled — authorized security testing carries
exploit and payload evidence the ``dangerous`` category flags, so the filters are a
false-positive source for partex's own gated, authorized work. :data:`GOOGLE_SAFETY_ENV`
overrides (``high``, ``off``, or a JSON list); the non-configurable CSAM/PII filters stay on."""

GOOGLE_SAFETY_PRESETS: dict[str, str] = {'off': 'OFF', 'high': 'BLOCK_ONLY_HIGH'}
"""Preset name → threshold, applied to every configurable category."""

GOOGLE_SAFETY_OFF_NOTE = 'no automated content-filter blocking'
"""What the ``off`` preset means in the startup warning; ``high`` keeps a high-severity block."""

GOOGLE_SAFETY_CATEGORIES: tuple[str, ...] = (
    'HARM_CATEGORY_HARASSMENT',
    'HARM_CATEGORY_HATE_SPEECH',
    'HARM_CATEGORY_SEXUALLY_EXPLICIT',
    'HARM_CATEGORY_DANGEROUS_CONTENT',
)
"""Gemini's configurable harm categories. CSAM and PII/SPII are separate, non-configurable filters."""

GOOGLE_SAFETY_THRESHOLDS: tuple[str, ...] = (
    'BLOCK_LOW_AND_ABOVE',
    'BLOCK_MEDIUM_AND_ABOVE',
    'BLOCK_ONLY_HIGH',
    'BLOCK_NONE',
    'OFF',
)
"""Thresholds the Gemini API accepts for a configurable harm category."""

type SearchProvider = Literal['anthropic', 'google', 'google-cloud', 'openai']
type SearchAuthMode = Literal['api_key', 'adc']
type AdcLoader = Callable[[], tuple[Any, str | None]]

SEARCH_MODEL_PREFIXES: tuple[SearchProvider, ...] = ('anthropic', 'google', 'google-cloud', 'openai')
"""Providers accepted by ``--search-model`` (native server-side web search only, never Gateway)."""

OPENAI_RESPONSES_ALIAS = 'openai-responses'
"""Also accepted for ``openai``; both resolve to the Responses API, the only OpenAI API with a full ``web_search`` tool."""

DECISION_MODEL_ENV = 'PARTEX_DECISION_MODEL'
"""Environment variable overriding ``--decision-model`` / ``-D`` (#256)."""

type DecisionProvider = Literal['google-decisions', 'openai-decisions', 'anthropic']
type DecisionAuthMode = Literal['api_key']

DECISION_MODEL_PREFIXES: tuple[DecisionProvider, ...] = ('google-decisions', 'openai-decisions', 'anthropic')
"""Providers accepted by ``--decision-model`` (``google-decisions:``, ``openai-decisions:``, or uncalibrated ``anthropic:``)."""


class ModelConfigError(PartexError):
    """``--model`` / ``--gateway-route`` / ``--search-model`` / ``--decision-model`` cannot be resolved (rule code ``model-config``)."""

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
    """Validate and resolve ``--search-model`` (native search: ``anthropic:``, ``google:``, ``google-cloud:``, ``openai:``).

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
    if raw_prefix == 'openai-chat':
        raise ModelConfigError(
            "--search-model 'openai-chat:' is not supported: Chat Completions search works only on search-preview "
            f'models without domain filters; use openai:<model> (Responses API). Accepted prefixes: {accepted}'
        )
    if raw_prefix == OPENAI_RESPONSES_ALIAS:
        raw_prefix = 'openai'
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

    if raw_prefix == 'openai':
        if not (environ.get('OPENAI_API_KEY') or '').strip():
            raise ModelConfigError(f'OPENAI_API_KEY is required for --search-model {normalized!r}')
        return SearchModelConfig(
            spec=normalized,
            provider='openai',
            model_name=model_name,
            auth_mode='api_key',
            # Pin the Responses API explicitly: ``openai:`` maps to it today, but only Responses has the full tool.
            model=f'{OPENAI_RESPONSES_ALIAS}:{model_name}',
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


@dataclass(frozen=True, slots=True)
class DecisionModelConfig:
    """Validated ``--decision-model`` configuration ready for :class:`~partex.agent_adapter.decide.DecisionRunner` (#256)."""

    spec: str
    provider: DecisionProvider
    model_name: str
    auth_mode: DecisionAuthMode
    model: Model | str
    calibrated: bool = True

    def startup_summary(self) -> str:
        """Operator-facing startup line (model and auth mode only — never credentials)."""
        suffix = '' if self.calibrated else '; uncalibrated NativeOutput — no probabilities'
        return f'{self.spec} (auth: {self.auth_mode}; bounded redacted excerpts leave this machine{suffix})'


def _resolve_decision_provider(
    provider: DecisionProvider,
    model_name: str,
    normalized: str,
    environ: Mapping[str, str],
) -> DecisionModelConfig:
    """Validate credentials for one decision provider and return its config.

    Kept as a dedicated dispatch helper so local decision backends (such as ``system-one:`` or
    Ollama-backed System One endpoints) can be added here without changing the caller contract.
    """
    match provider:
        case 'google-decisions':
            if not ((environ.get('GOOGLE_API_KEY') or '').strip() or (environ.get('GEMINI_API_KEY') or '').strip()):
                raise ModelConfigError(
                    f'GOOGLE_API_KEY (or GEMINI_API_KEY) is required for --decision-model {normalized!r}'
                )
            return DecisionModelConfig(
                spec=normalized,
                provider='google-decisions',
                model_name=model_name,
                auth_mode='api_key',
                model=normalized,
                calibrated=True,
            )
        case 'openai-decisions':
            if not (environ.get('OPENAI_API_KEY') or '').strip():
                raise ModelConfigError(f'OPENAI_API_KEY is required for --decision-model {normalized!r}')
            return DecisionModelConfig(
                spec=normalized,
                provider='openai-decisions',
                model_name=model_name,
                auth_mode='api_key',
                model=normalized,
                calibrated=True,
            )
        case 'anthropic':
            if not (environ.get('ANTHROPIC_API_KEY') or '').strip():
                raise ModelConfigError(f'ANTHROPIC_API_KEY is required for --decision-model {normalized!r}')
            return DecisionModelConfig(
                spec=normalized,
                provider='anthropic',
                model_name=model_name,
                auth_mode='api_key',
                model=normalized,
                calibrated=False,
            )


def resolve_decision_model(model: str, *, env: Mapping[str, str] | None = None) -> DecisionModelConfig:
    """Validate and resolve ``--decision-model`` / ``-D`` (``google-decisions:``, ``openai-decisions:``, ``anthropic:``).

    Rejects bare names and ``gateway/...`` explicitly: Pydantic AI Gateway proxies generative
    chat/responses endpoints rather than dedicated provider ``/decisions`` endpoints, and decision
    calls must bind directly to a verified endpoint instead of silently routing through Gateway.

    Also rejects ``google-cloud-decisions:`` (no Vertex ADC backend exists for Gemini Decisions in
    ``pydantic-ai``; use ``google-decisions:`` with ``GOOGLE_API_KEY`` or ``GEMINI_API_KEY``).
    ``anthropic:`` is allowed as a degraded uncalibrated ``NativeOutput`` option (``calibrated=False``,
    ``top_p=None``; never fakes ``p=1.0`` and requires explicit caller ``allow_uncalibrated=True`` opt-in).
    Error messages never include credential values.
    """
    accepted = ', '.join(f'{prefix}:<model>' for prefix in DECISION_MODEL_PREFIXES)
    spec = model.strip()
    if not spec:
        raise ModelConfigError(f'--decision-model is empty; accepted prefixes: {accepted}')
    if spec.startswith('gateway/') or ':' not in spec:
        raise ModelConfigError(
            f'--decision-model {spec!r} is not supported (gateway models and bare names are rejected: '
            'Pydantic AI Gateway proxies generative endpoints rather than calibrated /decisions endpoints); '
            f'accepted prefixes: {accepted}'
        )
    raw_prefix, _, raw_name = spec.partition(':')
    model_name = raw_name.strip()
    if raw_prefix == 'google-cloud-decisions':
        raise ModelConfigError(
            "--decision-model 'google-cloud-decisions:' is not supported: Vertex AI ADC is not supported "
            f'for the Gemini Decisions API; use google-decisions:<model> with GOOGLE_API_KEY or GEMINI_API_KEY. '
            f'Accepted prefixes: {accepted}'
        )
    if raw_prefix not in DECISION_MODEL_PREFIXES:
        raise ModelConfigError(
            f'--decision-model provider {raw_prefix!r} is not supported; accepted prefixes: {accepted}'
        )
    if not model_name:
        raise ModelConfigError(f'--decision-model {spec!r} is missing a model name after {raw_prefix!r}:')

    environ = os.environ if env is None else env
    normalized = f'{raw_prefix}:{model_name}'
    return _resolve_decision_provider(raw_prefix, model_name, normalized, environ)


# ── Gemini configurable content filters (issue #218) ───────────────────────────


def _is_google_model(model: Model | str) -> bool:
    """Whether *model* is a generative Gemini request path: ``google:``/``google-cloud:`` or ``GoogleModel``.

    ``google-decisions:`` / ``GoogleDecisionsModel`` is intentionally excluded: the Gemini Decisions
    endpoint accepts only ``{model, input, questions}`` with no ``safetySettings`` parameter (#256).
    """
    if isinstance(model, str):
        return model.split(':', 1)[0] in ('google', 'google-cloud')
    from pydantic_ai.models.google import GoogleModel

    return isinstance(model, GoogleModel)


def parse_google_safety_settings(raw: str) -> list[dict[str, str]]:
    """Parse :data:`GOOGLE_SAFETY_ENV`'s value: a preset or a JSON ``[{category, threshold}]`` list.

    Fails closed as :class:`ModelConfigError` on anything the Gemini API would reject or ignore
    (empty value, unknown preset, malformed JSON, not a list, missing or unknown keys) — a relaxed
    filter the operator asked for but did not get is worse than a refused startup.
    """
    value = raw.strip()
    hint = f'presets: {", ".join(GOOGLE_SAFETY_PRESETS)}; or a JSON list of {{"category", "threshold"}} objects'
    if not value:
        raise ModelConfigError(f'{GOOGLE_SAFETY_ENV} is empty; {hint}')
    if value in GOOGLE_SAFETY_PRESETS:
        threshold = GOOGLE_SAFETY_PRESETS[value]
        return [{'category': category, 'threshold': threshold} for category in GOOGLE_SAFETY_CATEGORIES]
    try:
        data: Any = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ModelConfigError(
            f'{GOOGLE_SAFETY_ENV} is neither a preset ({", ".join(GOOGLE_SAFETY_PRESETS)}) nor valid JSON: {exc}'
        ) from exc
    if not isinstance(data, list) or not data:
        raise ModelConfigError(f'{GOOGLE_SAFETY_ENV} must be a non-empty JSON list; {hint}')
    settings: list[dict[str, str]] = []
    for entry in cast('list[Any]', data):
        if not isinstance(entry, dict):
            raise ModelConfigError(f'{GOOGLE_SAFETY_ENV} entries must be {{"category", "threshold"}} objects; {hint}')
        record: dict[str, Any] = cast('dict[str, Any]', entry)
        if set(record) != {'category', 'threshold'}:
            raise ModelConfigError(f'{GOOGLE_SAFETY_ENV} entries must be {{"category", "threshold"}} objects; {hint}')
        category, threshold = record['category'], record['threshold']
        if not isinstance(category, str) or category not in GOOGLE_SAFETY_CATEGORIES:
            raise ModelConfigError(
                f'{GOOGLE_SAFETY_ENV} category {category!r} is not one of {", ".join(GOOGLE_SAFETY_CATEGORIES)}'
            )
        if not isinstance(threshold, str) or threshold not in GOOGLE_SAFETY_THRESHOLDS:
            raise ModelConfigError(
                f'{GOOGLE_SAFETY_ENV} threshold {threshold!r} is not one of {", ".join(GOOGLE_SAFETY_THRESHOLDS)}'
            )
        settings.append({'category': category, 'threshold': threshold})
    return settings


def resolve_google_safety_settings(model: Model | str, *, env: Mapping[str, str] | None = None) -> ModelSettings | None:
    """The ``google_safety_settings`` model settings for *model* (#218).

    Default **off** for a ``google:`` / ``google-cloud:`` model: the provider's configurable
    content filters are disabled (:data:`GOOGLE_SAFETY_DEFAULT_PRESET`), so authorized security
    work carrying exploit/payload evidence is not blocked by the ``dangerous`` category.
    :data:`GOOGLE_SAFETY_ENV` overrides with a preset or a JSON ``[{category, threshold}]``
    list. Any other model → ``None`` unset (its provider filters apply untouched), or a
    :class:`ModelConfigError` when the operator set the variable for it (fail closed: a silently
    skipped relaxation would hide that the filters are still on). Resolve before wrapping a
    model (``UsageRecordingModel`` passes per-request settings through unchanged).
    """
    raw = (os.environ if env is None else env).get(GOOGLE_SAFETY_ENV, '')
    google = _is_google_model(model)
    if not raw.strip():
        if not google:
            return None
        settings = parse_google_safety_settings(GOOGLE_SAFETY_DEFAULT_PRESET)
    else:
        settings = parse_google_safety_settings(raw)
        if not google:
            raise ModelConfigError(
                f'{GOOGLE_SAFETY_ENV} is set but this model is not a google:/google-cloud: model; '
                'the Gemini content filters only exist there'
            )
    return cast('ModelSettings', {'google_safety_settings': settings})


def google_safety_summary(settings: ModelSettings | None) -> str | None:
    """The operator-facing startup line for *settings* (``None`` when nothing was relaxed)."""
    if not settings:
        return None
    entries = [entry['category'] for entry in settings.get('google_safety_settings', [])]
    thresholds = {entry['threshold'] for entry in settings.get('google_safety_settings', [])}
    what = ', '.join(sorted(entries)) if entries else 'no categories'
    how = next(iter(thresholds)) if len(thresholds) == 1 else ' / '.join(sorted(thresholds))
    note = f' ({GOOGLE_SAFETY_OFF_NOTE})' if how == 'OFF' else ''
    return (
        f'Gemini configurable content filters: {what} → {how}{note}. '
        f'({GOOGLE_SAFETY_ENV} overrides; the provider CSAM/PII filters are non-configurable and stay on.)'
    )
