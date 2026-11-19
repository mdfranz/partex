"""Model resolution — ``--model`` / ``--gateway-route`` (issue #49). No provider is contacted."""

import pytest
from pydantic_ai.models.openai import OpenAIChatModel

from partex.models_config import (
    GATEWAY_BASE_URL_ENV,
    ModelConfigError,
    normalize_gateway_base_url,
    resolve_model,
)

DUMMY_EU_KEY = 'pylf_v2_eu_dummyKeyForTests'


@pytest.fixture
def gateway_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.setenv('PYDANTIC_AI_GATEWAY_API_KEY', DUMMY_EU_KEY)
    monkeypatch.delenv(GATEWAY_BASE_URL_ENV, raising=False)
    monkeypatch.delenv('PAIG_BASE_URL', raising=False)
    return monkeypatch


@pytest.mark.parametrize('model', ['gateway/anthropic:claude-sonnet-5-5', 'openai:gpt-6-sol', 'test'])
def test_model_strings_pass_through(model: str) -> None:
    assert resolve_model(f'  {model} ') == model


@pytest.mark.parametrize(
    ('model', 'route', 'message'),
    [
        ('', None, 'empty'),
        ('zai-org/GLM-5.3', None, 'no provider prefix'),
        ('gateway/anthropic:claude', 'doubleword', 'bare model name'),
        ('zai-org/GLM-5.3', 'a/b', 'single route name'),
        ('zai-org/GLM-5.3', ' / ', 'single route name'),
    ],
)
def test_bad_combinations_are_config_errors(model: str, route: str | None, message: str) -> None:
    with pytest.raises(ModelConfigError, match=message) as excinfo:
        resolve_model(model, gateway_route=route)
    assert excinfo.value.rule_code == 'model-config'


def test_routed_model_uses_the_route(gateway_env: pytest.MonkeyPatch) -> None:
    model = resolve_model('zai-org/GLM-5.3', gateway_route='doubleword')
    assert isinstance(model, OpenAIChatModel)
    assert model.model_name == 'zai-org/GLM-5.3'
    # The key's region gives the gateway; the chat request appends chat/completions.
    assert str(model.client.base_url) == 'https://gateway-eu.pydantic.dev/proxy/doubleword/'


@pytest.mark.parametrize(
    'configured',
    [
        'https://gateway-eu.pydantic.dev/proxy/doubleword',  # as the Gateway "Connect" page gives it
        'https://gateway-eu.pydantic.dev/proxy/doubleword/',
        'https://gateway-eu.pydantic.dev/proxy',
    ],
)
def test_base_url_ending_in_the_route_is_not_doubled(gateway_env: pytest.MonkeyPatch, configured: str) -> None:
    gateway_env.setenv(GATEWAY_BASE_URL_ENV, configured)
    model = resolve_model('zai-org/GLM-5.3', gateway_route='doubleword')
    assert isinstance(model, OpenAIChatModel)
    assert str(model.client.base_url) == 'https://gateway-eu.pydantic.dev/proxy/doubleword/'


def test_missing_gateway_key_is_a_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('PYDANTIC_AI_GATEWAY_API_KEY', raising=False)
    monkeypatch.delenv('PAIG_API_KEY', raising=False)
    with pytest.raises(ModelConfigError, match='PYDANTIC_AI_GATEWAY_API_KEY'):
        resolve_model('zai-org/GLM-5.3', gateway_route='doubleword')


def test_normalize_leaves_other_urls_and_unset_alone() -> None:
    env: dict[str, str] = {}
    normalize_gateway_base_url('doubleword', env)
    assert env == {}
    env[GATEWAY_BASE_URL_ENV] = 'https://gateway-us.pydantic.dev/proxy'
    normalize_gateway_base_url('doubleword', env)
    assert env[GATEWAY_BASE_URL_ENV] == 'https://gateway-us.pydantic.dev/proxy'
    env[GATEWAY_BASE_URL_ENV] = 'https://gateway-us.pydantic.dev/proxy/doubleword/'
    normalize_gateway_base_url('doubleword', env)
    assert env[GATEWAY_BASE_URL_ENV] == 'https://gateway-us.pydantic.dev/proxy'
