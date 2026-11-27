"""Model resolution — ``--model`` / ``--gateway-route`` (issue #49). No provider is contacted."""

import json

import pytest
from pydantic_ai.models.openai import OpenAIChatModel

from partex.models_config import (
    DECISION_MODEL_ENV,
    GATEWAY_BASE_URL_ENV,
    GOOGLE_SAFETY_CATEGORIES,
    GOOGLE_SAFETY_ENV,
    ModelConfigError,
    google_safety_summary,
    normalize_gateway_base_url,
    parse_google_safety_settings,
    resolve_decision_model,
    resolve_google_safety_settings,
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


# ── Gemini configurable content filters (issue #218) ───────────────────────────


ALL_CATEGORIES_OFF = [{'category': category, 'threshold': 'OFF'} for category in GOOGLE_SAFETY_CATEGORIES]


@pytest.mark.parametrize(
    ('preset', 'threshold'),
    [('off', 'OFF'), ('high', 'BLOCK_ONLY_HIGH')],
)
def test_safety_presets_cover_every_configurable_category(preset: str, threshold: str) -> None:
    assert parse_google_safety_settings(preset) == [
        {'category': category, 'threshold': threshold} for category in GOOGLE_SAFETY_CATEGORIES
    ]
    assert parse_google_safety_settings(f'  {preset} ') == parse_google_safety_settings(preset)


def test_safety_json_list_parses_per_category_thresholds() -> None:
    raw = json.dumps([{'category': 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold': 'BLOCK_ONLY_HIGH'}])
    assert parse_google_safety_settings(raw) == [
        {'category': 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold': 'BLOCK_ONLY_HIGH'}
    ]


@pytest.mark.parametrize(
    'raw',
    [
        '',
        '   ',
        'medium',
        'not json',
        '[]',
        '{}',
        '"a string"',
        '[{"category": "HARM_CATEGORY_HARASSMENT"}]',  # threshold missing
        '[{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "OFF", "extra": 1}]',
        '[{"category": "NOT_A_CATEGORY", "threshold": "OFF"}]',
        '[{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "MAYBE"}]',
    ],
)
def test_safety_parse_failures_are_config_errors(raw: str) -> None:
    with pytest.raises(ModelConfigError) as excinfo:
        parse_google_safety_settings(raw)
    assert excinfo.value.rule_code == 'model-config'


def test_safety_settings_default_off_for_google_models_only() -> None:
    """#218: a Google model role gets the off preset with no env var; others get nothing."""
    assert resolve_google_safety_settings('google:gemini-x', env={}) == {'google_safety_settings': ALL_CATEGORIES_OFF}
    assert resolve_google_safety_settings('openai:gpt-5', env={}) is None  # its provider filters untouched
    assert resolve_google_safety_settings('test', env={}) is None


def test_safety_settings_resolve_for_every_google_spec_shape() -> None:
    from pydantic_ai.models.google import GoogleModel

    expected = {'google_safety_settings': ALL_CATEGORIES_OFF}
    assert resolve_google_safety_settings('google:gemini-x', env={GOOGLE_SAFETY_ENV: 'off'}) == expected
    assert resolve_google_safety_settings('google-cloud:gemini-x', env={GOOGLE_SAFETY_ENV: 'off'}) == expected
    instance = GoogleModel.__new__(GoogleModel)  # no provider needed: only the type is checked
    assert resolve_google_safety_settings(instance, env={GOOGLE_SAFETY_ENV: 'off'}) == expected


@pytest.mark.parametrize('model', ['openai:gpt-5', 'anthropic:claude-sonnet-5-5', 'gateway/anthropic:claude', 'test'])
def test_safety_set_on_a_non_google_model_fails_closed(model: str) -> None:
    """The operator asked for adjusted filters; silently skipping them would hide that they are still on."""
    with pytest.raises(ModelConfigError, match='google:/google-cloud:'):
        resolve_google_safety_settings(model, env={GOOGLE_SAFETY_ENV: 'off'})


def test_safety_summary_names_what_was_relaxed_and_what_stays_on() -> None:
    settings = resolve_google_safety_settings('google:gemini-x', env={GOOGLE_SAFETY_ENV: 'off'})
    summary = google_safety_summary(settings)
    assert summary is not None
    assert 'OFF' in summary and 'CSAM/PII' in summary and GOOGLE_SAFETY_ENV in summary
    assert google_safety_summary(None) is None


def test_safety_summary_says_mixed_thresholds_without_a_single_note() -> None:
    raw = json.dumps(
        [
            {'category': 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold': 'BLOCK_NONE'},
            {'category': 'HARM_CATEGORY_HARASSMENT', 'threshold': 'BLOCK_ONLY_HIGH'},
        ]
    )
    settings = resolve_google_safety_settings('google:gemini-x', env={GOOGLE_SAFETY_ENV: raw})
    summary = google_safety_summary(settings)
    assert summary is not None and 'BLOCK_NONE / BLOCK_ONLY_HIGH' in summary


# ── Decision-model resolution (issue #256) ────────────────────────────────────


def test_resolve_decision_model_accepts_google_and_openai_decisions() -> None:
    goog = resolve_decision_model('google-decisions:gemini-decision-1', env={'GOOGLE_API_KEY': 'AIza-secret-val'})
    assert goog.provider == 'google-decisions'
    assert goog.model_name == 'gemini-decision-1'
    assert goog.calibrated is True
    assert 'AIza-secret-val' not in goog.startup_summary()

    goog_gemini = resolve_decision_model('google-decisions:gemini-decision-1', env={'GEMINI_API_KEY': 'AIza-gemini'})
    assert goog_gemini.spec == 'google-decisions:gemini-decision-1'

    oai = resolve_decision_model('openai-decisions:gpt-6-luna', env={'OPENAI_API_KEY': 'sk-secret-val'})
    assert oai.provider == 'openai-decisions'
    assert oai.model_name == 'gpt-6-luna'
    assert oai.calibrated is True
    assert 'sk-secret-val' not in oai.startup_summary()

    anth = resolve_decision_model('anthropic:claude-haiku-5-5', env={'ANTHROPIC_API_KEY': 'ant-secret-val'})
    assert anth.provider == 'anthropic'
    assert anth.model_name == 'claude-haiku-5-5'
    assert anth.calibrated is False
    assert 'uncalibrated' in anth.startup_summary()
    assert 'ant-secret-val' not in anth.startup_summary()
    assert DECISION_MODEL_ENV == 'PARTEX_DECISION_MODEL'


@pytest.mark.parametrize(
    ('spec', 'fragment'),
    [
        ('', 'empty'),
        ('   ', 'empty'),
        ('gemini-decision-1', 'gateway'),
        ('gateway/google:gemini-decision-1', 'Gateway'),
        ('gateway/openai-decisions:gpt-6-luna', 'Gateway'),
        ('google-cloud-decisions:gemini-decision-1', 'Vertex AI ADC'),
        ('google:gemini-3.8-flash', 'not supported'),
        ('openai:gpt-6-sol', 'not supported'),
        ('google-decisions:', 'missing a model name'),
        ('openai-decisions:   ', 'missing a model name'),
        ('anthropic:', 'missing a model name'),
    ],
)
def test_resolve_decision_model_rejects_disallowed_specs(spec: str, fragment: str) -> None:
    env = {'GOOGLE_API_KEY': 'AIza-k', 'OPENAI_API_KEY': 'sk-k', 'ANTHROPIC_API_KEY': 'ant-k'}
    with pytest.raises(ModelConfigError, match=fragment) as excinfo:
        resolve_decision_model(spec, env=env)
    assert excinfo.value.rule_code == 'model-config'
    for secret in env.values():
        assert secret not in str(excinfo.value)


def test_resolve_decision_model_missing_credentials_never_echoes_secrets() -> None:
    with pytest.raises(ModelConfigError, match='GOOGLE_API_KEY') as exc_g:
        resolve_decision_model(
            'google-decisions:gemini-decision-1', env={'GOOGLE_API_KEY': '  ', 'OPENAI_API_KEY': 'sk-unrelated'}
        )
    assert 'sk-unrelated' not in str(exc_g.value)

    with pytest.raises(ModelConfigError, match='OPENAI_API_KEY') as exc_o:
        resolve_decision_model('openai-decisions:gpt-6-luna', env={'OPENAI_API_KEY': ''})
    assert exc_o.value.rule_code == 'model-config'

    with pytest.raises(ModelConfigError, match='ANTHROPIC_API_KEY') as exc_a:
        resolve_decision_model('anthropic:claude-haiku-5-5', env={'ANTHROPIC_API_KEY': ' '})
    assert exc_a.value.rule_code == 'model-config'


def test_google_safety_settings_do_not_apply_to_google_decisions() -> None:
    assert resolve_google_safety_settings('google-decisions:gemini-decision-1', env={}) is None
    with pytest.raises(ModelConfigError, match='google:/google-cloud:'):
        resolve_google_safety_settings('google-decisions:gemini-decision-1', env={GOOGLE_SAFETY_ENV: 'off'})
