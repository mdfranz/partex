"""Engagement loading and validation — PLAN §4.1 rules E1–E7 (issue #11)."""

from pathlib import Path

import pytest

from partex.engagement import check_credentials_available, load_engagement, validate_engagement
from partex.errors import ValidationFailed

FIXTURES = Path(__file__).parent.parent / 'fixtures' / 'engagements'

# Fixture directory → expected rule code (one per failure mode).
FAILURE_FIXTURES = {
    'bad-schema-version': 'engagement-version',
    'unparseable-json': 'engagement-version',
    'missing-attestation': 'unauthorized',
    'missing-authorization': 'unauthorized',
    'empty-scope': 'scope-invalid',
    'base-url-outside-scope': 'scope-invalid',
    'rps-over-ceiling': 'scope-invalid',
    'requests-over-ceiling': 'scope-invalid',
    'exclusion-outside-prefixes': 'scope-invalid',
    'unparseable-host': 'scope-invalid',
    'inline-credential': 'credential-invalid',
    'bad-env-var-name': 'credential-invalid',
    'role-duplicate-env': 'credential-invalid',
}


@pytest.mark.parametrize('name,expected_rule', sorted(FAILURE_FIXTURES.items()))
def test_fixture_fails_with_rule_code(name: str, expected_rule: str) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        load_engagement(FIXTURES / name)
    assert excinfo.value.rule_code == expected_rule


def test_valid_engagement_loads_from_directory() -> None:
    engagement = load_engagement(FIXTURES / 'valid')
    assert engagement.schema_version == 1
    assert engagement.target.base_url == 'https://staging.example.test'
    assert engagement.scope.hosts == ['staging.example.test']
    assert engagement.scope.max_rps == 5
    assert engagement.credentials == {'session': 'PARTEX_CRED_SESSION'}
    assert engagement.roles == {'owner': 'PARTEX_CRED_OWNER', 'guest': 'PARTEX_CRED_GUEST'}


def test_valid_engagement_loads_from_manifest_file() -> None:
    engagement = load_engagement(FIXTURES / 'valid' / 'engagement.json')
    assert engagement.target.name == 'example-app'


def test_missing_manifest_file() -> None:
    with pytest.raises(ValidationFailed, match='cannot read') as excinfo:
        load_engagement(FIXTURES / 'does-not-exist')
    assert excinfo.value.rule_code == 'engagement-version'


def test_non_object_manifest() -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        validate_engagement(['not', 'an', 'object'])
    assert excinfo.value.rule_code == 'engagement-version'


def test_credentials_may_be_omitted() -> None:
    engagement = load_engagement(FIXTURES / 'valid')
    assert engagement is not None


def test_check_credentials_available_reports_all_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('PARTEX_CRED_SESSION', 'set')
    monkeypatch.delenv('PARTEX_CRED_OWNER', raising=False)
    monkeypatch.delenv('PARTEX_CRED_GUEST', raising=False)
    engagement = load_engagement(FIXTURES / 'valid')
    missing = check_credentials_available(engagement)
    assert missing == ['PARTEX_CRED_GUEST', 'PARTEX_CRED_OWNER']


def test_check_credentials_available_empty_when_all_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('PARTEX_CRED_SESSION', 'set')
    monkeypatch.setenv('PARTEX_CRED_OWNER', 'set')
    monkeypatch.setenv('PARTEX_CRED_GUEST', 'set')
    engagement = load_engagement(FIXTURES / 'valid')
    assert check_credentials_available(engagement) == []


def test_check_credentials_available_uses_injected_env() -> None:
    engagement = load_engagement(FIXTURES / 'valid')
    assert check_credentials_available(engagement, env={'PARTEX_CRED_OWNER': 'x'}) == [
        'PARTEX_CRED_GUEST',
        'PARTEX_CRED_SESSION',
    ]


def test_empty_env_var_name_rejected() -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        validate_engagement(
            {
                'schema_version': 1,
                'target': {'name': 'a', 'base_url': 'https://staging.example.test'},
                'scope': {'hosts': ['staging.example.test']},
                'authorization': {'attestation': 'ok', 'operator': 'op'},
                'credentials': {'session': ''},
            }
        )
    assert excinfo.value.rule_code == 'credential-invalid'


def test_role_value_must_be_env_var_name() -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        validate_engagement(
            {
                'schema_version': 1,
                'target': {'name': 'a', 'base_url': 'https://staging.example.test'},
                'scope': {'hosts': ['staging.example.test']},
                'authorization': {'attestation': 'ok', 'operator': 'op'},
                'roles': {'owner': 'secret-value-123'},
            }
        )
    assert excinfo.value.rule_code == 'credential-invalid'
