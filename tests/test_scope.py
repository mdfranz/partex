"""Scope matching against the hostile-URL corpus — PLAN §4.2 rules 1–3 (issue #11).

The corpus mirrors the issue checklist: userinfo/`@`, IDN and punycode,
trailing dot, uppercase host, percent-encoded `/` and `.`, `..` segments,
IPv6 literals, default-port elision, backslashes, embedded whitespace/control
characters, and `evil-example.test` vs `example.test`.
"""

import pytest

from partex.errors import ScopeViolation
from partex.models import Scope
from partex.scope import (
    MAX_REQUESTS_CEILING,
    MAX_RPS_CEILING,
    check_url,
    normalize_host,
    parse_scoped_url,
    validate_scope,
)


def scope_of(**overrides: object) -> Scope:
    """A staging-shaped scope with per-test overrides."""
    data: dict[str, object] = {
        'hosts': ['example.test'],
        'path_prefixes': ['/api'],
        'exclusions': ['/api/admin/shutdown'],
        'ports': [443],
        'max_rps': 5,
        'max_requests': 2000,
    }
    data.update(overrides)
    return Scope.model_validate(data)


# ── Host matching (rule 2): exact match, no suffix ─────────────────────────────


def test_exact_host_allowed() -> None:
    check_url(scope_of(), 'https://example.test/api/users')


def test_suffix_host_refused() -> None:
    with pytest.raises(ScopeViolation, match='not in scope hosts'):
        check_url(scope_of(), 'https://evil-example.test/api/users')
    with pytest.raises(ScopeViolation, match='not in scope hosts'):
        check_url(scope_of(), 'https://example.test.attacker.test/api')


def test_subdomain_refused() -> None:
    with pytest.raises(ScopeViolation, match='not in scope hosts'):
        check_url(scope_of(), 'https://sub.example.test/api')


def test_trailing_dot_and_uppercase_match() -> None:
    check_url(scope_of(), 'https://EXAMPLE.test./api/users')


def test_idn_unicode_and_punycode_collapse() -> None:
    check_url(scope_of(hosts=['münchen.test']), 'https://xn--mnchen-3ya.test/api')
    check_url(scope_of(hosts=['xn--mnchen-3ya.test']), 'https://münchen.test/api')


def test_percent_encoded_host_decodes() -> None:
    check_url(scope_of(), 'https://%65%78ample.test/api')
    with pytest.raises(ScopeViolation, match='not in scope hosts'):
        check_url(scope_of(), 'https://%65%78ample.evil.test/api')


def test_host_entry_with_port_or_path_refused() -> None:
    with pytest.raises(ScopeViolation):
        normalize_host('example.test:443')
    with pytest.raises(ScopeViolation):
        normalize_host('example.test/admin')
    with pytest.raises(ScopeViolation):
        normalize_host('user@example.test')


# ── Scheme and port (rule 1) ───────────────────────────────────────────────────


def test_non_http_scheme_refused() -> None:
    for url in ('ftp://example.test/api', 'file:///etc/passwd', '//example.test/api'):
        with pytest.raises(ScopeViolation, match='scheme|authority'):
            check_url(scope_of(), url)


def test_explicit_port_must_be_in_scope() -> None:
    with pytest.raises(ScopeViolation, match='not in scope ports'):
        check_url(scope_of(), 'https://example.test:8443/api')
    check_url(scope_of(ports=[443, 8443]), 'https://example.test:8443/api')


def test_default_port_elision() -> None:
    # No explicit port → scheme default, which must pass the port allowlist.
    check_url(scope_of(ports=[443]), 'https://example.test/api')
    # Empty ports allow only the scheme defaults.
    check_url(scope_of(ports=[]), 'https://example.test/api')
    check_url(scope_of(ports=[]), 'http://example.test/api')
    with pytest.raises(ScopeViolation, match='not in scope ports'):
        check_url(scope_of(ports=[]), 'https://example.test:8443/api')


def test_malformed_port_refused() -> None:
    for url in ('https://example.test:0/api', 'https://example.test:99999/api', 'https://example.test:8a/api'):
        with pytest.raises(ScopeViolation, match='port'):
            check_url(scope_of(), url)


# ── Hostile URL constructs (issue corpus) ─────────────────────────────────────


def test_userinfo_refused() -> None:
    with pytest.raises(ScopeViolation, match='userinfo'):
        check_url(scope_of(), 'https://user:pass@example.test/api')
    # `@` in the *path* is legal and stays in scope.
    check_url(scope_of(), 'https://example.test/api/@mentions')


def test_backslash_refused() -> None:
    with pytest.raises(ScopeViolation, match='backslash'):
        check_url(scope_of(), 'https://example.test/api\\..\\admin')


def test_control_and_separator_chars_refused() -> None:
    for url in ('https://example.test/api\x00', 'https://example.test/api\r\n', 'ht\u200btps://example.test/api'):
        with pytest.raises(ScopeViolation, match='control or separator'):
            check_url(scope_of(), url)


def test_ipv6_literals() -> None:
    check_url(scope_of(hosts=['::1'], ports=[]), 'https://[::1]/api')
    check_url(scope_of(hosts=['::1'], ports=[8443]), 'https://[::1]:8443/api')
    with pytest.raises(ScopeViolation, match='unbracketed'):
        check_url(scope_of(hosts=['::1']), 'https://::1/api')
    with pytest.raises(ScopeViolation, match='IPv6|unparseable'):
        check_url(scope_of(hosts=['::1']), 'https://[not-ipv6]/api')


# ── Path prefixes and exclusions (rule 3), every interpretation ───────────────


def test_prefix_required() -> None:
    with pytest.raises(ScopeViolation, match='prefix'):
        check_url(scope_of(), 'https://example.test/admin/panel')


def test_no_prefixes_means_all_paths() -> None:
    check_url(scope_of(path_prefixes=[]), 'https://example.test/admin/panel')


def test_exclusions_win() -> None:
    with pytest.raises(ScopeViolation, match='exclusion'):
        check_url(scope_of(), 'https://example.test/api/admin/shutdown')
    with pytest.raises(ScopeViolation, match='exclusion'):
        check_url(scope_of(), 'https://example.test/api/admin/shutdown?confirm=1')


def test_percent_encoded_path_decodes_before_matching() -> None:
    # Raw path starts with /api, but the decoded path escapes the prefix.
    with pytest.raises(ScopeViolation):
        check_url(scope_of(), 'https://example.test/api%2f..%2fadmin%2fpanel')


def test_dot_segments_resolved_before_matching() -> None:
    with pytest.raises(ScopeViolation):
        check_url(scope_of(), 'https://example.test/api/../admin/panel')
    check_url(scope_of(), 'https://example.test/api/users/../orders')


def test_candidate_paths_cover_all_interpretations() -> None:
    view = parse_scoped_url('https://example.test/api%2Fusers/./42')
    assert view.path == '/api%2Fusers/./42'
    assert '/api/users/42' in view.candidate_paths  # decoded + dot segments resolved
    assert '/api/users/./42' in view.candidate_paths  # decoded, dots intact


def test_empty_path_is_root() -> None:
    view = parse_scoped_url('https://example.test')
    assert view.path == '/'
    check_url(scope_of(path_prefixes=['/']), 'https://example.test')


# ── validate_scope (E3) ───────────────────────────────────────────────────────


def test_valid_scope_has_no_problems() -> None:
    assert validate_scope(scope_of()) == []


def test_validate_scope_flags_ceiling_overruns() -> None:
    problems = validate_scope(scope_of(max_rps=MAX_RPS_CEILING + 1))
    assert any('max_rps' in p for p in problems)
    problems = validate_scope(scope_of(max_requests=MAX_REQUESTS_CEILING + 1))
    assert any('max_requests' in p for p in problems)


def test_validate_scope_flags_relative_entries() -> None:
    problems = validate_scope(scope_of(path_prefixes=['api']))
    assert any('absolute path' in p for p in problems)


def test_validate_scope_flags_exclusion_outside_prefixes() -> None:
    problems = validate_scope(scope_of(exclusions=['/admin']))
    assert any('not within any path prefix' in p for p in problems)


def test_validate_scope_exclusion_ok_without_prefixes() -> None:
    # Empty path_prefixes allow everything, so any exclusion is within them.
    assert validate_scope(scope_of(path_prefixes=[], exclusions=['/admin'])) == []


def test_validate_scope_flags_bad_hosts() -> None:
    problems = validate_scope(scope_of(hosts=['example.test:443']))
    assert any('host' in p for p in problems)
