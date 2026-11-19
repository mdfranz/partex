"""Scope matching against the hostile-URL corpus — PLAN §4.2 rules 1–3 (issue #11).

The corpus mirrors the issue checklist: userinfo/`@`, IDN and punycode,
trailing dot, uppercase host, percent-encoded `/` and `.`, `..` segments,
IPv6 literals, default-port elision, backslashes, embedded whitespace/control
characters, and `evil-example.test` vs `example.test`.
"""

from typing import Any

import pytest

from partex.errors import ScopeViolation
from partex.models import Scope
from partex.scope import (
    MAX_REQUESTS_CEILING,
    MAX_RPS_CEILING,
    check_url,
    extend_scope,
    normalize_host,
    parse_scope_target,
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


# ── #36: path matching bypasses ───────────────────────────────────────────────
# scope_of(): prefix /api, exclusion /api/admin/shutdown. Each URL below reached the excluded
# endpoint (or left the prefix) under some server's interpretation and must be refused.


@pytest.mark.parametrize(
    'url',
    [
        pytest.param('https://example.test/api//admin/shutdown', id='double-slash'),
        pytest.param('https://example.test/api///admin//shutdown', id='slash-runs'),
        pytest.param('https://example.test//api/admin/shutdown', id='leading-double-slash'),
        pytest.param('https://example.test/api/ADMIN/shutdown', id='upper-segment'),
        pytest.param('https://example.test/API/Admin/Shutdown', id='mixed-case'),
        pytest.param('https://example.test/api/admin/shutdown/', id='trailing-slash'),
        pytest.param('https://example.test/api/admin;jsessionid=x/shutdown', id='matrix-param'),
        pytest.param('https://example.test/api/admin/shutdown;x', id='matrix-param-last'),
        pytest.param('https://example.test/api/admin/shutdown.', id='trailing-dot'),
        pytest.param('https://example.test/api/admin/shutdown%20', id='trailing-space'),
        pytest.param('https://example.test/api/admin/shutdown%2e', id='encoded-trailing-dot'),
        pytest.param('https://example.test/api/admin%2fshutdown', id='encoded-slash'),
        pytest.param('https://example.test/api//admin/./shutdown;x.', id='combined'),
    ],
)
def test_excluded_endpoint_refused_under_every_interpretation(url: str) -> None:
    with pytest.raises(ScopeViolation):
        check_url(scope_of(), url)


@pytest.mark.parametrize(
    'url',
    [
        pytest.param('https://example.test/apix/secret', id='sibling-prefix'),
        pytest.param('https://example.test/api-internal/x', id='dash-sibling'),
        pytest.param('https://example.test/api;x/../admin', id='matrix-then-dotdot'),
        pytest.param('https://example.test/API/users', id='prefix-case-refused'),
    ],
)
def test_prefix_matches_on_segment_boundary(url: str) -> None:
    with pytest.raises(ScopeViolation):
        check_url(scope_of(), url)


@pytest.mark.parametrize(
    'url',
    [
        pytest.param('https://example.test/api/%252e%252e/admin', id='double-encoded-dots'),
        pytest.param('https://example.test/api/admin%252fshutdown', id='double-encoded-slash'),
        pytest.param('https://example.test/api/100%2541', id='double-encoded-letter'),
        pytest.param('https://example.test/api/admin/shutdown%00.png', id='null-byte'),
        pytest.param('https://example.test/api/users%0a', id='encoded-newline'),
        pytest.param('https://example.test/api/users%e2%80%8b', id='encoded-zero-width'),
    ],
)
def test_double_encoding_and_decoded_controls_refused(url: str) -> None:
    with pytest.raises(ScopeViolation, match='double encoding|control or format'):
        check_url(scope_of(), url)


@pytest.mark.parametrize(
    'url',
    [
        'https://example.test/api',
        'https://example.test/api/',
        'https://example.test/api/users/42',
        'https://example.test/api/admin/shutdowns',  # sibling of the excluded segment, not under it
        'https://example.test/api/admin/status',
        'https://example.test/api/search%3Fq',  # one level of encoding is fine
        'https://example.test/api/100%25',  # a literal percent sign, encoded once
        'https://example.test/api/a%20b',
        'https://example.test/api/users?id=../../admin',  # query strings are not paths
    ],
)
def test_legitimate_paths_still_allowed(url: str) -> None:
    check_url(scope_of(), url)


def test_trailing_slash_prefix_covers_children_only() -> None:
    scope = scope_of(path_prefixes=['/api/'], exclusions=[])
    check_url(scope, 'https://example.test/api/users')
    with pytest.raises(ScopeViolation):
        check_url(scope, 'https://example.test/api')


def test_root_prefix_and_dotdot_at_root() -> None:
    scope = scope_of(path_prefixes=['/'], exclusions=['/logout'])
    check_url(scope, 'https://example.test/../../etc')  # '..' above root stays at root
    with pytest.raises(ScopeViolation):
        check_url(scope, 'https://example.test/../LOGOUT')


def test_candidate_paths_include_normalized_forms() -> None:
    view = parse_scoped_url('https://example.test/api//admin;x/shutdown.')
    assert '/api/admin/shutdown' in view.candidate_paths
    assert view.path == '/api//admin;x/shutdown.'


def test_validate_scope_uses_segment_boundaries() -> None:
    problems = validate_scope(scope_of(path_prefixes=['/api'], exclusions=['/apix/admin']))
    assert any('not within any path prefix' in p for p in problems)
    assert validate_scope(scope_of(path_prefixes=['/api'], exclusions=['/api', '/api/x'])) == []


# ── Hostile hosts and authorities not covered above ───────────────────────────


@pytest.mark.parametrize(
    ('host', 'message'),
    [
        ('', 'empty host'),
        ('ex%25ample.test', 'unresolved percent-escape'),
        ('[::1', 'malformed IPv6'),
        ('[zz::1]', 'invalid IPv6'),
        ('.', 'reduces to empty'),
        ('ex%0aample.test', 'control or separator'),
        ('a..b.test', 'empty label'),
        (('x' * 64) + 'é.test', 'internationalized'),
        ('example.test/x', 'path or userinfo'),
    ],
)
def test_normalize_host_refusals(host: str, message: str) -> None:
    with pytest.raises(ScopeViolation, match=message):
        normalize_host(host)


@pytest.mark.parametrize(
    ('url', 'message'),
    [
        ('https:///api', 'missing authority'),
        ('https://[::1/api', 'unparseable URL|malformed IPv6 authority'),
        ('https://[::1]x/api', 'unparseable URL|garbage after IPv6'),
        ('https://[::1]:x/api', 'invalid port'),
        ('https://:443/api', 'empty host'),
    ],
)
def test_malformed_authorities_refused(url: str, message: str) -> None:
    with pytest.raises(ScopeViolation, match=message):
        parse_scoped_url(url)


# ── operator scope extension: parsing and merging (issue #64) ─────────────────


def _scope(**update: object) -> Scope:
    data: dict[str, Any] = {'hosts': ['a.test'], 'path_prefixes': ['/'], 'exclusions': ['/logout'], 'ports': [443]}
    return Scope(**{**data, **update})


@pytest.mark.parametrize(
    ('spec', 'host', 'ports'),
    [
        ('b.test', 'b.test', {80, 443}),
        ('B.test:8443', 'b.test', {8443}),
        ('https://b.test/x', 'b.test', {443}),
        ('http://b.test:8080', 'b.test', {8080}),
    ],
)
def test_parse_scope_target(spec: str, host: str, ports: set[int]) -> None:
    assert parse_scope_target(spec) == (host, frozenset(ports))


@pytest.mark.parametrize('spec', ['', 'ftp://b.test', 'user@b.test', 'b test'])
def test_parse_scope_target_refuses_ambiguous_input(spec: str) -> None:
    with pytest.raises(ScopeViolation):
        parse_scope_target(spec)


def test_extend_adds_host_and_port_and_keeps_everything_else() -> None:
    extended = extend_scope(_scope(), 'b.test:8443')
    assert extended.hosts == ['a.test', 'b.test'] and extended.ports == [443, 8443]
    assert extended.exclusions == ['/logout'] and extended.path_prefixes == ['/']


def test_extend_with_a_known_host_and_port_is_a_no_op() -> None:
    assert extend_scope(_scope(), 'A.test:443') == _scope()


def test_extend_keeps_scheme_defaults_when_scope_has_no_explicit_ports() -> None:
    assert extend_scope(_scope(ports=[]), 'https://b.test').ports == []
    assert extend_scope(_scope(ports=[]), 'b.test:8080').ports == [80, 443, 8080]
