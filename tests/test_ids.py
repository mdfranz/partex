"""Tests for deterministic content-hash IDs — PLAN §12.

Golden-hash tests pin ID derivation so any change to the canonical JSON encoding
or the hash inputs is caught as a test failure.
"""

import hashlib
from typing import Any

from partex.ids import (
    canonical_json,
    engagement_id,
    evidence_id,
    finding_id,
    finding_key,
    normalized_operation_key,
    sha256_hex,
    verification_id,
)
from partex.models import (
    ConfigEvidence,
    ConfigExcerpt,
    Engagement,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
)

# ── canonical_json ────────────────────────────────────────────────────────────


def test_canonical_json_sorts_keys():
    result = canonical_json({'b': 1, 'a': 2, 'c': [3, 2, 1]})
    assert result == b'{"a":2,"b":1,"c":[3,2,1]}'


def test_canonical_json_nested_sort():
    result = canonical_json({'outer': {'b': 1, 'a': 2}})
    assert result == b'{"outer":{"a":2,"b":1}}'


def test_canonical_json_strings_escaped():
    result = canonical_json({'key': '\u00e9'})
    assert b'\\u00e9' in result  # ensure_ascii


def test_canonical_json_no_trailing_whitespace():
    result = canonical_json({'x': 1})
    assert not result.endswith(b' ')
    assert not result.endswith(b'\n')


def test_canonical_json_compact_separators():
    result = canonical_json({'a': 1, 'b': 2})
    assert b': ' not in result
    assert b', ' not in result


def test_canonical_json_empty_object():
    result = canonical_json({})
    assert result == b'{}'


def test_canonical_json_null():
    result = canonical_json({'a': None})
    assert result == b'{"a":null}'


# ── sha256_hex ────────────────────────────────────────────────────────────────


def test_sha256_hex_empty():
    assert sha256_hex(b'') == hashlib.sha256(b'').hexdigest()


def test_sha256_hex_known():
    # echo -n "hello" | sha256sum
    assert sha256_hex(b'hello') == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'


# ── evidence_id ────────────────────────────────────────────────────────────────


def test_evidence_id_prefix():
    ex = HttpExchange(
        request=HttpRequest(method='GET', url='https://example.test/', headers=[]),
        response=HttpResponse(status_code=200, headers=[]),
    )
    ev = HttpEvidence(id='ignored', source='f1', http=ex)
    eid = evidence_id(ev)
    assert eid.startswith('ev_')
    assert len(eid) == 3 + 16  # "ev_" + 16 hex chars


def test_evidence_id_excludes_id_source_secret_fields():
    """Evidence ID must not vary with id, source, or secret_fields."""
    ex = HttpExchange(
        request=HttpRequest(method='GET', url='https://example.test/', headers=[]),
        response=HttpResponse(status_code=200, headers=[]),
    )
    a = HttpEvidence(id='ev_a', source='bundle/a.json', http=ex, secret_fields=[])
    b = HttpEvidence(id='ev_b', source='capture:0', http=ex, secret_fields=['$.http.request.url'])
    assert evidence_id(a) == evidence_id(b)


def test_evidence_id_differs_on_content():
    ex1 = HttpExchange(
        request=HttpRequest(method='GET', url='https://example.test/a', headers=[]),
        response=HttpResponse(status_code=200, headers=[]),
    )
    ex2 = HttpExchange(
        request=HttpRequest(method='POST', url='https://example.test/a', headers=[]),
        response=HttpResponse(status_code=200, headers=[]),
    )
    a = HttpEvidence(id='ev_a', source='f', http=ex1)
    b = HttpEvidence(id='ev_a', source='f', http=ex2)
    assert evidence_id(a) != evidence_id(b)


def test_evidence_id_config():
    cfg = ConfigExcerpt(path='api.yaml', format='openapi', content='openapi: 3.0.0', revision='abc')
    ev = ConfigEvidence(id='ignored', source='f', config=cfg)
    eid = evidence_id(ev)
    assert eid.startswith('ev_')
    assert len(eid) == 19


def test_evidence_id_deterministic():
    """Same content → same ID across instantiations."""
    ex = HttpExchange(
        request=HttpRequest(method='GET', url='https://example.test/x', headers=[]),
        response=HttpResponse(status_code=200, headers=[]),
    )
    ids = {evidence_id(HttpEvidence(id=f'ev_{i}', source=f's{i}', http=ex)) for i in range(10)}
    assert len(ids) == 1


# ── finding_id ─────────────────────────────────────────────────────────────────


def test_finding_id_prefix():
    fid = finding_id('check', 'subject', 'title', ['ev_01'])
    assert fid.startswith('fn_')
    assert len(fid) == 3 + 16


def test_finding_id_uses_sorted_evidence_ids():
    """Finding ID should be identical regardless of evidence_ids ordering."""
    a = finding_id('check', 'subject', 'title', ['ev_c', 'ev_a', 'ev_b'])
    b = finding_id('check', 'subject', 'title', ['ev_a', 'ev_b', 'ev_c'])
    assert a == b


def test_finding_id_differs_on_check_id():
    a = finding_id('check-a', 'subject', 'title', ['ev_01'])
    b = finding_id('check-b', 'subject', 'title', ['ev_01'])
    assert a != b


def test_finding_id_differs_on_subject():
    """Two cookies on one response share title and evidence; subject keeps them apart (#39)."""
    a = finding_id('check', 'cookie:session', 'Weak Set-Cookie attributes', ['ev_01'])
    b = finding_id('check', 'cookie:remember_token', 'Weak Set-Cookie attributes', ['ev_01'])
    assert a != b


def test_finding_id_fields_are_delimited():
    """Moving text between subject and title changes the ID (NUL separators)."""
    assert finding_id('c', 'ab', 'c', ['ev_01']) != finding_id('c', 'a', 'bc', ['ev_01'])


def test_finding_id_differs_on_title():
    a = finding_id('check', 'subject', 'title A', ['ev_01'])
    b = finding_id('check', 'subject', 'title B', ['ev_01'])
    assert a != b


def test_finding_id_differs_on_evidence():
    a = finding_id('check', 'subject', 'title', ['ev_01'])
    b = finding_id('check', 'subject', 'title', ['ev_01', 'ev_02'])
    assert a != b


def test_finding_key_is_stable_across_evidence():
    k1 = finding_key('check', 'subject', 'title')
    assert k1.startswith('fk_')
    assert len(k1) == 3 + 16
    assert k1 == finding_key('check', 'subject', 'title')
    assert k1 != finding_key('check-2', 'subject', 'title')
    assert k1 != finding_key('check', 'subject-2', 'title')
    assert k1 != finding_key('check', 'subject', 'title-2')
    assert finding_key('c', 'ab', 'c') != finding_key('c', 'a', 'bc')


# ── verification_id ───────────────────────────────────────────────────────────


def test_verification_id_prefix():
    vid = verification_id('fn_01', ['ev_02'])
    assert vid.startswith('vf_')
    assert len(vid) == 3 + 16


def test_verification_id_differs_on_requests():
    a = verification_id('fn_01', ['ev_a'])
    b = verification_id('fn_01', ['ev_a', 'ev_b'])
    assert a != b


# ── engagement_id ──────────────────────────────────────────────────────────────


def _engagement(**overrides: Any) -> Engagement:
    data: dict[str, Any] = {
        'schema_version': 1,
        'target': {'name': 'app', 'base_url': 'https://app.example.test/'},
        'scope': {'hosts': ['app.example.test']},
        'authorization': {'attestation': 'SOW-1', 'operator': 'op'},
    }
    return Engagement.model_validate(data | overrides)


def test_engagement_id_prefix():
    eid = engagement_id(_engagement())
    assert eid.startswith('eng_')
    assert len(eid) == 4 + 16


def test_engagement_id_ignores_manifest_formatting():
    """Hashing the validated model: key order and explicit defaults don't change the ID."""
    explicit = _engagement(credentials={}, roles={}, suggested_checks=[])
    assert engagement_id(explicit) == engagement_id(_engagement())


def test_engagement_id_differs_on_content():
    other = _engagement(target={'name': 'other', 'base_url': 'https://app.example.test/'})
    assert engagement_id(other) != engagement_id(_engagement())


# ── normalized_operation_key ───────────────────────────────────────────────────


def test_normalized_operation_key_uppercases_method():
    assert normalized_operation_key('get', '/users/{id}') == 'GET /users/{id}'


def test_normalized_operation_key_already_uppercase():
    assert normalized_operation_key('POST', '/login') == 'POST /login'


# ── Golden-hash tests ──────────────────────────────────────────────────────────
# Pinning exact ID values so any change to the canonical encoding is caught.


def test_evidence_id_golden():
    ex = HttpExchange(
        request=HttpRequest(
            method='GET', url='https://example.test/api/v1/users', headers=[('Accept', 'application/json')]
        ),
        response=HttpResponse(status_code=200, headers=[('Content-Type', 'application/json')], body='[{"id":1}]'),
    )
    ev = HttpEvidence(id='placeholder', source='bundle/evidence/0001.json', http=ex)
    assert evidence_id(ev) == 'ev_38fe45c20d3d584d'


def test_finding_id_golden():
    fid = finding_id('header-security', 'header:strict-transport-security', 'Missing HSTS header', ['ev_abc', 'ev_def'])
    assert fid == 'fn_d7854dcdcf6cc27f'


def test_verification_id_golden():
    vid = verification_id('fn_01', ['ev_02'])
    assert vid == 'vf_fc5619439dd5ae20'
