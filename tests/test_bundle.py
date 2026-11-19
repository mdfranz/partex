"""Tests for bundle load and validation — PLAN §4.3 (V1–V4, V6)."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from partex import bundle as bundle_module
from partex.bundle import (
    MAX_CONTENT_BYTES,
    MAX_EVIDENCE_FILE_BYTES,
    MAX_HEADERS,
    MAX_MANIFEST_BYTES,
    MAX_URL_BYTES,
    load_bundle,
)
from partex.errors import ValidationFailed
from partex.ids import evidence_id
from partex.models import ConfigEvidence, HttpEvidence, get_header

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures' / 'bundles'
VALID = FIXTURES / 'valid'
MALFORMED = sorted(p for p in (FIXTURES / 'malformed').iterdir() if p.is_dir())


# ── helpers ───────────────────────────────────────────────────────────────────


def _exchange(
    *, url: str = 'https://app.example.test/', headers: list[list[str]] | None = None, body: str = 'ok'
) -> dict[str, Any]:
    return {
        'kind': 'http_exchange',
        'http': {
            'request': {'method': 'GET', 'url': url, 'headers': [['Host', 'app.example.test']]},
            'response': {'status_code': 200, 'headers': headers or [['Content-Type', 'text/html']], 'body': body},
        },
    }


def _write_bundle(root: Path, records: dict[str, Any], **manifest: Any) -> Path:
    """Write a bundle whose evidence files are *records* (name → JSON object, or raw bytes)."""
    root.mkdir(parents=True, exist_ok=True)
    for name, record in records.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(record if isinstance(record, bytes) else json.dumps(record).encode())
    data = {
        'schema_version': 1,
        'target': {'name': 'example-app', 'base_url': 'https://app.example.test'},
        'evidence_files': list(records),
    } | manifest
    (root / 'bundle.json').write_text(json.dumps(data))
    return root


def _rule(exc: pytest.ExceptionInfo[ValidationFailed]) -> str | None:
    return exc.value.rule_code


# ── valid fixture ─────────────────────────────────────────────────────────────


def test_valid_fixture_loads():
    loaded = load_bundle(VALID)

    assert loaded.root == VALID
    assert loaded.manifest.target.name == 'example-app'
    assert loaded.suggested_checks == ('header-security',)
    assert loaded.warnings == ()
    assert [e.source for e in loaded.evidence] == loaded.manifest.evidence_files
    assert [e.kind for e in loaded.evidence] == ['http_exchange'] * 5 + ['config_excerpt']
    for item in loaded.evidence:
        assert item.id == evidence_id(item)
        assert item.id.startswith('ev_')


def test_valid_fixture_redaction_markers_are_accepted():
    clean = load_bundle(VALID).evidence[0]
    assert isinstance(clean, HttpEvidence)
    assert get_header(clean.http.request.headers, 'Authorization') == '<redacted>'


def test_valid_fixture_openapi_excerpt_keeps_revision():
    excerpt = load_bundle(VALID).evidence[-1]
    assert isinstance(excerpt, ConfigEvidence)
    assert (excerpt.config.format, excerpt.config.revision) == ('openapi', 'v1.4.2')


def test_load_is_deterministic():
    first, second = load_bundle(VALID), load_bundle(str(VALID))
    assert first.fingerprint == second.fingerprint
    assert first.evidence == second.evidence


def test_evidence_id_ignores_source(tmp_path: Path):
    """The same content hashes the same under any file name (§12)."""
    a = load_bundle(_write_bundle(tmp_path / 'a', {'evidence/x.json': _exchange()}))
    b = load_bundle(_write_bundle(tmp_path / 'b', {'evidence/y.json': _exchange()}))
    assert a.evidence[0].id == b.evidence[0].id
    assert a.evidence[0].source != b.evidence[0].source


def test_secret_fields_are_carried(tmp_path: Path):
    record = _exchange() | {'secret_fields': ['$.http.request.headers[0][1]']}
    loaded = load_bundle(_write_bundle(tmp_path, {'e.json': record}))
    assert loaded.evidence[0].secret_fields == ['$.http.request.headers[0][1]']


@pytest.mark.parametrize(
    'path',
    ['$.http.request.headers.Host', '$.http.request.headers[5][1]', '$.http.request.headers[0]', '$.nope', 'http'],
)
def test_unresolvable_secret_field_is_evidence_invalid(tmp_path: Path, path: str):
    """A secret marking that names no string value is refused at load, never skipped at redaction."""
    record = _exchange() | {'secret_fields': [path]}
    with pytest.raises(ValidationFailed) as excinfo:
        load_bundle(_write_bundle(tmp_path, {'e.json': record}))
    assert excinfo.value.rule_code == 'evidence-invalid'


def test_empty_evidence_list_is_valid(tmp_path: Path):
    loaded = load_bundle(_write_bundle(tmp_path, {}))
    assert loaded.evidence == ()


# ── fingerprint ───────────────────────────────────────────────────────────────


def test_fingerprint_changes_with_any_referenced_file(tmp_path: Path):
    copy = tmp_path / 'bundle'
    shutil.copytree(VALID, copy)
    before = load_bundle(copy).fingerprint

    target = copy / 'evidence' / '0005-json-api.json'
    record = json.loads(target.read_text())
    record['http']['response']['body'] = '{"status":"degraded"}'
    target.write_text(json.dumps(record))
    assert load_bundle(copy).fingerprint != before


def test_fingerprint_ignores_unreferenced_files(tmp_path: Path):
    copy = tmp_path / 'bundle'
    shutil.copytree(VALID, copy)
    before = load_bundle(copy).fingerprint
    (copy / 'NOTES.txt').write_text('operator scratch notes')
    assert load_bundle(copy).fingerprint == before


# ── V3: dedup ─────────────────────────────────────────────────────────────────


def test_duplicate_content_is_deduplicated_with_warning(tmp_path: Path):
    records = {'evidence/1.json': _exchange(), 'evidence/2.json': _exchange(), 'evidence/3.json': _exchange(body='x')}
    loaded = load_bundle(_write_bundle(tmp_path, records))

    assert [e.source for e in loaded.evidence] == ['evidence/1.json', 'evidence/3.json']
    (warning,) = loaded.warnings
    assert warning.startswith('evidence/2.json: duplicate of evidence/1.json')


def test_same_file_listed_twice_is_deduplicated(tmp_path: Path):
    root = _write_bundle(tmp_path, {'e.json': _exchange()})
    manifest = json.loads((root / 'bundle.json').read_text())
    manifest['evidence_files'] = ['e.json', './e.json']
    (root / 'bundle.json').write_text(json.dumps(manifest))

    loaded = load_bundle(root)
    assert len(loaded.evidence) == 1
    assert len(loaded.warnings) == 1


# ── V6: suggested checks ──────────────────────────────────────────────────────


def test_unknown_suggested_checks_dropped_with_warning(tmp_path: Path):
    root = _write_bundle(tmp_path, {}, suggested_checks=['header-security', 'nope', 'version-disclosure'])
    loaded = load_bundle(root, known_checks={'header-security', 'version-disclosure'})

    assert loaded.suggested_checks == ('header-security', 'version-disclosure')
    assert loaded.warnings == ("bundle.json: suggested check 'nope' is not registered; dropped",)


def test_suggested_checks_kept_without_registry(tmp_path: Path):
    loaded = load_bundle(_write_bundle(tmp_path, {}, suggested_checks=['anything']))
    assert loaded.suggested_checks == ('anything',)
    assert loaded.warnings == ()


# ── malformed fixtures: one per failure mode ──────────────────────────────────


@pytest.mark.parametrize('case', MALFORMED, ids=[p.name for p in MALFORMED])
def test_malformed_fixture_fails_with_named_rule(case: Path):
    expected_rule = case.name.split('--')[0]
    with pytest.raises(ValidationFailed) as exc:
        load_bundle(case)
    assert _rule(exc) == expected_rule
    assert str(exc.value)


def test_every_failure_rule_has_a_fixture():
    rules = {p.name.split('--')[0] for p in MALFORMED}
    assert rules == {'bundle-parse', 'bundle-version', 'evidence-invalid', 'evidence-too-large'}


# ── V2 edge cases not worth a committed fixture ───────────────────────────────


@pytest.mark.parametrize('name', ['', 'evidence\\0001.json', 'evidence/../../x.json'])
def test_unsafe_evidence_names_rejected(tmp_path: Path, name: str):
    root = _write_bundle(tmp_path, {})
    (root / 'bundle.json').write_text(
        json.dumps(json.loads((root / 'bundle.json').read_text()) | {'evidence_files': [name]})
    )
    with pytest.raises(ValidationFailed) as exc:
        load_bundle(root)
    assert _rule(exc) == 'evidence-invalid'


def test_evidence_path_that_is_a_directory_rejected(tmp_path: Path):
    root = _write_bundle(tmp_path, {})
    (root / 'evidence').mkdir()
    (root / 'bundle.json').write_text(
        json.dumps(json.loads((root / 'bundle.json').read_text()) | {'evidence_files': ['evidence']})
    )
    with pytest.raises(ValidationFailed, match='not a regular file') as exc:
        load_bundle(root)
    assert _rule(exc) == 'evidence-invalid'


def test_symlink_inside_bundle_is_allowed(tmp_path: Path):
    root = _write_bundle(tmp_path, {'real/e.json': _exchange()})
    (root / 'link.json').symlink_to(root / 'real' / 'e.json')
    manifest = json.loads((root / 'bundle.json').read_text()) | {'evidence_files': ['link.json']}
    (root / 'bundle.json').write_text(json.dumps(manifest))
    assert load_bundle(root).evidence[0].source == 'link.json'


def test_bool_schema_version_rejected(tmp_path: Path):
    root = _write_bundle(tmp_path, {}, schema_version=True)
    with pytest.raises(ValidationFailed) as exc:
        load_bundle(root)
    assert _rule(exc) == 'bundle-version'


def test_missing_bundle_directory(tmp_path: Path):
    with pytest.raises(ValidationFailed, match='manifest not found') as exc:
        load_bundle(tmp_path / 'nope')
    assert _rule(exc) == 'bundle-parse'


# ── V4: caps ──────────────────────────────────────────────────────────────────


def test_body_at_cap_is_accepted(tmp_path: Path):
    loaded = load_bundle(_write_bundle(tmp_path, {'e.json': _exchange(body='a' * MAX_CONTENT_BYTES)}))
    assert len(loaded.evidence) == 1


@pytest.mark.parametrize(
    'record',
    [
        pytest.param(_exchange(body='a' * (MAX_CONTENT_BYTES + 1)), id='response-body'),
        pytest.param(_exchange(body='é' * (MAX_CONTENT_BYTES // 2 + 1)), id='response-body-utf8-bytes'),
        pytest.param(
            _exchange()
            | {
                'http': _exchange()['http']
                | {'request': _exchange()['http']['request'] | {'body': 'a' * (MAX_CONTENT_BYTES + 1)}}
            },
            id='request-body',
        ),
        pytest.param(_exchange(url='https://app.example.test/' + 'a' * MAX_URL_BYTES), id='url'),
        pytest.param(_exchange(headers=[[f'X-{i}', 'v'] for i in range(MAX_HEADERS + 1)]), id='response-headers'),
        pytest.param(
            {
                'kind': 'config_excerpt',
                'config': {'path': 'big.conf', 'format': 'config', 'content': 'a' * (MAX_CONTENT_BYTES + 1)},
            },
            id='config-excerpt',
        ),
    ],
)
def test_content_caps(tmp_path: Path, record: dict[str, Any]):
    with pytest.raises(ValidationFailed) as exc:
        load_bundle(_write_bundle(tmp_path, {'e.json': record}))
    assert _rule(exc) == 'evidence-too-large'


def test_request_header_cap(tmp_path: Path):
    record = _exchange()
    record['http']['request']['headers'] = [[f'X-{i}', 'v'] for i in range(MAX_HEADERS + 1)]
    with pytest.raises(ValidationFailed, match='request has') as exc:
        load_bundle(_write_bundle(tmp_path, {'e.json': record}))
    assert _rule(exc) == 'evidence-too-large'


def test_oversized_evidence_file_refused_before_parsing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(bundle_module, 'MAX_EVIDENCE_FILE_BYTES', 64)
    root = _write_bundle(tmp_path, {'e.json': b'x' * 65})  # not even JSON: size is checked first
    with pytest.raises(ValidationFailed) as exc:
        load_bundle(root)
    assert _rule(exc) == 'evidence-too-large'
    assert MAX_EVIDENCE_FILE_BYTES > MAX_CONTENT_BYTES


def test_oversized_manifest_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(bundle_module, 'MAX_MANIFEST_BYTES', 16)
    with pytest.raises(ValidationFailed) as exc:
        load_bundle(_write_bundle(tmp_path, {}))
    assert _rule(exc) == 'evidence-too-large'
    assert MAX_MANIFEST_BYTES >= 1024
