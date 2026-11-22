"""HAR import and bundle export — the MITM-free capture round-trip (issue #28; DEPS.md §3.6).

Both directions are exercised end to end against hermetic fixtures: the committed
``fixtures/har/fixture.har`` imports into a bundle whose ``header-security`` review reproduces
the review of ``fixtures/bundles/valid`` (same evidence IDs → same findings), and a live ``test``
run against the fixture app exports into a bundle that reviews cleanly. Drops, caps, secret
marking, determinism and CLI exit codes are pinned inline; no network beyond loopback, no model.
"""

import base64
import json
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from partex import cli, engine
from partex.bundle import MANIFEST_NAME, load_bundle
from partex.engine import ReviewResult, run_review, run_test
from partex.errors import PartexError, ValidationFailed
from partex.export import IncludeSecretsWarning
from partex.har_io import export_bundle, import_har
from partex.ids import evidence_id
from partex.models import (
    ConfigEvidence,
    ConfigExcerpt,
    Headers,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
    Scope,
)
from partex.storage import RunStore

FIXTURES = Path(__file__).parent.parent / 'fixtures'
FIXTURE_HAR = FIXTURES / 'har' / 'fixture.har'
VALID_BUNDLE = FIXTURES / 'bundles' / 'valid'
SECRET = 'Bearer har-test-secret-token'
FINDING_FIELDS = ('id', 'check_id', 'severity', 'subject', 'title', 'status')


# ── helpers ───────────────────────────────────────────────────────────────────


def write_har(path: Path, entries: Sequence[dict[str, Any]]) -> Path:
    """Write a minimal but spec-shaped HAR with *entries*."""
    path.write_text(
        json.dumps(
            {
                'log': {
                    'version': '1.2',
                    'creator': {'name': 'test', 'version': '1'},
                    'entries': list(entries),
                }
            }
        )
    )
    return path


def har_entry(
    url: str,
    *,
    method: str = 'GET',
    request_headers: Headers | None = None,
    status: int = 200,
    response_headers: Headers | None = None,
    content: dict[str, Any] | None = None,
    post_data: str | None = None,
) -> dict[str, Any]:
    """One spec-shaped HAR entry; header pairs become ``{name, value}`` objects."""
    request: dict[str, Any] = {
        'method': method,
        'url': url,
        'httpVersion': 'HTTP/1.1',
        'headers': [{'name': name, 'value': value} for name, value in (request_headers or [])],
        'queryString': [],
        'headersSize': -1,
        'bodySize': 0,
    }
    if post_data is not None:
        request['postData'] = {'mimeType': 'text/plain', 'text': post_data}
    response: dict[str, Any] = {
        'status': status,
        'statusText': 'OK',
        'httpVersion': 'HTTP/1.1',
        'headers': [{'name': name, 'value': value} for name, value in (response_headers or [])],
        'content': {} if content is None else content,
        'redirectURL': '',
        'headersSize': -1,
        'bodySize': 0,
    }
    return {'request': request, 'response': response, 'cache': {}, 'timings': {}}


def bundle_files(root: Path) -> dict[str, bytes]:
    """Every file of a written bundle, relative paths → bytes."""
    return {str(path.relative_to(root)): path.read_bytes() for path in sorted(root.rglob('*')) if path.is_file()}


def finding_rows(result: ReviewResult) -> list[tuple[Any, ...]]:
    return [tuple(getattr(finding, field) for field in FINDING_FIELDS) for finding in result.findings]


def make_evidence(
    url: str = 'https://app.example.test/',
    *,
    status: int = 200,
    headers: Headers | None = None,
    secret_headers: bool = False,
) -> HttpEvidence:
    """One HTTP evidence record, as the live client would commit it."""
    request_headers: Headers = [('Host', urllib.parse.urlsplit(url).hostname or 'app.example.test')]
    response_headers: Headers = headers or [('Content-Type', 'text/html; charset=utf-8')]
    if secret_headers:
        request_headers = [('Cookie', f'session={SECRET}'), *request_headers]
        response_headers = [('Set-Cookie', f'sid={SECRET}; Path=/'), *response_headers]
    evidence = HttpEvidence(
        id='',
        source='capture:test',
        http=HttpExchange(
            request=HttpRequest(method='GET', url=url, headers=request_headers),
            response=HttpResponse(status_code=status, headers=response_headers, body='<html></html>'),
        ),
        secret_fields=[] if not secret_headers else ['$.http.request.headers[0][1]', '$.http.response.headers[0][1]'],
    )
    return evidence.model_copy(update={'id': evidence_id(evidence)})


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / 'store' / 'partex.db'


# ── import: the fixture round-trip (DEPS.md §3.6) ─────────────────────────────


def test_import_fixture_har_produces_the_valid_bundle_evidence(tmp_path: Path) -> None:
    """The committed HAR imports into a bundle whose HTTP evidence matches fixtures/bundles/valid."""
    out = tmp_path / 'bundle'
    result = import_har(FIXTURE_HAR, out)
    assert result.evidence_count == 5
    assert result.dropped_out_of_scope == 1
    assert result.dropped_hosts == {'cdn.example.test': 1}
    assert result.base_url == 'https://app.example.test'

    loaded = load_bundle(out)
    assert len(loaded.evidence) == 5
    assert not loaded.warnings  # the cdn entry was already dropped at import, not deduped later
    valid = load_bundle(VALID_BUNDLE)
    assert all(isinstance(item, HttpEvidence) for item in loaded.evidence)
    imported_ids = {item.id for item in loaded.evidence if isinstance(item, HttpEvidence)}
    assert imported_ids
    valid_ids = {item.id for item in valid.evidence if isinstance(item, HttpEvidence)}
    assert imported_ids == valid_ids

    manifest = json.loads((out / MANIFEST_NAME).read_text())
    assert manifest['target']['name'] == 'app.example.test'
    assert 'cdn.example.test 1' in manifest['target']['notes']


def test_import_is_deterministic(tmp_path: Path) -> None:
    """Same (HAR, inferred target) → byte-identical bundle."""
    first, second = tmp_path / 'a', tmp_path / 'b'
    import_har(FIXTURE_HAR, first)
    import_har(FIXTURE_HAR, second)
    assert bundle_files(first) == bundle_files(second)


def test_explicit_target_overrides_the_inferred_one(tmp_path: Path) -> None:
    """``--target`` keeps only the entries at that origin; the app host becomes the drop histogram."""
    har = write_har(
        tmp_path / 'capture.har',
        [har_entry('https://app.example.test/'), har_entry('https://cdn.example.test/lib.js')],
    )
    out = tmp_path / 'bundle'
    result = import_har(har, out, target='https://cdn.example.test')
    assert result.evidence_count == 1
    assert result.dropped_out_of_scope == 1
    assert result.dropped_hosts == {'app.example.test': 1}
    loaded = load_bundle(out)
    assert all(isinstance(item, HttpEvidence) for item in loaded.evidence)
    assert [item.http.request.url for item in loaded.evidence if isinstance(item, HttpEvidence)] == [
        'https://cdn.example.test/lib.js'
    ]


def test_import_errors(tmp_path: Path) -> None:
    missing = tmp_path / 'nope.har'
    with pytest.raises(ValidationFailed, match='not found'):
        import_har(missing, tmp_path / 'b1')

    bad_json = tmp_path / 'bad.har'
    bad_json.write_text('not json')
    with pytest.raises(ValidationFailed, match='invalid HAR'):
        import_har(bad_json, tmp_path / 'b2')

    no_entries = tmp_path / 'no-entries.har'
    no_entries.write_text(json.dumps({'log': {'version': '1.2'}}))
    with pytest.raises(ValidationFailed, match='log.entries must be a list'):
        import_har(no_entries, tmp_path / 'b3')

    bad_entry = write_har(tmp_path / 'bad-entry.har', [{'request': {'method': 'GET'}}])
    with pytest.raises(ValidationFailed, match='entry 0'):
        import_har(bad_entry, tmp_path / 'b4')

    foreign = write_har(
        tmp_path / 'foreign.har',
        [har_entry('https://other.example.test/'), har_entry('https://more.example.test/x')],
    )
    with pytest.raises(ValidationFailed, match='no in-scope'):
        import_har(foreign, tmp_path / 'b5', target='https://app.example.test')
    # Without an explicit target the most frequent origin wins, so the import succeeds instead.
    assert import_har(foreign, tmp_path / 'b5b').evidence_count == 1

    unusable_target = write_har(tmp_path / 'unusable.har', [har_entry('https://app.example.test/')])
    with pytest.raises(ValidationFailed, match='no usable target'):
        import_har(unusable_target, tmp_path / 'b6', target='ftp://app.example.test/')


def test_import_body_and_cap_handling(tmp_path: Path) -> None:
    """base64 decodes, binaries refuse, oversize truncates, cap breakers drop with a count."""
    plain = har_entry('https://app.example.test/a', content={'text': 'hello'})
    b64 = har_entry(
        'https://app.example.test/b64',
        content={'encoding': 'base64', 'text': base64.b64encode('grüß'.encode()).decode()},
    )
    binary = har_entry(
        'https://app.example.test/bin',
        content={'encoding': 'base64', 'text': base64.b64encode(bytes([0, 159, 146, 150])).decode()},
    )
    truncated = har_entry('https://app.example.test/big', content={'text': 'x' * (256 * 1024 + 1)})
    long_url = har_entry('https://app.example.test/' + 'a' * (64 * 1024 + 1))
    many_headers = har_entry(
        'https://app.example.test/headers', response_headers=[(f'X-H{i}', 'v') for i in range(101)]
    )
    har = write_har(tmp_path / 'bodies.har', [plain, b64, binary, truncated, long_url, many_headers])
    result = import_har(har, tmp_path / 'bundle')
    assert result.evidence_count == 4  # plain, b64, binary, truncated
    assert result.dropped_oversize == 2  # long_url, many_headers
    loaded = load_bundle(tmp_path / 'bundle')
    by_url = {item.http.request.url: item for item in loaded.evidence if isinstance(item, HttpEvidence)}
    assert by_url['https://app.example.test/a'].http.response.body == 'hello'
    assert by_url['https://app.example.test/b64'].http.response.body == 'grüß'
    assert by_url['https://app.example.test/bin'].http.response.body is None
    assert by_url['https://app.example.test/bin'].http.response.body_note == 'refused'
    assert by_url['https://app.example.test/big'].http.response.body_note == 'truncated'
    assert len(by_url['https://app.example.test/big'].http.response.body.encode()) == 256 * 1024  # pyright: ignore[reportOptionalMemberAccess]


def test_import_marks_credential_headers_secret(tmp_path: Path) -> None:
    """Import blanket-marks request Cookie/Authorization and response Set-Cookie values."""
    har = write_har(
        tmp_path / 'creds.har',
        [
            har_entry(
                'https://app.example.test/',
                request_headers=[
                    ('Cookie', f'session={SECRET}'),
                    ('Authorization', SECRET),
                ],
                response_headers=[('Set-Cookie', f'sid={SECRET}; Path=/; Secure'), ('X-Info', 'fine')],
            )
        ],
    )
    out = tmp_path / 'bundle'
    import_har(har, out)
    record = json.loads((out / 'evidence' / '0001.json').read_text())
    assert record['secret_fields'] == [
        '$.http.request.headers[0][1]',
        '$.http.request.headers[1][1]',
        '$.http.response.headers[0][1]',
    ]
    load_bundle(out)  # paths resolve (V2): a bad marking would fail validation


# ── import → review: the round-trip experiment ───────────────────────────────


async def test_imported_har_review_reproduces_valid_bundle_findings(tmp_store: RunStore, tmp_path: Path) -> None:
    """review(import(fixture.har)) == review(fixtures/bundles/valid) for header-security."""
    imported = tmp_path / 'imported-bundle'
    import_har(FIXTURE_HAR, imported)
    original = await run_review(VALID_BUNDLE, tmp_store, ['header-security'])
    replayed = await run_review(imported, tmp_store, ['header-security'])
    assert original.state == 'checks_complete'
    assert replayed.state == 'checks_complete'
    assert finding_rows(replayed) == finding_rows(original)


# ── export ─────────────────────────────────────────────────────────────────────


async def test_export_redacts_by_default_and_optin_warns(tmp_store: RunStore, tmp_path: Path) -> None:
    run_id = await tmp_store.create_run(
        input_kind='engagement',
        input_ref='engagement.json',
        input_sha256='',
        engine_version=engine.engine_version(),
        selected_checks=('header-security',),
        scope_snapshot=Scope(hosts=['app.example.test'], ports=[]),
    )
    await tmp_store.add_evidence(run_id, make_evidence(secret_headers=True))
    await tmp_store.set_state(run_id, 'checks_complete')

    redacted = tmp_path / 'redacted'
    await export_bundle(tmp_store, run_id, redacted)
    record = json.loads((redacted / 'evidence' / '0001.json').read_text())
    assert SECRET not in json.dumps(record)
    assert '<redacted>' in record['http']['request']['headers'][0][1]
    assert record['http']['response']['headers'][0][1] == 'sid=<redacted>; Path=/'
    assert record['secret_fields']  # the markers stay, so future exports stay redact-on-export

    raw = tmp_path / 'raw'
    with pytest.warns(IncludeSecretsWarning, match='include_secrets=True'):
        await export_bundle(tmp_store, run_id, raw, include_secrets=True)
    raw_record = json.loads((raw / 'evidence' / '0001.json').read_text())
    assert SECRET in json.dumps(raw_record)


async def test_export_derives_target_and_is_deterministic(tmp_store: RunStore, tmp_path: Path) -> None:
    run_id = await tmp_store.create_run(
        input_kind='engagement',
        input_ref='engagement.json',
        input_sha256='',
        engine_version=engine.engine_version(),
        selected_checks=('header-security',),
        scope_snapshot=Scope(hosts=['app.example.test'], ports=[]),
    )
    await tmp_store.add_evidence(run_id, make_evidence('https://app.example.test/deep/path'))
    await tmp_store.set_state(run_id, 'checks_complete')

    first, second = tmp_path / 'a', tmp_path / 'b'
    result = await export_bundle(tmp_store, run_id, first)
    await export_bundle(tmp_store, run_id, second)
    assert result.target_name == 'app.example.test'
    assert result.base_url == 'https://app.example.test'
    assert bundle_files(first) == bundle_files(second)
    manifest = json.loads((first / MANIFEST_NAME).read_text())
    assert manifest['target'] == {
        'name': 'app.example.test',
        'base_url': 'https://app.example.test',
        'notes': f'exported from run {run_id}',
    }


async def test_export_errors(tmp_store: RunStore, tmp_path: Path) -> None:
    with pytest.raises(PartexError, match='not found') as excinfo:
        await export_bundle(tmp_store, 'run_does_not_exist', tmp_path / 'b1')
    assert excinfo.value.rule_code == 'run-not-found'

    empty = await tmp_store.create_run(
        input_kind='engagement',
        input_ref='engagement.json',
        input_sha256='',
        engine_version=engine.engine_version(),
        selected_checks=(),
    )
    with pytest.raises(ValidationFailed, match='no evidence'):
        await export_bundle(tmp_store, empty, tmp_path / 'b2')

    config_only = await tmp_store.create_run(
        input_kind='bundle',
        input_ref='bundle.json',
        input_sha256='',
        engine_version=engine.engine_version(),
        selected_checks=(),
    )
    config = ConfigEvidence(
        id='',
        source='evidence/0001.json',
        config=ConfigExcerpt(path='/api', format='openapi', content='{"openapi": "3.0.0"}'),
    )
    await tmp_store.add_evidence(config_only, config.model_copy(update={'id': evidence_id(config)}))
    with pytest.raises(ValidationFailed, match='no HTTP evidence'):
        await export_bundle(tmp_store, config_only, tmp_path / 'b3')


# ── live round-trip: test → export-bundle → review ────────────────────────────


async def test_live_run_exports_to_a_reviewable_bundle(target_app: object, tmp_store: RunStore, tmp_path: Path) -> None:
    """Live test on the fixture app → export-bundle → passive review over the captures."""
    base_url = target_app.base_url  # pyright: ignore[reportAttributeAccessIssue]
    port = target_app.port  # pyright: ignore[reportAttributeAccessIssue]
    engagement = tmp_path / 'engagement'
    engagement.mkdir()
    (engagement / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'fixture-app', 'base_url': base_url},
                'scope': {
                    'hosts': ['127.0.0.1'],
                    'path_prefixes': ['/'],
                    'exclusions': ['/admin/shutdown'],
                    'ports': [port],
                    'max_rps': 64,
                    'max_requests': 100,
                },
                'authorization': {
                    'attestation': 'local fixture app on loopback',
                    'operator': 'test',
                },
                'suggested_checks': ['version-disclosure'],
            }
        )
    )
    live = await run_test(engagement, tmp_store, ['version-disclosure'], authorized=True)
    assert live.state == 'checks_complete'
    assert live.evidence_count > 0

    exported = tmp_path / 'exported-bundle'
    export = await export_bundle(tmp_store, live.run_id, exported)
    assert export.evidence_count == live.evidence_count
    assert export.base_url == base_url
    assert export.target_name == '127.0.0.1'

    reviewed = await run_review(exported, tmp_store, ['header-security'])
    assert reviewed.state == 'checks_complete'
    assert finding_rows(reviewed), 'the fixture app has no security headers; review must flag that'


# ── CLI exit codes ─────────────────────────────────────────────────────────────


def test_cli_import_har(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _err = _run_cli(capsys, 'import-har', str(FIXTURE_HAR), '--out', str(tmp_path / 'bundle'))
    assert code == 0
    payload = json.loads(out)
    assert payload['evidence_count'] == 5
    assert payload['dropped_hosts'] == {'cdn.example.test': 1}

    bad = tmp_path / 'bad.har'
    bad.write_text('not json')
    code, _out, err = _run_cli(capsys, 'import-har', str(bad), '--out', str(tmp_path / 'b2'))
    assert code == 1
    assert 'partex: har-parse' in err


def test_cli_export_bundle(capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path) -> None:
    async def seed() -> str:
        async with await RunStore.open(db) as store:
            run_id = await store.create_run(
                input_kind='engagement',
                input_ref='engagement.json',
                input_sha256='',
                engine_version=engine.engine_version(),
                selected_checks=(),
                scope_snapshot=Scope(hosts=['app.example.test'], ports=[]),
            )
            await store.add_evidence(run_id, make_evidence())
            await store.set_state(run_id, 'checks_complete')
            return run_id

    import anyio

    run_id = anyio.run(seed)
    out = tmp_path / 'bundle'
    code, captured, _err = _run_cli(capsys, 'export-bundle', run_id, '--db', str(db), '--out', str(out))
    assert code == 0
    assert json.loads(captured)['evidence_count'] == 1

    code, _out, err = _run_cli(capsys, 'export-bundle', 'run_missing', '--db', str(db), '--out', str(out))
    assert code == 1
    assert 'partex:' in err


def _run_cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    """Run one CLI command in-process; capsys keeps stdout a non-TTY (JSON output)."""
    try:
        code = cli.main(list(argv))
    except SystemExit as exc:
        assert isinstance(exc.code, int)
        code = exc.code
    captured = capsys.readouterr()
    return code, captured.out, captured.err
