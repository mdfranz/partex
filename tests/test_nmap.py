"""nmap ``-oX`` import as authorized-URL-list entries — issue #215; PLAN §4.2 (#121).

The converter is pure, so most of it is tested against the synthetic scan fixtures under
``fixtures/nmap/``; the ``/scope nmap`` plugin staging and the CLI run against the loopback
target server. Nothing here opens a socket off loopback or calls a model.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from partex.agent_adapter.scope_plugin import ScopeControl
from partex.cli import main as cli_main
from partex.engine import live_session, probe_url_entries, run_test
from partex.errors import BudgetExhausted, PartexError, ScopeViolation
from partex.nmap import ScanSource, convert_nmap, ensure_base_url_entry, parse_nmap_xml
from partex.scope import parse_urls_file
from partex.storage import RunStore

pytest_plugins = ['plugins.target_server']

FIXTURES = Path(__file__).parent.parent / 'fixtures' / 'nmap'

# fixtures/nmap/version.xml in entry order (dual-stack host: one entry set per scanned address).
VERSION_ENTRIES = [
    'http://192.168.1.29:80/*',
    'http://[2001:db8::5]:80/*',
    'https://192.168.1.29:443/*',
    'https://[2001:db8::5]:443/*',
    'http://192.168.1.29:8080/*',  # http-alt is an HTTP service name
    'http://[2001:db8::5]:8080/*',
    'https://192.168.1.29:8081/*',  # tunnel="ssl" promotes an HTTP service to https
    'https://[2001:db8::5]:8081/*',
]


# ── converter ─────────────────────────────────────────────────────────────────


def test_sweep_imports_open_http_ports_and_skips_the_rest() -> None:
    imported = convert_nmap([FIXTURES / 'sweep.xml'])
    assert imported.entries == [
        'http://192.168.1.29:80/*',
        'https://192.168.1.29:443/*',  # no -sV: only the scheme defaults import
    ]
    assert imported.hosts == ['192.168.1.29']
    assert any('tcp/22 ssh' in note and 'not an HTTP(S) service' in note for note in imported.skipped)
    assert any('192.168.1.1 up but no HTTP(S) port open' in note for note in imported.skipped)
    assert all('192.168.1.2' not in note for note in imported.skipped)  # down host: not even a note
    raw = (FIXTURES / 'sweep.xml').read_bytes()
    assert imported.sources == [ScanSource(path=str(FIXTURES / 'sweep.xml'), sha256=hashlib.sha256(raw).hexdigest())]


def test_version_pass_resolves_schemes_and_skips_non_http() -> None:
    imported = convert_nmap([FIXTURES / 'version.xml'])
    assert imported.entries == VERSION_ENTRIES
    assert imported.hosts == ['192.168.1.29', '2001:db8::5']
    assert any('tcp/8000 http-alt?' in note for note in imported.skipped)  # near-miss name: not in the set


def test_tunnel_on_a_non_http_service_imports_nothing() -> None:
    """Real scans carry tunnel="ssl" on ajp13/xmpp ports; those are not HTTP targets."""
    entries, skipped = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="8009"><state state="open"/>'
        '<service name="ajp13" tunnel="ssl"/></port></ports></host></nmaprun>',
        source='scan.xml',
    )
    assert entries == []
    assert any('tcp/8009 ajp13' in note for note in skipped)


def test_scans_merge_deduped_first_seen() -> None:
    merged = convert_nmap([FIXTURES / 'sweep.xml', FIXTURES / 'version.xml'])
    # The sweep's two entries come first; the version pass adds only what the sweep missed, in its own order.
    assert merged.entries == [
        'http://192.168.1.29:80/*',
        'https://192.168.1.29:443/*',
        'http://[2001:db8::5]:80/*',
        'https://[2001:db8::5]:443/*',
        'http://192.168.1.29:8080/*',
        'http://[2001:db8::5]:8080/*',
        'https://192.168.1.29:8081/*',
        'https://[2001:db8::5]:8081/*',
    ]
    assert len(merged.sources) == 2


def test_use_hostnames_swaps_the_scanned_ip_for_the_ptr_name() -> None:
    imported = convert_nmap([FIXTURES / 'sweep.xml'], use_hostnames=True)
    assert imported.entries == ['http://app.local:80/*', 'https://app.local:443/*']
    assert imported.hosts == ['app.local']


@pytest.mark.parametrize(
    'xml',
    [
        '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun>&xxe;</nmaprun>',
        '<?xml version="1.0"?><!DOCTYPE nmaprun PUBLIC "-//x//y" "http://evil.test/d.dtd"><nmaprun/>',
    ],
)
def test_entity_and_external_dtd_refused(xml: str) -> None:
    # Either refusal is fine: the converter's own guard, or stdlib XML refusing the undefined
    # entity at parse time — both fail closed before anything is imported.
    with pytest.raises(PartexError, match='billion-laughs|does not parse'):
        parse_nmap_xml(xml, source='scan.xml')


def test_non_nmaprun_root_and_unparseable_refused() -> None:
    with pytest.raises(PartexError, match='expected "nmaprun"'):
        parse_nmap_xml('<other/>', source='scan.xml')
    with pytest.raises(PartexError, match='does not parse'):
        parse_nmap_xml('<nmaprun>', source='scan.xml')


def test_missing_and_empty_results_refused(tmp_path: Path) -> None:
    with pytest.raises(PartexError, match='cannot read'):
        convert_nmap([tmp_path / 'nope.xml'])
    down_only = tmp_path / 'down.xml'
    down_only.write_text(
        '<nmaprun><host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>',
        encoding='utf-8',
    )
    with pytest.raises(PartexError, match='no importable targets'):
        convert_nmap([down_only])


def test_oversize_scan_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import partex.nmap

    big = tmp_path / 'big.xml'
    big.write_bytes(b'0' * 64)
    monkeypatch.setattr(partex.nmap, 'MAX_NMAP_BYTES', 8)
    with pytest.raises(PartexError, match='over the'):
        partex.nmap.convert_nmap([big])


def test_ensure_base_url_entry_prepends_only_when_uncovered() -> None:
    covered = ensure_base_url_entry(['http://10.0.0.5:80/*'], 'http://10.0.0.5/home')
    assert covered == ['http://10.0.0.5:80/*']
    uncovered = ensure_base_url_entry(['http://10.0.0.5:80/*'], 'http://10.0.0.6:8080/home')
    assert uncovered == ['http://10.0.0.6:8080/home/*', 'http://10.0.0.5:80/*']


def test_written_file_round_trips_through_the_urls_file_parser() -> None:
    imported = convert_nmap([FIXTURES / 'sweep.xml'])
    text = '\n'.join(imported.as_lines())
    assert '# source:' in text and 'sha256' in text  # the provenance rides along as comments
    assert parse_urls_file(text) == imported.entries  # what --urls-file accepts is what was reviewed


# ── CLI ───────────────────────────────────────────────────────────────────────


def test_cli_nmap_prints_json_off_tty(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(['nmap', str(FIXTURES / 'sweep.xml')]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['entries'] == ['http://192.168.1.29:80/*', 'https://192.168.1.29:443/*']
    assert payload['hosts'] == ['192.168.1.29']
    assert payload['sources'][0]['sha256'] == hashlib.sha256((FIXTURES / 'sweep.xml').read_bytes()).hexdigest()


def test_cli_nmap_writes_an_urls_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / 'targets.txt'
    assert cli_main(['nmap', str(FIXTURES / 'sweep.xml'), '--out', str(out)]) == 0
    capsys.readouterr()
    written = out.read_text(encoding='utf-8')
    assert parse_urls_file(written) == ['http://192.168.1.29:80/*', 'https://192.168.1.29:443/*']
    assert f'# source: {FIXTURES / "sweep.xml"}' in written


def test_cli_nmap_failures_exit_fatal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(['nmap', str(tmp_path / 'nope.xml')]) == 1
    assert 'nmap-invalid' in capsys.readouterr().err
    down_only = tmp_path / 'down.xml'
    down_only.write_text('<nmaprun><host><status state="down"/></host></nmaprun>', encoding='utf-8')
    assert cli_main(['nmap', str(down_only)]) == 1
    assert 'nmap-invalid' in capsys.readouterr().err


# ── /scope nmap plugin (operator-only, stage → confirm) ────────────────────────


def engagement_dir(tmp_path: Path, server: Any) -> Path:
    directory = tmp_path / 'engagement'
    directory.mkdir()
    (directory / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'fixture', 'base_url': server.base_url},
                'scope': {
                    'hosts': ['127.0.0.1'],
                    'path_prefixes': ['/'],
                    'ports': [server.port],
                    'max_rps': 64,
                    'max_requests': 100,
                },
                'authorization': {'attestation': 'local fixture on loopback', 'operator': 'test'},
            }
        ),
        encoding='utf-8',
    )
    return directory


def scan_file(path: Path, host: str, port: int, *, service: str | None = 'http') -> Path:
    service_el = f'<service name="{service}"/>' if service else ''
    path.write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
        f'<nmaprun scanner="nmap" args="nmap -oX scan.xml {host}" start="1795370878" version="7.98" '
        f'xmloutputversion="1.05"><host><status state="up"/><address addr="{host}" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>{service_el}</port></ports>'
        f'</host></nmaprun>',
        encoding='utf-8',
    )
    return path


async def test_scope_nmap_stages_nothing_then_confirm_applies_and_audits(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    scan = scan_file(tmp_path / 'scan.xml', '127.0.0.1', target_server.port)
    async with live_session(engagement_dir(tmp_path, target_server), tmp_store, authorized=True, checks=()) as session:
        control = ScopeControl(session)
        staged = await control.handle(['nmap', str(scan)])
        assert f'+ url http://127.0.0.1:{target_server.port}/*' in staged
        assert 'Not in effect yet' in staged
        assert session.engagement.scope.urls == []  # staged changes nothing
        assert not [c for c in await tmp_store.tool_calls(session.run_id) if c.tool == 'scope_amend']

        confirmed = await control.handle(['confirm'])
        assert 'Imported 1 URL entries' in confirmed and str(scan) in confirmed
        assert session.engagement.scope.urls == [f'http://127.0.0.1:{target_server.port}/*']
        assert (await tmp_store.get_run(session.run_id)).scope_snapshot is not None

        evidence = await session.request('GET', f'{target_server.base_url}/anything')  # base target stays reachable
        assert evidence.http.response.status_code == 200

        with pytest.raises(ScopeViolation) as refused:  # port 80 joined scope.ports, but not the import
            await session.request('GET', 'http://127.0.0.1:80/')
        assert refused.value.kind == 'url-list'

        calls = [c for c in await tmp_store.tool_calls(session.run_id) if c.tool == 'scope_amend']
        assert len(calls) == 1  # one atomic amendment for the whole batch
        assert calls[0].args['action'] == 'import'
        assert calls[0].args['source'] == str(scan)
        assert calls[0].args['source_sha256'] == hashlib.sha256(scan.read_bytes()).hexdigest()
        assert calls[0].result['urls_after'] == 1


async def test_scope_nmap_keeps_the_baseline_target_reachable_when_activating_a_list(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    scan = scan_file(tmp_path / 'scan.xml', '10.0.0.5', 80)
    async with live_session(engagement_dir(tmp_path, target_server), tmp_store, authorized=True, checks=()) as session:
        control = ScopeControl(session)
        assert 'Not in effect yet' in await control.handle(['nmap', str(scan)])
        await control.handle(['confirm'])
        assert session.engagement.scope.urls == [
            f'http://127.0.0.1:{target_server.port}/*',  # prepended: the baseline target stays requestable
            'http://10.0.0.5:80/*',
        ]
        evidence = await session.request('GET', target_server.base_url)
        assert evidence.http.response.status_code == 200


async def test_scope_nmap_cancel_drop_and_refusals(target_server: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    async with live_session(engagement_dir(tmp_path, target_server), tmp_store, authorized=True, checks=()) as session:
        control = ScopeControl(session)
        assert 'Refused' in await control.handle(['nmap', str(tmp_path / 'missing.xml')])
        evil = tmp_path / 'evil.xml'
        evil.write_text(
            '<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/shadow">]><nmaprun>&x;</nmaprun>', encoding='utf-8'
        )
        assert 'Refused' in await control.handle(['nmap', str(evil)])

        scan = scan_file(tmp_path / 'scan.xml', '10.0.0.5', 80)
        assert 'Not in effect yet' in await control.handle(['nmap', str(scan)])
        assert 'Pending import (not in effect)' in await control.handle([])  # show() names the staged batch
        assert 'dropped' in await control.handle(['cancel'])
        assert 'Nothing pending' in await control.handle(['confirm'])
        assert session.engagement.scope.urls == []
        assert not [c for c in await tmp_store.tool_calls(session.run_id) if c.tool == 'scope_amend']


async def test_scope_nmap_already_listed_is_a_noop(target_server: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    directory = engagement_dir(tmp_path, target_server)
    manifest = json.loads((directory / 'engagement.json').read_text(encoding='utf-8'))
    manifest['scope']['urls'] = [f'http://127.0.0.1:{target_server.port}/*']
    (directory / 'engagement.json').write_text(json.dumps(manifest), encoding='utf-8')
    scan = scan_file(tmp_path / 'scan.xml', '127.0.0.1', target_server.port)
    async with live_session(directory, tmp_store, authorized=True, checks=()) as session:
        control = ScopeControl(session)
        staged = await control.handle(['nmap', str(scan)])
        assert 'already in the authorized URL list' in staged
        assert 'Nothing pending' in await control.handle(['confirm'])
        assert session.engagement.scope.urls == [f'http://127.0.0.1:{target_server.port}/*']
        assert not [c for c in await tmp_store.tool_calls(session.run_id) if c.tool == 'scope_amend']


# ── initial probe pass: one GET per listed entry at startup (#215) ─────────────


async def test_probe_pass_probes_each_entry_once_skipping_the_baseline(
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []

    async def request(url: str) -> object:
        calls.append(url)
        return object()

    probed, failed, unprobed = await probe_url_entries(
        request,
        entries=['http://h.test/', 'http://h.test/x', 'http://b.test:9/*', 'http://b.test:9/*'],
        base_url='http://h.test/',
    )
    assert calls == ['http://h.test/x', 'http://b.test:9']  # the baseline capture covers entry 1; duplicates collapse
    assert (probed, failed, unprobed) == (2, 0, 0)
    assert 'initial probe' in capsys.readouterr().err


async def test_probe_pass_tolerates_dead_hosts_and_stops_cleanly_at_the_budget(
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []

    async def request(url: str) -> object:
        calls.append(url)
        if url == 'http://dead.test:9':
            raise PartexError('request to http://dead.test:9 failed: connection refused')
        if url == 'http://last.test/':
            raise BudgetExhausted('max_requests budget (1) exhausted')
        return object()

    probed, failed, unprobed = await probe_url_entries(
        request,
        entries=['http://ok.test/x', 'http://dead.test:9/*', 'http://last.test/', 'http://never.test/x'],
        base_url='http://base.test/',
    )
    assert calls == ['http://ok.test/x', 'http://dead.test:9', 'http://last.test/']  # stopped at the budget
    assert (probed, failed, unprobed) == (1, 1, 2)  # never.test left unprobed, never a run failure
    assert 'unprobed' in capsys.readouterr().err


async def test_probe_pass_with_only_the_baseline_probes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    async def request(url: str) -> object:
        raise AssertionError(f'nothing should be probed, got {url}')

    assert await probe_url_entries(request, entries=['http://h.test/'], base_url='http://h.test/') == (0, 0, 0)
    assert capsys.readouterr().err == ''


async def test_probe_pass_shows_live_lines_on_a_terminal(capsys: pytest.CaptureFixture[str]) -> None:
    """The pass can take minutes at the rate limit; a blank terminal reads as a hang (#215)."""

    async def request(url: str) -> object:
        if url == 'http://dead.test:9':
            raise PartexError('request to http://dead.test:9 failed: connection refused')
        return object()

    _, failed, _ = await probe_url_entries(
        request,
        entries=['http://ok.test/', 'http://dead.test:9/*'],
        base_url='http://base.test/',
        verbose=True,
    )
    err = capsys.readouterr().err
    assert failed == 1
    assert 'probing 2 URL-list target(s)' in err  # the header lands before the first probe
    assert '[1/2] http://ok.test/ — ok' in err  # one line per probe, as it lands
    assert '[2/2] http://dead.test:9 — unreachable' in err
    assert 'initial probe of 3 URL-list target(s)' in err  # the summary still follows


async def test_probe_pass_is_quiet_off_a_terminal_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    """capsys's stderr is not a TTY, so the default (verbose=None) prints only the summary."""

    async def request(url: str) -> object:
        return object()

    await probe_url_entries(
        request, entries=['http://ok.test/', 'http://other.test/x'], base_url='http://base.test/', verbose=False
    )
    err = capsys.readouterr().err
    assert '[1/2]' not in err and 'probing 2 URL-list' not in err
    assert 'initial probe of 3 URL-list target(s): 2 probed, 0 unreachable, 0 unprobed' in err


def _engagement_with_urls(directory: Path, urls: list[str], ports: list[int]) -> Path:
    manifest = json.loads((directory / 'engagement.json').read_text(encoding='utf-8'))
    manifest['scope']['urls'] = urls
    manifest['scope']['ports'] = ports
    (directory / 'engagement.json').write_text(json.dumps(manifest), encoding='utf-8')
    return directory


async def test_live_session_probes_every_imported_entry(
    target_server: Any, tmp_path: Path, tmp_store: RunStore
) -> None:
    base, port = target_server.base_url, target_server.port
    urls = [f'{base}/*', f'http://127.0.0.1:{port}/alt/*', 'http://127.0.0.1:9/dead/*']
    directory = _engagement_with_urls(engagement_dir(tmp_path, target_server), urls, [port, 9])
    async with live_session(directory, tmp_store, authorized=True, checks=()) as session:
        paths = {request['path'] for request in target_server.requests}
        assert '/' in paths and '/alt' in paths  # the baseline GET plus the /alt entry probe
        assert session.engagement.scope.urls == urls
    assert (await tmp_store.get_run(session.run_id)).state == 'checks_complete'  # the dead :9 entry never fails it


async def test_run_test_probes_every_listed_entry(target_server: Any, tmp_path: Path, tmp_store: RunStore) -> None:
    base, port = target_server.base_url, target_server.port
    urls_file = tmp_path / 'urls.txt'
    urls_file.write_text(f'{base}/*\nhttp://127.0.0.1:{port}/alt/*\n', encoding='utf-8')
    result = await run_test(
        engagement_dir(tmp_path, target_server), tmp_store, ['version-disclosure'], authorized=True, urls_file=urls_file
    )
    assert result.state == 'checks_complete'
    paths = {request['path'] for request in target_server.requests}
    assert '/' in paths and '/alt' in paths
