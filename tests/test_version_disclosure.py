"""version-disclosure check unit tests — issue #21.

Pure unit tests against a canned client (no sockets), plus the non-finding
rule from ``skills/version-disclosure/SKILL.md``: generic product names
without version digits never become findings.
"""

from collections.abc import Sequence

from partex.checks.version_disclosure import (
    UNKNOWN_PROBE_PATH,
    version_disclosure_check,
)
from partex.errors import ScopeViolation
from partex.ids import evidence_id
from partex.models import Finding, FindingDraft, HttpEvidence, HttpExchange, HttpRequest, HttpResponse

BASE_URL = 'http://fixture.test:8443'


def exchange(
    path: str = '/',
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,  # one value per name; converted to pairs below
    body: str | None = None,
) -> HttpEvidence:
    """A canned captured exchange with a stable synthetic evidence id."""
    request = HttpRequest(method='GET', url=f'{BASE_URL}{path}', headers=[('host', 'fixture.test:8443')])
    response = HttpResponse(
        status_code=status,
        headers=list(({'content-type': 'text/plain'} | (headers or {})).items()),
        body=body if body is not None else 'ok',
    )
    evidence = HttpEvidence(id='', source='capture:test', http=HttpExchange(request=request, response=response))
    return evidence.model_copy(update={'id': evidence_id(evidence)})


class CannedClient:
    """A fake TargetClient: serves queued responses, records what was asked."""

    def __init__(self, responses: list[HttpEvidence]) -> None:
        self._responses = list(responses)
        self.requested: list[str] = []

    async def request(self, method: str, url: str, *, headers: object = None, body: object = None) -> HttpEvidence:
        self.requested.append(f'{method} {url}')
        return self._responses.pop(0)


def banners(evidence: HttpEvidence) -> list[str]:
    """Titles of banner drafts in *evidence* (single-exchange scan)."""
    return [draft.title for draft in version_disclosure_check._drafts_for(evidence)]


# ── Banner findings ──────────────────────────────────────────────────────────


def test_versioned_server_header_is_a_finding() -> None:
    drafts = version_disclosure_check._drafts_for(exchange(headers={'server': 'nginx/1.24.0'}))
    assert len(drafts) == 1
    assert drafts[0].severity == 'low'
    assert 'server' in drafts[0].title.lower()
    assert 'nginx/1.24.0' in drafts[0].description


def test_versioned_powered_by_and_aspnet_headers_are_findings() -> None:
    drafts = version_disclosure_check._drafts_for(
        exchange(headers={'x-powered-by': 'PHP/8.2.1', 'x-aspnet-version': '4.0.30319'})
    )
    assert len(drafts) == 2


def test_generic_product_without_version_digits_is_not_a_finding() -> None:
    """Skill non-finding rule: `Server: cloudflare` / `Server: nginx` stay quiet."""
    for value in ('cloudflare', 'nginx', 'Express', 'Microsoft-IIS'):
        assert banners(exchange(headers={'server': value})) == []


def test_stack_trace_body_is_a_medium_finding() -> None:
    drafts = version_disclosure_check._drafts_for(
        exchange(status=404, body='Traceback (most recent call last):\n  File "/var/www/app/x.py"')
    )
    assert len(drafts) == 1
    assert drafts[0].severity == 'medium'
    assert 'stack trace' in drafts[0].title.lower()


def test_clean_error_page_is_not_a_finding() -> None:
    assert version_disclosure_check._drafts_for(exchange(status=404, body='Not Found')) == []


def test_absolute_path_in_error_body_is_a_finding() -> None:
    drafts = version_disclosure_check._drafts_for(exchange(status=500, body='Fatal error: /var/www/app died'))
    assert len(drafts) == 1


def test_default_page_mentioning_paths_is_not_an_error_page() -> None:
    """#267: a 200 stock Apache/Ubuntu index names /var/www/html as documentation, not a leak."""
    body = (
        '<title>Apache2 Ubuntu Default Page: It works</title> ... replace this file (located at '
        '/var/www/html/index.html) ... configuration in /etc/apache2/'
    )
    assert version_disclosure_check._drafts_for(exchange(status=200, body=body)) == []


def test_stack_markers_on_2xx_are_not_an_error_page() -> None:
    """Skill §2 flags 4xx/5xx error bodies only."""
    assert version_disclosure_check._drafts_for(exchange(status=200, body='Fatal error: /var/www/app died')) == []


def test_verify_match_error_page_needs_an_error_status() -> None:
    original = exchange('/x', status=404, body='Traceback (most recent call last): boom')
    draft = version_disclosure_check._drafts_for(original)[0]
    finding = Finding(id='fn_test', status='reported', **draft.model_dump())
    served_as_200 = exchange('/x', status=200, body='Traceback (most recent call last): boom')
    assert version_disclosure_check.verify_match(finding, original, served_as_200) is False


# ── The probe flow ────────────────────────────────────────────────────────────


def test_applies_to_requires_http_evidence() -> None:
    assert version_disclosure_check.applies_to([exchange()]) is True
    assert version_disclosure_check.applies_to([]) is False


async def test_probe_reuses_baseline_and_probes_two_paths() -> None:
    baseline = exchange('/', headers={'server': 'FixtureTarget/2.3.1'})
    client = CannedClient(
        [
            exchange('/robots.txt'),
            exchange(UNKNOWN_PROBE_PATH, status=404, body='Traceback (most recent call last): boom'),
        ]
    )
    drafts = await version_disclosure_check.probe([baseline], client)
    # Baseline '/' is scanned but not re-requested; exactly two new probes.
    assert client.requested == [f'GET {BASE_URL}/robots.txt', f'GET {BASE_URL}{UNKNOWN_PROBE_PATH}']
    titles = [draft.title for draft in drafts]
    assert any('banner' in title.lower() for title in titles)
    assert any('stack trace' in title.lower() for title in titles)


async def test_probe_without_baseline_returns_no_new_requests() -> None:
    client = CannedClient([])
    assert await version_disclosure_check.probe([], client) == []
    assert client.requested == []


async def test_all_drafts_cite_evidence_and_claim_the_check() -> None:
    baseline = exchange('/', headers={'server': 'FixtureTarget/2.3.1'})
    client = CannedClient(
        [exchange('/robots.txt'), exchange(UNKNOWN_PROBE_PATH, status=404, body='Fatal error: /var/www/x')]
    )
    drafts: Sequence[FindingDraft] = await version_disclosure_check.probe([baseline], client)
    assert drafts
    for draft in drafts:
        assert draft.check_id == 'version-disclosure'
        assert draft.check_version == version_disclosure_check.version
        assert draft.evidence_ids == [baseline.id] or len(draft.evidence_ids) == 1


# ── verify_recipe + verify_match (issue #22) ──────────────────────────────────


def test_verify_recipe_replays_the_original_exchange() -> None:
    original = exchange('/', headers={'server': 'FixtureTarget/2.3.1'})
    draft = version_disclosure_check._drafts_for(original)[0]
    finding = Finding(id='fn_test', status='reported', **draft.model_dump())
    recipe = version_disclosure_check.verify_recipe(finding, [original])
    assert recipe is not None
    assert len(recipe.requests) == 1
    assert recipe.requests[0].method == 'GET'
    assert recipe.requests[0].path == original.http.request.url  # full URL for the scope gate


def test_verify_recipe_none_without_http_evidence() -> None:
    original = exchange('/', headers={'server': 'FixtureTarget/2.3.1'})
    draft = version_disclosure_check._drafts_for(original)[0]
    finding = Finding(id='fn_test', status='reported', **draft.model_dump())
    assert version_disclosure_check.verify_recipe(finding, []) is None


def test_verify_match_header_finding() -> None:
    original = exchange('/', headers={'server': 'FixtureTarget/2.3.1'})
    draft = version_disclosure_check._drafts_for(original)[0]
    finding = Finding(id='fn_test', status='reported', **draft.model_dump())
    same_banner = exchange('/', headers={'server': 'FixtureTarget/2.3.1'})
    clean_banner = exchange('/', headers={'server': 'FixtureTarget'})
    assert version_disclosure_check.verify_match(finding, original, same_banner) is True
    assert version_disclosure_check.verify_match(finding, original, clean_banner) is False


def test_verify_match_error_page_finding() -> None:
    original = exchange('/x', status=404, body='Traceback (most recent call last): boom')
    draft = version_disclosure_check._drafts_for(original)[0]
    finding = Finding(id='fn_test', status='reported', **draft.model_dump())
    still_leaky = exchange('/x', status=404, body='Fatal error: /var/www/x')
    fixed = exchange('/x', status=404, body='Not Found')
    assert version_disclosure_check.verify_match(finding, original, still_leaky) is True
    assert version_disclosure_check.verify_match(finding, original, fixed) is False


# ── Probe anchoring and dedup (#80) ──────────────────────────────────────────


class ScopeRefusingClient(CannedClient):
    """A fake client that raises ScopeViolation for URLs outside *allowed* prefixes."""

    def __init__(self, responses: list[HttpEvidence], allowed: tuple[str, ...]) -> None:
        super().__init__(responses)
        self._allowed = allowed
        self.refused: list[str] = []

    async def request(self, method: str, url: str, *, headers: object = None, body: object = None) -> HttpEvidence:
        path = url.split('fixture.test:8443', 1)[1]
        if not any(
            path == prefix or path.startswith(prefix if prefix.endswith('/') else prefix + '/')
            for prefix in self._allowed
        ):
            self.refused.append(f'{method} {url}')
            raise ScopeViolation(f'{path} is outside the engagement scope')
        return await super().request(method, url)


async def test_probe_anchors_under_narrow_path_prefixes() -> None:
    """A /api/v1-scoped engagement probes /api/v1/... — never the refused site root (#80)."""
    baseline = exchange('/api/v1/x', headers={'server': 'FixtureTarget/2.3.1'})
    client = ScopeRefusingClient(
        [
            exchange('/api/v1/robots.txt'),
            exchange(f'/api/v1{UNKNOWN_PROBE_PATH}', status=404, body='Fatal error: /var/www/x'),
        ],
        allowed=('/api/v1',),
    )
    drafts = await version_disclosure_check.probe([baseline], client)
    assert client.requested == [
        f'GET {BASE_URL}/api/v1/robots.txt',
        f'GET {BASE_URL}/api/v1{UNKNOWN_PROBE_PATH}',
    ]
    assert not client.refused  # anchored probes are in scope on the first try
    assert any('stack trace' in draft.title.lower() for draft in drafts)


async def test_probe_falls_back_to_root_when_anchor_refused() -> None:
    """An excluded anchored path falls back to the site-root probe before giving up."""
    baseline = exchange('/api/x', headers={'server': 'FixtureTarget/2.3.1'})
    served = {
        '/robots.txt': exchange('/robots.txt'),
        UNKNOWN_PROBE_PATH: exchange(UNKNOWN_PROBE_PATH, status=404),
    }

    class AnchorsRefused:
        def __init__(self) -> None:
            self.requested: list[str] = []

        async def request(self, method: str, url: str, *, headers: object = None, body: object = None) -> HttpEvidence:
            self.requested.append(f'{method} {url}')
            path = url.split('fixture.test:8443', 1)[1]
            if path.startswith('/api'):
                raise ScopeViolation(f'{path} is outside the engagement scope')
            return served[path]

    client = AnchorsRefused()
    drafts = await version_disclosure_check.probe([baseline], client)
    assert client.requested == [
        f'GET {BASE_URL}/api/robots.txt',  # anchored, refused (free — no wire bytes)
        f'GET {BASE_URL}/robots.txt',  # root fallback, served
        f'GET {BASE_URL}/api{UNKNOWN_PROBE_PATH}',  # anchored, refused
        f'GET {BASE_URL}{UNKNOWN_PROBE_PATH}',  # root fallback, served
    ]
    assert [draft.subject for draft in drafts] == ['header:server']


async def test_probe_skips_gracefully_when_all_paths_refused() -> None:
    """Both anchored and root probes refused → no drafts from probes, no ScopeViolation escape."""
    baseline = exchange('/api/x', headers={'server': 'FixtureTarget/2.3.1'})
    client = ScopeRefusingClient([], allowed=())
    drafts = await version_disclosure_check.probe([baseline], client)
    assert client.refused  # every attempt was refused, all before any wire bytes
    assert [draft.subject for draft in drafts] == ['header:server']  # only the baseline scan


async def test_same_banner_across_probes_is_one_finding() -> None:
    """`Server: nginx/1.24.0` on baseline, robots, and the 404 → one draft, primary evidence."""
    banner = {'server': 'nginx/1.24.0'}
    baseline = exchange('/', headers=banner)
    client = CannedClient(
        [exchange('/robots.txt', headers=banner), exchange(UNKNOWN_PROBE_PATH, status=404, headers=banner)]
    )
    drafts = await version_disclosure_check.probe([baseline], client)
    server_drafts = [draft for draft in drafts if draft.subject == 'header:server']
    assert len(server_drafts) == 1
    assert server_drafts[0].evidence_ids == [baseline.id]


async def test_distinct_banners_are_distinct_findings() -> None:
    baseline = exchange('/', headers={'server': 'nginx/1.24.0'})
    client = CannedClient(
        [
            exchange('/robots.txt', headers={'x-generator': 'Drupal 9.4.7'}),
            exchange(UNKNOWN_PROBE_PATH, status=404),
        ]
    )
    drafts = await version_disclosure_check.probe([baseline], client)
    subjects = {draft.subject for draft in drafts}
    assert subjects == {'header:server', 'header:x-generator'}


def test_generator_banner_is_info_server_banner_is_low() -> None:
    """Skill mapping: server/runtime identifiers are low; generator hints are info."""
    generator = version_disclosure_check._drafts_for(exchange(headers={'x-generator': 'WordPress 6.4.2'}))
    assert len(generator) == 1 and generator[0].severity == 'info'
    server = version_disclosure_check._drafts_for(exchange(headers={'server': 'nginx/1.24.0'}))
    assert len(server) == 1 and server[0].severity == 'low'


# ── Catch-all detection (issue #53) ───────────────────────────────────────────


def _page(url: str, status: int, body: str, content_type: str = 'text/html') -> HttpEvidence:
    exchange = HttpExchange(
        request=HttpRequest(method='GET', url=url, headers=[]),
        response=HttpResponse(status_code=status, headers=[('Content-Type', content_type)], body=body),
    )
    item = HttpEvidence(id='', source='capture:test', http=exchange)
    return item.model_copy(update={'id': evidence_id(item)})


def test_is_catch_all_ignores_per_request_tokens_and_matches_the_html_shell() -> None:
    from partex.checks.version_disclosure import is_catch_all

    shell = '<html><script nonce="abc123def456" src="/main.js"></script><body>app</body></html>'
    other = '<html><script nonce="zzz999yyy888" src="/main.js"></script><body>app</body></html>'
    base = _page('https://a.test/', 200, shell)
    assert is_catch_all(base, _page('https://a.test/partex-nonexistent-probe-0', 200, other))
    # Different body but the same script/stylesheet references: still the same shell.
    shell_two = '<html><script src="/main.js"></script><body>loading...</body></html>'
    assert is_catch_all(base, _page('https://a.test/partex-nonexistent-probe-0', 200, shell_two))
    # A real error: 404, or a 200 that is a different page.
    assert not is_catch_all(base, _page('https://a.test/partex-nonexistent-probe-0', 404, shell))
    assert not is_catch_all(base, _page('https://a.test/partex-nonexistent-probe-0', 200, '<html>Not Found</html>'))
    plain = '<script src="/main.js"></script> but served as plain text'
    assert not is_catch_all(base, _page('https://a.test/x', 200, plain, content_type='text/plain'))  # not an HTML shell


def test_coverage_cites_the_probe_and_baseline_for_a_catch_all() -> None:
    from partex.checks.version_disclosure import VersionDisclosureCheck

    shell = '<html><script src="/main.js"></script></html>'
    base = _page('https://a.test/', 200, shell)
    probe = _page('https://a.test/partex-nonexistent-probe-0', 200, shell)
    (entry,) = VersionDisclosureCheck().coverage([base, probe])
    assert entry.outcome == 'not_applicable' and set(entry.evidence_ids) == {base.id, probe.id}
    assert VersionDisclosureCheck().coverage([]) == []
