"""version-disclosure check unit tests — issue #21.

Pure unit tests against a canned client (no sockets), plus the non-finding
rule from ``skills/version-disclosure/SKILL.md``: generic product names
without version digits never become findings.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from partex import engine
from partex.checks.version_disclosure import (
    UNKNOWN_PROBE_PATH,
    version_disclosure_check,
)
from partex.errors import ScopeViolation
from partex.ids import evidence_id
from partex.models import Finding, FindingDraft, HttpEvidence, HttpExchange, HttpRequest, HttpResponse
from partex.storage import RunStore

pytest_plugins = ['plugins.target_server']

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


# ── Prefix anchoring, exclusion skip, dedup & severity (issue #80) ────────────


def test_x_generator_is_info_while_server_banners_are_low() -> None:
    drafts = version_disclosure_check._drafts_for(
        exchange(headers={'server': 'nginx/1.24.0', 'x-generator': 'WordPress 6.4.3'})
    )
    by_subject = {d.subject: d.severity for d in drafts}
    assert by_subject == {'header:server': 'low', 'header:x-generator': 'info'}


async def test_cross_probe_banner_dedup_emits_one_finding_for_primary_evidence() -> None:
    baseline = exchange('/', headers={'server': 'FixtureTarget/2.3.1'})
    client = CannedClient(
        [
            exchange('/robots.txt', headers={'server': 'FixtureTarget/2.3.1'}),
            exchange(
                UNKNOWN_PROBE_PATH,
                status=404,
                headers={'server': 'FixtureTarget/2.3.1'},
                body='Traceback (most recent call last): boom',
            ),
        ]
    )
    drafts = await version_disclosure_check.probe([baseline], client)
    banner_drafts = [d for d in drafts if d.subject == 'header:server']
    assert len(banner_drafts) == 1
    assert banner_drafts[0].evidence_ids == [baseline.id]


async def test_different_banner_values_across_probes_are_not_deduped() -> None:
    baseline = exchange('/', headers={'server': 'nginx/1.24.0'})
    client = CannedClient(
        [
            exchange('/robots.txt', headers={'server': 'Apache/2.4.58'}),
            exchange(UNKNOWN_PROBE_PATH, status=404, body='Not Found'),
        ]
    )
    drafts = await version_disclosure_check.probe([baseline], client)
    assert len([d for d in drafts if d.subject == 'header:server']) == 2


async def test_excluded_error_probe_skips_and_records_not_exercised() -> None:
    class ExcludingClient(CannedClient):
        async def request(self, method: str, url: str, *, headers: object = None, body: object = None) -> HttpEvidence:
            if url.endswith(UNKNOWN_PROBE_PATH):
                raise ScopeViolation('excluded')
            return await super().request(method, url, headers=headers, body=body)

    baseline = exchange('/api', headers={'server': 'FixtureTarget/2.3.1'})
    client = ExcludingClient([exchange('/api/robots.txt')])
    drafts = await version_disclosure_check.probe([baseline], client)
    subjects = {d.subject: d for d in drafts}
    assert 'header:server' in subjects
    assert 'error-page:not-exercised' in subjects
    assert subjects['error-page:not-exercised'].severity == 'info'


async def test_narrow_path_prefix_engagement_completes_and_dedups_end_to_end(
    target_server: Any, tmp_store: RunStore, tmp_path: Path
) -> None:
    """An engagement with path_prefixes=['/api'] probes under /api/... and dedups the server banner."""
    eng_dir = tmp_path / 'eng'
    eng_dir.mkdir()
    (eng_dir / 'engagement.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'target': {'name': 'api', 'base_url': f'http://127.0.0.1:{target_server.port}/api'},
                'scope': {
                    'hosts': ['127.0.0.1'],
                    'path_prefixes': ['/api'],
                    'exclusions': [],
                    'ports': [target_server.port],
                    'max_rps': 64,
                    'max_requests': 50,
                },
                'authorization': {'attestation': 'fixture', 'operator': 'test'},
            }
        )
    )

    result = await engine.run_test(eng_dir, tmp_store, ['version-disclosure'], authorized=True)
    assert result.state == 'checks_complete'
    assert [r['path'] for r in target_server.requests] == ['/api', '/api/robots.txt', f'/api{UNKNOWN_PROBE_PATH}']
    # Server: FixtureTarget/1.0 appeared on all 3 responses -> exactly 1 deduplicated banner finding.
    assert [f.subject for f in result.findings] == ['header:server']
