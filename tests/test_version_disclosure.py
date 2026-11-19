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
from partex.ids import evidence_id
from partex.models import FindingDraft, HttpEvidence, HttpExchange, HttpRequest, HttpResponse

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


def test_verify_recipe_is_none_until_22() -> None:
    assert version_disclosure_check.verify_recipe(object()) is None
