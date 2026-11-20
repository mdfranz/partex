"""version-disclosure — built-in active check for version banners and verbose errors.

PLAN §10 fixture 2 (issue #21).  Guidance lives in ``skills/version-disclosure/``
(data, never executed).  Probes ``GET /`` (reusing the engine's baseline capture
when present), ``GET /robots.txt``, and a deliberately unknown path that triggers
the error handler.

Findings per ``skills/version-disclosure/SKILL.md``: a header that discloses a
product/runtime identifier **with explicit version digits** (``info``/``low``),
and an error body exposing stack traces or absolute paths (``medium``).  Generic
product names without version digits are the skill's non-finding rule — they do
not become drafts.  ``verify_recipe``/#22: the single-request replay and the
same-class matcher live here (``skills/.../verification-criteria.md`` §3).
"""

import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from ..errors import ScopeViolation
from ..models import (
    Evidence,
    Finding,
    FindingDraft,
    HttpEvidence,
    Severity,
    VerificationRecipe,
    VerificationRequest,
    get_header,
)
from . import TargetClient

CHECK_ID = 'version-disclosure'
CHECK_VERSION = '0.1'
CHECK_TITLE = 'Version and Error Disclosure'
CHECK_DESCRIPTION = (
    'Probe for explicit software version banners (Server, X-Powered-By, '
    'X-AspNet-Version, X-Generator) and verbose error pages exposing stack '
    'traces or internal paths.'
)

# Explicit version token: one or more dot-separated numbers (2.3.1, 8.2, 2026.11).
_VERSION_DIGITS = re.compile(r'\d+(?:\.\d+)+')

BANNER_HEADERS = ('server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator')
INFO_BANNER_HEADERS = frozenset({'x-generator'})

# Skill reference (skills/version-disclosure/reference/verification-criteria.md §2):
# language runtime tracebacks, framework debug screens, absolute filesystem paths.
STACK_MARKERS = (
    'Traceback (most recent call last):',
    'at java.lang.',
    'NullReferenceException',
    'Fatal error:',
    '/var/www/',
    '/usr/lib/python',
    'C:\\inetpub\\',
)

# Deterministic unknown path (PLAN §10 fixture 2): stable URLs keep evidence and
# finding IDs comparable across replays of the same engagement.
UNKNOWN_PROBE_PATH = '/partex-nonexistent-probe-0'


def _origin_of(url: str) -> str:
    """Return ``scheme://authority`` for a captured request URL."""
    parts = urlsplit(url)
    return f'{parts.scheme}://{parts.netloc}'


def _anchor_prefix(baseline_url: str, client: TargetClient) -> str:
    """Return the normalized path prefix (``''`` for root, or ``'/api'`` without trailing slash)."""
    base_path = urlsplit(baseline_url).path.rstrip('/')
    if base_path:
        return base_path
    scope = getattr(client, 'scope', None)
    prefixes = getattr(scope, 'path_prefixes', None)
    if prefixes:
        first = str(prefixes[0]).rstrip('/')
        return '' if first == '/' else first
    return ''


class VersionDisclosureCheck:
    """The active probe: baseline reuse plus two targeted requests."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return any(isinstance(item, HttpEvidence) for item in evidence)

    async def probe(self, evidence: Sequence[Evidence], client: TargetClient) -> list[FindingDraft]:
        """Scan captured exchanges, then probe anchored robots.txt and error-handler paths."""
        captured = [item for item in evidence if isinstance(item, HttpEvidence)]
        if not captured:
            return []  # no baseline to derive an origin from

        origin = _origin_of(captured[0].http.request.url)
        anchor = _anchor_prefix(captured[0].http.request.url, client)
        exchanges = list(captured)

        for path in (f'{anchor}/robots.txt', f'{anchor}{UNKNOWN_PROBE_PATH}'):
            try:
                exchanges.append(await client.request('GET', f'{origin}{path}'))
            except ScopeViolation:
                if path.endswith(UNKNOWN_PROBE_PATH):
                    drafts = self._collect_drafts(exchanges)
                    drafts.append(
                        FindingDraft(
                            check_id=CHECK_ID,
                            check_version=CHECK_VERSION,
                            severity='info',
                            subject='error-page:not-exercised',
                            title='Error pages were not exercised (probe outside scope)',
                            description=(
                                f'The error-page probe {origin}{path} was refused by the engagement scope '
                                '(for example due to an exclusion or narrow path prefix), so error-page '
                                'disclosure was not exercised.'
                            ),
                            evidence_ids=[captured[0].id],
                            remediation='Verify manually or adjust scope exclusions if error-page testing is required.',
                        )
                    )
                    return drafts

        return self._collect_drafts(exchanges)

    def _collect_drafts(self, exchanges: Sequence[HttpEvidence]) -> list[FindingDraft]:
        """Emit deduplicated drafts across *exchanges* (one per (header, banner_value) citing primary evidence)."""
        seen_banners: set[tuple[str, str]] = set()
        drafts: list[FindingDraft] = []
        for exchange in exchanges:
            for draft, banner_key in self._drafts_with_keys(exchange):
                if banner_key is not None:
                    if banner_key in seen_banners:
                        continue
                    seen_banners.add(banner_key)
                drafts.append(draft)
        return drafts

    def _drafts_for(self, exchange: HttpEvidence) -> list[FindingDraft]:
        """Emit one draft per finding class the exchange exhibits (skill check mapping)."""
        return [draft for draft, _ in self._drafts_with_keys(exchange)]

    def _drafts_with_keys(self, exchange: HttpEvidence) -> list[tuple[FindingDraft, tuple[str, str] | None]]:
        drafts: list[tuple[FindingDraft, tuple[str, str] | None]] = []
        response = exchange.http.response
        request = exchange.http.request
        for header in BANNER_HEADERS:
            value = get_header(response.headers, header)
            if value and _VERSION_DIGITS.search(value):
                severity: Severity = 'info' if header in INFO_BANNER_HEADERS else 'low'
                drafts.append(
                    (
                        FindingDraft(
                            check_id=CHECK_ID,
                            check_version=CHECK_VERSION,
                            severity=severity,
                            subject=f'header:{header}',
                            title=f'Version banner disclosed via {header} header',
                            description=(
                                f'{request.method} {request.url} exposes {header}: {value!r}, an explicit '
                                'product/version token that fingerprints the stack for known-vulnerable '
                                'version matching (OWASP: Security Misconfiguration).'
                            ),
                            evidence_ids=[exchange.id],
                            remediation=(
                                f'Suppress version identifiers from the {header} response header '
                                '(server_tokens off or the platform equivalent).'
                            ),
                        ),
                        (header, value),
                    )
                )
        body = response.body or ''
        if any(marker in body for marker in STACK_MARKERS):
            drafts.append(
                (
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='medium',
                        subject='error-page',
                        title='Verbose error page discloses stack trace or internal paths',
                        description=(
                            f'The error response for {request.method} {request.url} exposes runtime '
                            'tracebacks, framework debug details, or absolute filesystem paths.'
                        ),
                        evidence_ids=[exchange.id],
                        remediation='Disable debug/verbose error pages in production; log details server-side only.',
                    ),
                    None,
                )
            )
        return drafts

    def verify_recipe(self, finding: Finding, evidence: Sequence[Evidence]) -> VerificationRecipe | None:
        """The single-request replay: re-send the exact exchange that produced the finding."""
        captured = [item for item in evidence if isinstance(item, HttpEvidence)]
        if not captured:
            return None
        original = captured[0]
        return VerificationRecipe(
            description=(
                f'Replay {original.http.request.method} {original.http.request.url} and re-test '
                f'the {finding.subject} finding ({finding.title}).'
            ),
            requests=[
                VerificationRequest(
                    method=original.http.request.method,
                    # Full URL, not a bare path: the runner's scope gate needs
                    # scheme/host/port, and the recipe must replay the exact target.
                    path=original.http.request.url,
                )
            ],
        )

    def verify_match(self, finding: Finding, original: HttpEvidence, replay: HttpEvidence) -> bool:
        """Confirmed iff the replay still exhibits the finding's class (skill §3)."""
        if finding.subject.startswith('header:'):
            header = finding.subject.removeprefix('header:')
            value = get_header(replay.http.response.headers, header)
            return value is not None and bool(_VERSION_DIGITS.search(value))
        if finding.subject == 'error-page':
            body = replay.http.response.body or ''
            return any(marker in body for marker in STACK_MARKERS)
        return False


version_disclosure_check = VersionDisclosureCheck()
