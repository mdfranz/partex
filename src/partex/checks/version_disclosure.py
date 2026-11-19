"""version-disclosure — built-in active check for version banners and verbose errors.

PLAN §10 fixture 2 (issue #21).  Guidance lives in ``skills/version-disclosure/``
(data, never executed).  Probes ``GET /`` (reusing the engine's baseline capture
when present), ``GET /robots.txt``, and a deliberately unknown path that triggers
the error handler.

Findings per ``skills/version-disclosure/SKILL.md``: a header that discloses a
product/runtime identifier **with explicit version digits** (``info``/``low``),
and an error body exposing stack traces or absolute paths (``medium``).  Generic
product names without version digits are the skill's non-finding rule — they do
not become drafts.  No ``verify_recipe`` yet: #22 adds the single-request replay.
"""

import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from ..models import Evidence, FindingDraft, HttpEvidence
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


class VersionDisclosureCheck:
    """The active probe: baseline reuse plus two targeted requests."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return any(isinstance(item, HttpEvidence) for item in evidence)

    async def probe(self, evidence: Sequence[Evidence], client: TargetClient) -> list[FindingDraft]:
        """Scan captured exchanges, then probe /robots.txt and the error handler."""
        captured = [item for item in evidence if isinstance(item, HttpEvidence)]
        drafts: list[FindingDraft] = []
        for exchange in captured:
            drafts.extend(self._drafts_for(exchange))
        if not captured:
            return drafts  # no baseline to derive an origin from
        origin = _origin_of(captured[0].http.request.url)
        robots = await client.request('GET', f'{origin}/robots.txt')
        drafts.extend(self._drafts_for(robots))
        error_page = await client.request('GET', f'{origin}{UNKNOWN_PROBE_PATH}')
        drafts.extend(self._drafts_for(error_page))
        return drafts

    def _drafts_for(self, exchange: HttpEvidence) -> list[FindingDraft]:
        """Emit one draft per finding class the exchange exhibits (skill check mapping)."""
        drafts: list[FindingDraft] = []
        response = exchange.http.response
        request = exchange.http.request
        for header in BANNER_HEADERS:
            value = response.headers.get(header)
            if value and _VERSION_DIGITS.search(value):
                drafts.append(
                    FindingDraft(
                        check_id=CHECK_ID,
                        check_version=CHECK_VERSION,
                        severity='low',
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
                    )
                )
        body = response.body or ''
        if any(marker in body for marker in STACK_MARKERS):
            drafts.append(
                FindingDraft(
                    check_id=CHECK_ID,
                    check_version=CHECK_VERSION,
                    severity='medium',
                    title='Verbose error page discloses stack trace or internal paths',
                    description=(
                        f'The error response for {request.method} {request.url} exposes runtime '
                        'tracebacks, framework debug details, or absolute filesystem paths.'
                    ),
                    evidence_ids=[exchange.id],
                    remediation='Disable debug/verbose error pages in production; log details server-side only.',
                )
            )
        return drafts

    def verify_recipe(self, finding: object) -> None:
        """No recipe yet — findings stay ``reported`` until #22 adds the replay."""
        return


version_disclosure_check = VersionDisclosureCheck()
