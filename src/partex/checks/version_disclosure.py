"""version-disclosure — built-in active check for version banners and verbose errors.

PLAN §10 fixture 2 (issue #21).  Guidance lives in ``skills/version-disclosure/``
(data, never executed).  Probes ``GET /`` (reusing the engine's baseline capture
when present), ``GET /robots.txt``, and a deliberately unknown path that triggers
the error handler.

Findings per ``skills/version-disclosure/SKILL.md``: a header that discloses a
product/runtime identifier **with explicit version digits** (``info``/``low``),
and a ``4xx``/``5xx`` error body exposing stack traces or absolute paths (``medium``;
``2xx`` pages never count, #267).  Generic product names without version digits are
the skill's non-finding rule — they do not become drafts.  ``verify_recipe``/#22: the single-request replay and the
same-class matcher live here (``skills/.../verification-criteria.md`` §3).
"""

import posixpath
import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from ..models import (
    CoverageEntry,
    Evidence,
    Finding,
    FindingDraft,
    HttpEvidence,
    Severity,
    VerificationRecipe,
    VerificationRequest,
    get_header,
)
from ..scope import ScopeViolation
from . import TargetClient

CHECK_ID = 'version-disclosure'
CHECK_VERSION = '0.4'
CHECK_TITLE = 'Version and Error Disclosure'
CHECK_DESCRIPTION = (
    'Probe for explicit software version banners (Server, X-Powered-By, '
    'X-AspNet-Version, X-Generator) and verbose error pages exposing stack '
    'traces or internal paths.'
)

# Explicit version token: one or more dot-separated numbers (2.3.1, 8.2, 2026.11).
_VERSION_DIGITS = re.compile(r'\d+(?:\.\d+)+')

BANNER_HEADERS = ('server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator')

# Skill §"Check Mapping": server/runtime identifiers are `low`; generator hints are `info`.
_BANNER_SEVERITIES: dict[str, Severity] = {
    'server': 'low',
    'x-powered-by': 'low',
    'x-aspnet-version': 'low',
    'x-aspnetmvc-version': 'low',
    'x-generator': 'info',
}

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


def discloses_error_details(status_code: int, body: str | None) -> bool:
    """Whether an error (``4xx``/``5xx``) response exposes stack traces or internal paths (skill §2).

    ``2xx`` pages never count: they mention paths as documentation (the stock Apache/Ubuntu
    "It works" index names ``/var/www/html``), which is not an error page (#267).
    """
    return status_code >= 400 and any(marker in (body or '') for marker in STACK_MARKERS)


# Deterministic unknown path (PLAN §10 fixture 2): stable URLs keep evidence and
# finding IDs comparable across replays of the same engagement.
UNKNOWN_PROBE_PATH = '/partex-nonexistent-probe-0'


ERROR_PAGE_RISK = 'error-page-disclosure'
"""Coverage ledger ``risk_area`` for the unknown-path (error handler) probe."""

_ASSET_REF = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_NONCE_ATTR = re.compile(r'(?:nonce|integrity)\s*=\s*["\'][^"\']*["\']', re.IGNORECASE)
_TOKEN = re.compile(r'[A-Za-z0-9_+/=-]{24,}')


def _normalized_body(body: str) -> str:
    """The body with per-request tokens (nonces, long random strings) and whitespace removed."""
    return re.sub(r'\s+', '', _TOKEN.sub('', _NONCE_ATTR.sub('', body)))


def _asset_refs(body: str) -> frozenset[str]:
    return frozenset(_ASSET_REF.findall(body))


def is_catch_all(baseline: HttpEvidence, probe: HttpEvidence) -> bool:
    """Whether the unknown-path probe was served the baseline's page, so no error handler ran (#53).

    True when the probe answered 2xx with the same body as the baseline after stripping per-request
    tokens, or with the same HTML shell (the same script/stylesheet references).
    """
    response = probe.http.response
    if not 200 <= response.status_code < 300 or response.body is None or baseline.http.response.body is None:
        return False
    if _normalized_body(response.body) == _normalized_body(baseline.http.response.body):
        return True
    ctype = (get_header(response.headers, 'content-type') or '').lower()
    refs = _asset_refs(response.body)
    return 'html' in ctype and bool(refs) and refs == _asset_refs(baseline.http.response.body)


def _origin_of(url: str) -> str:
    """Return ``scheme://authority`` for a captured request URL."""
    parts = urlsplit(url)
    return f'{parts.scheme}://{parts.netloc}'


def _anchor_dir(path: str) -> str:
    """The baseline capture's directory, '' at the site root — probes anchor under it (#80).

    ``/`` and ``/home`` anchor at the root (``''``); ``/api/v1/x`` anchors at ``/api/v1``, so a
    ``/api``-scoped engagement probes ``/api/v1/robots.txt`` instead of the refused ``/robots.txt``.
    """
    directory = posixpath.dirname(path)
    return '' if directory in ('', '/') else directory


class VersionDisclosureCheck:
    """The active probe: baseline reuse plus two targeted requests."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return any(isinstance(item, HttpEvidence) for item in evidence)

    async def probe(self, evidence: Sequence[Evidence], client: TargetClient) -> list[FindingDraft]:
        """Scan captured exchanges, then probe robots.txt and the error handler, scope-safely (#80).

        Probes anchor under the baseline capture's directory when the engagement targets a deeper
        path (a ``/api``-scoped engagement never asks for ``/robots.txt``), fall back to the site
        root when the anchored path is refused, and skip a probe that no in-scope path can serve.
        The same ``(header, banner)`` seen on several responses is **one** finding citing the
        primary evidence (docs/skills/version-disclosure.md §4).
        """
        captured = [item for item in evidence if isinstance(item, HttpEvidence)]
        drafts: list[FindingDraft] = []
        seen_banners: set[tuple[str, str]] = set()

        def scan(exchange: HttpEvidence) -> None:
            for key, draft in self._banner_drafts(exchange):
                if key in seen_banners:
                    continue
                seen_banners.add(key)
                drafts.append(draft)
            if error := self._error_draft(exchange):
                drafts.append(error)

        for exchange in captured:
            scan(exchange)
        if not captured:
            return drafts  # no baseline to derive an origin from

        origin = _origin_of(captured[0].http.request.url)
        anchor = _anchor_dir(urlsplit(captured[0].http.request.url).path)
        for anchored_path, root_path in (
            (f'{anchor}/robots.txt', '/robots.txt'),
            (f'{anchor}{UNKNOWN_PROBE_PATH}', UNKNOWN_PROBE_PATH),
        ):
            probed = await self._probe_scope_safe(client, f'{origin}{anchored_path}', f'{origin}{root_path}')
            if probed is not None:
                scan(probed)
        return drafts

    async def _probe_scope_safe(self, client: TargetClient, anchored_url: str, root_url: str) -> HttpEvidence | None:
        """Request *anchored_url*; on a scope refusal retry the site-root *root_url*, then give up.

        A ``ScopeViolation`` is raised by the scoped client before any bytes are written, so a
        refused attempt costs nothing on the wire. Letting it escape would fail the whole run
        (the engine turns an out-of-scope probe into ``checks_failed``) — the right behavior
        for a healthy narrow-scope engagement is to probe inside the scope, not to fail (#80).
        """
        try:
            return await client.request('GET', anchored_url)
        except ScopeViolation:
            if anchored_url == root_url:
                return None
        try:
            return await client.request('GET', root_url)
        except ScopeViolation:
            return None

    def _drafts_for(self, exchange: HttpEvidence) -> list[FindingDraft]:
        """One draft per finding class the exchange exhibits (skill check mapping)."""
        drafts = [draft for _key, draft in self._banner_drafts(exchange)]
        if error := self._error_draft(exchange):
            drafts.append(error)
        return drafts

    def _banner_drafts(self, exchange: HttpEvidence) -> list[tuple[tuple[str, str], FindingDraft]]:
        """``((header, banner value), draft)`` per version banner the response exposes."""
        out: list[tuple[tuple[str, str], FindingDraft]] = []
        response = exchange.http.response
        request = exchange.http.request
        for header in BANNER_HEADERS:
            value = get_header(response.headers, header)
            if value and _VERSION_DIGITS.search(value):
                out.append(
                    (
                        (header, value),
                        FindingDraft(
                            check_id=CHECK_ID,
                            check_version=CHECK_VERSION,
                            severity=_BANNER_SEVERITIES[header],
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
                    )
                )
        return out

    def _error_draft(self, exchange: HttpEvidence) -> FindingDraft | None:
        """The verbose-error-page draft, when the response body carries stack markers."""
        response = exchange.http.response
        if not discloses_error_details(response.status_code, response.body):
            return None
        request = exchange.http.request
        return FindingDraft(
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
        )

    def coverage(self, evidence: Sequence[Evidence]) -> list[CoverageEntry]:
        """What the error-handler probe did and did not exercise, as a ledger entry (#53).

        Without this a clean result reads as "error pages are clean" even when the unknown-path probe
        was served the app shell (a catch-all route) or never ran because no in-scope path could serve it.
        """
        captured = [item for item in evidence if isinstance(item, HttpEvidence)]
        if not captured:
            return []
        baseline = captured[0]
        surface = _origin_of(baseline.http.request.url)
        probe = next(
            (item for item in captured if urlsplit(item.http.request.url).path.endswith(UNKNOWN_PROBE_PATH)), None
        )
        if probe is None:
            return [
                CoverageEntry(
                    surface=surface,
                    risk_area=ERROR_PAGE_RISK,
                    outcome='not_applicable',
                    source='check_observed',
                    evidence_ids=[baseline.id],
                    reason='error handler not exercised: the unknown-path probe was refused by the engagement scope',
                )
            ]
        if is_catch_all(baseline, probe):
            return [
                CoverageEntry(
                    surface=surface,
                    risk_area=ERROR_PAGE_RISK,
                    outcome='not_applicable',
                    source='check_observed',
                    evidence_ids=[probe.id, baseline.id],
                    reason=(
                        'catch-all route: unknown paths return the application shell, so the server error '
                        'handler was not reached; try an unknown path under an API prefix the app exposes'
                    ),
                )
            ]
        if self._error_draft(probe) is not None:
            outcome, reason = 'reported', 'the error response disclosed stack traces or internal paths'
        else:
            outcome, reason = 'no_issue_found', 'the unknown-path probe reached an error response with no disclosure'
        return [
            CoverageEntry(
                surface=surface,
                risk_area=ERROR_PAGE_RISK,
                outcome=outcome,  # pyright: ignore[reportArgumentType]
                source='check_observed',
                evidence_ids=[probe.id],
                reason=reason,
            )
        ]

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

    def verify_match_all(self, finding: Finding, original: HttpEvidence, replays: Sequence[HttpEvidence]) -> bool:
        """Confirmed iff any replay still exhibits the finding's class (the recipe is a single re-send)."""
        return any(self.verify_match(finding, original, replay) for replay in replays)

    def verify_match(self, finding: Finding, original: HttpEvidence, replay: HttpEvidence) -> bool:
        """Confirmed iff the replay still exhibits the finding's class (skill §3)."""
        if finding.subject.startswith('header:'):
            header = finding.subject.removeprefix('header:')
            value = get_header(replay.http.response.headers, header)
            return value is not None and bool(_VERSION_DIGITS.search(value))
        if finding.subject == 'error-page':
            return discloses_error_details(replay.http.response.status_code, replay.http.response.body)
        return False


version_disclosure_check = VersionDisclosureCheck()
