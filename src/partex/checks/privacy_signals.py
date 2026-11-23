"""privacy-signals — built-in passive check for third-party tracker SDKs and missing consent signals (#224).

Pure function over validated evidence: no network, model or storage access.  Registered via the
``partex.checks`` entry point.  Guidance and the human-readable signature table live in
``skills/privacy-review/``; this module carries the same signatures as data so the check never imports
or executes anything under ``skills/`` (``tests/test_check_privacy_signals.py`` keeps the two in step).

What it reports are *static signals*, never compliance verdicts:

* a tracker, analytics, session-replay, error-monitoring, advertising, support-chat or CAPTCHA SDK that a
  captured page, script or runtime config references (one finding per vendor, every source cited);
* "no consent-management signal in the static evidence" when non-essential trackers (analytics, session
  replay, advertising) are referenced and no consent platform is.  That is a limitation of static
  evidence (a consent flow may load later or live server-side), so it is worded as one.

A bare vendor name is never proof: markers are loader URLs, init calls, config fields or ingest hosts.
A finding needs at least one *strong* marker; *weak* markers only corroborate.  Matched text is never
copied into a finding (it can contain a project key); only the marker's label is.
"""

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Literal

from ..models import Evidence, FindingDraft, HttpEvidence, Severity, get_header
from .js_analysis import iter_js_sources

CHECK_ID = 'privacy-signals'
CHECK_VERSION = '1.1'
CHECK_TITLE = 'Privacy Signals: Trackers and Consent'
CHECK_DESCRIPTION = (
    'Flag third-party tracker, analytics, session-replay, error-monitoring, advertising, support-chat and CAPTCHA '
    'SDKs referenced by captured pages, scripts and runtime config, and note when no consent-management signal '
    'accompanies non-essential ones. Static signals only, never a compliance verdict.'
)

type Category = Literal['analytics', 'session-replay', 'error-monitoring', 'advertising', 'support-chat', 'captcha']

_NON_ESSENTIAL: frozenset[Category] = frozenset({'analytics', 'session-replay', 'advertising'})
_SEVERITY: dict[Category, Severity] = {
    'analytics': 'info',
    'session-replay': 'low',
    'error-monitoring': 'info',
    'advertising': 'low',
    'support-chat': 'info',
    'captcha': 'info',
}

MAX_SCAN_CHARS = 2_000_000
"""Characters of one source scanned (the capture caps bodies well below this; it bounds a pathological asset)."""


@dataclass(frozen=True, slots=True)
class Marker:
    label: str
    """What the finding says was seen (never the matched text, which can embed a project key)."""
    pattern: re.Pattern[str]
    strong: bool = True


@dataclass(frozen=True, slots=True)
class Tracker:
    vendor: str
    category: Category
    markers: tuple[Marker, ...]


def _m(label: str, pattern: str, *, strong: bool = True) -> Marker:
    return Marker(label, re.compile(pattern), strong)


# Signature data (mirrored in skills/privacy-review/reference/tracker-signatures.md). Markers are loader URLs,
# init calls, config fields or ingest hosts: a vendor word alone ("amplitude" as an SVG attribute, "Intercom" as a
# hardware product name) matched nothing in the corpus that motivated this check and must not start to.
TRACKERS: tuple[Tracker, ...] = (
    Tracker(
        'Google Tag Manager',
        'analytics',
        (
            _m('googletagmanager.com/gtm.js loader', r'googletagmanager\.com/gtm\.js'),
            _m('GTM container ID', r'\bGTM-[A-Z0-9]{5,}\b', strong=False),
        ),
    ),
    Tracker(
        'Google tag / Analytics (gtag.js)',
        'analytics',
        (
            _m('googletagmanager.com/gtag/js loader', r'googletagmanager\.com/gtag/js'),
            _m('google-analytics.com endpoint', r'google-analytics\.com/(?:analytics|ga|collect|g/collect)'),
            _m('gtag config call', r"""\bgtag\(\s*['"]config['"]"""),
            _m('GA4 measurement ID', r"""['"]G-[A-Z0-9]{8,12}['"]""", strong=False),
        ),
    ),
    Tracker(
        'Sentry',
        'error-monitoring',
        (
            _m('Sentry ingest host', r'ingest(?:\.[a-z]{2})?\.sentry\.io'),
            _m('Sentry.init call', r'\bSentry\.init\('),
            _m('@sentry SDK package', r'@sentry/(?:browser|react|vue|angular|nextjs|node|core)\b', strong=False),
        ),
    ),
    Tracker(
        'Amplitude',
        'analytics',
        (
            _m('Amplitude CDN or API host', r'(?:cdn|api2?)\.amplitude\.com'),
            _m('Amplitude init call', r'\bamplitude\.(?:getInstance\(\)\.init|init)\('),
            _m('@amplitude SDK package', r'@amplitude/analytics', strong=False),
        ),
    ),
    Tracker(
        'PostHog',
        'analytics',
        (
            _m('PostHog host', r'(?:us|eu)\.i\.posthog\.com|app\.posthog\.com'),
            _m('posthog.init call', r'\bposthog\.init\('),
            _m('posthogApiKey config field', r'\bposthogApiKey\b'),
            _m('PostHog project key', r'\bphc_[A-Za-z0-9]{20,}\b'),
            _m('PostHog source-map chunk marker', r'\b_posthogChunkIds\b', strong=False),
        ),
    ),
    Tracker(
        'Segment',
        'analytics',
        (
            _m('Segment CDN', r'cdn\.segment\.(?:com|io)/analytics\.js'),
            _m('Segment load call', r'\banalytics\.load\(', strong=False),
        ),
    ),
    Tracker(
        'Mixpanel',
        'analytics',
        (
            _m('Mixpanel host', r'cdn\.mxpnl\.com|api(?:-eu)?\.mixpanel\.com'),
            _m('mixpanel.init call', r'\bmixpanel\.init\('),
        ),
    ),
    Tracker(
        'Heap',
        'analytics',
        (_m('Heap loader', r'cdn\.heapanalytics\.com'), _m('heap.load call', r'\bheap\.load\(')),
    ),
    Tracker(
        'Microsoft Clarity',
        'session-replay',
        (_m('Clarity tag', r'clarity\.ms/tag'),),
    ),
    Tracker(
        'Hotjar',
        'session-replay',
        (_m('Hotjar loader', r'static\.hotjar\.com'), _m('Hotjar settings object', r'\b_hjSettings\b')),
    ),
    Tracker(
        'FullStory',
        'session-replay',
        (
            _m('FullStory loader', r'fullstory\.com/s/fs\.js|edge\.fullstory\.com'),
            _m('_fs_host setting', r'\b_fs_host\b'),
        ),
    ),
    Tracker(
        'LogRocket',
        'session-replay',
        (
            _m('LogRocket loader', r'cdn\.logrocket\.io|cdn\.lgrckt-in\.com'),
            _m('LogRocket.init call', r'\bLogRocket\.init\('),
        ),
    ),
    Tracker(
        'Datadog RUM',
        'session-replay',
        (
            _m('Datadog browser agent', r'datadoghq-browser-agent\.com'),
            _m('Datadog RUM init call', r'\b(?:DD_RUM|datadogRum)\.init\('),
        ),
    ),
    Tracker(
        'Meta (Facebook) Pixel',
        'advertising',
        (
            _m('Meta pixel loader', r'connect\.facebook\.net/[^"\'\s]*/fbevents\.js'),
            _m('fbq init call', r"""\bfbq\(\s*['"]init['"]"""),
        ),
    ),
    Tracker(
        'LinkedIn Insight Tag',
        'advertising',
        (
            _m('LinkedIn Insight loader', r'snap\.licdn\.com/li\.lms-analytics'),
            _m('LinkedIn partner ID', r'\b_linkedin_partner_id\b'),
        ),
    ),
    Tracker(
        'X (Twitter) Pixel',
        'advertising',
        (
            _m('X pixel loader', r'static\.ads-twitter\.com/uwt\.js'),
            _m('twq config call', r"""\btwq\(\s*['"]config['"]"""),
        ),
    ),
    Tracker(
        'TikTok Pixel',
        'advertising',
        (_m('TikTok analytics host', r'analytics\.tiktok\.com'), _m('ttq.load call', r'\bttq\.load\(')),
    ),
    Tracker(
        'HubSpot',
        'advertising',
        (
            _m('HubSpot loader', r'js\.hs-(?:scripts|analytics)\.(?:net|com)'),
            _m('_hsq queue', r'\b_hsq\b', strong=False),
        ),
    ),
    Tracker(
        'Intercom',
        'support-chat',
        (
            _m('Intercom widget host', r'widget\.intercom\.io|js\.intercomcdn\.com'),
            _m('intercomSettings object', r'\bwindow\.intercomSettings\b'),
            _m('Intercom boot call', r"""\bIntercom\(\s*['"]boot['"]"""),
        ),
    ),
    Tracker(
        'Google reCAPTCHA',
        'captcha',
        (
            _m('reCAPTCHA loader', r'google\.com/recaptcha/(?:api|enterprise)\.js|recaptcha\.net/recaptcha'),
            _m('grecaptcha call', r'\bgrecaptcha\.(?:execute|render|ready)\(', strong=False),
        ),
    ),
    Tracker(
        'hCaptcha / Turnstile',
        'captcha',
        (
            _m('hCaptcha loader', r'hcaptcha\.com/1/api\.js'),
            _m('Turnstile loader', r'challenges\.cloudflare\.com/turnstile'),
        ),
    ),
)

# Consent-management platforms and cookie-banner markers. Any one in any captured source counts as a consent signal.
CONSENT_MARKERS: tuple[Marker, ...] = (
    _m('OneTrust', r'cdn\.cookielaw\.org|\bOptanonConsent\b|\bOneTrust\b'),
    _m('Cookiebot', r'consent\.cookiebot\.com|\bCookiebot\b'),
    _m('Osano', r'cmp\.osano\.com'),
    _m('Usercentrics', r'usercentrics\.eu|app\.usercentrics'),
    _m('TrustArc', r'consent\.trustarc\.com|\btrustarc\b'),
    _m('Didomi', r'sdk\.privacy-center\.org|\bDidomi\b'),
    _m('Quantcast Choice', r'quantcast\.mgr\.consensu\.org|\bquantcastChoice\b'),
    _m('Termly', r'app\.termly\.io'),
    _m('Klaro', r'\bklaro\.(?:js|config)\b|\bklaroConfig\b'),
    _m('cookieconsent', r'cookieconsent(?:\.min)?\.(?:js|css)|\bwindow\.cookieconsent\b'),
    _m('IAB TCF API', r'\b__tcfapi\b'),
    _m('Google Consent Mode', r"""\bgtag\(\s*['"]consent['"]"""),
)


@dataclass(slots=True)
class _Source:
    evidence_id: str
    url: str
    text: str


def _sources(evidence: Sequence[Evidence]) -> Iterator[_Source]:
    """Every readable body worth scanning: JavaScript (inline, downloaded or response) and 2xx HTTP bodies."""
    seen: set[str] = set()
    for evidence_id, url, data in iter_js_sources(evidence):
        seen.add(evidence_id)
        yield _Source(evidence_id, url, data.decode('utf-8', 'replace')[:MAX_SCAN_CHARS])
    for item in evidence:
        if not isinstance(item, HttpEvidence) or item.id in seen:
            continue
        response = item.http.response
        if not 200 <= response.status_code < 300 or not response.body:
            continue
        content_type = (get_header(response.headers, 'content-type') or '').lower()
        if content_type and not any(kind in content_type for kind in ('html', 'json', 'javascript', 'text', 'xml')):
            continue
        yield _Source(item.id, item.http.request.url, response.body[:MAX_SCAN_CHARS])


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of *url* with no path, query, fragment or userinfo (what a finding may show)."""
    match = re.match(r'(?i)^([a-z][a-z0-9+.-]*)://(?:[^/@]*@)?([^/?#]+)', url)
    return f'{match.group(1).lower()}://{match.group(2).lower()}' if match else 'unknown-origin'


def _slug(vendor: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', vendor.lower()).strip('-')


class PrivacySignalsCheck:
    """Passive check: tracker SDK references and the presence or absence of consent signals."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        """Applies when some captured response carries a body that could reference a tracker."""
        return any(True for _ in _sources(evidence))

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        found: dict[str, tuple[Tracker, list[str], set[str], set[str]]] = {}
        consent_seen = False
        for source in _sources(evidence):
            if not consent_seen and any(marker.pattern.search(source.text) for marker in CONSENT_MARKERS):
                consent_seen = True
            for tracker in TRACKERS:
                hits = [marker for marker in tracker.markers if marker.pattern.search(source.text)]
                if not any(marker.strong for marker in hits):
                    continue  # weak markers only corroborate; a bare weak hit is not proof
                _, ids, origins, labels = found.setdefault(tracker.vendor, (tracker, [], set(), set()))
                if source.evidence_id not in ids:
                    ids.append(source.evidence_id)
                origins.add(_origin(source.url))
                labels.update(marker.label for marker in hits)

        # Deterministic output: findings follow TRACKERS declaration order and cite evidence IDs sorted,
        # so the drafts are a pure function of the evidence set, not of the order it was captured in (issue #228).
        drafts: list[FindingDraft] = []
        for tracker in TRACKERS:
            if tracker.vendor not in found:
                continue
            _, ids, origins, labels = found[tracker.vendor]
            drafts.append(
                FindingDraft(
                    check_id=CHECK_ID,
                    check_version=CHECK_VERSION,
                    severity=_SEVERITY[tracker.category],
                    subject=f'tracker:{_slug(tracker.vendor)}',
                    title=f'Third-party {tracker.category} SDK referenced: {tracker.vendor}',
                    description=(
                        f'{len(ids)} captured source(s) from {", ".join(sorted(origins))} reference {tracker.vendor} '
                        f'({tracker.category}). Signals seen: {"; ".join(sorted(labels))}. This is a static signal that '
                        'the application may send visitor data to a third party; it does not show what is sent or '
                        'whether it happens before consent.'
                    ),
                    evidence_ids=sorted(ids),
                    remediation=(
                        'Confirm the SDK is intended and disclosed in the privacy notice, that it loads only after '
                        'consent where one is required, and that the data it receives is minimized.'
                    ),
                )
            )

        non_essential = [(t, ids) for t, ids, _, _ in found.values() if t.category in _NON_ESSENTIAL]
        if non_essential and not consent_seen:
            ids = sorted({i for _, group in non_essential for i in group})
            vendors = ', '.join(sorted(t.vendor for t, _ in non_essential))
            drafts.append(
                FindingDraft(
                    check_id=CHECK_ID,
                    check_version=CHECK_VERSION,
                    severity='info',
                    subject='consent:no-cmp-signal',
                    title='No consent-management signal observed alongside non-essential trackers',
                    description=(
                        f'Non-essential trackers are referenced ({vendors}) but none of the captured pages, scripts '
                        'or configs contains a consent-management platform signature or a consent API call. This is '
                        'a limitation of static evidence, not proof that no consent is requested: a consent flow may '
                        'load later, depend on region, or live server-side. Confirm in a browser session.'
                    ),
                    evidence_ids=sorted(ids),
                    remediation=(
                        'Check in a real browser, with a clean profile and from each relevant region, whether '
                        'non-essential trackers load before the visitor chooses.'
                    ),
                )
            )
        return drafts


privacy_signals_check = PrivacySignalsCheck()
