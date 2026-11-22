"""Tests for the privacy-signals passive check (issue #224).

Hermetic: the check is a pure function over validated evidence. Fixtures mirror what a real corpus showed: real
tracker markers (GTM/gtag loader, Sentry ingest host, a PostHog config key) and the false positives the signatures
must not start matching ("amplitude" as an SVG attribute, "Intercom" as a hardware product name).
"""

import re
from pathlib import Path

from partex.checks.privacy_signals import CONSENT_MARKERS, TRACKERS, PrivacySignalsCheck
from partex.ids import evidence_id
from partex.models import HttpEvidence, HttpExchange, HttpRequest, HttpResponse

check = PrivacySignalsCheck()
SIGNATURE_DOC = Path(__file__).parent.parent / 'skills' / 'privacy-review' / 'reference' / 'tracker-signatures.md'


def _http(
    body: str, url: str = 'https://app.test/main.js', content_type: str = 'application/javascript'
) -> HttpEvidence:
    ev = HttpEvidence(
        id='placeholder',
        source='test',
        http=HttpExchange(
            request=HttpRequest(method='GET', url=url, headers=[]),
            response=HttpResponse(status_code=200, headers=[('Content-Type', content_type)], body=body),
        ),
    )
    ev.id = evidence_id(ev)
    return ev


def _subjects(evidence: list[HttpEvidence]) -> dict[str, str]:
    return {draft.subject: draft.severity for draft in check.review(evidence)}


def test_real_loaders_and_hosts_are_reported_one_finding_per_vendor() -> None:
    gtag = _http('s.src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEFGH12";gtag("config","G-ABCDEFGH12")')
    sentry = _http('dsn:"https://k@o1.ingest.sentry.io/2"', url='https://app.test/vendor.js')
    drafts = {d.subject: d for d in check.review([gtag, sentry])}
    assert set(drafts) == {
        'tracker:google-tag-analytics-gtag-js',
        'tracker:sentry',
        'consent:no-cmp-signal',
    }
    assert drafts['tracker:sentry'].evidence_ids == [sentry.id]
    assert drafts['tracker:google-tag-analytics-gtag-js'].severity == 'info'


def test_findings_never_copy_matched_text_such_as_keys_or_ids() -> None:
    key = 'phc_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4'
    ev = _http(f"window.config = {{ posthogApiKey: '{key}' }}", url='https://app.test/config.js')
    drafts = check.review([ev])
    assert any(d.subject == 'tracker:posthog' for d in drafts)
    for draft in drafts:
        assert key not in draft.description and key not in draft.title
        assert 'G-ABCDEFGH12' not in draft.description


def test_vendor_words_that_are_not_trackers_do_not_fire() -> None:
    # "amplitude" as an SVG attribute name, "Intercom" as a hardware product, "posthog" in a build comment.
    svg = _http('{alphabetic:1,amplitude:2,arabicForm:3}')
    product = _http('{title:"UniFi Access G3 Intercom",mapping:["/ua-g3-intercom"]}')
    comment = _http('/* bundled for posthog-style dashboards */ var x = 1;')
    assert check.review([svg, product, comment]) == []


def test_weak_marker_alone_is_not_enough() -> None:
    assert check.review([_http('e._posthogChunkIds=e._posthogChunkIds||{}')]) == []
    assert check.review([_http('"GTM-ABCDEF"')]) == []


def test_session_replay_and_advertising_are_low_error_monitoring_is_info() -> None:
    evidence = [
        _http(
            '<script src="https://static.hotjar.com/c/hotjar-1.js"></script>',
            url='https://app.test/',
            content_type='text/html',
        ),
        _http('fbq("init","123")', url='https://app.test/fb.js'),
        _http('Sentry.init({})', url='https://app.test/s.js'),
    ]
    subjects = _subjects(evidence)
    assert subjects['tracker:hotjar'] == 'low'
    assert subjects['tracker:meta-facebook-pixel'] == 'low'
    assert subjects['tracker:sentry'] == 'info'


def test_consent_platform_suppresses_the_missing_consent_note() -> None:
    tracker = _http('posthog.init("k")')
    cmp = _http(
        '<script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>',
        url='https://app.test/',
        content_type='text/html',
    )
    assert 'consent:no-cmp-signal' in _subjects([tracker])
    assert 'consent:no-cmp-signal' not in _subjects([tracker, cmp])


def test_essential_only_trackers_do_not_trigger_the_consent_note() -> None:
    subjects = _subjects(
        [
            _http('Sentry.init({}); grecaptcha.execute("k")'),
            _http('<script src="https://www.google.com/recaptcha/api.js"></script>', content_type='text/html'),
        ]
    )
    assert 'consent:no-cmp-signal' not in subjects


def test_consent_finding_is_worded_as_a_static_evidence_limit() -> None:
    [*_, consent] = [d for d in check.review([_http('mixpanel.init("t")')]) if d.subject == 'consent:no-cmp-signal']
    assert 'limitation of static evidence' in consent.description
    assert 'Confirm in a browser' in consent.description
    assert 'violat' not in consent.description.lower()


def test_non_2xx_and_binary_responses_are_ignored() -> None:
    err = _http('Sentry.init({})', url='https://app.test/missing')
    err.http.response.status_code = 404
    image = _http('Sentry.init({})', url='https://app.test/logo', content_type='image/png')
    assert not check.applies_to([err, image]) and check.review([err, image]) == []


def test_skill_signature_table_names_every_vendor_in_the_check() -> None:
    """Skills are data the check never imports; this keeps the human-readable table in step with the code."""
    table = SIGNATURE_DOC.read_text(encoding='utf-8')
    for tracker in TRACKERS:
        assert f'| {tracker.vendor} | {tracker.category} |' in table, tracker.vendor
    for marker in CONSENT_MARKERS:
        assert re.split(r'[ (]', marker.label)[0].lower() in table.lower(), marker.label
