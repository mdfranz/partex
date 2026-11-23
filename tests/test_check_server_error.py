"""Tests for the server-error passive check (issue #128).

Hermetic: the check is a pure function over validated evidence.
"""

from partex.checks.server_error import CHECK_ID, ServerErrorCheck, discloses_internals, path_pattern
from partex.ids import evidence_id
from partex.models import ConfigEvidence, HttpEvidence, HttpExchange, HttpRequest, HttpResponse

check = ServerErrorCheck()


def _http(url: str = 'https://api.test/users/1', status: int = 500, body: str | None = 'oops', method: str = 'GET'):
    ev = HttpEvidence(
        id='placeholder',
        source='test',
        http=HttpExchange(
            request=HttpRequest(method=method, url=url, headers=[]),
            response=HttpResponse(status_code=status, headers=[], body=body),
        ),
    )
    ev.id = evidence_id(ev)
    return ev


def test_clean_capture_has_no_findings_and_does_not_apply() -> None:
    evidence = [_http(status=200), _http(status=404), _http(status=302)]
    assert not check.applies_to(evidence)
    assert check.review(evidence) == []


def test_plain_500_is_low() -> None:
    ev = _http()
    [draft] = check.review([ev])
    assert (draft.check_id, draft.severity, draft.evidence_ids) == (CHECK_ID, 'low', [ev.id])
    assert draft.subject == 'route:api.test/users/{id}'
    assert 'CWE-755' in draft.description


def test_stack_trace_body_is_medium() -> None:
    ev = _http(body='Traceback (most recent call last):\n  File "app.py"')
    [draft] = check.review([ev])
    assert draft.severity == 'medium'
    assert 'CWE-209' in draft.description


def test_bare_whitelabel_error_page_stays_low_until_stack_trace_present() -> None:
    """Spring Boot Whitelabel template without stack frames is CWE-755 low, not CWE-209 medium (#204)."""
    assert not discloses_internals('<html><body><h1>Whitelabel Error Page</h1><p>500</p></body></html>')
    assert discloses_internals('Whitelabel Error Page\n    at java.lang.Thread.run(Thread.java:840)')

    bare = _http(body='<html><body><h1>Whitelabel Error Page</h1><p>Internal Server Error</p></body></html>')
    [bare_draft] = check.review([bare])
    assert bare_draft.severity == 'low'
    assert 'CWE-209' not in bare_draft.description

    with_trace = _http(
        body='Whitelabel Error Page\njava.lang.RuntimeException: boom\n\tat org.springframework.web.DispatcherServlet'
    )
    [trace_draft] = check.review([with_trace])
    assert trace_draft.severity == 'medium'
    assert 'CWE-209' in trace_draft.description


def test_gateway_statuses_are_info_unless_debug_body() -> None:
    [plain] = check.review([_http(status=503)])
    [debug] = check.review([_http(status=502, body='Werkzeug Debugger')])
    assert (plain.severity, debug.severity) == ('info', 'medium')


def test_groups_by_host_and_path_pattern() -> None:
    a, b = _http('https://api.test/users/1'), _http('https://api.test/users/2?x=1')
    c = _http('https://api.test/orders/7', body='Fatal error: boom')
    other = _http('https://other.test/users/1')
    drafts = check.review([a, b, c, other])
    by_subject = {d.subject: d for d in drafts}
    assert set(by_subject) == {'route:api.test/users/{id}', 'route:api.test/orders/{id}', 'route:other.test/users/{id}'}
    assert by_subject['route:api.test/users/{id}'].evidence_ids == [a.id, b.id]
    assert by_subject['route:api.test/users/{id}'].severity == 'low'
    assert by_subject['route:api.test/orders/{id}'].severity == 'medium'


def test_group_severity_is_the_maximum() -> None:
    quiet, loud = _http('https://api.test/u/1'), _http('https://api.test/u/2', body='at java.lang.Thread')
    [draft] = check.review([quiet, loud])
    assert draft.severity == 'medium' and draft.evidence_ids == [quiet.id, loud.id]


def test_non_http_evidence_is_ignored() -> None:
    config = ConfigEvidence.model_construct(id='ev_x', source='test')
    assert not check.applies_to([config])


def test_path_pattern_collapses_identifiers() -> None:
    assert path_pattern('https://x.test/a/42/b/123e4567-e89b-12d3-a456-426614174000?q=1') == '/a/{id}/b/{id}'
    assert path_pattern('https://x.test/') == '/'
    assert path_pattern('https://x.test/v2/users') == '/v2/users'
