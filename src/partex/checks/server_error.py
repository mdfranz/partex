"""server-error — built-in passive check for unhandled server errors (5xx responses).

Issue #128.  Pure function over validated evidence: no I/O, network, model or storage access.
Registered via the ``partex.checks`` entry point.  Guidance lives in ``skills/server-error/``.

Operator- or agent-directed probes (malformed parameters, unexpected types) often provoke
HTTP 500s that nothing else records.  This check flags every captured 5xx response (CWE-755,
improper handling of exceptional conditions) and rates it higher when the body looks like a
stack trace or framework debug page (CWE-209, error message with sensitive information).

Findings aggregate **per host and path pattern**: numeric, UUID and long-hex path segments
collapse to ``{id}``, so fuzzing ``/api/users/1`` … ``/api/users/900`` yields one finding with
every affected evidence ID attached rather than one per request.
"""

import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from ..models import Evidence, FindingDraft, HttpEvidence, Severity

CHECK_ID = 'server-error'
CHECK_VERSION = '1.0'
CHECK_TITLE = 'Unhandled Server Errors'
CHECK_DESCRIPTION = (
    'Flag 5xx responses captured from the target, rated higher when the body discloses a stack '
    'trace or framework debug page, grouped by host and path pattern.'
)

# Gateway/availability statuses usually reflect infrastructure, not an unhandled application
# exception, so they are informational unless the body itself discloses internals.
_GATEWAY_STATUSES = frozenset({502, 503, 504})

# Stack-trace and debug-page markers (skills/server-error/SKILL.md). Data, not code.
DEBUG_MARKERS = (
    'Traceback (most recent call last):',
    "You're seeing this error because you have DEBUG = True",
    'Werkzeug Debugger',
    'Whitelabel Error Page',
    'at java.lang.',
    'at org.springframework.',
    'Exception in thread "',
    'System.NullReferenceException',
    'NullReferenceException',
    "Server Error in '/' Application",
    'Stack trace:',
    'Fatal error:',
    'ActionController::',
    'goroutine ',
    '/var/www/',
    '/usr/lib/python',
    'C:\\inetpub\\',
    'node_modules/',
)

_NUMERIC = re.compile(r'\d+')
_UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
_LONG_HEX = re.compile(r'[0-9a-fA-F]{16,}')

_SEVERITY_RANK: dict[Severity, int] = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def _host_of(url: str) -> str:
    """Lowercase host with an explicit non-default port (the aggregation identity)."""
    parts = urlsplit(url)
    host = (parts.hostname or '').lower()
    if not host:
        return url
    return f'{host}:{parts.port}' if parts.port is not None else host


def path_pattern(url: str) -> str:
    """The URL path with identifier-like segments collapsed to ``{id}`` (query string ignored)."""
    segments = [
        '{id}' if _NUMERIC.fullmatch(seg) or _UUID.fullmatch(seg) or _LONG_HEX.fullmatch(seg) else seg
        for seg in urlsplit(url).path.split('/')
    ]
    return '/'.join(segments) or '/'


def discloses_internals(body: str | None) -> bool:
    """Whether a response body looks like a stack trace or framework debug page."""
    return bool(body) and any(marker in (body or '') for marker in DEBUG_MARKERS)


def _severity(status: int, debug: bool) -> Severity:
    if debug:
        return 'medium'
    return 'info' if status in _GATEWAY_STATUSES else 'low'


class ServerErrorCheck:
    """Passive check: 5xx responses across captured HTTP exchanges."""

    check_id = CHECK_ID
    version = CHECK_VERSION
    title = CHECK_TITLE
    description = CHECK_DESCRIPTION

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        """Applies if any captured response has a 5xx status."""
        return any(isinstance(ev, HttpEvidence) and 500 <= ev.http.response.status_code <= 599 for ev in evidence)

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        """One draft per (host, path pattern), citing every 5xx exchange in the group."""
        groups: dict[tuple[str, str], list[HttpEvidence]] = {}
        for ev in evidence:
            if isinstance(ev, HttpEvidence) and 500 <= ev.http.response.status_code <= 599:
                groups.setdefault((_host_of(ev.http.request.url), path_pattern(ev.http.request.url)), []).append(ev)

        drafts: list[FindingDraft] = []
        for (host, pattern), group in groups.items():
            severity: Severity = 'info'
            debug_count = 0
            for ev in group:
                debug = discloses_internals(ev.http.response.body)
                debug_count += debug
                level = _severity(ev.http.response.status_code, debug)
                if _SEVERITY_RANK[level] > _SEVERITY_RANK[severity]:
                    severity = level
            statuses = sorted({ev.http.response.status_code for ev in group})
            methods = sorted({ev.http.request.method for ev in group})
            description = (
                f'{len(group)} captured response(s) from {host} for {"/".join(methods)} {pattern} returned '
                f'HTTP {", ".join(map(str, statuses))}, an unhandled server-side error condition (CWE-755).'
            )
            if debug_count:
                description += (
                    f' {debug_count} response(s) expose a stack trace or framework debug page, disclosing '
                    'internal details (CWE-209).'
                )
            drafts.append(
                FindingDraft(
                    check_id=CHECK_ID,
                    check_version=CHECK_VERSION,
                    severity=severity,
                    subject=f'route:{host}{pattern}',
                    title='Unhandled server error (5xx) response',
                    description=description,
                    evidence_ids=[ev.id for ev in group],
                    remediation=(
                        'Validate input and handle exceptions so the endpoint returns a 4xx for bad requests; '
                        'disable debug pages in production and log error details server-side only.'
                    ),
                )
            )
        return drafts


server_error_check = ServerErrorCheck()
