"""Scope model matching — the code-enforced attack-surface boundary. PLAN §4.2 rules 1–3.

Pure parsing and matching: no sockets, no target client.  The send-time gate
in ``target.py`` calls :func:`check_url` immediately before every request, so a
URL that fails any rule here never reaches the network.

Canonicalization policy (DEPS.md §3.5): be conservative.  Where a hostile URL
is ambiguous under RFC 3986 vs WHATWG semantics (backslashes, userinfo,
percent-encoded hosts, control characters, unbracketed IPv6), refuse rather
than guess — a refusal costs one blocked request, a wrong guess costs scope
bypass.  A URL is in scope only when *every* interpretation a server might
apply (raw, percent-decoded, dot-segment-resolved) is in scope.
"""

import ipaddress
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .errors import ScopeViolation
from .models import Scope

# E3 hard ceilings (PLAN §4.1): positive values with a hard upper bound so a
# mistyped engagement cannot grant runaway budgets.
MAX_RPS_CEILING = 64
MAX_REQUESTS_CEILING = 100_000

_HTTP_SCHEMES = frozenset({'http', 'https'})
_DEFAULT_PORTS: dict[str, int] = {'http': 80, 'https': 443}

# Cc/Cf/Zs/Zl/Zp: control, format (zero-width), and separator characters.
# Browsers strip or ignore several of these; refusing keeps partex's idea of
# the URL identical to the parser's.
_FORBIDDEN_CATEGORIES = frozenset({'Cc', 'Cf', 'Zs', 'Zl', 'Zp'})


@dataclass(frozen=True, slots=True)
class ScopedUrl:
    """A conservatively parsed URL in comparison-ready form.

    ``candidate_paths`` holds every path interpretation a server might apply
    to the same request: the raw path, the percent-decoded path, and both with
    dot segments resolved.  All of them must pass the scope rules.
    """

    scheme: str
    host: str
    port: int
    path: str
    candidate_paths: frozenset[str]


def _refuse(detail: str) -> ScopeViolation:
    return ScopeViolation(f'URL refused: {detail}', rule_code='scope-invalid')


def _check_no_forbidden_chars(url: str) -> None:
    for char in url:
        if ord(char) < 0x20 or ord(char) == 0x7F or unicodedata.category(char) in _FORBIDDEN_CATEGORIES:
            raise _refuse(f'control or separator character in URL ({char!r})')


def normalize_host(host: str) -> str:
    """Return the comparison form of *host* — the identity used for exact matching.

    Lowercases, strips one trailing dot, percent-decodes, unbrackets IPv6,
    and IDNA-encodes internationalized names so Unicode and punycode forms of
    the same host collapse to one identity.  Raises :class:`ScopeViolation` for
    anything that is not a bare host (userinfo, ports, slashes, empty labels).
    """
    if not host:
        raise _refuse('empty host')
    if '%' in host:
        host = unquote(host)
        if '%' in host:
            raise _refuse(f'unresolved percent-escape in host {host!r}')
    if host.startswith('['):
        if not host.endswith(']'):
            raise _refuse(f'malformed IPv6 literal {host!r}')
        inner = host[1:-1]
        try:
            return str(ipaddress.IPv6Address(inner))
        except ValueError:
            raise _refuse(f'invalid IPv6 literal {inner!r}') from None
    host = host.removesuffix('.')
    if not host:
        raise _refuse('host reduces to empty')
    host = host.lower()
    for char in host:
        if ord(char) < 0x20 or ord(char) == 0x7F or unicodedata.category(char) in _FORBIDDEN_CATEGORIES:
            raise _refuse(f'control or separator character in host ({char!r})')
    if ':' in host:
        # Scope entries may name a bare IPv6 address (URLs must bracket them —
        # the ambiguity is refused in parse_scoped_url before we get here).
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError:
            raise _refuse(f'host {host!r} contains port or unbracketed IPv6 syntax') from None
    if '/' in host or '\\' in host or '@' in host:
        raise _refuse(f'host {host!r} contains path or userinfo syntax')
    if not host.isascii():
        try:
            host = host.encode('idna').decode('ascii')
        except UnicodeError:
            raise _refuse(f'unparseable internationalized host {host!r}') from None
    if any(not label for label in host.split('.')):
        raise _refuse(f'empty label in host {host!r}')
    return host


def _remove_dot_segments(path: str) -> str:
    """Resolve ``.`` and ``..`` segments per RFC 3986 §5.2.4 (conservative form)."""
    output: list[str] = []
    for segment in path.split('/'):
        if segment == '.':
            continue
        if segment == '..':
            if len(output) > 1:
                output.pop()
            continue
        output.append(segment)
    result = '/'.join(output) or '/'
    if not result.startswith('/'):
        result = '/' + result
    return result


def parse_scoped_url(url: str) -> ScopedUrl:
    """Parse *url* conservatively, refusing every ambiguous form.

    Refused outright: non-HTTP schemes, backslashes (browsers reinterpret them
    as path separators), userinfo, unbracketed IPv6, control/format/separators,
    non-absolute paths, and malformed ports.
    """
    _check_no_forbidden_chars(url)
    if '\\' in url:
        raise _refuse('backslash in URL (ambiguous path separator)')
    try:
        parts = urlsplit(url)
    except ValueError:
        raise _refuse('unparseable URL') from None
    scheme = parts.scheme.lower()
    if scheme not in _HTTP_SCHEMES:
        raise _refuse(f'non-HTTP scheme {scheme!r}')
    netloc = parts.netloc
    if not netloc:
        raise _refuse('missing authority')
    if '@' in netloc:
        raise _refuse('userinfo in authority')
    if netloc.startswith('['):
        close = netloc.find(']')
        if close == -1:
            raise _refuse('malformed IPv6 authority')
        host_part, port_part = netloc[: close + 1], netloc[close + 1 :]
        if port_part:
            if not port_part.startswith(':'):
                raise _refuse(f'garbage after IPv6 literal {port_part!r}')
            port_part = port_part[1:]
    elif netloc.count(':') > 1:
        raise _refuse('unbracketed IPv6 address')
    elif ':' in netloc:
        host_part, _, port_part = netloc.rpartition(':')
    else:
        host_part, port_part = netloc, ''
    host = normalize_host(host_part)
    if port_part:
        if not port_part.isdigit() or not 0 < int(port_part) < 65536:
            raise _refuse(f'invalid port {port_part!r}')
        port = int(port_part)
    else:
        port = _DEFAULT_PORTS[scheme]
    raw_path = parts.path or '/'
    if not raw_path.startswith('/'):
        raise _refuse(f'path {raw_path!r} is not absolute')
    decoded_path = unquote(raw_path)
    candidate_paths = frozenset(
        {raw_path, decoded_path, _remove_dot_segments(raw_path), _remove_dot_segments(decoded_path)}
    )
    return ScopedUrl(scheme=scheme, host=host, port=port, path=raw_path, candidate_paths=candidate_paths)


def _path_allowed(scope: Scope, path: str) -> bool:
    """Return whether *path* matches an allowed prefix and no exclusion.

    Exclusions win over prefixes (PLAN §4.2 rule 3).
    """
    for exclusion in scope.exclusions:
        if path.startswith(exclusion):
            return False
    if not scope.path_prefixes:
        return True
    return any(path.startswith(prefix) for prefix in scope.path_prefixes)


def check_url(scope: Scope, url: str) -> None:
    """Refuse *url* unless every interpretation of it lies inside *scope*.

    Raises :class:`ScopeViolation` (before any bytes hit the wire) when the
    scheme, effective port, host, or any candidate path falls outside scope.
    An empty ``ports`` list allows only the scheme defaults (80/443) — never
    an arbitrary explicit port.
    """
    view = parse_scoped_url(url)
    allowed_hosts = {normalize_host(h) for h in scope.hosts}
    if view.host not in allowed_hosts:
        raise ScopeViolation(f'host {view.host!r} not in scope hosts', rule_code='scope-invalid')
    allowed_ports = set(scope.ports) if scope.ports else {80, 443}
    if view.port not in allowed_ports:
        raise ScopeViolation(f'port {view.port} not in scope ports {sorted(allowed_ports)}', rule_code='scope-invalid')
    for path in view.candidate_paths:
        if not _path_allowed(scope, path):
            raise ScopeViolation(f'path {path!r} matches no allowed prefix or an exclusion', rule_code='scope-invalid')


def validate_scope(scope: Scope) -> list[str]:
    """Return the E3 structural violations of *scope* (empty when valid).

    Checks: at least one parseable host, absolute path entries, exclusions
    within path prefixes, and budget ceilings.  The caller decides the failure
    mode (engagement loading raises ``scope-invalid``).
    """
    problems: list[str] = []
    for host in scope.hosts:
        try:
            normalize_host(host)
        except ScopeViolation as exc:
            problems.append(f'host {host!r}: {exc}')
    for field_name in ('path_prefixes', 'exclusions'):
        for entry in getattr(scope, field_name):
            if not entry or not entry.startswith('/'):
                problems.append(f'{field_name} entry {entry!r} must be an absolute path')
    for exclusion in scope.exclusions:
        if scope.path_prefixes and not any(exclusion.startswith(p) for p in scope.path_prefixes):
            problems.append(f'exclusion {exclusion!r} is not within any path prefix')
    if scope.max_rps > MAX_RPS_CEILING:
        problems.append(f'max_rps {scope.max_rps} exceeds ceiling {MAX_RPS_CEILING}')
    if scope.max_requests > MAX_REQUESTS_CEILING:
        problems.append(f'max_requests {scope.max_requests} exceeds ceiling {MAX_REQUESTS_CEILING}')
    return problems
