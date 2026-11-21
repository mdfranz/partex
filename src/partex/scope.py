"""Scope model matching — the code-enforced attack-surface boundary. PLAN §4.2 rules 1–3.

Pure parsing and matching: no sockets, no target client.  The send-time gate
in ``target.py`` calls :func:`check_url` immediately before every request, so a
URL that fails any rule here never reaches the network.

Canonicalization policy (DEPS.md §3.5): be conservative.  Where a hostile URL
is ambiguous under RFC 3986 vs WHATWG semantics (backslashes, userinfo,
percent-encoded hosts, control characters, unbracketed IPv6), refuse rather
than guess — a refusal costs one blocked request, a wrong guess costs scope
bypass.  A URL is in scope only when *every* interpretation a server might
apply is in scope: raw, percent-decoded, dot segments resolved, repeated
slashes collapsed, ``;`` matrix parameters stripped, and trailing dots/spaces
stripped from segments (IIS/Windows), in every combination.

Matching is on path-segment boundaries: ``/api`` covers ``/api`` and
``/api/...`` but not ``/apix``; a prefix ending in ``/`` covers only its
children.  Exclusions match case-insensitively (any casing is excluded);
prefixes stay case-sensitive, so a differently-cased path is refused rather
than allowed.  A path still percent-encoded after one decode (double encoding)
or containing control/format characters once decoded is refused outright.
"""

import ipaddress
import re
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


_DOUBLE_ENCODED = re.compile(r'%[0-9A-Fa-f]{2}')
_REPEATED_SLASHES = re.compile(r'/{2,}')


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
    return '/'.join(output) or '/'  # output[0] is the empty segment before the leading '/', never popped


def _collapse_slashes(path: str) -> str:
    """``//`` and longer runs → ``/`` (most servers and frameworks normalize this way)."""
    return _REPEATED_SLASHES.sub('/', path)


def _strip_matrix_params(path: str) -> str:
    """Drop ``;param`` suffixes from every segment (Java servlet containers ignore them when routing)."""
    return '/'.join(segment.split(';', 1)[0] for segment in path.split('/'))


def _strip_trailing_dots_and_spaces(path: str) -> str:
    """Strip trailing ``.`` and space from every segment except ``.``/``..`` (IIS and Windows file APIs do)."""
    return '/'.join(segment if segment in ('.', '..') else segment.rstrip('. ') for segment in path.split('/'))


_PATH_INTERPRETATIONS = (
    _remove_dot_segments,
    _collapse_slashes,
    _strip_matrix_params,
    _strip_trailing_dots_and_spaces,
)


def _interpretations(*paths: str) -> frozenset[str]:
    """Every path reachable from *paths* by any sequence of the normalizations a server might apply."""
    seen: set[str] = set()
    pending = list(paths)
    while pending:
        path = pending.pop()
        if path not in seen:
            seen.add(path)
            pending.extend(normalize(path) for normalize in _PATH_INTERPRETATIONS)
    return frozenset(seen)  # every normalization keeps the leading '/' the raw path is required to have


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
        if close == -1:  # pragma: no cover -- urlsplit already raises 'Invalid IPv6 URL'; kept as a backstop
            raise _refuse('malformed IPv6 authority')
        host_part, port_part = netloc[: close + 1], netloc[close + 1 :]
        if port_part:
            if not port_part.startswith(':'):  # pragma: no cover -- urlsplit already raises; kept as a backstop
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
    if not raw_path.startswith('/'):  # pragma: no cover -- RFC 3986: a path after an authority is empty or absolute
        raise _refuse(f'path {raw_path!r} is not absolute')
    decoded_path = unquote(raw_path)
    if _DOUBLE_ENCODED.search(decoded_path):
        raise _refuse(f'path {raw_path!r} is still percent-encoded after one decode (double encoding)')
    for char in decoded_path:
        if ord(char) < 0x20 or ord(char) == 0x7F or unicodedata.category(char) in ('Cc', 'Cf'):
            raise _refuse(f'control or format character in decoded path ({char!r})')
    candidate_paths = _interpretations(raw_path, decoded_path)
    return ScopedUrl(scheme=scheme, host=host, port=port, path=raw_path, candidate_paths=candidate_paths)


def path_under(path: str, prefix: str) -> bool:
    """Whether *path* is *prefix* or lies under it, on a path-segment boundary.

    ``/api`` covers ``/api``, ``/api/`` and ``/api/users`` but not ``/apix``; a prefix that ends
    in ``/`` (including ``/`` itself) covers exactly the paths that start with it.
    """
    if prefix.endswith('/'):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + '/')


def _path_allowed(scope: Scope, path: str) -> bool:
    """Return whether *path* matches an allowed prefix and no exclusion.

    Exclusions win over prefixes (PLAN §4.2 rule 3) and ignore case, so no casing of an
    excluded path gets through; prefixes are case-sensitive, so an unusual casing is refused.
    """
    folded = path.casefold()
    for exclusion in scope.exclusions:
        if path_under(folded, exclusion.casefold()):
            return False
    if not scope.path_prefixes:
        return True
    return any(path_under(path, prefix) for prefix in scope.path_prefixes)


_PREFIX_SUFFIX = '/*'
_DEFAULT_PORT_SET = frozenset({80, 443})


def _entry_url(entry: str) -> str:
    """The plain URL of an allowlist *entry*: a trailing ``/*`` (prefix marker) is dropped."""
    return entry.removesuffix(_PREFIX_SUFFIX) or '/' if entry.endswith(_PREFIX_SUFFIX) else entry


def _url_entry_matches(entry: str, view: ScopedUrl) -> bool:
    """Whether the allowlist *entry* covers *view*: same host and port, and every path interpretation matches.

    ``<url>`` matches that exact path only; ``<url>/*`` matches the path and everything under it (on a
    segment boundary). The query string is not compared. An entry without an explicit port covers both
    scheme defaults (80 and 443, whichever scheme it names); an explicit port pins that port.
    """
    plain = _entry_url(entry)
    parsed = parse_scoped_url(plain)
    ports = {parsed.port} if urlsplit(plain).port is not None else _DEFAULT_PORT_SET
    if parsed.host != view.host or view.port not in ports:
        return False
    if entry.endswith(_PREFIX_SUFFIX):
        return all(path_under(path, parsed.path) for path in view.candidate_paths)
    return view.candidate_paths <= parsed.candidate_paths


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
        raise ScopeViolation(f'host {view.host!r} not in scope hosts', rule_code='scope-invalid', kind='host')
    allowed_ports = set(scope.ports) if scope.ports else {80, 443}
    if view.port not in allowed_ports:
        raise ScopeViolation(
            f'port {view.port} not in scope ports {sorted(allowed_ports)}', rule_code='scope-invalid', kind='port'
        )
    for path in view.candidate_paths:
        if not _path_allowed(scope, path):
            raise ScopeViolation(
                f'path {path!r} matches no allowed prefix or an exclusion', rule_code='scope-invalid', kind='path'
            )
    if scope.urls and not any(_url_entry_matches(entry, view) for entry in scope.urls):
        raise ScopeViolation('URL is not in the authorized URL list', rule_code='scope-invalid', kind='url-list')


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
    for entry in scope.urls:
        try:
            parse_scoped_url(_entry_url(entry))
        except ScopeViolation as exc:
            problems.append(f'urls entry {entry!r}: {exc}')
    for exclusion in scope.exclusions:
        if scope.path_prefixes and not any(path_under(exclusion, p) for p in scope.path_prefixes):
            problems.append(f'exclusion {exclusion!r} is not within any path prefix')
    if scope.max_rps > MAX_RPS_CEILING:
        problems.append(f'max_rps {scope.max_rps} exceeds ceiling {MAX_RPS_CEILING}')
    if scope.max_requests > MAX_REQUESTS_CEILING:
        problems.append(f'max_requests {scope.max_requests} exceeds ceiling {MAX_REQUESTS_CEILING}')
    return problems


def parse_scope_target(spec: str) -> tuple[str, frozenset[int]]:
    """Parse an operator's ``host``, ``host:port`` or ``http(s)://host[:port][/…]`` into ``(host, ports)``.

    A bare host means both scheme defaults (80 and 443); a ``host:port`` or a URL means that one port
    (a URL without a port: its scheme's default). Raises :class:`ScopeViolation` for anything ambiguous.
    """
    spec = spec.strip()
    if '://' in spec:
        parsed = parse_scoped_url(spec)
        return parsed.host, frozenset({parsed.port})
    parsed = parse_scoped_url(f'http://{spec}/')
    explicit_port = ':' in spec.rsplit(']', 1)[-1]
    return parsed.host, frozenset({parsed.port} if explicit_port else {80, 443})


def _extend_url_list(scope: Scope, spec: str) -> Scope:
    """``extend_scope`` when an authorized URL list is active: only a full URL (``…/*`` for a prefix) widens it.

    A bare host or ``host:port`` would change nothing a request is checked against, so it is refused with a hint.
    """
    spec = spec.strip()
    if '://' not in spec:
        raise ScopeViolation(
            f'an authorized URL list is active, so scope grows by URL, not host: use /scope add <url> '
            f'(end it with /* for a path prefix), e.g. https://{spec}/*',
            rule_code='scope-invalid',
        )
    plain = _entry_url(spec)
    parse_scoped_url(plain)  # refuse anything ambiguous before it joins the list
    if spec in scope.urls:
        return scope
    extended = apply_urls(scope, [*scope.urls, spec])
    if problems := validate_scope(extended):
        raise ScopeViolation(f'extended scope is invalid: {"; ".join(problems)}', rule_code='scope-invalid')
    return extended


def extend_scope(scope: Scope, spec: str) -> Scope:
    """Return *scope* plus the host and port(s) named by *spec*; it only ever grows.

    Paths, exclusions and budgets are unchanged. When ``scope.ports`` is empty (scheme defaults only),
    adding a port keeps 80 and 443 explicitly. Raises :class:`ScopeViolation` when *spec* is ambiguous
    or the result fails the E3 checks.
    """
    if scope.urls:
        return _extend_url_list(scope, spec)
    return _extend_hosts_ports(scope, spec)


def _extend_hosts_ports(scope: Scope, spec: str) -> Scope:
    """The host/port half of :func:`extend_scope`, ignoring any URL list."""
    host, ports = parse_scope_target(spec)
    hosts = scope.hosts if host in {normalize_host(h) for h in scope.hosts} else [*scope.hosts, host]
    if scope.ports:
        merged_ports = [*scope.ports, *sorted(ports - set(scope.ports))]
    else:  # scheme defaults only: stay that way unless a non-default port is added
        extra = ports - {80, 443}
        merged_ports = [80, 443, *sorted(extra)] if extra else []
    extended = scope.model_copy(update={'hosts': hosts, 'ports': merged_ports})
    if problems := validate_scope(extended):
        raise ScopeViolation(f'extended scope is invalid: {"; ".join(problems)}', rule_code='scope-invalid')
    return extended


def _as_prefix(url: str) -> str:
    """*url* as a ``/*`` path-prefix entry: query and fragment dropped, so ``http://foo/`` becomes ``http://foo/*``."""
    if url.endswith(_PREFIX_SUFFIX):
        return url
    parts = urlsplit(url)
    return f'{parts.scheme}://{parts.netloc}{parts.path.rstrip("/")}{_PREFIX_SUFFIX}'


def parse_urls_file(text: str, *, recursive: bool = False) -> list[str]:
    """Parse an authorized-URLs file: one URL per line; blank lines and whole-line ``#`` comments are ignored (#121).

    A trailing ``/*`` makes an entry a path prefix; with *recursive* every entry is one. Duplicates collapse, keeping first-seen order. Raises
    :class:`ScopeViolation` naming the line for anything :func:`parse_scoped_url` refuses, and when the
    file lists no URL at all (an empty allowlist would silently mean "everything in scope").
    """
    urls: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        try:
            parse_scoped_url(_entry_url(line))
        except ScopeViolation as exc:
            raise ScopeViolation(f'line {number}: {exc}', rule_code='scope-invalid') from exc
        if recursive:
            line = _as_prefix(line)
        if line not in urls:
            urls.append(line)
    if not urls:
        raise ScopeViolation('authorized URLs file lists no URLs', rule_code='scope-invalid')
    return urls


def apply_urls(scope: Scope, urls: list[str]) -> Scope:
    """Return *scope* restricted to the exact *urls*; their hosts and ports are added so the other checks agree.

    Hosts and ports are only ever added (80 and 443 always, since entries without a port cover both);
    path prefixes, exclusions and budgets are unchanged.
    """
    extended = scope
    for url in urls:
        extended = _extend_hosts_ports(extended, _entry_url(url))
    ports = extended.ports
    if ports:  # 80 and 443 are always open for the listed URLs; an empty list already means exactly those
        ports = [*ports, *sorted(_DEFAULT_PORT_SET - set(ports))]
    return extended.model_copy(update={'urls': urls, 'ports': ports})
