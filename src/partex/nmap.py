"""nmap ``-oX`` scan output as authorized-URL-list entries — issue #215; PLAN §4.2 (#121), §8.

The converter is pure and offline: stdlib :mod:`xml.etree.ElementTree` only, no socket, no model,
and it reads nothing but operator-provided scan files. An import always produces #121 URL-list
entries — ``scheme://host:port/*`` pins host *and* port per entry — never ``scope.hosts`` /
``scope.ports`` additions, because scope ports apply to *every* host (importing ``a:443`` and
``b:8080`` as hosts+ports would also authorize ``a:8080`` and ``b:443``; the URL list cannot).

A scan is recon, not authorization: the E2 attestation gate is unchanged, and the printed entries
(or the ``--out`` file) are the operator's review artifact — editable lines that only become scope
through ``--urls-file`` (#121) or an operator-confirmed ``/scope nmap`` stage-and-confirm.
"""

import hashlib
import re
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .errors import PartexError, ScopeViolation
from .models import Scope
from .scope import check_url, normalize_host, parse_scoped_url

__all__ = ['NmapImport', 'ScanSource', 'convert_nmap', 'ensure_base_url_entry', 'parse_nmap_xml', 'urls_cover']

MAX_NMAP_BYTES = 64 * 1024 * 1024
"""Refuse to read a scan file larger than this before parsing (a /24 sweep with -sV stays far below)."""

WELL_KNOWN_SCHEMES: dict[int, str] = {80: 'http', 443: 'https'}
"""Ports imported with no ``-sV`` service name: the scheme defaults, nothing else."""

_HTTP_SERVICE_NAMES = frozenset({'http', 'https', 'http-alt', 'https-alt', 'http-proxy'})
"""nmap service names that mean an HTTP service. ``tunnel="ssl"`` alone does not: real scans carry it on
``ajp13``, ``xmpp`` and ``cslistener`` ports too, which are not HTTP targets however they are wrapped."""

_ENTRY_SUFFIX = '/*'

_ENTITY_DECL = re.compile(r'<!ENTITY', re.IGNORECASE)
_EXTERNAL_DTD = re.compile(r'<!DOCTYPE[^>]*\b(?:SYSTEM|PUBLIC)\b', re.IGNORECASE)
"""nmap's own plain ``<!DOCTYPE nmaprun>`` passes; entity declarations and external subsets do not."""


def _refuse(detail: str) -> PartexError:
    return PartexError(detail, rule_code='nmap-invalid')


@dataclass(frozen=True, slots=True)
class ScanSource:
    """One scan file the import read, with its sha256 for the run's audit trail."""

    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class NmapImport:
    """What one ``partex nmap`` conversion produced: entries, skip notes, and the scan sources."""

    entries: list[str]
    skipped: list[str]
    sources: list[ScanSource]

    @property
    def hosts(self) -> list[str]:
        """Distinct entry hosts, first-seen order (the operator's review counts)."""
        seen: list[str] = []
        for entry in self.entries:
            host = parse_scoped_url(entry.removesuffix(_ENTRY_SUFFIX) or '/').host
            if host not in seen:
                seen.append(host)
        return seen

    def as_lines(self) -> list[str]:
        """The ``--out`` file: ``--urls-file`` grammar — entries one per line, notes as ``#`` comments."""
        lines = ['# partex nmap import — review before use; each non-comment line authorizes one host:port']
        lines += [f'# source: {source.path} (sha256 {source.sha256})' for source in self.sources]
        lines += [f'# {note}' for note in self.skipped]
        return [*lines, *self.entries]


def _guard_text(text: str, source: str) -> None:
    """Refuse entity declarations and external DTDs before XML parsing (XXE / billion-laughs guard).

    nmap's own plain ``<!DOCTYPE nmaprun>`` passes; ``<!ENTITY`` (internal or external, even a
    harmless one) and any ``SYSTEM``/``PUBLIC`` subset do not. stdlib XML refuses most of these
    at parse time too — this guard is what makes the refusal explicit for every entry point.
    """
    if _ENTITY_DECL.search(text) or _EXTERNAL_DTD.search(text):
        raise _refuse(f'{source}: entity declaration or external DTD refused (XXE / billion-laughs guard)')


def _read_source(path: Path) -> tuple[str, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise _refuse(f'cannot read nmap scan file {path}: {exc}') from exc
    if len(raw) > MAX_NMAP_BYTES:
        raise _refuse(f'nmap scan file {path} is {len(raw)} bytes, over the {MAX_NMAP_BYTES} cap')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise _refuse(f'nmap scan file {path} is not UTF-8: {exc}') from exc
    _guard_text(text, str(path))
    return text, hashlib.sha256(raw).hexdigest()


def _service_label(service: ET.Element | None) -> str:
    name = service.get('name') if service is not None else None
    return name or 'no service name'


def _port_scheme(port: ET.Element, service: ET.Element | None) -> str | None:
    """The entry scheme for one open TCP port, or ``None`` to skip it as not an HTTP(S) service.

    ``-sV`` service names decide: an HTTP-family name imports as its scheme, and ``tunnel="ssl"``
    promotes it to https (``http tunnel="ssl"`` is https). A tunnel on any other service
    (``ajp13``, ``xmpp``, …) imports nothing — it is not an HTTP target. With no service name,
    only the scheme defaults {80, 443} import. Every other open port (ssh, dns, the database
    ports) is a skip note, never a guess: the operator can ``/scope add`` one by hand.
    """
    name = service.get('name') if service is not None else None
    if name in _HTTP_SERVICE_NAMES:
        if name in ('https', 'https-alt') or service is not None and service.get('tunnel') == 'ssl':
            return 'https'
        return 'http'
    return WELL_KNOWN_SCHEMES.get(int(port.get('portid') or 0))


def parse_nmap_xml(text: str, *, source: str, use_hostnames: bool = False) -> tuple[list[str], list[str]]:
    """Parse one nmap ``-oX`` document into ``(entries, skip_notes)``.

    Deterministic and document-ordered. Up hosts with open TCP ports become
    ``scheme://host:port/*`` entries — one set per scanned address (a dual-stack host is two
    targets), or per PTR hostname only with *use_hostnames*, since reverse DNS can be stale or
    wrong. Everything else is a note.
    """
    _guard_text(text, source)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise _refuse(f'{source} does not parse as XML: {exc}') from exc
    if root.tag != 'nmaprun':
        raise _refuse(f'{source} is not nmap -oX output (root element {root.tag!r}, expected "nmaprun")')
    entries: list[str] = []
    skipped: list[str] = []
    for host in root.iter('host'):  # <hosthint> elements (pre-scan hints) never match 'host'
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue  # down / unscanned hosts are not importable targets and not worth a note
        addresses = [
            addr
            for a in host.iter('address')
            if (addr := a.get('addr')) is not None and a.get('addrtype') in ('ipv4', 'ipv6')
        ]
        hostname = host.find('hostnames/hostname')
        label = hostname.get('name') if use_hostnames and hostname is not None else None
        if label is not None:
            raw = label
            try:
                label = normalize_host(label)
            except PartexError as exc:
                skipped.append(f'{source}: PTR hostname {raw!r} unusable ({exc}); using the IP')
                label = None
        # A dual-stack host shows both addresses; each is its own scanned target, so each gets entries.
        # A PTR hostname (use_hostnames) replaces them: one host identity per scan row.
        targets = [label] if label is not None else addresses
        if not targets:
            skipped.append(f'{source}: up host with no IP address; not imported')
            continue
        importable = False
        for port in host.iter('port'):
            if port.get('protocol') != 'tcp':
                continue
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue  # closed / filtered ports are scan noise, not skip notes
            scheme = _port_scheme(port, port.find('service'))
            if scheme is None:
                skipped.append(
                    f'{source}: {targets[0]} tcp/{port.get("portid")} {_service_label(port.find("service"))}'
                    ' — not an HTTP(S) service; add one with /scope add <url> if wanted'
                )
                continue
            for target in targets:
                bracketed = f'[{target}]' if ':' in target else target
                entry = f'{scheme}://{bracketed}:{port.get("portid")}{_ENTRY_SUFFIX}'
                if entry not in entries:
                    entries.append(entry)
            importable = True
        if not importable:
            skipped.append(f'{source}: {", ".join(targets)} up but no HTTP(S) port open; not imported')
    return entries, skipped


def convert_nmap(paths: Sequence[Path | str], *, use_hostnames: bool = False) -> NmapImport:
    """Convert one or more nmap ``-oX`` scan files (a sweep plus a ``-sV`` pass) into one import.

    Entries union across files, keeping first-seen order; skip notes accumulate per file. Raises
    :class:`PartexError` (``nmap-invalid``) for anything the converter refuses to guess at —
    unreadable or oversize files, entity declarations, non-nmap XML — and when the scans import
    no URL at all (an empty authorized list would silently mean "everything in scope").
    """
    entries: list[str] = []
    skipped: list[str] = []
    sources: list[ScanSource] = []
    for raw in paths:
        path = Path(raw).expanduser()
        text, digest = _read_source(path)
        file_entries, file_skipped = parse_nmap_xml(text, source=str(path), use_hostnames=use_hostnames)
        sources.append(ScanSource(path=str(path), sha256=digest))
        for entry in file_entries:
            if entry not in entries:
                entries.append(entry)
        skipped.extend(note for note in file_skipped if note not in skipped)
    if not entries:
        raise _refuse(
            'no importable targets in ' + ', '.join(str(p) for p in paths) + ' (no up host with an open HTTP(S) port)'
        )
    return NmapImport(entries=entries, skipped=skipped, sources=sources)


def urls_cover(entries: Sequence[str], url: str) -> bool:
    """Whether the URL-list *entries* would admit *url* through the send-time gate (#121).

    Probes the public :func:`partex.scope.check_url` with a scope holding exactly the entries,
    so coverage here is the gate's own rule, never a re-implementation of it.
    """
    view = parse_scoped_url(url)
    probe = Scope(hosts=[view.host], ports=[view.port], urls=[*entries])
    try:
        check_url(probe, url)
    except ScopeViolation:
        return False
    return True


def ensure_base_url_entry(entries: Sequence[str], base_url: str) -> list[str]:
    """Prepend a ``/*`` entry covering *base_url* unless an entry already covers it (#215).

    Activating a URL list narrows rule 3 for *every* request, including the engagement's baseline
    target, so an import batch must keep ``target.base_url`` reachable: not covered → its own
    ``scheme://host[:port]/path/*`` entry goes first (:func:`urls_cover` decides coverage).
    """
    if urls_cover(entries, base_url):
        return list(entries)
    parts = urlsplit(base_url)
    return [f'{parts.scheme}://{parts.netloc}{parts.path.rstrip("/")}{_ENTRY_SUFFIX}', *entries]
