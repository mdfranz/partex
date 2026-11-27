"""Scoped HTTP target client — the only module that opens sockets. PLAN §4.2; issue #20.

Every outbound request — from an active check, the verification runner, or the
agent's HTTP tool — goes through :class:`ScopedHttpClient`, which enforces the
engagement scope immediately before send:

1. **Scheme and port** — ``http``/``https`` only; the effective port must be in
   ``scope.ports`` (empty list: scheme defaults only).
2. **Host** — exact match against ``scope.hosts``; no suffix matching.  A
   per-run **DNS pin** resolves each in-scope host once, connects to the
   pinned address, and preserves the original ``Host`` header, SNI, and
   hostname certificate verification (via the ``sni_hostname`` request
   extension) — the DNS-rebinding guard.
3. **Path** — allowed prefix with exclusions winning, over every
   interpretation of the path (raw, percent-decoded, dot-segment-resolved).
4. **Redirects** — never followed automatically; a redirect is captured as
   evidence and :meth:`ScopedHttpClient.follow_redirect` re-validates the
   location rule-by-rule before any follow.
5. **Budgets** — a token-bucket limiter enforces ``max_rps`` and a run-level
   counter enforces ``max_requests``; exhaustion raises
   :class:`BudgetExhausted` (a clean end to active work, not an error).

There is no API that skips validation: ``request`` and ``follow_redirect`` are
the only send paths, and both validate before resolving or sending anything.

Capture: every exchange becomes an :class:`HttpEvidence` record (canonical
``ev_`` id, ``capture:<run-seq>``-style source) with credential-matched
headers and bodies marked in ``secret_fields``, handed to the engine's commit
callback.  ``target.py`` never writes storage.
"""

import codecs
import hashlib
import importlib.metadata
import ipaddress
import os
import re
import socket
import time
import uuid
from collections.abc import Awaitable, Callable, Generator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Literal, Self
from urllib.parse import unquote, urljoin, urlsplit

import anyio
import httpx2
import logfire

from partex.bundle import MAX_CONTENT_BYTES
from partex.checks import HeaderInput
from partex.engagement import Engagement
from partex.errors import BudgetExhausted, PartexError, ScopeViolation
from partex.ids import evidence_id
from partex.models import (
    SAFE_METHODS,
    ArtifactAsset,
    ArtifactEvidence,
    Headers,
    HttpEvidence,
    HttpExchange,
    HttpRequest,
    HttpResponse,
    Scope,
    TlsPolicy,
    get_header,
)
from partex.scope import check_url, normalize_host, parse_scoped_url, validate_scope
from partex.telemetry import suppress_unconfigured_warning

type Resolver = Callable[[str], str]

CaptureCallback = Callable[[HttpEvidence], Awaitable[None]]
ArtifactCallback = Callable[[ArtifactEvidence], Awaitable[None]]
SpendCallback = Callable[[], Awaitable[None]]
"""Called once for a download that sent a request but stored no artifact (non-2xx, oversize, mid-stream error)."""

DEFAULT_SOURCE = 'capture:local'
_RUN_CAPTURE_SOURCE = re.compile(r'capture:(run_[0-9a-f]{32})(?::.*)?')
DEFAULT_TIMEOUT = httpx2.Timeout(30.0)
DEFAULT_MAX_ASSET_BYTES = 20 * 1024 * 1024  # 20 MiB ceiling for full-body asset downloads

# A response body that is not valid UTF-8, or is dominated by non-printable
# bytes, is captured as headers only (PLAN §4.3: binary bytes are never
# stored; Content-Type is a hint, not the arbiter).
_NON_PRINTABLE_LIMIT = 0.3

MAX_BODY_BYTES = MAX_CONTENT_BYTES
"""Decoded response bytes kept per exchange (the bundle cap, so a capture always re-imports). The body is
streamed and reading stops one byte past the cap: a hostile or huge response, or a decompression bomb,
never lands in memory, storage, or a model's context whole."""

# Request headers that carry credentials whatever their value (PLAN §5): marked secret on every
# capture, as is every Set-Cookie the target issues (redacted value-only, attributes stay visible).
_CREDENTIAL_REQUEST_HEADERS = frozenset({'authorization', 'proxy-authorization', 'cookie'})


def _default_resolver(host: str) -> str:
    """Resolve *host* to an address via getaddrinfo (preferring IPv4 when available)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ipv4 = [info for info in infos if info[0] == socket.AF_INET]
    chosen = ipv4[0] if ipv4 else infos[0]
    return str(chosen[4][0])


def _header_pairs(headers: httpx2.Headers) -> Headers:
    """Headers as wire-order ``(name, value)`` pairs, original casing and repeats preserved."""
    return [(key.decode(headers.encoding), value.decode(headers.encoding)) for key, value in headers.raw]


def _decode_body(content: bytes, *, truncated: bool) -> tuple[str | None, Literal['truncated', 'refused'] | None]:
    """Decode a captured body for storage: ``(text, body_note)``.

    Binary or non-UTF-8 content is refused (``(None, 'refused')``). A truncated body may end inside
    a multi-byte character; the incomplete tail is dropped rather than refusing the whole body.
    """
    decoder = codecs.getincrementaldecoder('utf-8')()
    try:
        text = decoder.decode(content, final=not truncated)
    except UnicodeDecodeError:
        return None, 'refused'
    non_printable = sum(1 for ch in text if ord(ch) < 0x20 and ch not in '\t\n\r')
    if non_printable > _NON_PRINTABLE_LIMIT * max(len(text), 1):
        return None, 'refused'
    return text, 'truncated' if truncated else None


async def _read_capped(response: httpx2.Response) -> tuple[bytes, bool]:
    """Read at most :data:`MAX_BODY_BYTES` of the decoded body: ``(content, truncated)``."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            break
    content = b''.join(chunks)
    return content[:MAX_BODY_BYTES], size > MAX_BODY_BYTES


class TokenBucket:
    """A burst-free rate limiter: one token, refilled at *rate* per second.

    ``clock`` and ``sleep`` are injectable for deterministic tests.
    """

    def __init__(
        self,
        rate: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    ) -> None:
        self._rate = rate
        self._clock = clock
        self._sleep = sleep
        self._tokens = 1.0
        self._last = clock()
        self._lock = anyio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        while True:
            async with self._lock:
                now = self._clock()
                self._tokens = min(1.0, self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            await self._sleep(wait)


class RequestBudget:
    """Engagement-wide request budget: run counter + rate bucket (§4.2 rule 5).

    One budget object is shared by the primary handle and every role handle
    (PLAN §4.1 D2, issue #23) so ``max_requests`` / ``max_rps`` are the
    *engagement's*, never multiplied per client.  :meth:`acquire` reserves one
    request (raising :class:`BudgetExhausted` when the counter is spent) and
    paces it against the rate bucket; the client records the send after the
    response lands.
    """

    def __init__(self, max_requests: int, max_rps: int, max_write_requests: int = 0) -> None:
        self.max_requests = max_requests
        self.max_write_requests = max_write_requests
        self._remaining: int | None = max_requests or None  # None: unlimited (``max_requests == 0``)
        self._writes_remaining = max_write_requests
        self._sent = 0
        self._lock = anyio.Lock()
        self._bucket = TokenBucket(float(max_rps))

    @property
    def requests_spent(self) -> int:
        """Requests successfully sent under this budget."""
        return self._sent

    @property
    def requests_remaining(self) -> int | None:
        """Request slots not yet reserved; ``None`` when the budget is unlimited (``max_requests == 0``)."""
        return self._remaining

    @property
    def writes_remaining(self) -> int:
        """State-changing request slots not yet reserved (``max_write_requests``, #65)."""
        return self._writes_remaining

    def record_send(self) -> None:
        """Record one completed send (called by the client after the response lands)."""
        self._sent += 1

    async def acquire(self, *, write: bool = False) -> None:
        """Reserve one request slot (and, for a *write*, one write slot) and pace it, or raise :class:`BudgetExhausted`.

        Both counters are checked and taken under one lock, so concurrent calls cannot overrun either budget.
        """
        async with self._lock:
            if self._remaining is not None and self._remaining <= 0:
                raise BudgetExhausted(
                    f'max_requests budget ({self.max_requests}) exhausted; {self._sent} requests were sent'
                )
            if write and self._writes_remaining <= 0:
                raise BudgetExhausted(f'max_write_requests budget ({self.max_write_requests}) exhausted')
            if self._remaining is not None:
                self._remaining -= 1
            if write:
                self._writes_remaining -= 1
        await self._bucket.acquire()


class _PinnedTransport(httpx2.AsyncHTTPTransport):
    """Rewrite the request to the pinned address, preserving Host and SNI.

    The URL host becomes the pinned IP so httpcore connects to the address
    resolved once per run; the ``Host`` header (set when the request was built)
    and the ``sni_hostname`` extension keep the original hostname for header
    routing, SNI, and certificate verification.

    Certificates are verified unless ``is_insecure(host)`` says the operator accepted invalid TLS for that
    host (#71); only then is a second, non-verifying transport used, so one host never weakens another.
    """

    def __init__(
        self,
        pins: dict[str, str],
        *,
        inner: httpx2.AsyncBaseTransport | None = None,
        is_insecure: Callable[[str], bool] | None = None,
    ) -> None:
        super().__init__(trust_env=False)
        self._pins = pins
        self._inner = inner
        self._is_insecure = is_insecure
        self._insecure_transport: httpx2.AsyncHTTPTransport | None = None

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        host = request.url.host
        pin = self._pins.get(host)
        if pin is not None and pin != host:
            request.url = request.url.copy_with(host=pin)
            request.extensions = {**request.extensions, 'sni_hostname': host}
        if self._inner is not None:
            return await self._inner.handle_async_request(request)
        if request.url.scheme == 'https' and self._is_insecure is not None and self._is_insecure(host):
            if self._insecure_transport is None:
                self._insecure_transport = httpx2.AsyncHTTPTransport(trust_env=False, verify=False)
            return await self._insecure_transport.handle_async_request(request)
        return await super().handle_async_request(request)

    async def aclose(self) -> None:
        if self._insecure_transport is not None:
            await self._insecure_transport.aclose()
        await super().aclose()


def tls_unverified(tls: TlsPolicy, host: str) -> bool:
    """Whether *tls* accepts invalid certificates for *host* (#71, #101).

    ``verify: false`` with no ``insecure_hosts`` covers every host in scope, including hosts the operator adds
    later with ``/scope add``. With ``insecure_hosts`` listed, only those hosts are relaxed; added hosts stay strict.
    """
    if tls.verify:
        return False
    try:
        normalized = normalize_host(host)
    except ScopeViolation:
        return False
    if not tls.insecure_hosts:
        return True
    return normalized in {normalize_host(h) for h in tls.insecure_hosts}


def default_user_agent() -> str:
    """``partex/<engine version>``: what a run presents as when the engagement sets no ``http.user_agent`` (#135).

    Honest and stable per run, without disclosing the underlying HTTP library and its version.
    """
    return f'partex/{importlib.metadata.version("partex")}'


class ScopedHttpClient:
    """The engagement-scoped HTTP client — the single send-time scope gate.

    All requests validate against the engagement scope before anything reaches
    the network, share the engagement's rate/request budgets, and return as
    captured :class:`HttpEvidence` records (with ``secret_fields`` marked for
    credential-matched headers and bodies).
    """

    def __init__(
        self,
        engagement: Engagement,
        *,
        secrets: Sequence[str] = (),
        source: str = DEFAULT_SOURCE,
        on_capture: CaptureCallback | None = None,
        on_artifact: ArtifactCallback | None = None,
        on_failed_send: SpendCallback | None = None,
        resolver: Resolver | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
        timeout: httpx2.Timeout | float = DEFAULT_TIMEOUT,
        budget: RequestBudget | None = None,
        pins: dict[str, str] | None = None,
    ) -> None:
        self._engagement = engagement
        self._secrets = tuple(s for s in secrets if s)
        self._source = source
        capture = _RUN_CAPTURE_SOURCE.fullmatch(source)
        self._run_id = capture[1] if capture else None
        self._on_capture = on_capture
        self._on_artifact = on_artifact
        self._on_failed_send = on_failed_send
        self._resolver: Resolver = resolver if resolver is not None else _default_resolver
        # The DNS pin table may be shared across handles (role clients resolve
        # each in-scope host once per engagement, not once per role).  The lock
        # stays per-client: two concurrent clients may, benignly, both resolve
        # the same host before either writes the pin.
        self._pins: dict[str, str] = pins if pins is not None else {}
        self._pin_lock = anyio.Lock()
        # One engagement-wide budget shared by every handle bound to it (D2):
        # passing a shared RequestBudget is what makes role clients pool their
        # request/rate allowance instead of each getting a fresh one.
        self._budget = (
            budget
            if budget is not None
            else RequestBudget(
                engagement.scope.max_requests, engagement.scope.max_rps, engagement.scope.max_write_requests
            )
        )
        # A client-level default, so every send path inherits it (request, download_asset, redirects, seeded
        # probes, agent tools, verify replay); a request's own User-Agent header still wins (#135).
        self._client = httpx2.AsyncClient(
            transport=_PinnedTransport(self._pins, inner=transport, is_insecure=self._tls_unverified),
            follow_redirects=False,
            timeout=timeout,
            headers={'User-Agent': engagement.http.user_agent or default_user_agent()},
        )

    @property
    def budget(self) -> RequestBudget:
        """The engagement budget this client draws on (read its remaining counts; it cannot be bypassed)."""
        return self._budget

    @property
    def requests_spent(self) -> int:
        """Number of in-scope requests sent under this client's budget."""
        return self._budget.requests_spent

    def _tls_unverified(self, host: str) -> bool:
        """Whether the operator accepted invalid TLS for *host* (engagement ``tls``; never a model choice)."""
        return tls_unverified(self._engagement.tls, host)

    def set_scope(self, scope: Scope) -> None:
        """Swap in an operator-extended scope; every later request is gated by it (budgets are unchanged).

        Extend-only: the new scope must keep every current host, port, path prefix and exclusion and pass the
        E3 checks, so this can never loosen a boundary. Not a send path: each request is still gated.
        """
        current = self._engagement.scope
        shrinks = (
            not set(current.hosts) <= set(scope.hosts)
            or not set(current.ports) <= set(scope.ports)
            or current.path_prefixes != scope.path_prefixes
            or current.exclusions != scope.exclusions
            or (scope.max_rps, scope.max_requests) != (current.max_rps, current.max_requests)
            or (scope.allowed_methods, scope.max_write_requests)
            != (current.allowed_methods, current.max_write_requests)
        )
        if shrinks or validate_scope(scope):
            raise ScopeViolation('scope may only be extended with hosts or ports', rule_code='scope-invalid')
        self._engagement = self._engagement.model_copy(update={'scope': scope})

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client (no further requests may be sent)."""
        await self._client.aclose()

    def _trace_value(self, value: str) -> str:
        return '[redacted]' if self._carries_secret(value) or self._carries_secret(unquote(value)) else value

    @contextmanager
    def _request_span(self, request: httpx2.Request) -> Generator[logfire.LogfireSpan]:
        """Record only request metadata, before the transport substitutes the pinned address."""
        path = urlsplit(str(request.url)).path or '/'
        suppress_unconfigured_warning()
        with ExitStack() as stack:
            span = stack.enter_context(
                logfire.span(
                    'target request {method} {host}{path}',
                    method=self._trace_value(request.method),
                    host=self._trace_value(request.url.host),
                    path=self._trace_value(path),
                    run_id=self._run_id,
                )
            )
            try:
                yield span
            except BaseException:
                # Logfire would otherwise record the raw exception, which can contain the URL or payload.
                span.set_attribute('request_failed', True)
                stack.close()
                raise

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: HeaderInput | None = None,
        body: str | None = None,
    ) -> HttpEvidence:
        """Send one request through the scope gate and return captured evidence.

        Raises :class:`ScopeViolation` (before any bytes or DNS), including for a method the engagement's
        ``allowed_methods`` does not list, and :class:`BudgetExhausted` when the engagement budget (or, for a
        state-changing method, ``max_write_requests``) is spent. Operator approval of a write happens before
        this call and never bypasses it (#65).
        """
        verb = method.upper()
        check_url(self._engagement.scope, url)  # rules 1–3, before resolution
        if verb not in self._engagement.scope.allowed_methods:
            raise ScopeViolation(
                f'method {verb} is not in the engagement allowed_methods '
                f'({", ".join(self._engagement.scope.allowed_methods)})',
                rule_code='scope-invalid',
                kind='method',
            )
        await self._budget.acquire(write=verb not in SAFE_METHODS)  # rule 5, plus the write budget
        await self._pin_host(url)  # rule 2: resolve once per run
        header_list = list(headers.items()) if isinstance(headers, Mapping) else list(headers or ())
        # build_request (not a bare httpx2.Request) so the client cookie jar and
        # default headers merge into the outbound request — `send()` transmits a
        # request as-is, and role handles must carry their session cookies the
        # way the operator's browser would.
        http_request = self._client.build_request(
            method.upper(), url, headers=header_list or None, content=body.encode() if body else None
        )
        # The pinned transport rewrites ``request.url`` to the resolved address; evidence
        # records the URL as requested (hostname, not IP) so redirects and re-import stay in scope.
        requested_url = str(http_request.url)
        with self._request_span(http_request) as span:
            try:
                response = await self._client.send(http_request, follow_redirects=False, stream=True)
                span.set_attribute('status_code', response.status_code)
                try:
                    content, truncated = await _read_capped(response)
                finally:
                    await response.aclose()
            except httpx2.HTTPError as exc:
                raise PartexError(f'request to {url} failed: {exc}') from exc
            self._budget.record_send()
            evidence = await self._capture(http_request, requested_url, response, body, content, truncated)
            span.set_attribute('evidence_id', evidence.id)
            return evidence

    async def download_asset(
        self,
        url: str,
        *,
        dest_dir: Path,
        headers: HeaderInput | None = None,
        max_bytes: int = DEFAULT_MAX_ASSET_BYTES,
    ) -> ArtifactEvidence:
        """Stream a scoped GET-only asset (e.g. full JS bundle) to *dest_dir* up to *max_bytes*.

        Out-of-scope, excluded, non-2xx, or over-ceiling responses fail before or without storing.
        Stored files are content-addressed by sha256 with mode ``0600``.
        """
        check_url(self._engagement.scope, url)
        if max_bytes <= 0:
            raise PartexError(f'max_bytes must be positive, got {max_bytes}')
        await self._budget.acquire()
        await self._pin_host(url)
        header_list = list(headers.items()) if isinstance(headers, Mapping) else list(headers or ())
        http_request = self._client.build_request('GET', url, headers=header_list or None)
        requested_url = str(http_request.url)
        tmp_path = dest_dir / f'.tmp-{uuid.uuid4().hex}'
        with self._request_span(http_request) as span:
            sent = False
            try:
                response = await self._client.send(http_request, follow_redirects=False, stream=True)
                span.set_attribute('status_code', response.status_code)
                self._budget.record_send()
                sent = True
                try:
                    if not 200 <= response.status_code < 300:
                        raise PartexError(f'asset download {url} returned HTTP {response.status_code}')
                    raw_len = response.headers.get('content-length')
                    if raw_len is not None:
                        try:
                            if int(raw_len) > max_bytes:
                                raise PartexError(f'asset {url} exceeds max_bytes ({max_bytes})')
                        except ValueError:
                            pass
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    os.chmod(dest_dir, 0o700)
                    hasher = hashlib.sha256()
                    size = 0
                    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    try:
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > max_bytes:
                                raise PartexError(f'asset {url} exceeds max_bytes ({max_bytes})')
                            hasher.update(chunk)
                            os.write(fd, chunk)
                    finally:
                        os.close(fd)
                finally:
                    await response.aclose()
            except httpx2.HTTPError as exc:
                tmp_path.unlink(missing_ok=True)
                await self._record_failed_send(sent)
                raise PartexError(f'asset download {url} failed: {exc}') from exc
            except Exception:
                tmp_path.unlink(missing_ok=True)
                await self._record_failed_send(sent)
                raise
            except BaseException:  # cancellation: clean up, no further awaits
                tmp_path.unlink(missing_ok=True)
                raise

            digest = hasher.hexdigest()
            final_path = dest_dir / digest
            os.replace(tmp_path, final_path)
            os.chmod(final_path, 0o600)

            resp_headers = _header_pairs(response.headers)
            secret_fields = [
                f'$.artifact.headers[{index}][1]'
                for index, (name, _) in enumerate(resp_headers)
                if name.lower() == 'set-cookie'
            ]
            asset = ArtifactAsset(
                url=requested_url,
                status_code=response.status_code,
                headers=resp_headers,
                content_type=get_header(resp_headers, 'content-type'),
                sha256=digest,
                size_bytes=size,
            )
            evidence = ArtifactEvidence(
                id='',
                source=self._source,
                artifact=asset,
                file_path=str(final_path),
                secret_fields=secret_fields,
                tls_verified=not (
                    urlsplit(url).scheme == 'https' and self._tls_unverified(urlsplit(url).hostname or '')
                ),
            )
            evidence = evidence.model_copy(update={'id': evidence_id(evidence)})
            if self._on_artifact is not None:
                await self._on_artifact(evidence)
            span.set_attribute('evidence_id', evidence.id)
            return evidence

    async def _record_failed_send(self, sent: bool) -> None:
        """A download that reached the target but stored nothing still spent a request; persist it."""
        if sent and self._on_failed_send is not None:
            await self._on_failed_send()

    async def follow_redirect(self, evidence: HttpEvidence) -> HttpEvidence:
        """Follow a captured redirect after re-validating its location.

        Redirects are never followed automatically (rule 4).  The location —
        absolute or relative — is resolved and checked against the scope
        *before* any follow; out-of-scope or excluded locations raise
        :class:`ScopeViolation`.  Status 303 converts to ``GET`` with no body;
        307/308 preserve method and body.
        """
        response = evidence.http.response
        if not 300 <= response.status_code < 400:
            raise PartexError(f'not a redirect: status {response.status_code}')
        location = get_header(response.headers, 'location')
        if location is None:
            raise PartexError('redirect response has no Location header')
        absolute = urljoin(evidence.http.request.url, location)
        check_url(self._engagement.scope, absolute)  # re-validated rule-by-rule
        if response.status_code == 303:
            return await self.request('GET', absolute, headers=self._forwardable_headers(evidence))
        return await self.request(
            evidence.http.request.method,
            absolute,
            headers=self._forwardable_headers(evidence),
            body=evidence.http.request.body,
        )

    def _forwardable_headers(self, evidence: HttpEvidence) -> Headers:
        """Recorded request headers, minus per-target fields recomputed on send."""
        return [
            (key, value)
            for key, value in evidence.http.request.headers
            if key.lower() not in {'host', 'content-length'}
        ]

    async def _pin_host(self, url: str) -> None:
        """Resolve the URL's host once per client, pinning the address (rule 2)."""
        host = parse_scoped_url(url).host
        if host in self._pins:
            return
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            self._pins[host] = host  # IP literal: nothing to resolve or pin
            return
        async with self._pin_lock:
            if host in self._pins:
                return
            try:
                resolved = await anyio.to_thread.run_sync(self._resolver, host)
            except OSError as exc:
                raise PartexError(f'DNS resolution failed for {host}: {exc}') from exc
            self._pins[host] = resolved

    async def _capture(
        self,
        request: httpx2.Request,
        url: str,
        response: httpx2.Response,
        body: str | None,
        content: bytes,
        truncated: bool,
    ) -> HttpEvidence:
        """Build the ``ev_`` record for a sent exchange, mark secrets, commit via callback."""
        request_model = HttpRequest(
            method=request.method,
            url=url,
            headers=_header_pairs(request.headers),
            body=body,
        )
        response_body, body_note = _decode_body(content, truncated=truncated)
        response_model = HttpResponse(
            status_code=response.status_code,
            headers=_header_pairs(response.headers),
            body=response_body,
            body_note=body_note,
        )
        evidence = HttpEvidence(
            id='',
            source=self._source,
            http=HttpExchange(request=request_model, response=response_model),
            secret_fields=self._secret_fields(request_model, body, response_model),
            tls_verified=not (urlsplit(url).scheme == 'https' and self._tls_unverified(urlsplit(url).hostname or '')),
        )
        evidence = evidence.model_copy(update={'id': evidence_id(evidence)})
        if self._on_capture is not None:
            await self._on_capture(evidence)
        return evidence

    def _secret_fields(self, request: HttpRequest, body: str | None, response: HttpResponse) -> list[str]:
        """Mark secret: credential request headers (by name) and anything carrying an engagement
        credential, and every ``Set-Cookie`` the target issued (redaction keeps its attributes)."""
        paths: list[str] = []
        for index, (name, value) in enumerate(request.headers):
            if name.lower() in _CREDENTIAL_REQUEST_HEADERS or self._carries_secret(value):
                paths.append(f'$.http.request.headers[{index}][1]')
        if body is not None and self._carries_secret(body):
            paths.append('$.http.request.body')
        for index, (name, _) in enumerate(response.headers):
            if name.lower() == 'set-cookie':
                paths.append(f'$.http.response.headers[{index}][1]')
        return paths

    def _carries_secret(self, text: str) -> bool:
        return any(secret in text for secret in self._secrets)
