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

import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Self
from urllib.parse import urljoin

import anyio
import httpx2

from partex.checks import HeaderInput
from partex.engagement import Engagement
from partex.errors import BudgetExhausted, PartexError
from partex.ids import evidence_id
from partex.models import Headers, HttpEvidence, HttpExchange, HttpRequest, HttpResponse, get_header
from partex.scope import check_url, parse_scoped_url

type Resolver = Callable[[str], str]

CaptureCallback = Callable[[HttpEvidence], Awaitable[None]]

DEFAULT_SOURCE = 'capture:local'
DEFAULT_TIMEOUT = httpx2.Timeout(30.0)

# A response body that is not valid UTF-8, or is dominated by non-printable
# bytes, is captured as headers only (PLAN §4.3: binary bytes are never
# stored; Content-Type is a hint, not the arbiter).
_NON_PRINTABLE_LIMIT = 0.3


def _default_resolver(host: str) -> str:
    """Resolve *host* to an address via getaddrinfo (first result wins)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return str(infos[0][4][0])


def _header_pairs(headers: httpx2.Headers) -> Headers:
    """Headers as wire-order ``(name, value)`` pairs, original casing and repeats preserved."""
    return [(key.decode(headers.encoding), value.decode(headers.encoding)) for key, value in headers.raw]


def _decode_body(content: bytes) -> str | None:
    """Decode a response body for storage, or return ``None`` to refuse it."""
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        return None
    non_printable = sum(1 for ch in text if ord(ch) < 0x20 and ch not in '\t\n\r')
    if non_printable > _NON_PRINTABLE_LIMIT * max(len(text), 1):
        return None
    return text


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


class _PinnedTransport(httpx2.AsyncHTTPTransport):
    """Rewrite the request to the pinned address, preserving Host and SNI.

    The URL host becomes the pinned IP so httpcore connects to the address
    resolved once per run; the ``Host`` header (set when the request was built)
    and the ``sni_hostname`` extension keep the original hostname for header
    routing, SNI, and certificate verification.
    """

    def __init__(self, pins: dict[str, str], *, inner: httpx2.AsyncBaseTransport | None = None) -> None:
        super().__init__(trust_env=False)
        self._pins = pins
        self._inner = inner

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        host = request.url.host
        pin = self._pins.get(host)
        if pin is not None and pin != host:
            request.url = request.url.copy_with(host=pin)
            request.extensions = {**request.extensions, 'sni_hostname': host}
        if self._inner is not None:
            return await self._inner.handle_async_request(request)
        return await super().handle_async_request(request)


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
        resolver: Resolver | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
        timeout: httpx2.Timeout | float = DEFAULT_TIMEOUT,
    ) -> None:
        self._engagement = engagement
        self._secrets = tuple(s for s in secrets if s)
        self._source = source
        self._on_capture = on_capture
        self._resolver: Resolver = resolver if resolver is not None else _default_resolver
        self._pins: dict[str, str] = {}
        self._pin_lock = anyio.Lock()
        self._budget_lock = anyio.Lock()
        self._remaining = engagement.scope.max_requests
        self._sent = 0
        self._bucket = TokenBucket(float(engagement.scope.max_rps))
        self._client = httpx2.AsyncClient(
            transport=_PinnedTransport(self._pins, inner=transport),
            follow_redirects=False,
            timeout=timeout,
        )

    @property
    def requests_spent(self) -> int:
        """Number of in-scope requests this client has sent."""
        return self._sent

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client (no further requests may be sent)."""
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: HeaderInput | None = None,
        body: str | None = None,
    ) -> HttpEvidence:
        """Send one request through the scope gate and return captured evidence.

        Raises :class:`ScopeViolation` (before any bytes or DNS), and
        :class:`BudgetExhausted` when the engagement budget is spent.
        """
        check_url(self._engagement.scope, url)  # rules 1–3, before resolution
        await self._acquire_budget()  # rule 5
        await self._pin_host(url)  # rule 2: resolve once per run
        header_list = list(headers.items()) if isinstance(headers, Mapping) else list(headers or ())
        http_request = httpx2.Request(
            method.upper(), url, headers=header_list or None, content=body.encode() if body else None
        )
        # The pinned transport rewrites ``request.url`` to the resolved address; evidence
        # records the URL as requested (hostname, not IP) so redirects and re-import stay in scope.
        requested_url = str(http_request.url)
        try:
            response = await self._client.send(http_request, follow_redirects=False)
            await response.aread()
        except httpx2.HTTPError as exc:
            raise PartexError(f'request to {url} failed: {exc}') from exc
        self._sent += 1
        return await self._capture(http_request, requested_url, response, body)

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

    async def _acquire_budget(self) -> None:
        async with self._budget_lock:
            if self._remaining <= 0:
                raise BudgetExhausted(
                    f'max_requests budget ({self._engagement.scope.max_requests}) exhausted; '
                    f'{self._sent} requests were sent'
                )
            self._remaining -= 1
        await self._bucket.acquire()

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
        self, request: httpx2.Request, url: str, response: httpx2.Response, body: str | None
    ) -> HttpEvidence:
        """Build the ``ev_`` record for a sent exchange, mark secrets, commit via callback."""
        request_model = HttpRequest(
            method=request.method,
            url=url,
            headers=_header_pairs(request.headers),
            body=body,
        )
        response_model = HttpResponse(
            status_code=response.status_code,
            headers=_header_pairs(response.headers),
            body=_decode_body(response.content),
        )
        evidence = HttpEvidence(
            id='',
            source=self._source,
            http=HttpExchange(request=request_model, response=response_model),
            secret_fields=self._secret_fields(request_model, body),
        )
        evidence = evidence.model_copy(update={'id': evidence_id(evidence)})
        if self._on_capture is not None:
            await self._on_capture(evidence)
        return evidence

    def _secret_fields(self, request: HttpRequest, body: str | None) -> list[str]:
        """Mark credential-matched headers and the request body as secret."""
        if not self._secrets:
            return []
        paths: list[str] = []
        for index, (_, value) in enumerate(request.headers):
            if any(secret in value for secret in self._secrets):
                paths.append(f'$.http.request.headers[{index}][1]')
        if body is not None and any(secret in body for secret in self._secrets):
            paths.append('$.http.request.body')
        return paths
