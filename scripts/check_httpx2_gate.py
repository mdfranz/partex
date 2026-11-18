"""M0 httpx2 API gate (DEPS.md §3.9 / §8.1; PLAN.md §4.2 rules 2 and 4).

`target.py` must connect to a pinned resolver result — the DNS-rebinding guard — while
keeping the original `Host` header, SNI, and hostname certificate verification, and must
never follow redirects. This gate proves httpx2's custom-transport surface provides all of
that without hand-rolled sockets, against a loopback-only TLS server whose hostname
deliberately does not exist in DNS: a connection can only be established through the pinned
address, and certificate verification can only succeed against the original hostname.

On failure, the fallback is `httpx` 0.28.x (DEPS.md §3.9); the result of this gate is
recorded there. Everything stays on `127.0.0.1`, so the suite remains hermetic.
"""

import json
import ssl
import subprocess
import sys
from collections.abc import AsyncIterable, AsyncIterator, Iterable
from importlib import metadata
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

import anyio
import httpcore2
import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

GATE_HOST = 'partex-gate.test'

# A loopback-only TLS server. CRLF is spelled `bytes((13, 10))` so the embedded source
# needs no backslash escapes. The server prints its port on stdout, then appends one JSON
# line per request — SNI as seen at the handshake, the `Host` header, method, and target.
SERVER_SOURCE = """
import asyncio
import json
import ssl
import sys
from pathlib import Path

cert_path, key_path, records_path = sys.argv[1], sys.argv[2], sys.argv[3]
CRLF = bytes((13, 10))
records = Path(records_path)
seen_sni = []


def note_server_name(ssl_object, server_name, context):
    seen_sni.append(server_name)


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert_path, key_path)
context.set_servername_callback(note_server_name)


async def handle(reader, writer):
    sni = seen_sni[-1] if seen_sni else None
    request_line = (await reader.readline())[:-2].decode()
    headers = {}
    while line := await reader.readline():
        if line == CRLF:
            break
        name, _, value = line[:-2].decode().partition(':')
        headers[name.strip().lower()] = value.strip()
    method, target, _ = request_line.split(' ', 2)
    with records.open('a') as f:
        f.write(json.dumps({'sni': sni, 'host': headers.get('host'), 'method': method, 'target': target}))
        f.write(chr(10))
    if target == '/redirect':
        body = b''
        writer.write(CRLF.join((b'HTTP/1.1 302 Found', b'Location: /', b'Content-Length: 0', b'Connection: close')) + CRLF + CRLF)
    else:
        body = json.dumps({'ok': True}).encode()
        writer.write(
            CRLF.join((b'HTTP/1.1 200 OK', b'Content-Type: application/json', b'Content-Length: ' + str(len(body)).encode(), b'Connection: close'))
            + CRLF
            + CRLF
            + body
        )
    await writer.drain()
    writer.close()


async def main():
    server = await asyncio.start_server(handle, '127.0.0.1', 0, ssl=context)
    print(server.sockets[0].getsockname()[1], flush=True)
    async with server:
        await server.serve_forever()


asyncio.run(main())
"""


def generate_certificate(scratch: Path) -> tuple[Path, Path]:
    """Write a throwaway CA and a leaf certificate for `GATE_HOST`; return (ca, leaf)."""
    import datetime

    now = datetime.datetime.now(datetime.UTC)

    def name(common_name: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name('partex-gate-ca'))
        .issuer_name(name('partex-gate-ca'))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(name(GATE_HOST))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(GATE_HOST)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = scratch / 'ca.pem'
    leaf_pem = scratch / 'leaf.pem'
    key_pem = scratch / 'leaf.key'
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    leaf_pem.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return ca_pem, leaf_pem


class PinnedNetworkBackend(httpcore2.AsyncNetworkBackend):
    """Connects to the pinned resolver result, ignoring the origin host it is handed.

    `connect_tcp` receives the *origin* host (from the request URL); the TLS layer still
    uses the origin for SNI and certificate verification, which is exactly the split the
    DNS-rebinding guard needs. `AutoBackend` is imported from a private module on purpose:
    if httpcore2 ever moves it, this gate fails and DEPS.md §3.9's httpx fallback applies.
    """

    def __init__(self, resolved_ip: str) -> None:
        from httpcore2._backends.auto import AutoBackend

        self._resolved_ip = resolved_ip
        self._delegate: httpcore2.AsyncNetworkBackend = AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        return await self._delegate.connect_tcp(
            self._resolved_ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        return await self._delegate.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class CoreResponseStream(httpx2.AsyncByteStream):
    """Adapts a httpcore2 response stream to httpx2, mirroring httpx2's own default transport."""

    def __init__(self, stream: AsyncIterable[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        aclose = getattr(self._stream, 'aclose', None)
        if aclose is not None:
            await aclose()


class PinnedTransport(httpx2.AsyncBaseTransport):
    """A custom transport whose connections go to `resolved_ip`, keeping the original
    `Host` header, SNI, and hostname certificate verification from the request URL."""

    def __init__(self, resolved_ip: str, cafile: Path) -> None:
        ssl_context = ssl.create_default_context(cafile=str(cafile))
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=ssl_context, network_backend=PinnedNetworkBackend(resolved_ip)
        )

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        core_request = httpcore2.Request(
            method=request.method,
            url=httpcore2.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        core_response = await self._pool.handle_async_request(core_request)
        stream = core_response.stream
        assert isinstance(stream, AsyncIterable)
        # httpcore2 leaves `Response.extensions` untyped (pyright infers a partially-unknown
        # union from its unannotated constructor); pass it through as-is.
        extensions = cast(dict[str, Any], core_response.extensions)  # pyright: ignore[reportUnknownMemberType]
        return httpx2.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=CoreResponseStream(stream),
            extensions=extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def certificate_verification_error(exc: BaseException) -> ssl.SSLCertVerificationError | None:
    """Walk the cause/context chain for the TLS verification failure (httpx2 wraps it)."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return current
        current = current.__cause__ or current.__context__
    return None


async def _client_checks(port: int, cafile: Path) -> None:
    """The async half: everything that runs through httpx2's custom transport."""
    base_url = f'https://{GATE_HOST}:{port}'
    transport = PinnedTransport('127.0.0.1', cafile)
    async with httpx2.AsyncClient(transport=transport, follow_redirects=False, timeout=10.0) as client:
        # The pinned connection carries the original Host header and SNI, and the
        # certificate verifies against the original hostname — not the address.
        response = await client.get(f'{base_url}/')
        assert response.status_code == 200
        assert response.json() == {'ok': True}

        # Redirects are captured, never followed (PLAN.md §4.2 rule 4).
        redirect = await client.get(f'{base_url}/redirect')
        assert redirect.status_code == 302
        assert redirect.headers['location'] == '/'

        # Negative control: the same pinned server, but the origin is the address
        # itself, which the certificate does not cover. Handshake failure here proves
        # verification happens against the origin hostname, not the pinned address.
        # (httpx2 maps httpcore2 exceptions to its own only in its default transport,
        # so a custom transport surfaces the httpcore2 error directly.)
        with pytest.raises(httpcore2.ConnectError) as connect_error:
            await client.get(f'https://127.0.0.1:{port}/')
        assert certificate_verification_error(connect_error.value) is not None


def test_httpx2_gate() -> None:
    """The synchronous half: certificate files, the server subprocess, and its records."""
    with TemporaryDirectory(prefix='partex-httpx2-gate-') as temporary_directory:
        scratch = Path(temporary_directory)
        ca_pem, leaf_pem = generate_certificate(scratch)
        records_path = scratch / 'records.jsonl'
        server = subprocess.Popen(
            [sys.executable, '-c', SERVER_SOURCE, str(leaf_pem), str(scratch / 'leaf.key'), str(records_path)],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert server.stdout is not None
        port_line = server.stdout.readline().strip()
        if not port_line:
            raise ValueError('gate server exited before printing its port')
        port = int(port_line)
        try:
            anyio.run(_client_checks, port, ca_pem)

            records = [json.loads(line) for line in records_path.read_text().splitlines()]
            assert len(records) == 2
            for record in records:
                assert record['host'] == f'{GATE_HOST}:{port}'
                assert record['sni'] == GATE_HOST
            assert records[1]['target'] == '/redirect'
        finally:
            server.terminate()
            server.wait(timeout=10.0)


def main() -> None:
    """Run the gate outside pytest and report the pinned API versions."""
    test_httpx2_gate()
    print(f'httpx2 {metadata.version("httpx2")} gate passed')


if __name__ == '__main__':
    main()
