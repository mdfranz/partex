"""``target_server``: a tiny stdlib HTTP server on 127.0.0.1 for target-client tests (#20).

Every received request is appended to ``server.requests`` — the socket-level
spy tests use to assert that refused requests never put bytes on the wire.
"""

import http.server
import threading
from collections.abc import Iterator
from typing import cast
from urllib.parse import parse_qs, urlparse

import pytest


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    """Deliberately fixture-shaped responses; records everything it receives."""

    # A real version banner, so version-disclosure checks have something to find.
    server_version = 'FixtureTarget/1.0'
    sys_version = ''

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def _handle(self) -> None:
        server = cast('_FixtureServer', self.server)
        length = int(self.headers.get('content-length') or 0)
        request_body = self.rfile.read(length).decode('utf-8', errors='replace') if length else ''
        server.requests.append(
            {
                'method': self.command,
                'path': self.path,
                'host_header': self.headers.get('Host', ''),
                'cookie_header': self.headers.get('Cookie', ''),
                'body': request_body,
            }
        )
        parsed = urlparse(self.path)
        if parsed.path == '/redirect':
            query = parse_qs(parsed.query)
            location = query.get('to', ['/'])[0]
            code = int(query.get('code', ['302'])[0])
            self.send_response(code)
            self.send_header('Location', location)
            self.send_header('Content-Length', '0')
            self.end_headers()
        elif parsed.path == '/set-cookie':
            # Issue #23: a session-setting endpoint for cookie-isolation tests.
            query = parse_qs(parsed.query)
            value = query.get('value', ['marker'])[0]
            payload = b'{"ok": true}'
            self.send_response(200)
            self.send_header('Set-Cookie', f'role_marker={value}; Path=/')
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif parsed.path == '/binary':
            payload = b'\x00\xff\xfe\x00\x01not-text\x00\xff'
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            payload = (
                f'{{"path": "{self.path}", "host": "{self.headers.get("Host", "")}", '
                f'"method": "{self.command}", "body": "{request_body}"}}'
            ).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep test output clean


class _FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args: object) -> None:
        super().__init__(*args)  # pyright: ignore[reportUnknownMemberType, reportArgumentType]
        self.requests: list[dict[str, str]] = []

    @property
    def base_url(self) -> str:
        host, port = self.server_address[:2]
        return f'http://{host}:{port}'

    @property
    def port(self) -> int:
        port = self.server_address[1]
        return int(port)  # pyright: ignore[reportUnknownArgumentType]


@pytest.fixture
def target_server() -> Iterator[_FixtureServer]:
    """A running fixture target on 127.0.0.1 with an ephemeral port."""
    server = _FixtureServer(('127.0.0.1', 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
