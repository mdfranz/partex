"""Deliberately vulnerable fixture target app — PLAN §13, issue #21.

A stdlib ``http.server`` app bound to ``127.0.0.1``.  It serves exactly the
surface the validation experiments need:

- ``/`` — HTML response with a **version-leaking** ``Server`` banner and no
  security headers (deliberately vulnerable).
- ``/robots.txt`` — plain metadata response (the banner rides along).
- any unknown path — a ``404`` whose body is a fake **stack trace** with
  absolute paths (the verbose-error surface), or, with ``catch_all`` set, ``200``
  with the normal app shell (a single-page-app catch-all route, #53).
- ``/admin/shutdown`` — an in-scope-shaped path that fixture engagements put
  in ``scope.exclusions`` (the scope-gate decoy).

Every received request is recorded in ``server.requests`` so tests can assert
that refused work never put bytes on the wire.  ``main()`` binds a fixed port
for operator use; tests call :func:`make_server` for an ephemeral port.
"""

import http.server
import threading
from urllib.parse import urlparse

STACK_TRACE_BODY = (
    'Traceback (most recent call last):\n'
    '  File "/var/www/app/views.py", line 42, in handler\n'
    '    return render(page)\n'
    'RuntimeError: fixture boom\n'
    'Fatal error: unhandled exception in /var/www/app\n'
)

INDEX_HTML = '<html><body><h1>fixture target app</h1></body></html>'


class _FixtureApp(http.server.BaseHTTPRequestHandler):
    # The deliberate leak: explicit version digits for version-disclosure to find.
    server_version = 'FixtureTarget/2.3.1'
    sys_version = ''

    def version_string(self) -> str:
        """The hardened variant (PLAN §13.4): no version digits in the banner."""
        if getattr(self.server, 'hardened', False):
            return 'FixtureTarget'
        return super().version_string()

    def do_GET(self) -> None:
        server: _FixtureAppServer = self.server
        server.requests.append({'method': self.command, 'path': self.path})
        path = urlparse(self.path).path
        if path == '/':
            self._send(200, 'text/html', INDEX_HTML)
        elif path == '/robots.txt':
            self._send(200, 'text/plain', 'User-agent: *\nDisallow: /admin/\n')
        elif server.catch_all:
            self._send(200, 'text/html', INDEX_HTML)  # SPA-style catch-all: no error handler is ever reached
        else:
            # Unknown paths get the verbose error page — the deliberately
            # vulnerable default handler (including /admin/shutdown).  The
            # hardened variant serves clean errors instead (verify tests, #22).
            body = 'Not Found' if server.hardened else STACK_TRACE_BODY
            self._send(404, 'text/plain', body)

    def _send(self, code: int, content_type: str, body: str) -> None:
        payload = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep test output clean


class _FixtureAppServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args: object) -> None:
        super().__init__(*args)  # pyright: ignore[reportUnknownMemberType, reportArgumentType]
        self.requests: list[dict[str, str]] = []
        # Toggled by verification tests (#22) to simulate the target being
        # fixed between the finding and the replay (PLAN §13.4: the hardened
        # variant yields `not_reproduced`).
        self.hardened: bool = False
        # SPA variant (#53): unknown paths answer 200 with the app shell instead of an error page.
        self.catch_all: bool = False

    @property
    def base_url(self) -> str:
        host, port = self.server_address[:2]
        return f'http://{host}:{port}'

    @property
    def port(self) -> int:
        return int(self.server_address[1])  # pyright: ignore[reportUnknownArgumentType]


def make_server(host: str = '127.0.0.1', port: int = 0) -> _FixtureAppServer:
    """Build (not start) a fixture app server; tests own its lifecycle."""
    return _FixtureAppServer((host, port), _FixtureApp)


def serve_thread(server: _FixtureAppServer) -> threading.Thread:
    """Start serving in a daemon thread."""
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def main() -> None:
    """Operator entry point: run on a fixed localhost port."""
    server = make_server(port=8765)
    serve_thread(server)
    print(f'fixture target app listening on {server.base_url} (ctrl-c to stop)')
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
