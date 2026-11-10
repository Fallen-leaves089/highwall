"""Small stateful HTTP decoy used by the isolated honeypot deployment."""

from __future__ import annotations

import html
import http.client
import ipaddress
import json
import os
import secrets
import socket
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY_BYTES = 128 * 1024
MAX_CONNECTIONS = 32
IDLE_TIMEOUT_SECONDS = 30.0
MAX_CONNECTION_SECONDS = 120.0
MAX_HEADER_LINE_BYTES = 8192
MAX_HEADERS = 64
MAX_LOG_VALUE = 256

http.client._MAXLINE = MAX_HEADER_LINE_BYTES
http.client._MAXHEADERS = MAX_HEADERS
BaseHTTPRequestHandler.max_line_length = MAX_HEADER_LINE_BYTES
BaseHTTPRequestHandler.max_headers = MAX_HEADERS


def _listen_host() -> str:
    raw = os.environ.get("LISTEN_HOST", "127.0.0.1").strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise SystemExit("LISTEN_HOST must be an IPv4 literal") from exc
    if address.version != 4:
        raise SystemExit("LISTEN_HOST must be an IPv4 literal")
    return str(address)


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc
    if value < 1:
        raise SystemExit(f"{name} must be positive")
    return value


def _positive_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number") from exc
    if value <= 0:
        raise SystemExit(f"{name} must be positive")
    return value


def _log_value(value: str) -> str:
    cleaned = "".join(ch if 0x20 <= ord(ch) <= 0x7E else "?" for ch in value)
    return (cleaned[:MAX_LOG_VALUE] or "-")


def _page(title: str, body: str) -> bytes:
    document = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui,sans-serif;background:#f4f6f8;margin:0}"
        "main{max-width:760px;margin:48px auto;background:#fff;padding:32px;"
        "border-radius:8px;box-shadow:0 2px 16px #0002}label{display:block;margin:16px 0 6px}"
        "input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #bbb;border-radius:4px}"
        "button{margin-top:20px;padding:10px 18px;border:0;border-radius:4px;background:#175a9b;color:#fff}"
        "code,pre{background:#eef1f4;padding:2px 5px;border-radius:3px}</style></head><body>"
        f"<main>{body}</main></body></html>"
    )
    return document.encode("utf-8")


class DecoyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.24.0"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.idle_timeout)
        self._lifetime_timer = threading.Timer(self.server.max_connection_seconds, self._expire_connection)
        self._lifetime_timer.daemon = True
        self._lifetime_timer.start()

    def finish(self) -> None:
        timer = getattr(self, "_lifetime_timer", None)
        if timer is not None:
            timer.cancel()
        super().finish()

    def _expire_connection(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _request_path(self) -> str:
        raw = getattr(self, "path", "")
        try:
            return urllib.parse.urlsplit(raw).path or "/"
        except ValueError:
            return "-"

    def _write_log(self, status: str, size: str) -> None:
        headers = getattr(self, "headers", None)
        declared = headers.get("X-Forwarded-For", "-") if headers is not None else "-"
        peer = getattr(self, "client_address", ("-", 0))[0]
        method = getattr(self, "command", None) or "-"
        sys.stdout.write(
            f"peer={_log_value(str(peer))} declared_xff={_log_value(str(declared or '-'))} "
            f"method={_log_value(str(method))} path={_log_value(self._request_path())} "
            f"status={_log_value(status)} bytes={_log_value(size)}\n"
        )
        sys.stdout.flush()

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        self._write_log(str(code), str(size))

    def log_error(self, format: str, *args: object) -> None:
        self._write_log("error", "-")

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _send(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = "text/html; charset=utf-8",
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self) -> bytes | None:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError:
            self._send(400, _page("Bad request", "<h1>Bad request</h1>"))
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(413, _page("Too large", "<h1>Request body too large</h1>"))
            return None
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self._send(400, _page("Bad request", "<h1>Incomplete request body</h1>"))
            return None
        return body

    def _logged_in(self) -> bool:
        cookie = self.headers.get("Cookie", "")
        return any(part.strip().startswith("session=") for part in cookie.split(";"))

    def _redirect(self, location: str, headers: tuple[tuple[str, str], ...] = ()) -> None:
        self._send(303, b"", headers=(("Location", location), *headers))

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            self._redirect("/login")
            return
        if path == "/login":
            body = _page(
                "Operations Portal",
                "<h1>Operations Portal</h1><p>Restricted internal access.</p>"
                "<form method=\"post\" action=\"/login\">"
                "<label>Username</label><input name=\"username\" autocomplete=\"username\">"
                "<label>Password</label><input type=\"password\" name=\"password\" autocomplete=\"current-password\">"
                "<button type=\"submit\">Sign in</button></form>",
            )
            self._send(200, body)
            return
        if path == "/admin":
            if not self._logged_in():
                self._redirect("/login")
                return
            body = _page(
                "Admin Console",
                "<h1>Admin Console</h1><p>Signed in as <code>ops-admin</code>.</p>"
                "<table><tr><th>Service</th><th>State</th></tr>"
                "<tr><td>build-runner-01</td><td>healthy</td></tr>"
                "<tr><td>backup-scheduler</td><td>degraded</td></tr></table>"
                "<h2>Upload</h2><form method=\"post\" action=\"/admin/upload\">"
                "<input type=\"file\" name=\"artifact\"><button type=\"submit\">Queue upload</button></form>"
                "<p><a href=\"/api/config\">Service configuration</a></p>",
            )
            self._send(200, body)
            return
        if path == "/api/config":
            if not self._logged_in():
                self._send(403, _page("Forbidden", "<h1>Authentication required</h1>"))
                return
            payload = json.dumps(
                {
                    "environment": "staging",
                    "region": "internal-1",
                    "features": ["artifacts", "schedules", "diagnostics"],
                    "database_host": "db.staging.invalid",
                },
                indent=2,
            ).encode("utf-8")
            self._send(200, payload, content_type="application/json")
            return
        if path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\n", content_type="text/plain")
            return
        self._send(404, _page("Not found", "<h1>404 Not Found</h1>"))

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        body = self._read_body()
        if body is None:
            return
        if path == "/login":
            form = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
            username = form.get("username", [""])[0]
            if not username:
                self._send(400, _page("Sign in failed", "<h1>Username is required</h1>"))
                return
            token = secrets.token_hex(16)
            self._redirect(
                "/admin",
                headers=(("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Lax"),),
            )
            return
        if path == "/admin/upload":
            if not self._logged_in():
                self._send(403, _page("Forbidden", "<h1>Authentication required</h1>"))
                return
            self._send(202, _page("Queued", "<h1>Artifact queued</h1><p>Job 4812 is pending.</p>"))
            return
        self._send(404, _page("Not found", "<h1>404 Not Found</h1>"))

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_PUT(self) -> None:
        self.do_POST()

    def do_DELETE(self) -> None:
        body = self._read_body()
        if body is None:
            return
        self._send(405, _page("Not allowed", "<h1>Method not allowed</h1>"))


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        max_connections: int,
        idle_timeout: float,
        max_connection_seconds: float,
    ) -> None:
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self.max_connection_seconds = max_connection_seconds
        self._active_connections = 0
        self._active_lock = threading.Lock()
        super().__init__(server_address, handler)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        with self._active_lock:
            if self._active_connections >= self.max_connections:
                accepted = False
            else:
                self._active_connections += 1
                accepted = True
        if not accepted:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._active_lock:
                self._active_connections -= 1
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active_connections -= 1


def main() -> None:
    port = int(os.environ.get("DECOY_PORT", "8080"))
    listen_host = _listen_host()
    max_connections = _positive_int("DECOY_MAX_CONNECTIONS", MAX_CONNECTIONS)
    idle_timeout = _positive_float("DECOY_IDLE_TIMEOUT_SECONDS", IDLE_TIMEOUT_SECONDS)
    max_connection_seconds = _positive_float("DECOY_MAX_CONNECTION_SECONDS", MAX_CONNECTION_SECONDS)
    server = BoundedThreadingHTTPServer(
        (listen_host, port),
        DecoyHandler,
        max_connections=max_connections,
        idle_timeout=idle_timeout,
        max_connection_seconds=max_connection_seconds,
    )
    server.daemon_threads = True
    sys.stdout.write(
        f"decoy web listening on {listen_host}:{port} max_connections={max_connections} "
        f"idle={idle_timeout}s total={max_connection_seconds}s\n"
    )
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
