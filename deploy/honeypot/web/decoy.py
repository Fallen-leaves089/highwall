"""Small stateful HTTP decoy used by the isolated honeypot deployment."""

from __future__ import annotations

import html
import json
import os
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY_BYTES = 128 * 1024


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

    def log_message(self, format: str, *args: object) -> None:
        forwarded = self.headers.get("X-Forwarded-For", self.client_address[0])
        sys.stdout.write(
            f"client={forwarded} method={self.command} path={self.path.split('?', 1)[0]} "
            f"message={format % args}\n"
        )
        sys.stdout.flush()

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


def main() -> None:
    port = int(os.environ.get("DECOY_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), DecoyHandler)
    server.daemon_threads = True
    sys.stdout.write(f"decoy web listening on {port}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
