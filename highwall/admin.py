"""Read-only management endpoint, restricted to loopback and bearer auth."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import __version__
from .audit import AuditRecord
from .config import canonicalize_host
from .runtime import Runtime

_LOG = logging.getLogger(__name__)
_MAX_ADMIN_CONNECTIONS = 16


class AdminHandler(BaseHTTPRequestHandler):
    server: "AdminServer"
    protocol_version = "HTTP/1.1"
    server_version = "HighWall"
    sys_version = ""
    timeout = 10.0

    def version_string(self) -> str:
        return "HighWall"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        return

    def _peer_is_loopback(self) -> bool:
        try:
            address = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return address.is_loopback

    def _host_is_loopback(self) -> bool:
        values = self.headers.get_all("Host") or []
        if len(values) != 1 or not values[0]:
            return False
        try:
            canonical = canonicalize_host(values[0])
            parsed = urllib.parse.urlsplit("//" + canonical)
            host = parsed.hostname
            port = parsed.port if parsed.port is not None else 80
            if host is None or port != self.server.server_address[1]:
                return False
            if host == "localhost":
                return True
            return ipaddress.ip_address(host).is_loopback
        except (ValueError, TypeError):
            return False

    def _authorized(self) -> bool:
        token = self.server.runtime.admin_token
        if not token:
            return False
        values = self.headers.get_all("Authorization") or []
        if len(values) != 1:
            return False
        scheme, separator, provided = values[0].partition(" ")
        if not separator or scheme.lower() != "bearer" or not provided or " " in provided:
            return False
        try:
            provided_bytes = provided.encode("ascii")
            expected_bytes = token.encode("ascii")
        except UnicodeEncodeError:
            return False
        return hmac.compare_digest(hashlib.sha256(provided_bytes).digest(), hashlib.sha256(expected_bytes).digest())

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")

    def _audit(self, status: int, path: str) -> None:
        self.server.runtime.metrics.inc("admin_requests_total")
        self.server.runtime.audit.write(
            AuditRecord(
                event="admin_access",
                client_ip=self.client_address[0],
                method=self.command or "",
                path=path,
                status=status,
                outcome="allowed" if status < 400 else "blocked",
            )
        )

    def _respond(self, status: int, content_type: str, body: bytes, head_only: bool = False) -> None:
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            if not head_only and body:
                self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            pass
        finally:
            self._audit(status, urllib.parse.urlsplit(self.path).path)

    def _json(self, status: int, value: Any, head_only: bool = False) -> None:
        body = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self._respond(status, "application/json; charset=utf-8", body, head_only)

    def _error(self, status: int, code: str, head_only: bool = False) -> None:
        self._json(status, {"error": code}, head_only)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._error(int(code), "request_rejected")

    def _dispatch(self, head_only: bool = False, method_allowed: bool = True) -> None:
        if not self._peer_is_loopback():
            self._error(403, "forbidden", head_only)
            return
        if not self._host_is_loopback():
            self._error(400, "invalid_host", head_only)
            return
        if self.path.startswith("//") or not self.path.startswith("/"):
            self._error(400, "bad_request", head_only)
            return
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if not method_allowed:
            self._error(405, "method_not_allowed", head_only)
            return
        if path == "/healthz":
            if parsed.query:
                self._error(400, "bad_request", head_only)
                return
            self._json(
                200,
                {
                    "status": "ok",
                    "version": __version__,
                    "uptime_seconds": round(self.server.runtime.uptime_seconds(), 3),
                },
                head_only,
            )
            return
        if not self._authorized():
            self.close_connection = True
            body = b'{"error":"unauthorized"}'
            try:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="highwall-admin"')
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self._security_headers()
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)
                    self.wfile.flush()
            except OSError:
                pass
            finally:
                self._audit(401, path)
            return
        if path == "/metrics":
            if parsed.query:
                self._error(400, "bad_request", head_only)
                return
            extra = {
                "uptime_seconds": self.server.runtime.uptime_seconds(),
                "rate_limit_clients": float(self.server.runtime.per_ip_limiter.size()) if self.server.runtime.per_ip_limiter else 0.0,
                "auto_ban_entries": float(self.server.runtime.auto_ban.size()) if self.server.runtime.auto_ban else 0.0,
                "honeypot_ban_entries": float(self.server.runtime.honeypot_ban.active_bans())
                if self.server.runtime.honeypot_ban
                else 0.0,
            }
            body = self.server.runtime.metrics.prometheus(extra).encode("utf-8")
            self._respond(200, "text/plain; version=0.0.4; charset=utf-8", body, head_only)
            return
        if path == "/offenders":
            if parsed.query:
                self._error(400, "bad_request", head_only)
                return
            registry = self.server.runtime.offenders
            records = registry.active() if registry is not None else []
            self._json(
                200,
                {
                    "count": len(records),
                    "marks": [
                        record.as_public(
                            include_client_ip=self.server.runtime.config.alerting.include_client_ip
                        )
                        for record in records
                    ],
                },
                head_only,
            )
            return
        if path == "/audit/tail":
            try:
                query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=bool(parsed.query))
            except ValueError:
                self._error(400, "bad_request", head_only)
                return
            if any(key != "lines" for key in query):
                self._error(400, "bad_request", head_only)
                return
            values = query.get("lines", ["50"])
            if len(values) != 1 or not values[0].isdigit():
                self._error(400, "bad_request", head_only)
                return
            limit = int(values[0], 10)
            if not 1 <= limit <= self.server.runtime.config.admin.audit_tail_max_lines:
                self._error(400, "bad_request", head_only)
                return
            self._json(200, {"events": self.server.runtime.audit.tail(limit)}, head_only)
            return
        self._error(404, "not_found", head_only)

    def do_GET(self) -> None:
        self._dispatch(False)

    def do_HEAD(self) -> None:
        self._dispatch(True)

    def do_POST(self) -> None:
        self._dispatch(False, method_allowed=False)

    def do_PUT(self) -> None:
        self._dispatch(False, method_allowed=False)

    def do_PATCH(self) -> None:
        self._dispatch(False, method_allowed=False)

    def do_DELETE(self) -> None:
        self._dispatch(False, method_allowed=False)

    def do_OPTIONS(self) -> None:
        self._dispatch(False, method_allowed=False)

    def do_TRACE(self) -> None:
        self._dispatch(False, method_allowed=False)

    def do_CONNECT(self) -> None:
        self._dispatch(False, method_allowed=False)


class AdminServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"
    block_on_close = False

    def __init__(self, address: tuple[str, int], runtime: Runtime) -> None:
        try:
            if ipaddress.ip_address(address[0]).version == 6:
                self.address_family = socket.AF_INET6
        except ValueError:
            pass
        self.runtime = runtime
        self._slots = threading.BoundedSemaphore(_MAX_ADMIN_CONNECTIONS)
        super().__init__(address, AdminHandler)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        _LOG.error("admin connection handler failed")


def build_admin_server(runtime: Runtime) -> AdminServer | None:
    admin = runtime.config.admin
    if not admin.enabled:
        return None
    if runtime.admin_token is None:
        raise ValueError("admin token is required when admin is enabled")
    return AdminServer((admin.listen_host, admin.listen_port), runtime)
