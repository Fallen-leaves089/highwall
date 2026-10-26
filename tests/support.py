"""Shared test fixtures for HighWall."""

from __future__ import annotations

import copy
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from highwall.config import Config, parse_config
from highwall.proxy import GatewayServer
from highwall.runtime import Runtime


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def base_config(
    base_dir: Path,
    upstream_port: int,
    *,
    overrides: dict[str, Any] | None = None,
) -> Config:
    data: dict[str, Any] = {
        "version": 1,
        "server": {
            "listen_host": "127.0.0.1",
            "listen_port": 18090,
            "max_connections": 32,
            "header_timeout": 1.0,
            "body_timeout": 2.0,
        },
        "upstream": {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": upstream_port,
            "connect_timeout": 0.3,
            "read_timeout": 1.0,
            "max_response_bytes": 65536,
        },
        "policy": {
            "allowed_hosts": ["test.local"],
            "allowed_methods": ["GET", "HEAD", "POST"],
            "allowed_path_prefixes": ["/"],
            "deny_path_prefixes": ["/.git", "/.env", "/server-status"],
            "reject_encoded_separators": True,
            "reject_duplicate_headers": True,
            "reject_get_body": True,
            "allowed_body_content_types": [
                "application/x-www-form-urlencoded",
                "application/json",
                "text/plain",
            ],
            "max_request_line": 4096,
            "max_header_count": 32,
            "max_header_bytes": 8192,
            "max_body_bytes": 4096,
            "waf_enabled": True,
            "waf_mode": "block",
            "waf_rules": ["sqli", "xss", "traversal", "cmdi", "jndi"],
        },
        "rate_limit": {
            "enabled": False,
            "per_ip_rate": 20,
            "per_ip_burst": 40,
            "global_rate": 200,
            "global_burst": 400,
        },
        "audit": {
            "path": "audit.jsonl",
            "max_bytes": 1048576,
            "backup_count": 2,
            "include_client_ip": True,
        },
        "admin": {"enabled": False},
    }
    if overrides:
        _merge(data, overrides)
    return parse_config(data, base_dir)


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


class UpstreamState:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def add(self, item: dict[str, Any]) -> None:
        with self.lock:
            self.requests.append(item)

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.requests)


class _StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "StubUpstream"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        self.server.state.add(
            {
                "method": self.command,
                "path": self.path,
                "headers": list(self.headers.items()),
                "body": body,
            }
        )
        path = self.path.split("?", 1)[0]
        if path == "/slow":
            time.sleep(0.3)
        if path == "/hold":
            self.server.hold_release.wait(5.0)
        if path == "/big":
            payload = b"x" * 100000
            status = 200
        elif path == "/status/404":
            payload = b"not found"
            status = 404
        elif path == "/status/500":
            payload = b"upstream failure"
            status = 500
        elif path == "/unsafe":
            payload = b"unsafe"
            status = 200
        elif path == "/leak-secret":
            payload = b"debug dump\n-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAK\n"
            status = 200
        elif path == "/leak-debug":
            payload = b"Traceback (most recent call last):\n  File \"app.py\", line 1, in <module>\n"
            status = 200
        elif path == "/echo":
            payload = json.dumps(
                {
                    "path": self.path,
                    "host": self.headers.get("Host"),
                    "xff": self.headers.get("X-Forwarded-For"),
                    "body": body.decode("utf-8", errors="replace"),
                },
                separators=(",", ":"),
            ).encode("utf-8")
            status = 200
        else:
            payload = b"hello from upstream"
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Server", "upstream-secret")
        self.send_header("X-Powered-By", "php/leaky")
        self.send_header("X-Custom", "keep-me")
        self.send_header("Content-Security-Policy", "default-src *")
        self.send_header("Set-Cookie", "a=1; Path=/")
        self.send_header("Set-Cookie", "b=2; Path=/")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(payload)
            except OSError:
                pass

    do_GET = _handle
    do_HEAD = _handle
    do_POST = _handle
    do_PUT = _handle


class StubUpstream:
    def __init__(self) -> None:
        self.state = UpstreamState()
        self.hold_release = threading.Event()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
        self.server.state = self.state
        self.server.hold_release = self.hold_release
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self) -> "StubUpstream":
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


class RawUpstream:
    """One-shot byte-level upstream for malformed response tests."""

    def __init__(self, response: bytes | list[tuple[bytes, float]]) -> None:
        self._response = response
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = int(self.server.getsockname()[1])
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            self.server.settimeout(2.0)
            connection, _ = self.server.accept()
            connection.settimeout(2.0)
            try:
                connection.recv(65536)
                if isinstance(self._response, bytes):
                    connection.sendall(self._response)
                else:
                    for chunk, delay in self._response:
                        if delay:
                            time.sleep(delay)
                        connection.sendall(chunk)
            except OSError:
                pass
            finally:
                connection.close()
        except OSError:
            pass
        finally:
            self.server.close()

    def __enter__(self) -> "RawUpstream":
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        try:
            self.server.close()
        except OSError:
            pass
        self.thread.join(timeout=2.0)


class GatewayHarness:
    def __init__(self, config: Config, token: str | None = None) -> None:
        self.runtime = Runtime.build(config, admin_token=token)
        self.server = GatewayServer(("127.0.0.1", 0), self.runtime)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self) -> "GatewayHarness":
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


def build_request(
    method: str = "GET",
    path: str = "/ok",
    *,
    host: str | None = "test.local",
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    include_content_length: bool = True,
    version: str = "HTTP/1.1",
) -> bytes:
    lines = [f"{method} {path} {version}"]
    if host is not None:
        lines.append(f"Host: {host}")
    if headers:
        lines.extend(f"{name}: {value}" for name, value in headers)
    if include_content_length and (body or method in {"POST", "PUT", "PATCH"}):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def send_raw(port: int, payload: bytes, *, timeout: float = 3.0, half_close: bool = True) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        if half_close:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def request_once(port: int, payload: bytes, **kwargs: Any) -> bytes:
    return send_raw(port, payload, **kwargs)


def parse_response(raw: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise AssertionError(f"incomplete response: {raw[:200]!r}")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    status = int(parts[1])
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon:
            raise AssertionError(f"bad response header: {line!r}")
        headers.append((name.decode("ascii"), value.strip().decode("latin-1")))
    return status, headers, body


def header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    lowered = name.lower()
    return [value for header_name, value in headers if header_name.lower() == lowered]


def audit_text(base_dir: Path) -> str:
    path = base_dir / "audit.jsonl"
    return path.read_text("utf-8") if path.exists() else ""
