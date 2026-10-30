"""Strict reverse proxy, bounded request reader, and response sanitizer."""

from __future__ import annotations

import http.client
import ipaddress
import logging
import os
import re
import secrets
import socket
import socketserver
import ssl
import threading
import time
from dataclasses import dataclass
from email.utils import formatdate
from http import HTTPStatus
from typing import Any, Iterable

from .audit import AuditRecord
from .config import Config, HoneypotRoute
from .dlp import inspect_response
from .errors import (
    BadGateway,
    GatewayTimeout,
    HighWallError,
    MethodNotAllowed,
    RequestTimeout,
    ServiceUnavailable,
    TooManyRequests,
)
from .integrity import inspect_integrity
from .protocol import (
    RequestHead,
    discard_request_body,
    read_request_body,
    read_request_head,
)
from .runtime import Runtime
from .tlsfingerprint import TLSProfile, peek_tls_profile
from .waf import (
    HeadInspection,
    inspect_body,
    normalize_ip,
    resolve_client_ip,
    validate_head,
)

_LOG = logging.getLogger(__name__)

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_REQUEST_STRIPPED = _HOP_BY_HOP | {
    "accept-encoding",
    "expect",
    "forwarded",
    "front-end-https",
    "host",
    "content-length",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-forwarded-protocol",
    "x-forwarded-proto",
    "x-forwarded-server",
    "x-forwarded-ssl",
    "x-http-method-override",
    "x-method-override",
    "x-original-host",
    "x-original-url",
    "x-real-ip",
    "x-request-id",
    "x-rewrite-url",
    "x-url-scheme",
}
_RESPONSE_STRIPPED = _HOP_BY_HOP | {
    "alt-svc",
    "content-encoding",
    "content-length",
    "content-security-policy",
    "content-security-policy-report-only",
    "date",
    "expect-ct",
    "permissions-policy",
    "public-key-pins",
    "referrer-policy",
    "server",
    "strict-transport-security",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
    "x-request-id",
}
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CIRCUIT_STATE_CODES = {"closed": 0.0, "half_open": 1.0, "open": 2.0}
_TARPIT_BODY = (
    b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    b"<title>Processing</title></head><body><h1>Request accepted</h1>"
    b"<p>This request is being processed. Please wait.</p></body></html>"
)


@dataclass(frozen=True)
class UpstreamResponse:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    upstream_content_length: int | None


class DeadlineReader:
    """Buffered socket reader with one absolute deadline per phase."""

    def __init__(self, sock: socket.socket, io_timeout: float, total_timeout: float) -> None:
        self.sock = sock
        self.io_timeout = max(0.05, io_timeout)
        self.reset_deadline(total_timeout)
        self.buffer = bytearray()

    def reset_deadline(self, total_timeout: float) -> None:
        self.deadline = time.monotonic() + max(0.05, total_timeout)

    def _recv(self) -> bytes:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request phase deadline exceeded")
        self.sock.settimeout(min(self.io_timeout, remaining))
        return self.sock.recv(65536)

    def readline(self, limit: int) -> bytes:
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                take = newline + 1
                if take > limit:
                    data = bytes(self.buffer[: limit + 1])
                    del self.buffer[: limit + 1]
                    return data
                data = bytes(self.buffer[:take])
                del self.buffer[:take]
                return data
            if len(self.buffer) > limit:
                data = bytes(self.buffer[: limit + 1])
                del self.buffer[: limit + 1]
                return data
            chunk = self._recv()
            if not chunk:
                data = bytes(self.buffer)
                self.buffer.clear()
                return data
            self.buffer.extend(chunk)

    def read(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("negative read length")
        result = bytearray()
        if self.buffer:
            take = min(length, len(self.buffer))
            result.extend(self.buffer[:take])
            del self.buffer[:take]
        while len(result) < length:
            chunk = self._recv()
            if not chunk:
                break
            needed = length - len(result)
            if len(chunk) > needed:
                result.extend(chunk[:needed])
                self.buffer.extend(chunk[needed:])
                break
            result.extend(chunk)
        return bytes(result)


def _connection_tokens(headers: Iterable[tuple[str, str]]) -> set[str]:
    tokens: set[str] = set()
    for name, value in headers:
        if name.lower() != "connection":
            continue
        for token in value.split(","):
            cleaned = token.strip().lower()
            if cleaned and _TOKEN_RE.fullmatch(cleaned):
                tokens.add(cleaned)
    return tokens


def _valid_header_name(name: str) -> bool:
    return bool(_TOKEN_RE.fullmatch(name))


def _valid_header_value(value: str) -> bool:
    for ch in value:
        code = ord(ch)
        if code == 0x7F or (code < 0x20 and ch != "\t") or code > 0xFF:
            return False
    return True


def _safe_reason(reason: str, status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        cleaned = "".join(ch if 0x20 <= ord(ch) <= 0x7E else " " for ch in reason)
        return cleaned[:64] or "Response"


def _upstream_content_length(headers: tuple[tuple[str, str], ...]) -> int | None:
    values = [value.strip() for name, value in headers if name.lower() == "content-length"]
    if not values:
        return None
    if len(values) != 1:
        raise BadGateway("ambiguous upstream Content-Length", rule_id="HW-UPSTREAM-1008")
    value = values[0]
    if not value or len(value) > 20 or not value.isascii() or not value.isdigit():
        raise BadGateway("invalid upstream Content-Length", rule_id="HW-UPSTREAM-1008")
    length = int(value, 10)
    if length > 2**63 - 1:
        raise BadGateway("invalid upstream Content-Length", rule_id="HW-UPSTREAM-1008")
    return length


class UpstreamProxy:
    def __init__(self, config: Config) -> None:
        self.config = config

    def _request_headers(
        self,
        inspection: HeadInspection,
        head: RequestHead,
        body: bytes,
        request_id: str,
        downstream_tls: bool,
    ) -> list[tuple[str, str]]:
        drop = set(_REQUEST_STRIPPED)
        drop.update(_connection_tokens(head.headers))
        forwarded: list[tuple[str, str]] = []
        for name, value in head.headers:
            lower = name.lower()
            if lower in drop or lower.startswith("proxy-"):
                continue
            forwarded.append((name, value))
        host_header = self.config.upstream.host_header or inspection.host
        forwarded.append(("Host", host_header))
        forwarded.append(("X-Forwarded-For", inspection.client_ip))
        forwarded.append(("X-Forwarded-Proto", "https" if downstream_tls else "http"))
        forwarded.append(("X-Forwarded-Host", inspection.host))
        forwarded.append(("X-Request-ID", request_id))
        forwarded.append(("Accept-Encoding", "identity"))
        if body or head.content_length > 0 or inspection.method in {"POST", "PUT", "PATCH"}:
            forwarded.append(("Content-Length", str(len(body))))
        forwarded.append(("Connection", "close"))
        return forwarded

    def request(
        self,
        head: RequestHead,
        inspection: HeadInspection,
        body: bytes,
        request_id: str,
        downstream_tls: bool,
    ) -> UpstreamResponse:
        config = self.config.upstream
        connection_class = http.client.HTTPSConnection if config.scheme == "https" else http.client.HTTPConnection
        deadline = time.monotonic() + config.total_timeout
        connect_timeout = min(config.connect_timeout, config.total_timeout)
        connection = connection_class(config.host, config.port, timeout=connect_timeout)
        timed_out = threading.Event()

        def expire_connection() -> None:
            timed_out.set()
            try:
                connection.close()
            except OSError:
                pass

        watchdog = threading.Timer(max(0.05, deadline - time.monotonic()), expire_connection)
        watchdog.daemon = True
        watchdog.start()
        try:
            connection.connect()
            if connection.sock is not None:
                remaining = max(0.05, deadline - time.monotonic())
                connection.sock.settimeout(min(config.read_timeout, remaining))
            connection.putrequest(head.method, inspection.upstream_target, skip_host=True, skip_accept_encoding=True)
            for name, value in self._request_headers(inspection, head, body, request_id, downstream_tls):
                connection.putheader(name, value)
            connection.endheaders(body if body else None)
            response = connection.getresponse()
            if 100 <= response.status < 200:
                raise BadGateway("interim upstream responses are not accepted", rule_id="HW-UPSTREAM-1007")
            if response.status < 200 or response.status > 599:
                raise BadGateway("invalid upstream status", rule_id="HW-UPSTREAM-1007")
            headers = tuple(response.getheaders())
            content_encoding = [
                value.strip().lower()
                for name, value in headers
                if name.lower() == "content-encoding"
            ]
            if len(content_encoding) > 1 or (content_encoding and content_encoding[0] != "identity"):
                raise BadGateway("encoded upstream responses are not accepted", rule_id="HW-UPSTREAM-1011")
            if len(headers) > 200:
                raise BadGateway("upstream response has too many headers", rule_id="HW-UPSTREAM-1001")
            header_bytes = sum(len(name) + len(value) + 4 for name, value in headers)
            if header_bytes > 65536:
                raise BadGateway("upstream response headers are too large", rule_id="HW-UPSTREAM-1002")
            upstream_content_length = _upstream_content_length(headers)
            transfer_encoding = [
                value.strip().lower()
                for name, value in headers
                if name.lower() == "transfer-encoding"
            ]
            if transfer_encoding:
                if len(transfer_encoding) != 1 or transfer_encoding[0] != "chunked":
                    raise BadGateway("unsupported upstream Transfer-Encoding", rule_id="HW-UPSTREAM-1009")
                if upstream_content_length is not None:
                    raise BadGateway("ambiguous upstream message framing", rule_id="HW-UPSTREAM-1008")
            if upstream_content_length is not None and upstream_content_length > config.max_response_bytes and head.method != "HEAD":
                raise BadGateway("upstream response exceeds configured limit", rule_id="HW-UPSTREAM-1003")
            if head.method == "HEAD" or response.status in {204, 304}:
                body_bytes = b""
            else:
                body_bytes = response.read(config.max_response_bytes + 1)
                if timed_out.is_set() or time.monotonic() >= deadline:
                    raise GatewayTimeout("upstream timed out", rule_id="HW-UPSTREAM-1004")
                if len(body_bytes) > config.max_response_bytes:
                    raise BadGateway("upstream response exceeds configured limit", rule_id="HW-UPSTREAM-1003")
                if upstream_content_length is not None and len(body_bytes) != upstream_content_length:
                    raise BadGateway("upstream Content-Length mismatch", rule_id="HW-UPSTREAM-1010")
            if timed_out.is_set() or time.monotonic() >= deadline:
                raise GatewayTimeout("upstream timed out", rule_id="HW-UPSTREAM-1004")
            return UpstreamResponse(
                status=response.status,
                reason=response.reason or "",
                headers=headers,
                body=body_bytes,
                upstream_content_length=upstream_content_length,
            )
        except TimeoutError as exc:
            raise GatewayTimeout("upstream timed out", rule_id="HW-UPSTREAM-1004") from exc
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            if timed_out.is_set() or time.monotonic() >= deadline:
                raise GatewayTimeout("upstream timed out", rule_id="HW-UPSTREAM-1004") from exc
            raise BadGateway("upstream connection failed", rule_id="HW-UPSTREAM-1004") from exc
        finally:
            watchdog.cancel()
            connection.close()


def _effective_security_headers(runtime: Runtime) -> list[tuple[str, str]]:
    headers = list(runtime.config.policy.security_headers)
    if runtime.config.server.tls.enabled and not any(
        name.lower() == "strict-transport-security" for name, _ in headers
    ):
        headers.append(("Strict-Transport-Security", "max-age=31536000"))
    return headers


def _clean_response_headers(
    response: UpstreamResponse,
    method: str,
    runtime: Runtime,
    request_id: str,
) -> tuple[list[tuple[str, str]], int | None]:
    upstream_connection = _connection_tokens(response.headers)
    configured_security = {name.lower(): (name, value) for name, value in _effective_security_headers(runtime)}
    drop = set(_RESPONSE_STRIPPED) | upstream_connection | set(configured_security)
    headers: list[tuple[str, str]] = []
    for name, value in response.headers:
        lower = name.lower()
        if lower in drop:
            continue
        if not _valid_header_name(name) or not _valid_header_value(value):
            raise BadGateway("upstream returned an unsafe header", rule_id="HW-UPSTREAM-1005")
        headers.append((name, value))
    present = {name.lower() for name, _ in headers}
    for name, value in configured_security.values():
        lower = name.lower()
        if lower in present or lower == "x-request-id":
            continue
        if not _valid_header_name(name) or not _valid_header_value(value):
            raise BadGateway("unsafe configured response header", rule_id="HW-UPSTREAM-1006")
        headers.append((name, value))
        present.add(lower)
    headers.append(("X-Request-ID", request_id))
    headers.append(("Connection", "close"))
    if response.status == 204:
        content_length = None
    elif method == "HEAD":
        content_length = response.upstream_content_length if response.upstream_content_length is not None else 0
    elif response.status == 304:
        content_length = response.upstream_content_length
    else:
        content_length = len(response.body)
    if content_length is not None:
        headers.append(("Content-Length", str(content_length)))
    return headers, content_length


def _honeypot_headers(
    route: HoneypotRoute,
    runtime: Runtime,
    request_id: str,
) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = [
        ("Content-Type", route.content_type),
        ("Cache-Control", "no-store"),
        ("X-Request-ID", request_id),
    ]
    present = {name.lower() for name, _ in headers}
    effective_security = _effective_security_headers(runtime)
    policy_security = {name.lower() for name, _ in effective_security}
    for name, value in route.headers:
        lower = name.lower()
        if lower not in present and lower not in policy_security:
            headers.append((name, value))
            present.add(lower)
    for name, value in effective_security:
        lower = name.lower()
        if lower not in present:
            headers.append((name, value))
            present.add(lower)
    return headers


def _error_page(status: int, code: str, request_id: str, rule_id: str) -> bytes:
    rule = rule_id or "-"
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>HighWall {status}</title></head><body><h1>{status}</h1>"
        f"<p>{code}</p><p>Request ID: {request_id}</p><p>Rule: {rule}</p>"
        "</body></html>"
    ).encode("utf-8")


class ProxyHandler(socketserver.BaseRequestHandler):
    server: "GatewayServer"

    def _send_bytes(self, data: bytes, deadline: float) -> None:
        view = memoryview(data)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("response send deadline exceeded")
            self.request.settimeout(max(0.05, remaining))
            sent = self.request.send(view[:65536])
            if sent <= 0:
                raise OSError("connection closed during send")
            view = view[sent:]

    def _send(
        self,
        status: int,
        headers: list[tuple[str, str]],
        body: bytes,
        *,
        method: str | None = None,
        content_length: int | None = None,
        server_header: str = "HighWall",
    ) -> int:
        runtime = self._runtime
        reason = _safe_reason("", status)
        lines = [f"HTTP/1.1 {status} {reason}"]
        lines.append(f"Date: {formatdate(usegmt=True)}")
        safe_server = server_header if _valid_header_value(server_header) else "HighWall"
        lines.append(f"Server: {safe_server}")
        lines.append("Connection: close")
        for name, value in headers:
            if not _valid_header_name(name) or not _valid_header_value(value):
                continue
            if name.lower() in {"content-length", "connection"}:
                continue
            lines.append(f"{name}: {value}")
        if content_length is not None:
            lines.append(f"Content-Length: {content_length}")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="strict")
        deadline = time.monotonic() + max(1.0, min(runtime.config.server.body_timeout, 30.0))
        try:
            self._send_bytes(head, deadline)
            send_body = method != "HEAD" and status not in {204, 304} and bool(body)
            if send_body:
                self._send_bytes(body, deadline)
                return len(body)
            return 0
        except (OSError, TimeoutError):
            return 0

    def _send_slow(
        self,
        status: int,
        headers: list[tuple[str, str]],
        body: bytes,
        *,
        method: str | None = None,
        duration_ms: int,
        content_length: int | None = None,
        server_header: str = "HighWall",
    ) -> int:
        runtime = self._runtime
        duration = max(0.0, min(float(duration_ms) / 1000.0, 60.0))
        reason = _safe_reason("", status)
        lines = [f"HTTP/1.1 {status} {reason}"]
        lines.append(f"Date: {formatdate(usegmt=True)}")
        safe_server = server_header if _valid_header_value(server_header) else "HighWall"
        lines.append(f"Server: {safe_server}")
        lines.append("Connection: close")
        present = {"server", "date", "connection", "content-length"}
        for name, value in headers:
            if not _valid_header_name(name) or not _valid_header_value(value):
                continue
            lower = name.lower()
            if lower in present:
                continue
            lines.append(f"{name}: {value}")
            present.add(lower)
        for name, value in _effective_security_headers(runtime):
            if name.lower() not in present:
                lines.append(f"{name}: {value}")
                present.add(name.lower())
        if content_length is not None:
            lines.append(f"Content-Length: {content_length}")
        head_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="strict")
        deadline = time.monotonic() + duration + max(1.0, min(runtime.config.server.body_timeout, 30.0))
        sent = 0
        try:
            self._send_bytes(head_bytes, deadline)
            if method == "HEAD" or status in {204, 304} or not body:
                if duration:
                    time.sleep(duration)
                return 0
            chunk_size = 64
            chunks = [body[offset : offset + chunk_size] for offset in range(0, len(body), chunk_size)]
            interval = duration / max(1, len(chunks))
            body_started = time.monotonic()
            for index, chunk in enumerate(chunks):
                if interval:
                    send_at = body_started + interval * (index + 1)
                    remaining = send_at - time.monotonic()
                    if remaining > 0:
                        time.sleep(remaining)
                self._send_bytes(chunk, deadline)
                sent += len(chunk)
            return sent
        except (OSError, TimeoutError):
            return sent
    def _send_error(
        self,
        error: HighWallError,
        request_id: str,
        method: str | None,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> int:
        body = _error_page(error.status, error.code, request_id, error.rule_id or "")
        headers: list[tuple[str, str]] = [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
        ]
        if isinstance(error, MethodNotAllowed) and error.allow:
            headers.append(("Allow", ", ".join(error.allow)))
        present = {name.lower() for name, _ in headers}
        for name, value in _effective_security_headers(self._runtime):
            if name.lower() not in present:
                headers.append((name, value))
                present.add(name.lower())
        if "x-content-type-options" not in present:
            headers.append(("X-Content-Type-Options", "nosniff"))
        if extra_headers:
            headers.extend(extra_headers)
        return self._send(error.status, headers, body, method=method, content_length=len(body))

    def handle(self) -> None:
        runtime, upstream = self.server.acquire_runtime()
        self._runtime = runtime
        try:
            self._handle(runtime, upstream)
        finally:
            self.server.release_runtime(runtime)

    def _handle(self, runtime: Runtime, upstream: "UpstreamProxy") -> None:
        policy = runtime.config.policy
        metrics = runtime.metrics
        request_id = secrets.token_hex(12)
        peer_ip = "unknown"
        try:
            peer_ip = normalize_ip(self.client_address[0])
        except HighWallError:
            pass
        client_ip = peer_ip
        tls_profile = self.server.take_tls_profile(self.client_address)
        head: RequestHead | None = None
        inspection: HeadInspection | None = None
        status = 500
        rule_id = ""
        response_bytes = 0
        request_body_bytes = 0
        phase = "parse"
        audit_needed = False
        forwarded = False
        honeypot_hit = False
        waf_detected = False
        dlp_detected = False
        integrity_detected = False
        response_blocked = False
        blocked_kind = ""
        banned_request = False
        route_slot_key: str | None = None
        fingerprint = ""
        shape_fingerprint = ""
        threat_delay_ms = 0
        threat_tarpitted = False
        threat_blocked = False
        threat_alert: dict | None = None
        tarpit_acquired = False
        ddos_alerts: list[dict] = []
        started = time.monotonic()
        metrics.inc("active_requests")

        def finish_audit() -> None:
            nonlocal threat_alert
            duration_ms = int((time.monotonic() - started) * 1000)
            if honeypot_hit:
                event = "honeypot_hit"
                outcome_text = "decoy"
                metrics.inc("honeypot_hits_total")
            elif response_blocked:
                if blocked_kind == "integrity":
                    event = "response_integrity_blocked"
                    metrics.inc("integrity_blocked_total")
                else:
                    event = "response_blocked"
                    metrics.inc("dlp_blocked_total")
                outcome_text = "blocked"
                metrics.inc("blocked_total")
            elif threat_tarpitted:
                event = "threat_tarpitted"
                outcome_text = "contained"
                metrics.inc("threat_tarpitted_total")
            elif threat_blocked:
                event = "threat_blocked"
                outcome_text = "blocked"
                metrics.inc("threat_blocked_total")
                metrics.inc("blocked_total")
            elif forwarded:
                metrics.inc("allowed_total")
                if threat_delay_ms:
                    event = "request_allowed_throttled"
                    outcome_text = "allowed_throttled"
                    metrics.inc("threat_throttled_total")
                elif integrity_detected:
                    event = "response_allowed_with_integrity_detection"
                    outcome_text = "allowed_response_integrity_detection"
                elif dlp_detected:
                    event = "response_allowed_with_detection"
                    outcome_text = "allowed_response_detection"
                elif waf_detected:
                    event = "request_allowed_waf_detect"
                    outcome_text = "allowed_waf_detect"
                else:
                    event = "request_allowed"
                    outcome_text = "allowed"
            elif status == 429:
                event = "rate_limited"
                outcome_text = "blocked"
                metrics.inc("rate_limited_total")
                metrics.inc("blocked_total")
            elif status in {502, 503, 504}:
                event = "upstream_error"
                outcome_text = "error"
                metrics.inc("upstream_errors_total")
            else:
                event = "request_blocked"
                outcome_text = "blocked"
                metrics.inc("blocked_total")
            if not forwarded and phase == "parse" and status >= 400:
                metrics.inc("parse_errors_total")
            if not forwarded and status >= 400 and rule_id.startswith("HW-WAF-"):
                metrics.inc("waf_blocked_total")
            if (
                runtime.auto_ban is not None
                and runtime.config.rate_limit.enabled
                and runtime.config.rate_limit.auto_ban_threshold > 0
                and not banned_request
                and not honeypot_hit
                and not forwarded
                and not threat_blocked
                and client_ip not in {"", "unknown"}
                and status in {400, 403, 405, 408, 413, 414, 415, 417, 429, 431}
            ):
                decision = runtime.auto_ban.record_violation(client_ip)
                if not decision.allowed:
                    metrics.inc("auto_bans_total")
                metrics.set("auto_ban_entries", float(runtime.auto_ban.size()))
            metrics.add("request_bytes_total", request_body_bytes)
            metrics.add("response_bytes_total", response_bytes)
            metrics.set("audit_write_failures_total", runtime.audit.writes_failed)
            runtime.audit.write(
                AuditRecord(
                    event=event,
                    request_id=request_id,
                    client_ip=client_ip,
                    method=head.method if head else "",
                    path=head.target.split("?", 1)[0] if head else "",
                    status=status,
                    outcome=outcome_text,
                    rule_id=rule_id,
                    duration_ms=duration_ms,
                    request_bytes=request_body_bytes,
                    response_bytes=response_bytes,
                    detail="",
                )
            )
            if runtime.ddos_detector is not None:
                if rule_id == "HW-RATE-1002":
                    runtime.ddos_detector.record_global_rejection()
                if status in {502, 503, 504} and not forwarded:
                    runtime.ddos_detector.record_upstream_error()
                ddos_result = runtime.ddos_detector.evaluate()
                for alert in ddos_result.alerts:
                    ddos_alerts.append(alert)
            if (
                runtime.threat_detector is not None
                and fingerprint
                and not threat_tarpitted
                and not threat_blocked
            ):
                violation = runtime.threat_detector.record_violation(
                    fingerprint,
                    shape_fingerprint,
                    rule_id,
                    status,
                    client_ip=client_ip,
                    request_id=request_id,
                )
                if violation is not None and violation.alert is not None and threat_alert is None:
                    threat_alert = violation.alert
                    runtime.emit_alert(
                        threat_alert,
                        f"{threat_alert.get('event', 'threat')}:{fingerprint}",
                    )
                    metrics.inc("threat_detected_total")
                    runtime.audit.write(
                        AuditRecord(
                            event="threat_detected",
                            request_id=request_id,
                            client_ip=client_ip,
                            method=head.method if head else "",
                            path=head.target.split("?", 1)[0] if head else "",
                            status=status,
                            outcome=str(threat_alert.get("confidence", "")),
                            rule_id=str(threat_alert.get("rule_id", "HW-THREAT-1001")),
                            detail=(
                                f"fingerprint={fingerprint};"
                                f"score={threat_alert.get('score', 0)};"
                                f"signals={','.join(str(item) for item in threat_alert.get('signals', []))}"
                            ),
                        )
                    )
            for alert in ddos_alerts:
                runtime.emit_alert(alert, str(alert.get("event", "ddos")))
                runtime.audit.write(
                    AuditRecord(
                        event=str(alert.get("event", "ddos_suspected")),
                        request_id=request_id,
                        client_ip=client_ip,
                        method=head.method if head else "",
                        path=head.target.split("?", 1)[0] if head else "",
                        status=status,
                        outcome="alerted",
                        rule_id="HW-DDOS-1001",
                        detail="layer=L7",
                    )
                )

        try:
            reader = DeadlineReader(
                self.request,
                runtime.config.server.header_timeout,
                runtime.config.server.header_timeout,
            )
            audit_needed = True
            head = read_request_head(reader, peer_ip, policy)
            if head is None:
                audit_needed = False
                status = 0
                return
            metrics.inc("requests_total")
            if runtime.audit.unavailable:
                metrics.set("audit_unavailable", 1.0)
                raise ServiceUnavailable("audit log is unavailable", rule_id="HW-AUDIT-1001")
            phase = "rate_limit"
            client_ip = resolve_client_ip(head, policy)
            for banner in (runtime.auto_ban, runtime.honeypot_ban):
                if banner is None:
                    continue
                ban = banner.check(client_ip)
                if not ban.allowed:
                    banned_request = True
                    if banner is runtime.honeypot_ban:
                        metrics.inc("honeypot_ban_rejections_total")
                    else:
                        metrics.inc("auto_ban_rejections_total")
                    exc = TooManyRequests("client is temporarily banned", rule_id="HW-RATE-1003")
                    exc.retry_after = ban.retry_after
                    raise exc
            if runtime.per_ip_limiter is not None:
                decision = runtime.per_ip_limiter.consume(client_ip)
                if not decision.allowed:
                    exc = TooManyRequests("per-client rate limit exceeded", rule_id="HW-RATE-1001")
                    exc.retry_after = decision.retry_after
                    raise exc
            if runtime.global_limiter is not None:
                decision = runtime.global_limiter.consume("global")
                if not decision.allowed:
                    exc = TooManyRequests("global rate limit exceeded", rule_id="HW-RATE-1002")
                    exc.retry_after = decision.retry_after
                    raise exc
            if runtime.ddos_detector is not None:
                runtime.ddos_detector.record_request(connection_load=self.server.connection_load())
                ddos_result = runtime.ddos_detector.evaluate()
                for alert in ddos_result.alerts:
                    ddos_alerts.append(alert)
            if runtime.threat_detector is not None:
                assessment = runtime.threat_detector.assess(
                    head,
                    client_ip,
                    tls_profile,
                    request_id=request_id,
                )
                fingerprint = assessment.fingerprint
                shape_fingerprint = assessment.shape_fingerprint
                if assessment.ban_ip and runtime.auto_ban is not None:
                    runtime.auto_ban.force_ban(client_ip, max(1.0, assessment.ban_seconds))
                    metrics.inc("auto_bans_total")
                    metrics.set("auto_ban_entries", float(runtime.auto_ban.size()))
                if assessment.alert is not None:
                    threat_alert = assessment.alert
                    runtime.emit_alert(
                        threat_alert,
                        f"{threat_alert.get('event', 'threat')}:{fingerprint}",
                    )
                    metrics.inc("threat_detected_total")
                    runtime.audit.write(
                        AuditRecord(
                            event="threat_detected",
                            request_id=request_id,
                            client_ip=client_ip,
                            method=head.method,
                            path=head.target.split("?", 1)[0],
                            status=0,
                            outcome=str(threat_alert.get("confidence", "")),
                            rule_id=str(threat_alert.get("rule_id", "HW-THREAT-1001")),
                            detail=(
                                f"fingerprint={fingerprint};"
                                f"score={threat_alert.get('score', 0)};"
                                f"signals={','.join(str(item) for item in threat_alert.get('signals', []))}"
                            ),
                        )
                    )
                if assessment.action == "tarpit":
                    if not runtime.threat_detector.acquire_tarpit(fingerprint):
                        threat_blocked = True
                        metrics.inc("threat_tarpit_shed_total")
                        exc = TooManyRequests("containment capacity is full", rule_id="HW-THREAT-1004")
                        exc.retry_after = 1.0
                        raise exc
                    tarpit_acquired = True
                    threat_tarpitted = True
                    phase = "tarpit"
                    status = 200
                    rule_id = "HW-THREAT-1003"
                    response_bytes = self._send_slow(
                        status,
                        [
                            ("Content-Type", "text/html; charset=utf-8"),
                            ("Cache-Control", "no-store"),
                        ],
                        _TARPIT_BODY,
                        method=head.method,
                        duration_ms=int(assessment.hold_seconds * 1000),
                        content_length=len(_TARPIT_BODY),
                    )
                    return
                if assessment.action == "block":
                    threat_blocked = True
                    exc = TooManyRequests("attacker is temporarily contained", rule_id="HW-THREAT-1002")
                    exc.retry_after = max(1.0, assessment.retry_after)
                    raise exc
                if assessment.action == "throttle" and assessment.delay_ms > 0:
                    threat_delay_ms = assessment.delay_ms
                    if runtime.threat_detector.acquire_delay():
                        try:
                            time.sleep(threat_delay_ms / 1000.0)
                        finally:
                            runtime.threat_detector.release_delay()
                    else:
                        metrics.inc("threat_delay_shed_total")
            phase = "validate"
            inspection = validate_head(head, client_ip, policy)
            if inspection.waf_hit:
                rule_id = inspection.waf_hit
                waf_detected = True
            if inspection.route is not None and inspection.route.rate > 0:
                route_limiter = runtime.route_limiters.get(inspection.route.path_prefix)
                if route_limiter is not None:
                    decision = route_limiter.consume(client_ip)
                    if not decision.allowed:
                        metrics.inc("route_rate_limit_rejections_total")
                        exc = TooManyRequests("route rate limit exceeded", rule_id="HW-RATE-1101")
                        exc.retry_after = decision.retry_after
                        raise exc
            if inspection.route is not None and inspection.route.max_concurrent > 0:
                route_slot_key = inspection.route.path_prefix
                if not self.server.acquire_route_slot(route_slot_key, inspection.route.max_concurrent):
                    route_slot_key = None
                    metrics.inc("route_concurrency_rejections_total")
                    unavailable = ServiceUnavailable(
                        "route concurrency limit exceeded",
                        rule_id="HW-ROUTE-1001",
                    )
                    unavailable.retry_after = 1.0
                    raise unavailable
            phase = "body"
            reader.reset_deadline(runtime.config.server.body_timeout)
            if inspection.honeypot is not None:
                decoy = inspection.honeypot
                request_body_bytes = discard_request_body(reader, head)
                phase = "honeypot"
                honeypot_hit = True
                rule_id = f"HW-HONEY-{decoy.id}"
                if runtime.honeypot_ban is not None and client_ip not in {"", "unknown"}:
                    runtime.honeypot_ban.force_ban(client_ip)
                    metrics.inc("honeypot_bans_total")
                    metrics.set("honeypot_ban_entries", float(runtime.honeypot_ban.active_bans()))
                if decoy.delay_ms:
                    time.sleep(decoy.delay_ms / 1000.0)
                status = decoy.status
                response_bytes = self._send(
                    status,
                    _honeypot_headers(decoy, runtime, request_id),
                    decoy.body,
                    method=head.method,
                    content_length=len(decoy.body),
                    server_header=decoy.server_header,
                )
                return
            body = read_request_body(reader, head)
            request_body_bytes = len(body)
            phase = "waf_body"
            body_waf_hit = inspect_body(body, inspection.content_type, policy, charset=inspection.charset)
            if body_waf_hit:
                waf_detected = True
                if not rule_id:
                    rule_id = body_waf_hit
            phase = "upstream"
            breaker = runtime.circuit_breaker
            breaker_token: int | None = None
            if breaker is not None:
                circuit_decision = breaker.allow()
                metrics.set("circuit_state", _CIRCUIT_STATE_CODES[circuit_decision.state])
                if not circuit_decision.allowed:
                    metrics.inc("circuit_rejections_total")
                    unavailable = ServiceUnavailable(
                        "upstream circuit is open",
                        rule_id="HW-CB-1001",
                    )
                    unavailable.retry_after = circuit_decision.retry_after
                    raise unavailable
                breaker_token = circuit_decision.token
            try:
                response = upstream.request(
                    head,
                    inspection,
                    body,
                    request_id,
                    self.server.tls_enabled,
                )
            except (BadGateway, GatewayTimeout):
                if breaker is not None and breaker_token is not None:
                    opened = breaker.record_failure(breaker_token)
                    metrics.set("circuit_state", _CIRCUIT_STATE_CODES[breaker.current_state()])
                    if opened:
                        metrics.inc("circuit_open_total")
                raise
            if breaker is not None and breaker_token is not None:
                if response.status >= 500:
                    opened = breaker.record_failure(breaker_token)
                    recovered = False
                else:
                    opened = False
                    recovered = breaker.record_success(breaker_token)
                metrics.set("circuit_state", _CIRCUIT_STATE_CODES[breaker.current_state()])
                if opened:
                    metrics.inc("circuit_open_total")
                if recovered:
                    metrics.inc("circuit_recovered_total")
            response_content_type = next(
                (value for name, value in response.headers if name.lower() == "content-type"),
                None,
            )
            integrity_hit = inspect_integrity(
                head.method,
                inspection.route_path,
                response.status,
                response.body,
                policy,
            )
            if integrity_hit is not None:
                integrity_detected = True
                metrics.inc("integrity_detected_total")
                if policy.response_integrity_mode == "block":
                    response_blocked = True
                    blocked_kind = "integrity"
                    rule_id = integrity_hit.rule_id
                    raise BadGateway("upstream response failed integrity policy", rule_id=integrity_hit.rule_id)
                if not rule_id:
                    rule_id = integrity_hit.rule_id
            dlp_hit = inspect_response(response.body, response_content_type, policy, headers=response.headers)
            if dlp_hit is not None:
                dlp_detected = True
                metrics.inc("dlp_detected_total")
                if policy.response_scan_mode == "block":
                    response_blocked = True
                    blocked_kind = "dlp"
                    rule_id = dlp_hit.rule_id
                    raise BadGateway("upstream response blocked by content policy", rule_id=dlp_hit.rule_id)
                if not rule_id:
                    rule_id = dlp_hit.rule_id
            headers, content_length = _clean_response_headers(response, head.method, runtime, request_id)
            status = response.status
            forwarded = True
            phase = "response"
            response_bytes = self._send(
                status,
                headers,
                response.body,
                method=head.method,
                content_length=content_length,
            )
        except HighWallError as exc:
            status = exc.status
            rule_id = exc.rule_id or rule_id
            extra: list[tuple[str, str]] = []
            retry_after = getattr(exc, "retry_after", None)
            if retry_after is not None:
                extra.append(("Retry-After", str(max(1, int(retry_after + 0.999)))))
            response_bytes = self._send_error(exc, request_id, head.method if head else None, extra)
        except TimeoutError:
            status = 408
            rule_id = "HW-PROTO-1202"
            response_bytes = self._send_error(
                RequestTimeout("request timed out", rule_id=rule_id),
                request_id,
                head.method if head else None,
            )
        except Exception as exc:
            status = 500
            rule_id = "HW-INTERNAL-1001"
            _LOG.error("unhandled proxy error (%s)", type(exc).__name__)
            response_bytes = self._send_error(
                HighWallError("internal gateway error", rule_id=rule_id),
                request_id,
                head.method if head else None,
            )
        finally:
            if route_slot_key is not None:
                self.server.release_route_slot(route_slot_key)
            if tarpit_acquired and runtime.threat_detector is not None:
                runtime.threat_detector.release_tarpit(fingerprint)
            metrics.inc("active_requests", -1)
            if audit_needed:
                finish_audit()


class GatewayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = os.name != "nt"
    daemon_threads = True
    block_on_close = False
    request_queue_size = 128

    def __init__(
        self,
        address: tuple[str, int],
        runtime: Runtime,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self.runtime = runtime
        self.tls_context = tls_context
        self.tls_enabled = tls_context is not None
        self.upstream = UpstreamProxy(runtime.config)
        self.generation = 0
        self._runtime_lock = threading.RLock()
        self._runtime_refs: dict[int, tuple[Runtime, int]] = {}
        self._retired_runtimes: dict[int, Runtime] = {}
        self._alert_refs: dict[int, tuple[Any, int]] = {}
        self._draining = threading.Event()
        self._slots = threading.BoundedSemaphore(runtime.config.server.max_connections)
        inflight = runtime.config.server.max_inflight_requests
        self._request_slots = threading.BoundedSemaphore(inflight) if inflight > 0 else None
        self._ip_counts: dict[str, int] = {}
        self._ip_lock = threading.Lock()
        self._route_counts: dict[str, int] = {}
        self._route_lock = threading.Lock()
        self._active_connections = 0
        self._connection_lock = threading.Lock()
        self._drain_condition = threading.Condition(self._connection_lock)
        self._active_sockets: set[socket.socket] = set()
        self._pending_ip_keys: dict[int, tuple[socket.socket, str | None]] = {}
        self._tls_profiles: dict[tuple, TLSProfile | None] = {}
        self._tls_profile_lock = threading.Lock()
        self._register_alert_dispatcher(runtime)
        try:
            if ipaddress.ip_address(address[0]).version == 6:
                self.address_family = socket.AF_INET6
        except ValueError:
            pass
        super().__init__(address, ProxyHandler)

    def connection_load(self) -> float:
        with self._connection_lock:
            return min(1.0, self._active_connections / max(1, self.runtime.config.server.max_connections))

    def acquire_runtime(self) -> tuple[Runtime, UpstreamProxy]:
        with self._runtime_lock:
            runtime = self.runtime
            current = self._runtime_refs.get(id(runtime))
            count = current[1] if current is not None else 0
            self._runtime_refs[id(runtime)] = (runtime, count + 1)
            return runtime, self.upstream

    def _register_alert_dispatcher(self, runtime: Runtime) -> None:
        dispatcher = runtime.alert_dispatcher
        if dispatcher is None:
            return
        current = self._alert_refs.get(id(dispatcher))
        count = current[1] if current is not None else 0
        self._alert_refs[id(dispatcher)] = (dispatcher, count + 1)

    def _release_alert_dispatcher(self, runtime: Runtime) -> None:
        dispatcher = runtime.alert_dispatcher
        if dispatcher is None:
            return
        close_dispatcher = None
        with self._runtime_lock:
            current = self._alert_refs.get(id(dispatcher))
            if current is None:
                return
            _, count = current
            if count <= 1:
                self._alert_refs.pop(id(dispatcher), None)
                close_dispatcher = dispatcher
            else:
                self._alert_refs[id(dispatcher)] = (dispatcher, count - 1)
        if close_dispatcher is not None:
            close_dispatcher.close()

    def release_runtime(self, runtime: Runtime) -> None:
        close_runtime = False
        with self._runtime_lock:
            current = self._runtime_refs.get(id(runtime))
            if current is None:
                return
            _, count = current
            if count <= 1:
                self._runtime_refs.pop(id(runtime), None)
                retired = self._retired_runtimes.pop(id(runtime), None)
                if retired is not None:
                    close_runtime = True
            else:
                self._runtime_refs[id(runtime)] = (runtime, count - 1)
        if close_runtime:
            self._release_alert_dispatcher(runtime)
            runtime.close(close_alerts=False)

    def reload(self, runtime: Runtime, tls_context: ssl.SSLContext | None) -> int:
        close_runtime: Runtime | None = None
        new_upstream = UpstreamProxy(runtime.config)
        with self._runtime_lock:
            old = self.runtime
            if old is not runtime:
                self._register_alert_dispatcher(runtime)
            self.runtime = runtime
            self.upstream = new_upstream
            self.tls_context = tls_context
            self.tls_enabled = tls_context is not None
            self.generation += 1
            if old is not runtime:
                refs = self._runtime_refs.get(id(old))
                if refs is None:
                    close_runtime = old
                else:
                    self._retired_runtimes[id(old)] = old
        if close_runtime is not None:
            self._release_alert_dispatcher(close_runtime)
            close_runtime.close(close_alerts=False)
        return self.generation

    def begin_drain(self) -> None:
        self._draining.set()

    @property
    def draining(self) -> bool:
        return self._draining.is_set()

    def wait_for_drain(self, timeout: float) -> bool:
        if timeout <= 0:
            with self._connection_lock:
                return self._active_connections == 0
        deadline = time.monotonic() + timeout
        with self._drain_condition:
            while self._active_connections > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._drain_condition.wait(remaining)
            return True

    def abort_connections(self) -> None:
        with self._connection_lock:
            sockets = list(self._active_sockets)
        for connection in sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def close_all_runtimes(self) -> None:
        with self._runtime_lock:
            current = self.runtime
            retired = list(self._retired_runtimes.values())
            self._retired_runtimes.clear()
            self._runtime_refs.clear()
        current.close(close_alerts=False)
        self._release_alert_dispatcher(current)
        for runtime in retired:
            runtime.close(close_alerts=False)
            self._release_alert_dispatcher(runtime)

    def store_tls_profile(self, client_address: tuple, profile: TLSProfile) -> None:
        key = tuple(client_address)
        with self._tls_profile_lock:
            self._tls_profiles[key] = profile
            while len(self._tls_profiles) > max(64, self.runtime.config.server.max_connections * 2):
                self._tls_profiles.pop(next(iter(self._tls_profiles)))

    def take_tls_profile(self, client_address: tuple) -> TLSProfile | None:
        with self._tls_profile_lock:
            return self._tls_profiles.pop(tuple(client_address), None)

    def _record_tls_failure(self, runtime: Runtime) -> None:
        detector = runtime.ddos_detector
        if detector is None:
            return
        detector.record_tls_failure()
        for alert in detector.evaluate().alerts:
            runtime.emit_alert(alert, str(alert.get("event", "ddos")))

    def _reject_busy(self, request: socket.socket, runtime: Runtime) -> None:
        peer_ip = ""
        try:
            peer_ip = str(request.getpeername()[0])
        except (OSError, IndexError, TypeError):
            peer_ip = ""
        request_id = secrets.token_hex(12)
        started = time.monotonic()
        body = b""
        if not self.tls_enabled:
            body = (
                b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n"
                b"Retry-After: 1\r\nContent-Length: 0\r\nX-Request-ID: "
                + request_id.encode("ascii")
                + b"\r\n\r\n"
            )
        if body:
            try:
                request.settimeout(1.0)
                request.sendall(body)
                try:
                    request.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                request.settimeout(0.05)
                deadline = time.monotonic() + 0.2
                drained = 0
                while drained < 65536 and time.monotonic() < deadline:
                    try:
                        chunk = request.recv(min(4096, 65536 - drained))
                    except (socket.timeout, TimeoutError):
                        break
                    if not chunk:
                        break
                    drained += len(chunk)
            except OSError:
                pass
        try:
            request.close()
        except OSError:
            pass
        runtime.metrics.inc("blocked_total")
        runtime.audit.write(
            AuditRecord(
                event="request_blocked",
                request_id=request_id,
                client_ip=peer_ip,
                status=503,
                outcome="blocked",
                rule_id="HW-SERVER-1001",
                duration_ms=int((time.monotonic() - started) * 1000),
                response_bytes=len(body),
                detail="inflight_limit",
            )
        )
        detector = runtime.ddos_detector
        if detector is not None:
            detector.record_connection_rejection()
            for alert in detector.evaluate().alerts:
                runtime.emit_alert(alert, str(alert.get("event", "ddos")))

    def _accept_tls(
        self,
        request: socket.socket,
        client_address: tuple,
        runtime: Runtime,
    ) -> socket.socket | None:
        context = self.tls_context
        assert context is not None
        profile: TLSProfile | None = None
        if isinstance(context, ssl.SSLContext):
            profile = peek_tls_profile(request, runtime.config.server.tls.handshake_timeout)
        request.settimeout(runtime.config.server.tls.handshake_timeout)
        try:
            wrapped = context.wrap_socket(request, server_side=True)
        except Exception:
            runtime.metrics.inc("tls_handshake_failures_total")
            self._record_tls_failure(runtime)
            return None
        if profile is not None:
            self.store_tls_profile(client_address, profile)
        return wrapped

    def _connection_key(self, client_address: tuple[str, int], runtime: Runtime) -> str | None:
        if runtime.config.server.max_connections_per_ip <= 0:
            return None
        try:
            address = ipaddress.ip_address(client_address[0].split("%", 1)[0])
        except (ValueError, IndexError):
            return None
        if any(address in network for network in runtime.config.policy.trusted_proxies):
            return None
        return str(address)

    def _acquire_ip_slot(self, key: str, runtime: Runtime) -> bool:
        with self._ip_lock:
            current = self._ip_counts.get(key, 0)
            if current >= runtime.config.server.max_connections_per_ip:
                return False
            self._ip_counts[key] = current + 1
            return True

    def _release_ip_slot(self, key: str) -> None:
        with self._ip_lock:
            current = self._ip_counts.get(key, 0)
            if current <= 1:
                self._ip_counts.pop(key, None)
            else:
                self._ip_counts[key] = current - 1

    def acquire_route_slot(self, key: str, limit: int) -> bool:
        with self._route_lock:
            current = self._route_counts.get(key, 0)
            if current >= limit:
                return False
            self._route_counts[key] = current + 1
            return True

    def release_route_slot(self, key: str) -> None:
        with self._route_lock:
            current = self._route_counts.get(key, 0)
            if current <= 1:
                self._route_counts.pop(key, None)
            else:
                self._route_counts[key] = current - 1

    def process_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        if not isinstance(request, socket.socket):
            raise TypeError("expected a TCP socket")
        runtime = self.runtime
        if self._draining.is_set():
            runtime.metrics.inc("drain_rejections_total")
            self._reject_busy(request, runtime)
            return
        if not self._slots.acquire(blocking=False):
            self._reject_busy(request, runtime)
            return
        ip_key = self._connection_key(client_address, runtime)
        if ip_key is not None and not self._acquire_ip_slot(ip_key, runtime):
            self._slots.release()
            runtime.metrics.inc("ip_connection_rejections_total")
            self._reject_busy(request, runtime)
            return
        with self._connection_lock:
            self._active_connections += 1
            self._active_sockets.add(request)
            self._pending_ip_keys[id(request)] = (request, ip_key)
        runtime.metrics.set("active_connections", float(self._active_connections))
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._drain_condition:
                self._active_connections = max(0, self._active_connections - 1)
                self._active_sockets.discard(request)
                self._pending_ip_keys.pop(id(request), None)
                self._drain_condition.notify_all()
            runtime.metrics.set("active_connections", float(self._active_connections))
            if ip_key is not None:
                self._release_ip_slot(ip_key)
            self._slots.release()
            raise

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        if not isinstance(request, socket.socket):
            raise TypeError("expected a TCP socket")
        runtime = self.runtime
        with self._connection_lock:
            pending = self._pending_ip_keys.pop(id(request), None)
        ip_key = pending[1] if pending is not None and pending[0] is request else None
        request_slot_acquired = False
        connection = request
        handed_off = False
        if self._request_slots is not None:
            if not self._request_slots.acquire(blocking=False):
                runtime.metrics.inc("inflight_rejections_total")
                self._reject_busy(request, runtime)
            else:
                request_slot_acquired = True
        try:
            if self._request_slots is not None and not request_slot_acquired:
                return
            if self.tls_context is not None:
                accepted = self._accept_tls(request, client_address, runtime)
                if accepted is None:
                    return
                connection = accepted
                with self._connection_lock:
                    self._active_sockets.add(connection)
            handed_off = True
            super().process_request_thread(connection, client_address)
        finally:
            if not handed_off:
                try:
                    connection.close()
                except OSError:
                    pass
            if request_slot_acquired and self._request_slots is not None:
                self._request_slots.release()
            with self._drain_condition:
                self._active_connections = max(0, self._active_connections - 1)
                self._active_sockets.discard(request)
                self._active_sockets.discard(connection)
                self._drain_condition.notify_all()
            runtime.metrics.set("active_connections", float(self._active_connections))
            if ip_key is not None:
                self._release_ip_slot(ip_key)
            self._slots.release()

    def handle_error(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        _LOG.error("connection handler failed")


def build_tls_context(config: Config) -> ssl.SSLContext | None:
    tls = config.server.tls
    if not tls.enabled:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2 if tls.min_version == "TLSv1_2" else ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    assert tls.cert_file is not None and tls.key_file is not None
    context.load_cert_chain(str(tls.cert_file), str(tls.key_file))
    return context
