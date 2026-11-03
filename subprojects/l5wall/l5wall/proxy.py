"""Bounded TLS-to-HTTP/1.1 bridge for the B+D-1 transition path.

The bridge terminates TLS with L5Wall, validates the first HTTP/1 request head,
checks SNI/Host consistency, and forwards the decrypted byte stream to a local
HighWall listener.  It deliberately does not accept H2/H3 or act as an L7
parser beyond the bounded checks needed for the transition boundary.
"""

from __future__ import annotations

import errno
import ipaddress
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .config import L5Config
from .gateway import L5Denied, L5HandshakeError, L5Wall

_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_MAX_CHUNK = 64 * 1024
_METHOD_RE = re.compile(rb"^[A-Z]+$")
_ACCEPT_BACKOFF_INITIAL_SECONDS = 0.05
_ACCEPT_BACKOFF_MAX_SECONDS = 1.0
_LOGGER = logging.getLogger(__name__)
_TRANSIENT_ACCEPT_ERRNOS = frozenset(
    getattr(errno, name)
    for name in (
        "EINTR",
        "EAGAIN",
        "EWOULDBLOCK",
        "ECONNABORTED",
        "ECONNRESET",
        "EMFILE",
        "ENFILE",
        "ENOBUFS",
        "ENOMEM",
        "WSAEINTR",
        "WSAEWOULDBLOCK",
        "WSAECONNABORTED",
        "WSAECONNRESET",
        "WSAEMFILE",
        "WSAENOBUFS",
    )
    if hasattr(errno, name)
)


class L5ProxyError(OSError):
    """A bridge-level rejection or resource-limit failure."""


class L5ProxyServer:
    """A bounded, fail-closed TLS terminator for a local HighWall listener."""

    def __init__(self, config: L5Config) -> None:
        if any(protocol != "http/1.1" for protocol in config.allowed_alpn):
            raise ValueError("serve mode currently supports only the http/1.1 ALPN")
        self.config = config
        self.wall = L5Wall(config)
        self._listener: socket.socket | None = None
        self._bound: tuple[str, int] | None = None
        self._stopped = threading.Event()
        self._shutdown_lock = threading.Lock()
        self._shutdown_started = False
        self._executor = ThreadPoolExecutor(
            max_workers=config.max_connections,
            thread_name_prefix="l5wall",
        )
        self._slots = threading.BoundedSemaphore(config.max_connections)
        self._connection_condition = threading.Condition()
        self._active_connections = 0
        self._active_sockets: set[socket.socket] = set()
        self._force_closing = False

    @property
    def address(self) -> tuple[str, int]:
        if self._bound is None:
            raise RuntimeError("server is not bound")
        return self._bound

    def bind(self) -> tuple[str, int]:
        if self._listener is not None:
            return self.address
        family = socket.AF_INET6 if ":" in self.config.listen_host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((self.config.listen_host, self.config.listen_port))
            listener.listen(max(16, min(1024, self.config.max_connections * 2)))
            listener.settimeout(0.5)
        except OSError:
            listener.close()
            raise
        self._listener = listener
        address = listener.getsockname()
        self._bound = (str(address[0]), int(address[1]))
        return self._bound

    def serve_forever(self) -> None:
        self.bind()
        listener = self._listener
        assert listener is not None
        backoff = _ACCEPT_BACKOFF_INITIAL_SECONDS
        while not self._stopped.is_set():
            try:
                raw, peer = self._accept(listener)
            except socket.timeout:
                backoff = _ACCEPT_BACKOFF_INITIAL_SECONDS
                continue
            except OSError as exc:
                if self._stopped.is_set():
                    break
                if not _is_transient_accept_error(exc):
                    _LOGGER.error("fatal listener accept error: %s", exc)
                    raise L5ProxyError(f"listener accept failed: {exc}") from exc
                delay = backoff
                backoff = min(_ACCEPT_BACKOFF_MAX_SECONDS, backoff * 2)
                _LOGGER.warning(
                    "transient listener accept error (%s); retrying in %.0f ms",
                    exc,
                    delay * 1000,
                )
                self._stopped.wait(delay)
                continue
            backoff = _ACCEPT_BACKOFF_INITIAL_SECONDS
            if self._stopped.is_set():
                _quiet_close(raw)
                break
            if not self._slots.acquire(blocking=False):
                _quiet_close(raw)
                continue
            self._begin_connection(raw)
            try:
                self._executor.submit(self._run_connection, raw, peer)
            except RuntimeError as exc:
                self._slots.release()
                self._finish_connection((raw,))
                _quiet_close(raw)
                if self._stopped.is_set():
                    break
                raise L5ProxyError("connection executor is not accepting work") from exc

    def _accept(self, listener: socket.socket) -> tuple[socket.socket, tuple[Any, ...]]:
        return listener.accept()

    def request_stop(self) -> None:
        """Stop accepting new work; the serving thread performs the bounded drain."""
        self._stopped.set()

    def stop(self) -> None:
        with self._shutdown_lock:
            if self._shutdown_started:
                return
            self._shutdown_started = True

        self.request_stop()
        listener = self._listener
        self._listener = None
        if listener is not None:
            _quiet_close(listener)
        self._executor.shutdown(wait=False, cancel_futures=False)

        deadline = time.monotonic() + self.config.shutdown_timeout
        forced_sockets: list[socket.socket] = []
        with self._connection_condition:
            while self._active_connections:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._force_closing = True
                    forced_sockets = list(self._active_sockets)
                    break
                self._connection_condition.wait(remaining)

        if forced_sockets:
            _LOGGER.warning(
                "shutdown drain deadline reached with %d connection(s); closing them",
                self._active_connections,
            )
            for active_socket in forced_sockets:
                _quiet_close(active_socket)
            with self._connection_condition:
                forced_deadline = time.monotonic() + 1.0
                while self._active_connections:
                    remaining = forced_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._connection_condition.wait(remaining)

        self._executor.shutdown(wait=True, cancel_futures=True)

    def close(self) -> None:
        self.stop()

    def _run_connection(self, raw: socket.socket, _peer: tuple[Any, ...]) -> None:
        client: socket.socket | None = None
        upstream: socket.socket | None = None
        sockets: list[socket.socket] = [raw]
        try:
            raw.settimeout(self.config.handshake_timeout)
            connection = self.wall.wrap(raw)
            client = connection.socket
            sockets.append(client)
            self._track_socket(client)
            client.settimeout(self.config.idle_timeout)
            prefix = b""
            if self.config.require_sni_host_match:
                prefix = _read_request_head(client, self.config.max_request_head_bytes, self.config.idle_timeout)
                _validate_request_head(prefix, connection.decision.metadata.sni)
            upstream = socket.create_connection(
                (self.config.upstream_host, self.config.upstream_port),
                timeout=self.config.connect_timeout,
            )
            sockets.append(upstream)
            self._track_socket(upstream)
            upstream.settimeout(self.config.idle_timeout)
            if prefix:
                upstream.sendall(prefix)
            _relay_pair(client, upstream, self.config.idle_timeout, self.config.max_bytes_per_direction)
        except (L5Denied, L5HandshakeError, L5ProxyError, OSError, ValueError):
            pass
        finally:
            if client is not None:
                _quiet_close(client)
            elif isinstance(raw, socket.socket):
                _quiet_close(raw)
            if upstream is not None:
                _quiet_close(upstream)
            self._slots.release()
            self._finish_connection(sockets)

    def _begin_connection(self, raw: socket.socket) -> None:
        with self._connection_condition:
            self._active_connections += 1
            self._active_sockets.add(raw)

    def _track_socket(self, active_socket: socket.socket) -> None:
        close_now = False
        with self._connection_condition:
            if self._force_closing:
                close_now = True
            else:
                self._active_sockets.add(active_socket)
        if close_now:
            _quiet_close(active_socket)
            raise L5ProxyError("server shutdown deadline reached")

    def _finish_connection(self, sockets: list[socket.socket] | tuple[socket.socket, ...]) -> None:
        with self._connection_condition:
            for active_socket in sockets:
                self._active_sockets.discard(active_socket)
            self._active_connections -= 1
            self._connection_condition.notify_all()


def _is_transient_accept_error(error: OSError) -> bool:
    if isinstance(error, (InterruptedError, BlockingIOError, ConnectionAbortedError, ConnectionResetError)):
        return True
    winerror = getattr(error, "winerror", None)
    return error.errno in _TRANSIENT_ACCEPT_ERRNOS or winerror in _TRANSIENT_ACCEPT_ERRNOS


def _read_request_head(sock: socket.socket, limit: int, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while b"\r\n\r\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise L5ProxyError("request head timed out")
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(_MAX_CHUNK, limit - len(data)))
        except socket.timeout as exc:
            raise L5ProxyError("request head timed out") from exc
        if not chunk:
            raise L5ProxyError("request head ended before headers completed")
        data.extend(chunk)
        if len(data) > limit:
            raise L5ProxyError("request head exceeds configured limit")
    return bytes(data)


def _validate_request_head(data: bytes, sni: str) -> None:
    marker = data.find(b"\r\n\r\n")
    if marker < 0:
        raise L5ProxyError("request head is incomplete")
    head = data[: marker + 4]
    if b"\r" in head.replace(b"\r\n", b"") or b"\n" in head.replace(b"\r\n", b""):
        raise L5ProxyError("request head contains bare CR or LF")
    lines = head[:-4].split(b"\r\n")
    if not lines:
        raise L5ProxyError("request head is empty")
    request_line = lines[0].split(b" ")
    if len(request_line) != 3 or not _METHOD_RE.fullmatch(request_line[0]):
        raise L5ProxyError("invalid HTTP/1 request line")
    if request_line[2] not in {b"HTTP/1.0", b"HTTP/1.1"}:
        raise L5ProxyError("only HTTP/1.0 and HTTP/1.1 are accepted on this bridge")
    host_values: list[str] = []
    content_lengths = 0
    has_transfer_encoding = False
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"}:
            raise L5ProxyError("invalid HTTP header line")
        name, separator, value = line.partition(b":")
        if not separator or not _TOKEN_RE.fullmatch(name):
            raise L5ProxyError("invalid HTTP header name")
        normalized = name.lower()
        if any(byte < 0x20 and byte != 0x09 for byte in value) or b"\x7f" in value:
            raise L5ProxyError("invalid HTTP header value")
        stripped = value.strip(b" \t")
        if normalized == b"host":
            if not stripped or any(char in stripped for char in b" \t,"):
                raise L5ProxyError("invalid Host header")
            host_values.append(stripped.decode("ascii", "strict"))
        elif normalized == b"content-length":
            content_lengths += 1
        elif normalized in {b"transfer-encoding", b"te", b"trailer", b"expect", b"upgrade"}:
            has_transfer_encoding = True
        elif normalized == b"connection":
            tokens = {token.strip().lower() for token in stripped.split(b",")}
            if b"upgrade" in tokens:
                raise L5ProxyError("Upgrade requests are not accepted on this bridge")
    if len(host_values) != 1:
        raise L5ProxyError("exactly one Host header is required")
    if content_lengths > 1 or has_transfer_encoding:
        raise L5ProxyError("ambiguous request framing is not accepted on this bridge")
    host = _normalize_host(host_values[0])
    expected = sni.strip().rstrip(".").lower()
    if not expected or host != expected:
        raise L5ProxyError("SNI and Host do not match")


def _normalize_host(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate or candidate.startswith("[") or candidate.count(":") > 1:
        raise L5ProxyError("invalid Host authority")
    if ":" in candidate:
        host, port = candidate.rsplit(":", 1)
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise L5ProxyError("invalid Host port")
        candidate = host
    if not candidate:
        raise L5ProxyError("Host is empty")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(candidate):
            raise L5ProxyError("invalid Host name")
    return candidate.lower()


def _relay_pair(client: socket.socket, upstream: socket.socket, timeout: float, limit: int) -> None:
    errors: list[BaseException] = []

    def forward(source: socket.socket, destination: socket.socket) -> None:
        try:
            _relay(source, destination, timeout, limit)
        except BaseException as exc:  # propagate thread failures to the owner
            errors.append(exc)
            _quiet_close(source)
            _quiet_close(destination)

    thread = threading.Thread(target=forward, args=(client, upstream), daemon=True)
    thread.start()
    forward(upstream, client)
    thread.join(timeout=max(1.0, timeout))
    if errors:
        raise L5ProxyError("relay failed") from errors[0]


def _relay(source: socket.socket, destination: socket.socket, timeout: float, limit: int) -> None:
    total = 0
    source.settimeout(timeout)
    while total < limit:
        try:
            chunk = source.recv(min(_MAX_CHUNK, limit - total))
        except socket.timeout as exc:
            raise L5ProxyError("relay idle timeout") from exc
        if not chunk:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return
        total += len(chunk)
        destination.sendall(chunk)
    raise L5ProxyError("relay byte limit exceeded")


def _quiet_close(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
