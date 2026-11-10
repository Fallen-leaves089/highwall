"""Minimal TCP forwarder for host-loopback honeypot access."""

from __future__ import annotations

import ctypes
import ipaddress
import os
import socket
import subprocess
import sys
import threading
import time

BUFFER_SIZE = 65536
CONNECT_TIMEOUT = 5.0
MAX_CONNECTIONS = 64
MAX_CONNECTIONS_PER_IP = 16
IDLE_TIMEOUT_SECONDS = 300.0
MAX_CONNECTION_SECONDS = 3600.0
MAX_BYTES_PER_DIRECTION = 64 * 1024 * 1024
NOBODY_UID = 65534
NOBODY_GID = 65534
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38


def _port(name: str) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc
    if not 1 <= value <= 65535:
        raise SystemExit(f"{name} must be between 1 and 65535")
    return value


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


def _default_routes() -> str:
    result = subprocess.run(
        ["ip", "route", "show"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"cannot inspect default route: {result.stderr.strip()}")
    return "\n".join(line for line in result.stdout.splitlines() if line.split()[:1] == ["default"])


def _remove_default_routes() -> None:
    for _ in range(4):
        if not _default_routes():
            return
        result = subprocess.run(
            ["ip", "route", "del", "default"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise SystemExit(f"cannot remove default route: {result.stderr.strip()}")
    if _default_routes():
        raise SystemExit("default route is still present")


def _drop_privileges() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    for capability in range(64):
        libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0)
    os.setgroups([])
    os.setgid(NOBODY_GID)
    os.setuid(NOBODY_UID)


class ConnectionLimiter:
    def __init__(self, max_total: int, max_per_ip: int) -> None:
        self.max_total = max_total
        self.max_per_ip = max_per_ip
        self._lock = threading.Lock()
        self._total = 0
        self._per_ip: dict[str, int] = {}

    def acquire(self, peer: str) -> bool:
        with self._lock:
            current = self._per_ip.get(peer, 0)
            if self._total >= self.max_total or current >= self.max_per_ip:
                return False
            self._total += 1
            self._per_ip[peer] = current + 1
            return True

    def release(self, peer: str) -> None:
        with self._lock:
            if self._total > 0:
                self._total -= 1
            current = self._per_ip.get(peer, 0)
            if current <= 1:
                self._per_ip.pop(peer, None)
            else:
                self._per_ip[peer] = current - 1


def _shutdown_pair(first: socket.socket, second: socket.socket) -> None:
    for sock in (first, second):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _pipe(
    source: socket.socket,
    destination: socket.socket,
    *,
    deadline: float,
    idle_timeout: float,
    max_bytes: int,
) -> None:
    transferred = 0
    aborted = True
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            source.settimeout(min(idle_timeout, remaining))
            data = source.recv(BUFFER_SIZE)
            if not data:
                aborted = False
                break
            transferred += len(data)
            if transferred > max_bytes:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            destination.settimeout(min(idle_timeout, remaining))
            destination.sendall(data)
    except OSError:
        pass
    finally:
        if aborted:
            _shutdown_pair(source, destination)
        else:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass


def _handle(
    client: socket.socket,
    target: tuple[str, int],
    limiter: ConnectionLimiter,
    peer: str,
    deadline: float,
    idle_timeout: float,
    max_bytes: int,
) -> None:
    upstream: socket.socket | None = None
    try:
        try:
            upstream = socket.create_connection(target, timeout=CONNECT_TIMEOUT)
        except OSError:
            return
        writer = threading.Thread(
            target=_pipe,
            args=(client, upstream),
            kwargs={"deadline": deadline, "idle_timeout": idle_timeout, "max_bytes": max_bytes},
            daemon=True,
        )
        writer.start()
        _pipe(
            upstream,
            client,
            deadline=deadline,
            idle_timeout=idle_timeout,
            max_bytes=max_bytes,
        )
        writer.join(timeout=1.0)
    finally:
        if upstream is not None:
            _shutdown_pair(client, upstream)
            upstream.close()
        client.close()
        limiter.release(peer)


def main() -> int:
    listen_port = _port("LISTEN_PORT")
    listen_host = _listen_host()
    target_port = _port("TARGET_PORT")
    max_connections = _positive_int("MAX_CONNECTIONS", MAX_CONNECTIONS)
    max_connections_per_ip = _positive_int("MAX_CONNECTIONS_PER_IP", MAX_CONNECTIONS_PER_IP)
    idle_timeout = _positive_float("IDLE_TIMEOUT_SECONDS", IDLE_TIMEOUT_SECONDS)
    max_connection_seconds = _positive_float("MAX_CONNECTION_SECONDS", MAX_CONNECTION_SECONDS)
    max_bytes = _positive_int("MAX_BYTES_PER_DIRECTION", MAX_BYTES_PER_DIRECTION)
    target_host = os.environ.get("TARGET_HOST", "").strip()
    if not target_host:
        raise SystemExit("TARGET_HOST is required")
    try:
        ipaddress.ip_address(target_host)
    except ValueError as exc:
        raise SystemExit("TARGET_HOST must be an IP literal") from exc

    if os.geteuid() == 0:
        _remove_default_routes()
        _drop_privileges()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(128)
    sys.stdout.write(
        f"relay listening on {listen_host}:{listen_port} -> {target_host}:{target_port} as uid {os.getuid()} "
        f"limits={max_connections}/{max_connections_per_ip} idle={idle_timeout}s "
        f"total={max_connection_seconds}s bytes={max_bytes}\n"
    )
    sys.stdout.flush()
    target = (target_host, target_port)
    limiter = ConnectionLimiter(max_connections, max_connections_per_ip)
    while True:
        client, address = server.accept()
        peer = str(address[0])
        if not limiter.acquire(peer):
            client.close()
            continue
        worker = threading.Thread(
            target=_handle,
            args=(client, target, limiter, peer, time.monotonic() + max_connection_seconds),
            kwargs={"idle_timeout": idle_timeout, "max_bytes": max_bytes},
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError:
            client.close()
            limiter.release(peer)


if __name__ == "__main__":
    raise SystemExit(main())
