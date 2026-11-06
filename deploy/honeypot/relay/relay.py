"""Minimal TCP forwarder for host-loopback honeypot access."""

from __future__ import annotations

import ctypes
import ipaddress
import os
import socket
import subprocess
import sys
import threading

BUFFER_SIZE = 65536
CONNECT_TIMEOUT = 5.0
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


def _pipe(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            data = source.recv(BUFFER_SIZE)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(client: socket.socket, target: tuple[str, int]) -> None:
    try:
        upstream = socket.create_connection(target, timeout=CONNECT_TIMEOUT)
    except OSError:
        client.close()
        return
    threading.Thread(target=_pipe, args=(client, upstream), daemon=True).start()
    _pipe(upstream, client)
    client.close()
    upstream.close()


def main() -> int:
    listen_port = _port("LISTEN_PORT")
    target_port = _port("TARGET_PORT")
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
    server.bind(("0.0.0.0", listen_port))
    server.listen(128)
    sys.stdout.write(f"relay listening on {listen_port} -> {target_host}:{target_port} as uid {os.getuid()}\n")
    sys.stdout.flush()
    target = (target_host, target_port)
    while True:
        client, _ = server.accept()
        threading.Thread(target=_handle, args=(client, target), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
