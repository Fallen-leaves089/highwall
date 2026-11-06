"""Verify the isolated honeypot deployment without third-party dependencies."""

from __future__ import annotations

import argparse
import http.client
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parent


class CheckFailed(RuntimeError):
    pass


@dataclass(frozen=True)
class Result:
    name: str
    status: str
    detail: str


def _http(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 4.0,
) -> tuple[int, list[tuple[str, str]], bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheaders(), response.read()
    finally:
        connection.close()


def _header_values(headers: Iterable[tuple[str, str]], name: str) -> list[str]:
    lowered = name.lower()
    return [value for header_name, value in headers if header_name.lower() == lowered]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailed(message)


def _check_web_login(host: str, port: int, timeout: float) -> str:
    status, _, body = _http(host, port, "GET", "/login", timeout=timeout)
    _require(status == 200, f"GET /login returned {status}")
    _require(b"<form" in body, "login page has no form")
    _require(b"Sign in" in body, "login page is missing its title")
    return "login page is present"


def _check_web_session(host: str, port: int, timeout: float) -> str:
    body = b"username=ops-admin&password=decoy-only"
    status, headers, _ = _http(
        host,
        port,
        "POST",
        "/login",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
        },
        body=body,
        timeout=timeout,
    )
    _require(status in {302, 303}, f"POST /login returned {status}")
    cookies = _header_values(headers, "Set-Cookie")
    _require(bool(cookies), "POST /login did not set a session cookie")
    cookie = cookies[0].split(";", 1)[0]
    _require(cookie.startswith("session="), "session cookie has an unexpected name")

    status, _, page = _http(
        host,
        port,
        "GET",
        "/admin",
        headers={"Cookie": cookie},
        timeout=timeout,
    )
    _require(status == 200, f"GET /admin with a session returned {status}")
    _require(b"Admin Console" in page, "authenticated page is missing expected content")
    return "login redirect and session flow work"


def _read_ssh_banner(host: str, port: int, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        banner = b""
        while b"\n" not in banner and len(banner) < 256:
            chunk = sock.recv(128)
            if not chunk:
                break
            banner += chunk
        return banner


def _check_ssh_banner(host: str, port: int, timeout: float) -> str:
    banner = _read_ssh_banner(host, port, timeout)
    _require(banner.startswith(b"SSH-2.0-OpenSSH_"), f"unexpected SSH banner: {banner[:80]!r}")
    return banner.split(b"\n", 1)[0].decode("ascii", errors="replace")


def _compose(*args: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _docker_ready() -> tuple[bool, str]:
    try:
        process = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Docker is unavailable: {exc}"
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip() or "Docker daemon is not running"
        return False, detail
    return True, process.stdout.strip()


def _check_running(services: Iterable[str]) -> str:
    process = _compose("ps", "--services", "--filter", "status=running")
    _require(process.returncode == 0, (process.stderr or process.stdout).strip())
    running = {line.strip() for line in process.stdout.splitlines() if line.strip()}
    missing = sorted(set(services) - running)
    _require(not missing, f"services not running: {', '.join(missing)}")
    return "containers are running"


def _check_loopback_ports() -> str:
    checks = (("ssh-forward", "2222"), ("web-forward", "8080"))
    details: list[str] = []
    for service, container_port in checks:
        process = _compose("port", service, container_port)
        _require(process.returncode == 0, (process.stderr or process.stdout).strip())
        bindings = [line.strip() for line in process.stdout.splitlines() if line.strip()]
        _require(bool(bindings), f"{service} has no published port")
        _require(
            all(binding.startswith("127.0.0.1:") for binding in bindings),
            f"{service} is not loopback-only: {', '.join(bindings)}",
        )
        details.append(f"{service}={bindings[0]}")
    return ", ".join(details)


def _check_web_egress_blocked() -> str:
    script = (
        "import socket, sys\n"
        "sock = socket.socket()\n"
        "sock.settimeout(2)\n"
        "try:\n"
        "    sock.connect(('1.1.1.1', 80))\n"
        "except OSError:\n"
        "    print('BLOCKED')\n"
        "    sys.exit(0)\n"
        "print('REACHABLE')\n"
        "sys.exit(1)\n"
    )
    process = _compose("exec", "-T", "web-live", "python", "-c", script)
    _require("REACHABLE" not in process.stdout, "web container can reach the public Internet")
    _require(
        "BLOCKED" in process.stdout,
        f"egress check failed: {(process.stderr or process.stdout).strip()}",
    )
    return "web container has no public egress"


def _check_forwarder_egress_blocked() -> str:
    script = (
        "import socket, sys\n"
        "sock = socket.socket()\n"
        "sock.settimeout(2)\n"
        "try:\n"
        "    sock.connect(('1.1.1.1', 80))\n"
        "except OSError:\n"
        "    print('BLOCKED')\n"
        "    sys.exit(0)\n"
        "print('REACHABLE')\n"
        "sys.exit(1)\n"
    )
    checked: list[str] = []
    for service in ("ssh-forward", "web-forward"):
        process = _compose("exec", "-T", service, "python", "-c", script)
        _require(
            "REACHABLE" not in process.stdout,
            f"{service} can reach the public Internet",
        )
        _require(
            "BLOCKED" in process.stdout,
            f"{service} egress check failed: {(process.stderr or process.stdout).strip()}",
        )
        checked.append(service)
    return f"{', '.join(checked)} have no public egress"


def _check_forwarder_isolation() -> str:
    script = (
        "import socket, sys\n"
        "sock = socket.socket()\n"
        "sock.settimeout(2)\n"
        "try:\n"
        "    sock.connect((sys.argv[1], int(sys.argv[2])))\n"
        "except OSError:\n"
        "    print('BLOCKED')\n"
        "    sys.exit(0)\n"
        "print('REACHABLE')\n"
        "sys.exit(1)\n"
    )
    checks = (
        ("ssh-forward", "172.31.0.20", "8080"),
        ("web-forward", "172.30.0.10", "2222"),
    )
    for service, host, port in checks:
        process = _compose("exec", "-T", service, "python", "-c", script, host, port)
        _require(
            "REACHABLE" not in process.stdout,
            f"{service} can reach the other decoy network",
        )
        _require(
            "BLOCKED" in process.stdout,
            f"{service} isolation check failed: {(process.stderr or process.stdout).strip()}",
        )
    return "forwarders cannot reach the other decoy network"


def _check_cross_container_blocked() -> str:
    process = _compose(
        "exec",
        "-T",
        "ssh-live",
        "sh",
        "-c",
        "command -v nc >/dev/null 2>&1 || { echo NC_MISSING; exit 127; }; "
        "if nc -z -w 2 172.31.0.20 8080; then echo REACHABLE; exit 1; "
        "else echo BLOCKED; exit 0; fi",
    )
    if process.returncode == 127:
        return "skipped: nc is not installed in the SSH image"
    _require("REACHABLE" not in process.stdout, "SSH container can reach the web decoy network")
    _require(
        "BLOCKED" in process.stdout,
        f"cross-network check failed: {(process.stderr or process.stdout).strip()}",
    )
    return "SSH and web containers are network-isolated"


def _run(name: str, check: Callable[[], str], *, attempts: int = 1, retry_delay: float = 0.5) -> Result:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return Result(name, "PASS", check())
        except (CheckFailed, OSError, http.client.HTTPException, subprocess.SubprocessError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(retry_delay)
    assert last_error is not None
    return Result(name, "FAIL", str(last_error))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web-host", default="127.0.0.1")
    parser.add_argument("--web-port", type=int, default=18080)
    parser.add_argument("--ssh-host", default="127.0.0.1")
    parser.add_argument("--ssh-port", type=int, default=12222)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument(
        "--docker",
        choices=("auto", "require", "skip"),
        default="auto",
        help="run Docker Compose checks when available (default: auto)",
    )
    args = parser.parse_args(argv)

    results = [
        _run(
            "web/login",
            lambda: _check_web_login(args.web_host, args.web_port, args.timeout),
            attempts=20,
        ),
        _run(
            "web/session",
            lambda: _check_web_session(args.web_host, args.web_port, args.timeout),
            attempts=20,
        ),
        _run(
            "ssh/banner",
            lambda: _check_ssh_banner(args.ssh_host, args.ssh_port, args.timeout),
            attempts=20,
        ),
    ]

    if args.docker != "skip":
        ready, detail = _docker_ready()
        if ready:
            results.extend(
                [
                    _run(
                        "docker/services",
                        lambda: _check_running(("ssh-live", "web-live", "ssh-forward", "web-forward")),
                    ),
                    _run("docker/loopback", _check_loopback_ports),
                    _run("docker/web-egress", _check_web_egress_blocked),
                    _run("docker/forwarder-egress", _check_forwarder_egress_blocked),
                    _run("docker/cross-network", _check_cross_container_blocked),
                    _run("docker/forwarder-isolation", _check_forwarder_isolation),
                ]
            )
        elif args.docker == "require":
            results.append(Result("docker/daemon", "FAIL", detail))
        else:
            results.append(Result("docker/daemon", "SKIP", detail))

    for result in results:
        print(f"[{result.status}] {result.name}: {result.detail}")
    return 0 if all(result.status != "FAIL" for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
