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
PUBLIC_PROBE_TARGETS = (("1.1.1.1", 80), ("1.1.1.1", 53))
METADATA_PROBE_TARGETS = (
    ("169.254.169.254", 80),
    ("169.254.170.2", 80),
    ("100.100.100.200", 80),
)
HOST_API_PROBE_PORTS = (2375, 2376)
FORWARDER_GATEWAYS = {
    "ssh-forward": ("172.32.0.1", "172.30.0.1"),
    "web-forward": ("172.33.0.1", "172.31.0.1"),
}
PROBE_SCRIPT = (
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


def _probe_blocked(service: str, host: str, port: int) -> None:
    process = _compose("exec", "-T", service, "python", "-c", PROBE_SCRIPT, host, str(port))
    output = "\n".join(part.strip() for part in (process.stdout, process.stderr) if part and part.strip())
    _require("REACHABLE" not in output, f"{service} can reach {host}:{port}")
    _require("BLOCKED" in output, f"{service} probe failed for {host}:{port}: {output}")


def _check_web_egress_blocked() -> str:
    targets = (*PUBLIC_PROBE_TARGETS, *METADATA_PROBE_TARGETS)
    targets += tuple(("172.31.0.1", port) for port in HOST_API_PROBE_PORTS)
    for host, port in targets:
        _probe_blocked("web-live", host, port)
    return "web container cannot reach public, metadata, or host API endpoints"


def _check_forwarder_egress_blocked() -> str:
    checked: list[str] = []
    for service, gateways in FORWARDER_GATEWAYS.items():
        targets = (*PUBLIC_PROBE_TARGETS, *METADATA_PROBE_TARGETS)
        targets += tuple((gateway, port) for gateway in gateways for port in HOST_API_PROBE_PORTS)
        for host, port in targets:
            _probe_blocked(service, host, port)
        checked.append(service)
    return f"{', '.join(checked)} cannot reach public, metadata, or host API endpoints"


def _check_ssh_egress_blocked() -> str:
    targets = (*PUBLIC_PROBE_TARGETS, *METADATA_PROBE_TARGETS)
    targets += tuple(("172.30.0.1", port) for port in HOST_API_PROBE_PORTS)
    commands = ["command -v nc >/dev/null 2>&1 || { echo PROBE_MISSING; exit 127; }"]
    for host, port in targets:
        commands.append(f"if nc -z -w 2 {host} {port}; then echo REACHABLE:{host}:{port}; exit 1; fi")
    commands.append("echo BLOCKED; exit 0")
    process = _compose("exec", "-T", "ssh-live", "sh", "-c", "; ".join(commands))
    if process.returncode == 127:
        return "skipped: nc is not installed in the SSH image"
    output = "\n".join(part.strip() for part in (process.stdout, process.stderr) if part and part.strip())
    _require("REACHABLE" not in output, f"SSH container can reach an external endpoint: {output}")
    _require("BLOCKED" in output, f"SSH egress check failed: {output}")
    return "SSH container cannot reach public, metadata, or host API endpoints"


def _check_forwarder_isolation() -> str:
    checks = (
        ("ssh-forward", "172.31.0.20", "8080"),
        ("web-forward", "172.30.0.10", "2222"),
    )
    for service, host, port in checks:
        _probe_blocked(service, host, int(port))
    return "forwarders cannot reach the other decoy network"


def _check_web_cross_container_blocked() -> str:
    _probe_blocked("web-live", "172.30.0.10", 2222)
    return "web container cannot reach the SSH decoy network"


def _check_cross_container_blocked() -> str:
    process = _compose(
        "exec",
        "-T",
        "ssh-live",
        "sh",
        "-c",
        "if command -v nc >/dev/null 2>&1; then "
        "if nc -z -w 2 172.31.0.20 8080; then echo REACHABLE; exit 1; "
        "else echo BLOCKED; exit 0; fi; fi; "
        "if command -v wget >/dev/null 2>&1; then "
        "if wget -q -T 2 -O /dev/null http://172.31.0.20:8080/; then echo REACHABLE; exit 1; "
        "else echo BLOCKED; exit 0; fi; fi; "
        "echo PROBE_MISSING; exit 127",
    )
    if process.returncode == 127:
        return "skipped: nc and wget are not installed in the SSH image"
    output = "\n".join(part.strip() for part in (process.stdout, process.stderr) if part and part.strip())
    _require("REACHABLE" not in output, "SSH container can reach the web decoy network")
    _require(
        "BLOCKED" in process.stdout,
        f"cross-network check failed: {output}",
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
                    _run("docker/ssh-egress", _check_ssh_egress_blocked),
                    _run("docker/cross-network", _check_cross_container_blocked),
                    _run("docker/web-cross-network", _check_web_cross_container_blocked),
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
