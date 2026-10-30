"""Authorized attack/defense acceptance tests for the L4 + L7 chain.

Every listener in this module binds to a loopback ephemeral port. The tests
never scan, connect to, or modify external hosts, firewall rules, or services.

Topology per test::

    attack client -> L4Wall -> HighWall -> stub upstream

The suite is intentionally black-box at the HTTP edge: it sends raw bytes over
real TCP sockets and verifies what reaches the upstream.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ipaddress
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
L4_ROOT = ROOT / "subprojects" / "l4wall"
for _path in (ROOT, L4_ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from l4wall.audit import AuditWriter  # noqa: E402
from l4wall.config import GatewayConfig, example_config, parse_config  # noqa: E402
from l4wall.gateway import Gateway  # noqa: E402
from l4wall.metrics import Metrics  # noqa: E402
from l4wall.shared_state import SharedRedisSource, run_shared_ban_sync  # noqa: E402
from l4wall.tracker import BanStore, ThreatTracker  # noqa: E402

from tests.support import (  # noqa: E402
    GatewayHarness,
    StubUpstream,
    base_config,
    build_request,
    header_values,
    parse_response,
    request_once,
    send_raw,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _send(port: int, payload: bytes, *, timeout: float = 3.0) -> bytes:
    try:
        return send_raw(port, payload, timeout=timeout)
    except OSError:
        return b""


def _events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    result: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            result.append(value)
    return result


def _wait_until(predicate: Callable[[], bool], *, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _closed_events(server: "_L4Server") -> int:
    return sum(1 for event in _events(server.audit_path) if event.get("event") == "connection_closed")


def _shared_document(entries: list[dict[str, Any]], *, version: int = 1) -> bytes:
    return json.dumps(
        {"version": version, "updated": time.time(), "entries": entries},
        separators=(",", ":"),
    ).encode("utf-8")


class _FakeRedis:
    """Minimal RESP server that answers every GET with the same payload."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(16)
        self._socket.settimeout(0.1)
        self.port = int(self._socket.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(1.0)
                try:
                    while True:
                        data = b""
                        while data.count(b"\r\n") < 5 and len(data) < 8192:
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        if not data:
                            break
                        lines = data.split(b"\r\n")
                        command = lines[2].upper() if len(lines) > 2 else b""
                        if command == b"GET":
                            payload = self.payload
                            connection.sendall(b"$%d\r\n%s\r\n" % (len(payload), payload))
                        elif command in {b"SELECT", b"AUTH"}:
                            connection.sendall(b"+OK\r\n")
                        else:
                            connection.sendall(b"-ERR unsupported\r\n")
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._socket.close()
        self._thread.join(timeout=2.0)


class _L4Server:
    """Run an L4Wall gateway on its own asyncio loop inside a thread."""

    def __init__(self, config: GatewayConfig, audit_path: Path) -> None:
        self.config = config
        self.audit_path = audit_path
        self.loop: asyncio.AbstractEventLoop | None = None
        self.audit: AuditWriter | None = None
        self.metrics: Metrics | None = None
        self.tracker: ThreatTracker | None = None
        self.gateway: Gateway | None = None
        self.sync_task: asyncio.Task[None] | None = None
        self.error: BaseException | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(5.0):
            raise RuntimeError("L4Wall did not start")
        if self.error is not None:
            raise self.error

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self.loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._setup())
        except BaseException as exc:  # pragma: no cover - startup failure path
            self.error = exc
            self._ready.set()
            loop.close()
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                with contextlib.suppress(Exception):
                    loop.run_until_complete(asyncio.wait(pending, timeout=2.0))
            with contextlib.suppress(Exception):
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    async def _setup(self) -> None:
        threat = self.config.threat
        self.audit = AuditWriter(
            self.audit_path,
            max_bytes=self.config.audit.max_bytes,
            backup_count=self.config.audit.backup_count,
            on_write_failure=self.config.audit.on_write_failure,
            include_client_ip=self.config.audit.include_client_ip,
        )
        self.metrics = Metrics(self.config.metrics_enabled)
        bans = BanStore(
            threat.offender_path,
            max_entries=threat.max_ban_entries,
            prefix_v4=threat.ban_prefix_v4,
            prefix_v6=threat.ban_prefix_v6,
            max_remote_ttl=threat.shared_bans.max_ttl_seconds,
        )
        self.tracker = ThreatTracker(threat, bans)
        self.gateway = Gateway(self.config, audit=self.audit, metrics=self.metrics, tracker=self.tracker)
        await self.gateway.start()
        if threat.shared_bans.enabled:
            source = SharedRedisSource(
                threat.shared_bans,
                prefix_v4=threat.ban_prefix_v4,
                prefix_v6=threat.ban_prefix_v6,
                max_entries=threat.max_ban_entries,
            )
            self.sync_task = asyncio.create_task(
                run_shared_ban_sync(
                    source,
                    bans,
                    self.audit,
                    self.metrics,
                    interval=threat.shared_bans.sync_interval_seconds,
                )
            )

    @property
    def port(self) -> int:
        if self.gateway is None:
            raise RuntimeError("gateway is not ready")
        return self.gateway.listener_ports["web"]

    @property
    def api_port(self) -> int:
        if self.gateway is None:
            raise RuntimeError("gateway is not ready")
        return self.gateway.listener_ports["api"]

    def stop(self) -> None:
        loop = self.loop
        if loop is None:
            return
        self.loop = None

        async def shutdown() -> None:
            if self.sync_task is not None:
                self.sync_task.cancel()
                await asyncio.gather(self.sync_task, return_exceptions=True)
            if self.gateway is not None:
                await self.gateway.stop()

        future = asyncio.run_coroutine_threadsafe(shutdown(), loop)
        try:
            future.result(8.0)
        except Exception:
            future.cancel()
        if self.audit is not None:
            with contextlib.suppress(Exception):
                self.audit.close()
            self.audit = None
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(loop.stop)
        self._thread.join(5.0)


class Chain:
    """Loopback-only L4Wall -> HighWall -> stub upstream test harness."""

    def __init__(
        self,
        *,
        highwall_overrides: dict[str, Any] | None = None,
        listener_updates: dict[str, Any] | None = None,
        threat_updates: dict[str, Any] | None = None,
        two_listeners: bool = False,
        shared_payload: bytes | None = None,
        shared_unreachable: bool = False,
    ) -> None:
        self.highwall_overrides = highwall_overrides
        self.listener_updates = listener_updates or {}
        self.threat_updates = threat_updates or {}
        self.two_listeners = two_listeners
        self.shared_payload = shared_payload
        self.shared_unreachable = shared_unreachable
        self._temp: tempfile.TemporaryDirectory[str] | None = None
        self.directory: Path | None = None
        self.stub: StubUpstream | None = None
        self.highwall: GatewayHarness | None = None
        self.redis: _FakeRedis | None = None
        self.l4: _L4Server | None = None
        self._servers: list[_L4Server] = []
        self._audit_seq = 0

    def __enter__(self) -> "Chain":
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name)
        self.stub = StubUpstream()
        self.stub.__enter__()
        highwall_config = base_config(
            self.directory / "highwall",
            self.stub.port,
            overrides=self.highwall_overrides,
        )
        self.highwall = GatewayHarness(highwall_config)
        self.highwall.__enter__()
        if self.shared_payload is not None:
            self.redis = _FakeRedis(self.shared_payload)
            self.redis.start()
        self.start_l4()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        with contextlib.suppress(Exception):
            while self._servers:
                self._servers.pop().stop()
        if self.redis is not None:
            with contextlib.suppress(Exception):
                self.redis.close()
        if self.highwall is not None:
            with contextlib.suppress(Exception):
                self.highwall.__exit__(exc_type, exc, tb)
        if self.stub is not None:
            with contextlib.suppress(Exception):
                self.stub.__exit__(exc_type, exc, tb)
        if self._temp is not None:
            with contextlib.suppress(Exception):
                self._temp.cleanup()

    def _shared_port(self) -> int:
        if self.redis is not None:
            return self.redis.port
        if self.shared_unreachable:
            return _free_port()
        return _free_port()

    def _l4_config(self) -> tuple[GatewayConfig, Path]:
        assert self.directory is not None
        assert self.highwall is not None
        base = parse_config(example_config())
        primary = base.listeners[0]
        updates: dict[str, Any] = {
            "name": "web",
            "listen_port": 0,
            "upstream_host": "127.0.0.1",
            "upstream_port": self.highwall.port,
            "allowed_client_networks": (ipaddress.ip_network("127.0.0.1/32"),),
            "denied_client_networks": (),
            "connect_timeout": 1.0,
            "first_byte_timeout": 5.0,
            "idle_timeout": 5.0,
            "max_connection_seconds": 10.0,
            "max_bytes_per_direction": 65536,
            "max_connections_per_ip": 16,
            "new_connections_per_second": 1000.0,
            "new_connections_burst": 1000,
            "read_chunk_bytes": 65536,
        }
        updates.update(self.listener_updates)
        primary = dataclasses.replace(primary, **updates)
        listeners = [primary]
        if self.two_listeners:
            listeners.append(dataclasses.replace(primary, name="api", listen_port=0))
        threat = dataclasses.replace(
            base.threat,
            offender_path=str(self.directory / "offenders.json"),
            shared_bans=dataclasses.replace(
                base.threat.shared_bans,
                enabled=self.shared_payload is not None or self.shared_unreachable,
                host="127.0.0.1",
                port=self._shared_port(),
                connect_timeout=0.2,
                read_timeout=0.2,
                sync_interval_seconds=0.05,
                password_env="",
                max_payload_bytes=65536,
                max_ttl_seconds=300.0,
            ),
        )
        if self.threat_updates:
            threat = dataclasses.replace(threat, **self.threat_updates)
        server = dataclasses.replace(
            base.server,
            max_connections=128,
            max_connections_per_ip=64,
            shutdown_timeout=2.0,
        )
        self._audit_seq += 1
        audit_path = self.directory / f"l4-audit-{self._audit_seq}.jsonl"
        audit = dataclasses.replace(base.audit, path=str(audit_path))
        return dataclasses.replace(base, server=server, listeners=tuple(listeners), threat=threat, audit=audit), audit_path

    def start_l4(self) -> None:
        if self.shared_payload is not None and self.redis is None:
            self.redis = _FakeRedis(self.shared_payload)
            self.redis.start()
        config, audit_path = self._l4_config()
        server = _L4Server(config, audit_path)
        server.start()
        self._servers.append(server)
        self.l4 = server

    def stop_l4(self) -> None:
        if self._servers:
            server = self._servers.pop()
            server.stop()
            self.l4 = self._servers[-1] if self._servers else None

    def restart_l4(self) -> None:
        self.stop_l4()
        self.start_l4()


ZERO_BYTE_THREAT: dict[str, Any] = {
    "enabled": True,
    "mode": "block",
    "window_seconds": 30.0,
    "min_connections": 99,
    "min_distinct_listeners": 99,
    "min_short_connections": 99,
    "min_zero_byte_connections": 1,
    "min_rejections": 99,
    "agent_min_signals": 1,
    "agent_score": 10,
    "score_threshold": 10,
    "confirm_score": 10,
    "confirm_after_seconds": 1.0,
    "confirmed_containment_seconds": 30.0,
}

FANOUT_THREAT: dict[str, Any] = {
    "enabled": True,
    "mode": "block",
    "window_seconds": 30.0,
    "min_connections": 2,
    "min_distinct_listeners": 2,
    "min_short_connections": 99,
    "min_zero_byte_connections": 99,
    "min_rejections": 99,
    "agent_min_signals": 2,
    "agent_score": 30,
    "score_threshold": 30,
    "confirm_score": 30,
    "confirm_after_seconds": 1.0,
    "confirmed_containment_seconds": 30.0,
    "short_connection_seconds": 5.0,
    "short_connection_bytes": 65536,
}


class ChainAttackDefenseTests(unittest.TestCase):
    IP = ipaddress.ip_address("127.0.0.1")

    def _probe_zero_bytes(self, port: int) -> None:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0):
            pass

    def test_normal_request_passes_whole_chain(self) -> None:
        with Chain() as chain:
            status, _, body = parse_response(_send(chain.l4.port, build_request(path="/echo")))
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["path"], "/echo")
            self.assertEqual(len(chain.stub.state.snapshot()), 1)

    def test_wrong_host_is_blocked_before_upstream(self) -> None:
        with Chain() as chain:
            status, _, _ = parse_response(_send(chain.l4.port, build_request(path="/ok", host="evil.local")))
            self.assertEqual(status, 403)
            self.assertEqual(chain.stub.state.snapshot(), [])

    def test_absolute_uri_and_duplicate_host_are_blocked(self) -> None:
        with Chain() as chain:
            absolute = b"GET http://evil.local/ok HTTP/1.1\r\nHost: test.local\r\n\r\n"
            status, _, _ = parse_response(_send(chain.l4.port, absolute))
            self.assertEqual(status, 400)

            duplicate = build_request(headers=[("Host", "test.local")])
            status, _, _ = parse_response(_send(chain.l4.port, duplicate))
            self.assertEqual(status, 400)
            self.assertEqual(chain.stub.state.snapshot(), [])

    def test_request_smuggling_variants_are_blocked(self) -> None:
        samples = [
            (
                b"POST /ok HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 1\r\nContent-Length: 1\r\n\r\nA"
            ),
            (
                b"POST /ok HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ),
            (
                b"POST /ok HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ),
        ]
        with Chain() as chain:
            for raw in samples:
                with self.subTest(raw=raw[:64]):
                    status, _, _ = parse_response(_send(chain.l4.port, raw))
                    self.assertEqual(status, 400)
            self.assertEqual(chain.stub.state.snapshot(), [])

    def test_path_traversal_variants_are_blocked(self) -> None:
        samples = ["/a/../b", "/%2e%2e/etc/passwd", "/a%2fb", "/a%252e%252e%252fb", "/a%00b", "/.git/config"]
        with Chain() as chain:
            for path in samples:
                with self.subTest(path=path):
                    status, _, _ = parse_response(_send(chain.l4.port, build_request(path=path)))
                    self.assertIn(status, {400, 403})
            self.assertEqual(chain.stub.state.snapshot(), [])

    def test_waf_categories_are_blocked(self) -> None:
        cases = [
            ("sqli", build_request(path="/ok?q=%27%20OR%201%3D1")),
            ("cmdi", build_request(path="/ok?q=%3Bsh")),
            ("jndi", build_request(path="/ok?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D")),
            (
                "xss",
                build_request(
                    method="POST",
                    path="/ok",
                    headers=[("Content-Type", "application/json")],
                    body=b'{"comment":"<script>alert(1)</script>"}',
                ),
            ),
        ]
        with Chain() as chain:
            for name, payload in cases:
                with self.subTest(rule=name):
                    status, _, _ = parse_response(_send(chain.l4.port, payload))
                    self.assertEqual(status, 403)
            self.assertEqual(chain.stub.state.snapshot(), [])

    def test_oversized_and_get_body_requests_are_blocked(self) -> None:
        get_body = build_request(method="GET", headers=[("Content-Type", "text/plain")], body=b"A")
        too_large = (
            b"POST /ok HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 5000\r\n\r\n"
        )
        long_path = build_request(path="/" + "a" * 5000)
        long_headers = build_request(headers=[(f"X-Long-{index}", "a" * 800) for index in range(12)])
        with Chain() as chain:
            for payload, expected in (
                (get_body, 400),
                (too_large, 413),
                (long_path, 414),
                (long_headers, 431),
            ):
                with self.subTest(expected=expected):
                    status, _, _ = parse_response(_send(chain.l4.port, payload))
                    self.assertEqual(status, expected)
            self.assertEqual(chain.stub.state.snapshot(), [])

    def test_dlp_blocks_private_key_and_debug_trace(self) -> None:
        with Chain() as chain:
            status, _, body = parse_response(_send(chain.l4.port, build_request(path="/leak-secret")))
            self.assertEqual(status, 502)
            self.assertNotIn(b"PRIVATE KEY", body)
            status, _, body = parse_response(_send(chain.l4.port, build_request(path="/leak-debug")))
            self.assertEqual(status, 502)
            self.assertNotIn(b"Traceback", body)

    def test_csrf_origin_is_required_for_unsafe_methods(self) -> None:
        overrides = {"policy": {"allowed_origins": ["https://test.local"]}}
        with Chain(highwall_overrides=overrides) as chain:
            missing = build_request(
                method="POST",
                path="/echo",
                headers=[("Content-Type", "application/json")],
                body=b"{}",
            )
            wrong = build_request(
                method="POST",
                path="/echo",
                headers=[("Content-Type", "application/json"), ("Origin", "https://evil.test")],
                body=b"{}",
            )
            good = build_request(
                method="POST",
                path="/echo",
                headers=[("Content-Type", "application/json"), ("Origin", "https://test.local")],
                body=b"{}",
            )
            self.assertEqual(parse_response(_send(chain.l4.port, missing))[0], 403)
            self.assertEqual(parse_response(_send(chain.l4.port, wrong))[0], 403)
            self.assertEqual(parse_response(_send(chain.l4.port, good))[0], 200)
            self.assertEqual(len(chain.stub.state.snapshot()), 1)

    def test_spoofed_xff_is_not_trusted(self) -> None:
        with Chain() as chain:
            payload = build_request(path="/echo", headers=[("X-Forwarded-For", "203.0.113.9")])
            status, _, body = parse_response(_send(chain.l4.port, payload))
            self.assertEqual(status, 200)
            echoed = json.loads(body)
            self.assertNotEqual(echoed["xff"], "203.0.113.9")
            self.assertEqual(echoed["xff"], "127.0.0.1")

    def test_slow_header_deadline_returns_408(self) -> None:
        overrides = {"server": {"header_timeout": 0.3}}
        with Chain(highwall_overrides=overrides, listener_updates={"first_byte_timeout": 5.0}) as chain:
            sock = socket.create_connection(("127.0.0.1", chain.l4.port), timeout=1.0)
            try:
                sock.sendall(b"GET /ok HTTP/1.1\r\nHost: test.local\r\n")
                time.sleep(0.6)
                sock.settimeout(2.0)
                chunks: list[bytes] = []
                while True:
                    try:
                        chunk = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                sock.close()
            status, _, _ = parse_response(b"".join(chunks))
            self.assertEqual(status, 408)

    def test_highwall_per_ip_rate_limit_returns_429(self) -> None:
        overrides = {
            "rate_limit": {
                "enabled": True,
                "per_ip_rate": 1.0,
                "per_ip_burst": 1,
                "global_rate": 100.0,
                "global_burst": 100,
            }
        }
        with Chain(highwall_overrides=overrides) as chain:
            first = parse_response(_send(chain.l4.port, build_request(path="/ok")))
            second = parse_response(_send(chain.l4.port, build_request(path="/ok")))
            self.assertEqual(first[0], 200)
            self.assertEqual(second[0], 429)
            self.assertEqual(len(header_values(second[1], "Retry-After")), 1)
            self.assertEqual(len(chain.stub.state.snapshot()), 1)

    def test_upstream_timeout_returns_504(self) -> None:
        overrides = {"upstream": {"read_timeout": 0.1}}
        with Chain(highwall_overrides=overrides) as chain:
            status, _, _ = parse_response(_send(chain.l4.port, build_request(path="/slow")))
            self.assertEqual(status, 504)

    def test_l4_source_allowlist_blocks_before_highwall(self) -> None:
        updates = {"allowed_client_networks": (ipaddress.ip_network("10.0.0.0/8"),)}
        with Chain(listener_updates=updates) as chain:
            self.assertEqual(_send(chain.l4.port, build_request(path="/ok")), b"")
            self.assertEqual(chain.stub.state.snapshot(), [])
            self.assertTrue(
                any(event.get("reason") == "source_not_allowed" for event in _events(chain.l4.audit_path))
            )

    def test_l4_per_ip_concurrency_limit(self) -> None:
        updates = {"max_connections_per_ip": 2, "first_byte_timeout": 30.0, "idle_timeout": 30.0}
        highwall_overrides = {"server": {"header_timeout": 30.0, "body_timeout": 30.0}}
        with Chain(listener_updates=updates, highwall_overrides=highwall_overrides) as chain:
            held = [socket.create_connection(("127.0.0.1", chain.l4.port), timeout=2.0) for _ in range(2)]
            try:
                self.assertTrue(
                    _wait_until(
                        lambda: chain.l4.metrics is not None
                        and chain.l4.metrics.snapshot().get("l4wall_active_connections", 0) >= 2
                    )
                )
                self.assertEqual(_send(chain.l4.port, build_request(path="/ok")), b"")
                self.assertTrue(
                    _wait_until(
                        lambda: any(
                            event.get("reason") == "ip_capacity" for event in _events(chain.l4.audit_path)
                        )
                    )
                )
            finally:
                for connection in held:
                    connection.close()
            self.assertEqual(chain.stub.state.snapshot(), [])

    def test_l4_new_connection_rate_limit(self) -> None:
        updates = {"new_connections_per_second": 0.01, "new_connections_burst": 1}
        with Chain(listener_updates=updates) as chain:
            self.assertEqual(parse_response(_send(chain.l4.port, build_request(path="/ok")))[0], 200)
            self.assertEqual(_send(chain.l4.port, build_request(path="/ok")), b"")
            self.assertTrue(
                _wait_until(
                    lambda: any(event.get("reason") == "connection_rate" for event in _events(chain.l4.audit_path))
                )
            )

    def test_l4_first_byte_timeout(self) -> None:
        updates = {"first_byte_timeout": 0.2, "idle_timeout": 5.0}
        with Chain(listener_updates=updates) as chain:
            sock = socket.create_connection(("127.0.0.1", chain.l4.port), timeout=1.0)
            try:
                time.sleep(0.5)
                sock.settimeout(2.0)
                self.assertEqual(sock.recv(4096), b"")
            finally:
                sock.close()
            self.assertTrue(
                _wait_until(
                    lambda: any(event.get("reason") == "first_byte_timeout" for event in _events(chain.l4.audit_path))
                )
            )

    def test_l4_byte_limit(self) -> None:
        updates = {"max_bytes_per_direction": 64}
        with Chain(listener_updates=updates) as chain:
            self.assertEqual(_send(chain.l4.port, b"X" * 256), b"")
            self.assertTrue(
                _wait_until(
                    lambda: any(event.get("reason") == "byte_limit" for event in _events(chain.l4.audit_path))
                )
            )

    def test_l4_zero_byte_probe_bans_source_and_stops_later_requests(self) -> None:
        with Chain(threat_updates=ZERO_BYTE_THREAT) as chain:
            self._probe_zero_bytes(chain.l4.port)
            self.assertTrue(_wait_until(lambda: chain.l4.tracker is not None and chain.l4.tracker.bans.check(self.IP)))
            self.assertEqual(_send(chain.l4.port, build_request(path="/after-ban")), b"")
            self.assertEqual(chain.stub.state.snapshot(), [])
            events = _events(chain.l4.audit_path)
            self.assertTrue(any(event.get("event") == "source_banned" for event in events))
            self.assertTrue(any(event.get("reason") == "banned" for event in events))

    def test_l4_listener_fanout_triggers_ban(self) -> None:
        with Chain(two_listeners=True, threat_updates=FANOUT_THREAT) as chain:
            self.assertEqual(parse_response(_send(chain.l4.port, build_request(path="/ok")))[0], 200)
            self.assertTrue(_wait_until(lambda: _closed_events(chain.l4) >= 1))
            self.assertEqual(parse_response(_send(chain.l4.api_port, build_request(path="/ok")))[0], 200)
            self.assertTrue(_wait_until(lambda: chain.l4.tracker is not None and chain.l4.tracker.bans.check(self.IP)))
            self.assertEqual(_send(chain.l4.port, build_request(path="/after-ban")), b"")

    def test_l4_ban_survives_restart(self) -> None:
        with Chain(threat_updates=ZERO_BYTE_THREAT) as chain:
            self._probe_zero_bytes(chain.l4.port)
            self.assertTrue(_wait_until(lambda: chain.l4.tracker is not None and chain.l4.tracker.bans.check(self.IP)))
            chain.restart_l4()
            self.assertEqual(_send(chain.l4.port, build_request(path="/after-restart")), b"")
            self.assertEqual(chain.stub.state.snapshot(), [])
            events = _events(chain.l4.audit_path)
            self.assertTrue(any(event.get("reason") == "banned" for event in events))

    def test_shared_ban_is_imported_and_blocks_traffic(self) -> None:
        now = time.time()
        payload = _shared_document(
            [
                {
                    "network": "127.0.0.1/32",
                    "reason": "central-blocklist",
                    "created": now,
                    "expires": now + 300.0,
                }
            ]
        )
        with Chain(shared_payload=payload, threat_updates={"enabled": False}) as chain:
            self.assertTrue(_wait_until(lambda: chain.l4.tracker is not None and chain.l4.tracker.bans.check(self.IP)))
            self.assertEqual(_send(chain.l4.port, build_request(path="/shared-ban")), b"")
            self.assertEqual(chain.stub.state.snapshot(), [])
            events = _events(chain.l4.audit_path)
            self.assertTrue(any(event.get("event") == "shared_sync_ok" for event in events))
            self.assertTrue(chain.l4.metrics is not None)
            self.assertGreater(chain.l4.metrics.snapshot()["l4wall_shared_entries_imported_total"], 0)

    def test_shared_overwide_prefix_is_rejected(self) -> None:
        now = time.time()
        payload = _shared_document(
            [
                {
                    "network": "10.0.0.0/8",
                    "reason": "too-wide",
                    "created": now,
                    "expires": now + 300.0,
                }
            ]
        )
        with Chain(shared_payload=payload, threat_updates={"enabled": False}) as chain:
            self.assertTrue(
                _wait_until(
                    lambda: any(event.get("event") == "shared_sync_rejected" for event in _events(chain.l4.audit_path))
                )
            )
            self.assertEqual(parse_response(_send(chain.l4.port, build_request(path="/ok")))[0], 200)
            self.assertIsNotNone(chain.l4.tracker)
            self.assertIsNone(chain.l4.tracker.bans.check(ipaddress.ip_address("10.1.2.3")))

    def test_shared_failure_does_not_break_local_ban(self) -> None:
        with Chain(threat_updates=ZERO_BYTE_THREAT, shared_unreachable=True) as chain:
            self._probe_zero_bytes(chain.l4.port)
            self.assertTrue(_wait_until(lambda: chain.l4.tracker is not None and chain.l4.tracker.bans.check(self.IP)))
            self.assertEqual(_send(chain.l4.port, build_request(path="/after-ban")), b"")
            self.assertEqual(chain.stub.state.snapshot(), [])
            self.assertTrue(
                _wait_until(
                    lambda: any(event.get("event") == "shared_sync_failed" for event in _events(chain.l4.audit_path))
                )
            )

    def test_bad_shared_payload_does_not_clear_persisted_ban(self) -> None:
        with Chain(threat_updates=ZERO_BYTE_THREAT) as chain:
            self._probe_zero_bytes(chain.l4.port)
            self.assertTrue(_wait_until(lambda: chain.l4.tracker is not None and chain.l4.tracker.bans.check(self.IP)))
            chain.stop_l4()
            chain.shared_payload = b"{not-json"
            chain.start_l4()
            self.assertTrue(
                _wait_until(
                    lambda: any(
                        event.get("event") == "shared_sync_failed"
                        and "invalid shared ban payload" in str(event.get("error", ""))
                        for event in _events(chain.l4.audit_path)
                    )
                )
            )
            self.assertEqual(_send(chain.l4.port, build_request(path="/after-bad-shared")), b"")
            self.assertEqual(chain.stub.state.snapshot(), [])

    def test_direct_highwall_and_upstream_access_bypasses_l4_acl(self) -> None:
        updates = {"allowed_client_networks": (ipaddress.ip_network("10.0.0.0/8"),)}
        with Chain(listener_updates=updates) as chain:
            self.assertEqual(_send(chain.l4.port, build_request(path="/ok")), b"")
            self.assertIsNotNone(chain.highwall)
            assert chain.highwall is not None
            status, _, _ = parse_response(request_once(chain.highwall.port, build_request(path="/ok")))
            self.assertEqual(status, 200)
            status, _, _ = parse_response(request_once(chain.stub.port, build_request(path="/ok?q=%27%20OR%201%3D1")))
            self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
