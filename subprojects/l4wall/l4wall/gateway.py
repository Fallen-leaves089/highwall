"""Asyncio TCP data plane for L4Wall."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass
from functools import partial

from .audit import AuditWriter
from .config import GatewayConfig, ListenerConfig
from .errors import SessionError
from .metrics import Metrics
from .policy import IPAddress, SourcePolicy, normalize_ip
from .ratelimit import TokenBucket
from .tracker import Assessment, ConnectionRecord, ThreatTracker

LOGGER = logging.getLogger("l4wall")


@dataclass
class SessionResult:
    bytes_in: int = 0
    bytes_out: int = 0
    reason: str = "closed"


class Gateway:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        audit: AuditWriter,
        metrics: Metrics,
        tracker: ThreatTracker,
    ) -> None:
        self.config = config
        self.audit = audit
        self.metrics = metrics
        self.tracker = tracker
        self._servers: list[asyncio.AbstractServer] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self._active_total = 0
        self._active_per_ip: dict[str, int] = {}
        self._buckets: dict[str, TokenBucket] = {
            listener.name: TokenBucket(listener.new_connections_per_second, listener.new_connections_burst)
            for listener in config.listeners
        }
        self._policies: dict[str, SourcePolicy] = {
            listener.name: SourcePolicy(listener.allowed_client_networks, listener.denied_client_networks)
            for listener in config.listeners
        }
        self._stopping = asyncio.Event()
        self._listener_ports: dict[str, int] = {}

    @property
    def listener_ports(self) -> dict[str, int]:
        return dict(self._listener_ports)

    async def start(self) -> None:
        if self._servers:
            raise RuntimeError("gateway is already started")
        try:
            for listener in self.config.listeners:
                server = await asyncio.start_server(
                    partial(self._spawn, listener),
                    host=self.config.server.listen_host,
                    port=listener.listen_port,
                    backlog=self.config.server.accept_backlog,
                )
                self._servers.append(server)
                sockets = server.sockets
                port = sockets[0].getsockname()[1] if sockets else listener.listen_port
                self._listener_ports[listener.name] = port
                LOGGER.info(
                    "listening name=%s host=%s port=%s upstream=%s:%s",
                    listener.name,
                    self.config.server.listen_host,
                    port,
                    listener.upstream_host,
                    listener.upstream_port,
                )
        except OSError:
            await self._close_servers()
            raise

    async def serve_forever(self) -> None:
        await self._stopping.wait()

    async def stop(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        await self._close_servers()
        tasks = list(self._tasks)
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=self.config.server.shutdown_timeout)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                with contextlib.suppress(Exception):
                    task.result()
        self.audit.close()

    async def _close_servers(self) -> None:
        servers = self._servers
        self._servers = []
        for server in servers:
            server.close()
        for server in servers:
            with contextlib.suppress(Exception):
                await server.wait_closed()

    def _spawn(self, listener: ListenerConfig, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(self._handle(listener, reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, listener: ListenerConfig, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        started = time.monotonic()
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if isinstance(peer, tuple) and peer else ""
        address = normalize_ip(peer_ip) if peer_ip else None
        admitted = False
        recorded = False
        reason = "closed"
        result = SessionResult()
        try:
            if address is None:
                reason = "invalid_peer"
                self._denied(listener, peer_ip, reason, 0, ())
                recorded = True
                return
            if self._stopping.is_set():
                reason = "shutting_down"
                self._denied(listener, peer_ip, reason, 0, ())
                recorded = True
                return
            assessment = self._admit(listener, address, started)
            if assessment.action == "deny":
                reason = assessment.reason
                self._denied(listener, peer_ip, reason, assessment.score, assessment.signals)
                recorded = True
                if reason != "audit_unhealthy":
                    self._record(listener, address, started, started, False, reason, 0, 0)
                if assessment.reason == "agent_confirmed" and self.tracker.bans.check(address) is not None:
                    self.metrics.inc("l4wall_threat_confirmed_total")
                    self.audit.write(
                        "source_banned",
                        listener=listener.name,
                        client_ip=peer_ip,
                        reason=assessment.reason,
                        score=assessment.score,
                    )
                return
            self._inc_active(address)
            admitted = True
            if assessment.action == "throttle":
                self.metrics.inc("l4wall_connections_throttled_total")
                self.audit.write(
                    "connection_throttled",
                    listener=listener.name,
                    client_ip=peer_ip,
                    delay_ms=assessment.throttle_ms,
                    score=assessment.score,
                    signals=list(assessment.signals),
                )
                if not self.audit.healthy:
                    reason = "audit_unhealthy"
                    return
                await asyncio.sleep(assessment.throttle_ms / 1000.0)
                if self._stopping.is_set():
                    reason = "shutting_down"
                    return
            self.metrics.inc("l4wall_connections_total")
            self.audit.write(
                "connection_allowed",
                listener=listener.name,
                client_ip=peer_ip,
                upstream=f"{listener.upstream_host}:{listener.upstream_port}",
                score=assessment.score,
                signals=list(assessment.signals),
            )
            if not self.audit.healthy:
                reason = "audit_unhealthy"
                return
            try:
                result = await asyncio.wait_for(
                    self._session(listener, reader, writer), timeout=listener.max_connection_seconds
                )
                reason = result.reason
            except asyncio.TimeoutError:
                reason = "max_duration"
            except SessionError as exc:
                reason = str(exc)
                if reason.startswith("upstream_"):
                    self.metrics.inc("l4wall_upstream_errors_total")
                    self.audit.write(
                        "upstream_error",
                        listener=listener.name,
                        client_ip=peer_ip,
                        error=reason,
                    )
            except (ConnectionError, OSError):
                reason = "io_error"
                self.metrics.inc("l4wall_upstream_errors_total")
                self.audit.write("upstream_error", listener=listener.name, client_ip=peer_ip, error="io_error")
            except asyncio.CancelledError:
                reason = "cancelled"
                raise
            except Exception:
                reason = "internal_error"
                LOGGER.exception("unhandled session error")
                self.audit.write("internal_error", listener=listener.name, client_ip=peer_ip)
        finally:
            if admitted and address is not None:
                self._dec_active(address)
            await _close_writer(writer)
            if not recorded and address is not None:
                elapsed = time.monotonic() - started
                assessment = self._record(
                    listener,
                    address,
                    started,
                    time.monotonic(),
                    admitted,
                    reason,
                    result.bytes_in,
                    result.bytes_out,
                )
                self.metrics.inc("l4wall_sessions_closed_total")
                self.metrics.inc("l4wall_bytes_in_total", result.bytes_in)
                self.metrics.inc("l4wall_bytes_out_total", result.bytes_out)
                self.audit.write(
                    "connection_closed",
                    listener=listener.name,
                    client_ip=peer_ip,
                    reason=reason,
                    duration_ms=int(elapsed * 1000),
                    bytes_in=result.bytes_in,
                    bytes_out=result.bytes_out,
                    score=assessment.score,
                    signals=list(assessment.signals),
                )
                if assessment.confirmed and self.tracker.bans.check(address) is not None:
                    self.metrics.inc("l4wall_threat_confirmed_total")
                    self.audit.write(
                        "source_banned",
                        listener=listener.name,
                        client_ip=peer_ip,
                        reason=assessment.reason,
                        score=assessment.score,
                    )

    def _admit(self, listener: ListenerConfig, address: IPAddress, now: float) -> Assessment:
        if not self.audit.healthy:
            return Assessment(0, ("audit_unhealthy",), False, True, True, "deny", 0, "audit_unhealthy")
        allowed, source_reason = self._policies[listener.name].evaluate(address)
        if not allowed:
            return Assessment(0, (source_reason,), False, False, False, "deny", 0, source_reason)
        assessment = self.tracker.pre_connection(address, now)
        if assessment.action == "deny":
            return assessment
        if assessment.suspected:
            self.metrics.inc("l4wall_threat_suspected_total")
        key = str(address)
        if self._active_total >= self.config.server.max_connections:
            return Assessment(0, ("server_capacity",), False, False, False, "deny", 0, "server_capacity")
        if self._active_per_ip.get(key, 0) >= self.config.server.max_connections_per_ip:
            return Assessment(0, ("ip_capacity",), False, False, False, "deny", 0, "ip_capacity")
        if self._active_per_ip.get(key, 0) >= listener.max_connections_per_ip:
            return Assessment(0, ("ip_capacity",), False, False, False, "deny", 0, "ip_capacity")
        if not self._buckets[listener.name].allow(now):
            return Assessment(0, ("connection_rate",), False, False, False, "deny", 0, "connection_rate")
        return assessment

    def _denied(
        self, listener: ListenerConfig, peer_ip: str, reason: str, score: int, signals: tuple[str, ...]
    ) -> None:
        self.metrics.inc("l4wall_connections_denied_total")
        self.audit.write(
            "connection_denied",
            listener=listener.name,
            client_ip=peer_ip,
            reason=reason,
            score=score,
            signals=list(signals),
        )

    def _record(
        self,
        listener: ListenerConfig,
        address: IPAddress,
        started: float,
        ended: float,
        accepted: bool,
        reason: str,
        bytes_in: int,
        bytes_out: int,
    ) -> Assessment:
        record = ConnectionRecord(
            ts=ended,
            listener=listener.name,
            accepted=accepted,
            reason=reason,
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            duration=max(0.0, ended - started),
        )
        return self.tracker.record(address, record, ended)

    def _inc_active(self, address: IPAddress) -> None:
        key = str(address)
        self._active_total += 1
        self._active_per_ip[key] = self._active_per_ip.get(key, 0) + 1
        self.metrics.set_gauge("l4wall_active_connections", self._active_total)
        self.metrics.set_gauge("l4wall_active_clients", len(self._active_per_ip))

    def _dec_active(self, address: IPAddress) -> None:
        key = str(address)
        self._active_total = max(0, self._active_total - 1)
        remaining = self._active_per_ip.get(key, 0) - 1
        if remaining > 0:
            self._active_per_ip[key] = remaining
        else:
            self._active_per_ip.pop(key, None)
        self.metrics.set_gauge("l4wall_active_connections", self._active_total)
        self.metrics.set_gauge("l4wall_active_clients", len(self._active_per_ip))

    async def _session(
        self, listener: ListenerConfig, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> SessionResult:
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(listener.upstream_host, listener.upstream_port),
                timeout=listener.connect_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise SessionError("upstream_connect_timeout") from exc
        except OSError as exc:
            raise SessionError("upstream_unreachable") from exc
        stats = SessionResult()
        try:
            await self._pump_both(listener, client_reader, client_writer, upstream_reader, upstream_writer, stats)
        finally:
            await _close_writer(upstream_writer)
        return stats

    async def _pump_both(
        self,
        listener: ListenerConfig,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        stats: SessionResult,
    ) -> None:
        to_upstream = asyncio.create_task(
            self._pump(client_reader, upstream_writer, listener, stats, incoming=True)
        )
        to_client = asyncio.create_task(
            self._pump(upstream_reader, client_writer, listener, stats, incoming=False)
        )
        try:
            await asyncio.gather(to_upstream, to_client)
        finally:
            for task in (to_upstream, to_client):
                if not task.done():
                    task.cancel()
            await asyncio.gather(to_upstream, to_client, return_exceptions=True)

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        listener: ListenerConfig,
        stats: SessionResult,
        *,
        incoming: bool,
    ) -> None:
        first = True
        while True:
            timeout = (listener.first_byte_timeout if incoming else listener.idle_timeout) if first else listener.idle_timeout
            try:
                data = await asyncio.wait_for(reader.read(listener.read_chunk_bytes), timeout=timeout)
            except asyncio.TimeoutError as exc:
                raise SessionError("first_byte_timeout" if first else "idle_timeout") from exc
            if not data:
                with contextlib.suppress(OSError, NotImplementedError):
                    writer.write_eof()
                return
            first = False
            if incoming:
                stats.bytes_in += len(data)
                total = stats.bytes_in
            else:
                stats.bytes_out += len(data)
                total = stats.bytes_out
            if total > listener.max_bytes_per_direction:
                raise SessionError("byte_limit")
            writer.write(data)
            await writer.drain()


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()
    # Do not swallow CancelledError here: shutdown cancels session tasks and
    # must be able to observe that cancellation promptly.
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)

