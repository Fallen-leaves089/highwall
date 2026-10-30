from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ipaddress
import socket
import tempfile
import unittest
from pathlib import Path
from typing import Any

from l4wall.audit import AuditWriter
from l4wall.config import example_config, parse_config
from l4wall.gateway import Gateway
from l4wall.metrics import Metrics
from l4wall.tracker import BanStore, ThreatTracker


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name)
        self.echo_server = await asyncio.start_server(self._echo, "127.0.0.1", 0)
        sockets = self.echo_server.sockets or []
        self.echo_port = int(sockets[0].getsockname()[1])
        self.gateway: Gateway | None = None

    async def asyncTearDown(self) -> None:
        if self.gateway is not None:
            await self.gateway.stop()
        self.echo_server.close()
        with contextlib.suppress(Exception):
            await self.echo_server.wait_closed()
        self._temp.cleanup()

    async def _echo(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _start_gateway(
        self,
        *,
        listener_updates: dict[str, Any] | None = None,
        server_updates: dict[str, Any] | None = None,
        threat_updates: dict[str, Any] | None = None,
    ) -> tuple[Gateway, int, AuditWriter]:
        config = parse_config(example_config())
        listener = dataclasses.replace(
            config.listeners[0],
            listen_port=free_port(),
            upstream_host="127.0.0.1",
            upstream_port=self.echo_port,
            allowed_client_networks=(ipaddress.ip_network("127.0.0.1/32"),),
            denied_client_networks=(),
            connect_timeout=1.0,
            first_byte_timeout=0.5,
            idle_timeout=0.5,
            max_connection_seconds=3.0,
            max_bytes_per_direction=1024,
            max_connections_per_ip=10,
            new_connections_per_second=100.0,
            new_connections_burst=100,
        )
        if listener_updates:
            listener = dataclasses.replace(listener, **listener_updates)
        server = dataclasses.replace(
            config.server,
            max_connections=32,
            max_connections_per_ip=10,
            shutdown_timeout=1.0,
        )
        if server_updates:
            server = dataclasses.replace(server, **server_updates)
        threat = dataclasses.replace(
            config.threat,
            offender_path=str(self.directory / "offenders.json"),
            mode="score",
        )
        if threat_updates:
            threat = dataclasses.replace(threat, **threat_updates)
        config = dataclasses.replace(config, server=server, listeners=(listener,), threat=threat)
        audit = AuditWriter(self.directory / "audit.jsonl")
        bans = BanStore(
            threat.offender_path,
            max_entries=threat.max_ban_entries,
            prefix_v4=threat.ban_prefix_v4,
            prefix_v6=threat.ban_prefix_v6,
        )
        tracker = ThreatTracker(threat, bans)
        gateway = Gateway(config, audit=audit, metrics=Metrics(True), tracker=tracker)
        await gateway.start()
        self.gateway = gateway
        return gateway, listener.listen_port, audit

    async def _read_until_closed(self, reader: asyncio.StreamReader) -> bytes:
        return await asyncio.wait_for(reader.read(), timeout=2.0)

    async def test_echo_round_trip(self) -> None:
        gateway, port, audit = await self._start_gateway()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"hello")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(5), 2.0), b"hello")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        text = audit.path.read_text(encoding="utf-8")
        self.assertIn('"event":"connection_allowed"', text)
        self.assertIn('"event":"connection_closed"', text)
        self.assertEqual(gateway.listener_ports["web"], port)

    async def test_source_not_allowed(self) -> None:
        _, port, audit = await self._start_gateway(
            listener_updates={"allowed_client_networks": (ipaddress.ip_network("10.0.0.0/8"),)}
        )
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await self._read_until_closed(reader), b"")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        text = audit.path.read_text(encoding="utf-8")
        self.assertIn('"reason":"source_not_allowed"', text)

    async def test_connection_rate_limit(self) -> None:
        _, port, audit = await self._start_gateway(
            listener_updates={"new_connections_per_second": 0.01, "new_connections_burst": 1}
        )
        first_reader, first_writer = await asyncio.open_connection("127.0.0.1", port)
        first_writer.write(b"x")
        await first_writer.drain()
        self.assertEqual(await asyncio.wait_for(first_reader.readexactly(1), 2.0), b"x")
        second_reader, second_writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await self._read_until_closed(second_reader), b"")
        second_writer.close()
        await second_writer.wait_closed()
        first_writer.close()
        await first_writer.wait_closed()
        await asyncio.sleep(0.05)
        text = audit.path.read_text(encoding="utf-8")
        self.assertIn('"reason":"connection_rate"', text)

    async def test_byte_limit(self) -> None:
        _, port, audit = await self._start_gateway(
            listener_updates={"max_bytes_per_direction": 4}
        )
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"12345678")
        await writer.drain()
        self.assertEqual(await self._read_until_closed(reader), b"")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        text = audit.path.read_text(encoding="utf-8")
        self.assertIn('"reason":"byte_limit"', text)

    async def test_first_byte_timeout(self) -> None:
        _, port, audit = await self._start_gateway(
            listener_updates={"first_byte_timeout": 0.2}
        )
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await self._read_until_closed(reader), b"")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        text = audit.path.read_text(encoding="utf-8")
        self.assertIn('"reason":"first_byte_timeout"', text)

    async def test_pre_banned_source_is_denied(self) -> None:
        gateway, port, audit = await self._start_gateway()
        gateway.tracker.bans.ban(ipaddress.ip_address("127.0.0.1"), "test", 60)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await self._read_until_closed(reader), b"")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        text = audit.path.read_text(encoding="utf-8")
        self.assertIn('"reason":"banned"', text)

    async def test_per_ip_connection_cap(self) -> None:
        _, port, audit = await self._start_gateway(
            listener_updates={"max_connections_per_ip": 1}
        )
        first_reader, first_writer = await asyncio.open_connection("127.0.0.1", port)
        first_writer.write(b"x")
        await first_writer.drain()
        self.assertEqual(await asyncio.wait_for(first_reader.readexactly(1), 2.0), b"x")
        second_reader, second_writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await self._read_until_closed(second_reader), b"")
        second_writer.close()
        await second_writer.wait_closed()
        first_writer.close()
        await first_writer.wait_closed()
        await asyncio.sleep(0.05)
        text = audit.path.read_text(encoding="utf-8")
        self.assertIn('"reason":"ip_capacity"', text)


if __name__ == "__main__":
    unittest.main()

