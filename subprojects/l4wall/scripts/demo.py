"""Single-machine L4Wall demo.

Starts an echo upstream, two protected listeners, sends a normal request,
then simulates an agent-like scan with fan-out, short connections, and
zero-byte probes. No administrator rights and no external network needed.
"""

# ruff: noqa: E402

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ipaddress
import socket
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from l4wall.audit import AuditWriter
from l4wall.config import example_config, parse_config
from l4wall.gateway import Gateway
from l4wall.metrics import Metrics
from l4wall.tracker import BanStore, ThreatTracker


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


async def normal_request(port: int) -> bool:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"hello")
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.readexactly(5), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return data == b"hello"


async def probe(port: int, payload: bytes) -> None:
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
    except OSError:
        return
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        with contextlib.suppress(asyncio.TimeoutError, OSError):
            await asyncio.wait_for(reader.read(), timeout=0.15)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def main() -> int:
    with tempfile.TemporaryDirectory(prefix="l4wall-demo-") as directory:
        work = Path(directory)
        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        sockets = upstream.sockets or []
        upstream_port = int(sockets[0].getsockname()[1])

        config = parse_config(example_config())
        web = dataclasses.replace(
            config.listeners[0],
            listen_port=free_port(),
            upstream_host="127.0.0.1",
            upstream_port=upstream_port,
            allowed_client_networks=(ipaddress.ip_network("127.0.0.1/32"),),
            denied_client_networks=(),
            first_byte_timeout=0.2,
            idle_timeout=1.0,
            max_connection_seconds=3.0,
            max_connections_per_ip=16,
            new_connections_per_second=100.0,
            new_connections_burst=100,
        )
        api = dataclasses.replace(web, name="api", listen_port=free_port())
        threat = dataclasses.replace(
            config.threat,
            mode="block",
            window_seconds=10.0,
            min_connections=8,
            min_distinct_listeners=2,
            min_short_connections=6,
            min_zero_byte_connections=4,
            min_rejections=2,
            score_threshold=60,
            confirm_score=75,
            confirm_after_seconds=60.0,
            confirmed_containment_seconds=60.0,
            mark_ttl_seconds=60.0,
            agent_min_signals=2,
            agent_score=30,
            offender_path=str(work / "offenders.json"),
        )
        config = dataclasses.replace(config, listeners=(web, api), threat=threat)
        audit = AuditWriter(work / "audit.jsonl")
        bans = BanStore(
            threat.offender_path,
            max_entries=threat.max_ban_entries,
            prefix_v4=threat.ban_prefix_v4,
            prefix_v6=threat.ban_prefix_v6,
        )
        tracker = ThreatTracker(threat, bans)
        gateway = Gateway(config, audit=audit, metrics=Metrics(True), tracker=tracker)
        await gateway.start()
        print("L4Wall single-machine demo")
        print(f"  web: 127.0.0.1:{web.listen_port} -> 127.0.0.1:{upstream_port}")
        print(f"  api: 127.0.0.1:{api.listen_port} -> 127.0.0.1:{upstream_port}")
        try:
            ok = await normal_request(web.listen_port)
            print(f"[{'PASS' if ok else 'FAIL'}] normal echo")
            for index in range(12):
                port = web.listen_port if index % 2 == 0 else api.listen_port
                payload = b"" if index < 6 else b"x"
                await probe(port, payload)
            print("[INFO] agent probes: 12 connections across web/api")
            entry = gateway.tracker.bans.check(ipaddress.ip_address("127.0.0.1"))
            print(f"[{'PASS' if entry else 'FAIL'}] source banned: {entry.network if entry else 'not banned'}")
            print("[audit]")
            for line in audit.tail(20):
                print(f"  {line}")
            return 0 if ok and entry else 1
        finally:
            await gateway.stop()
            upstream.close()
            with contextlib.suppress(Exception):
                await upstream.wait_closed()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

