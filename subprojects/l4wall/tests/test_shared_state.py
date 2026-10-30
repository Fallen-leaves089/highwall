from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from l4wall.audit import AuditWriter
from l4wall.config import SharedBansConfig, example_config, parse_config
from l4wall.metrics import Metrics
from l4wall.shared_state import (
    SharedFetchResult,
    SharedRedisSource,
    SharedStateError,
    parse_shared_bans,
    run_shared_ban_sync,
)
from l4wall.tracker import BanEntry, BanStore


def shared_config(**updates: Any) -> SharedBansConfig:
    raw = example_config()
    raw["threat_detection"]["shared_bans"].update(updates)
    return parse_config(raw).threat.shared_bans


def payload(entries: list[dict[str, Any]], *, version: int = 1) -> bytes:
    return json.dumps({"version": version, "updated": 1000.0, "entries": entries}).encode("utf-8")


def entry(network: str, *, now: float, ttl: float = 60.0, reason: str = "agent") -> dict[str, Any]:
    return {"network": network, "reason": reason, "created": now, "expires": now + ttl}


class SharedPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = shared_config(max_payload_bytes=4096, max_ttl_seconds=3600.0)
        self.now = 1_000_000.0

    def parse(self, raw: bytes, *, max_entries: int = 100) -> SharedFetchResult:
        return parse_shared_bans(
            raw,
            now=self.now,
            config=self.config,
            prefix_v4=32,
            prefix_v6=128,
            max_entries=max_entries,
        )

    def test_valid_entry_is_imported_with_source_marker(self) -> None:
        result = self.parse(payload([entry("203.0.113.7/32", now=self.now)]))
        self.assertEqual(result.rejected, 0)
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(result.entries[0].reason, "shared:agent")
        self.assertEqual(result.entries[0].source, "remote")

    def test_expired_and_broad_prefix_entries_are_rejected(self) -> None:
        result = self.parse(
            payload(
                [
                    entry("203.0.113.7/32", now=self.now, ttl=-1),
                    entry("198.51.100.0/24", now=self.now),
                ]
            )
        )
        self.assertEqual(result.entries, ())
        self.assertEqual(result.rejected, 2)

    def test_version_unknown_field_duplicate_and_non_finite_are_rejected(self) -> None:
        bad_documents = [
            payload([], version=2),
            b'{"version":1,"entries":[],"extra":true}',
            b'{"version":1,"version":1,"entries":[]}',
            b'{"version":1,"entries":[],"updated":NaN}',
            b'{"version":1,"entries":[]} trailing',
        ]
        for document in bad_documents:
            with self.subTest(document=document):
                with self.assertRaises(SharedStateError):
                    self.parse(document)

    def test_entry_limit_and_payload_limit_are_enforced(self) -> None:
        result = self.parse(payload([entry(f"192.0.2.{index}/32", now=self.now) for index in range(3)]), max_entries=2)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.rejected, 1)
        with self.assertRaises(SharedStateError):
            self.parse(b"x" * 5000)

    def test_remote_ttl_is_clamped(self) -> None:
        result = self.parse(payload([entry("192.0.2.8/32", now=self.now, ttl=99999)]))
        self.assertEqual(result.entries[0].expires, self.now + 3600.0)


class BanMergeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.path = Path(self._temp.name) / "offenders.json"

    def tearDown(self) -> None:
        self._temp.cleanup()

    def store(self, **updates: Any) -> BanStore:
        values = {"max_entries": 10, "prefix_v4": 32, "prefix_v6": 128}
        values.update(updates)
        return BanStore(self.path, **values)

    def remote(self, address: str, *, now: float, ttl: float, reason: str = "shared") -> BanEntry:
        return BanEntry(
            network=ipaddress.ip_network(address, strict=False),
            reason=reason,
            created=now,
            expires=now + ttl,
            source="remote",
        )

    def test_remote_entry_cannot_remove_shorten_or_rename_local_ban(self) -> None:
        now = time.time()
        store = self.store()
        address = ipaddress.ip_address("203.0.113.9")
        store.ban(address, "local_reason", 300)
        local = store.check(address, now)
        assert local is not None
        changed = store.merge_remote([self.remote("203.0.113.9/32", now=now, ttl=10, reason="remote")], now)
        merged = store.check(address, now)
        assert merged is not None
        self.assertEqual(changed, 0)
        self.assertEqual(merged.reason, "local_reason")
        self.assertEqual(merged.source, "local")
        self.assertGreaterEqual(merged.expires, local.expires)

    def test_remote_entries_only_extend(self) -> None:
        now = 2_000_000.0
        store = self.store()
        address = ipaddress.ip_address("198.51.100.20")
        self.assertEqual(store.merge_remote([self.remote("198.51.100.20/32", now=now, ttl=100)], now), 1)
        first = store.check(address, now)
        assert first is not None
        self.assertEqual(first.expires, now + 100)
        self.assertEqual(store.merge_remote([self.remote("198.51.100.20/32", now=now, ttl=50)], now), 0)
        self.assertEqual(store.merge_remote([self.remote("198.51.100.20/32", now=now, ttl=200)], now), 1)
        second = store.check(address, now)
        assert second is not None
        self.assertEqual(second.expires, now + 200)

    def test_remote_capacity_cannot_evict_local_entries(self) -> None:
        now = time.time()
        store = self.store(max_entries=2)
        first = ipaddress.ip_address("192.0.2.1")
        second = ipaddress.ip_address("192.0.2.2")
        third = ipaddress.ip_address("192.0.2.3")
        store.ban(first, "one", 60)
        store.ban(second, "two", 60)
        self.assertEqual(store.merge_remote([self.remote("192.0.2.3/32", now=now, ttl=60)], now), 0)
        self.assertIsNotNone(store.check(first, now))
        self.assertIsNotNone(store.check(second, now))
        self.assertIsNone(store.check(third, now))

    def test_remote_capacity_evicts_oldest_remote_not_local(self) -> None:
        now = time.time()
        store = self.store(max_entries=2)
        local = ipaddress.ip_address("192.0.2.10")
        store.ban(local, "local", 60)
        store.merge_remote([self.remote("192.0.2.11/32", now=now - 20, ttl=60)], now)
        store.merge_remote([self.remote("192.0.2.12/32", now=now, ttl=60)], now)
        self.assertIsNotNone(store.check(local, now))
        self.assertIsNone(store.check(ipaddress.ip_address("192.0.2.11"), now))
        self.assertIsNotNone(store.check(ipaddress.ip_address("192.0.2.12"), now))

    def test_remote_ttl_is_capped_again_in_store(self) -> None:
        now = 3_000_000.0
        store = self.store(max_remote_ttl=30.0)
        address = ipaddress.ip_address("198.51.100.30")
        store.merge_remote([self.remote("198.51.100.30/32", now=now, ttl=9999)], now)
        imported = store.check(address, now)
        assert imported is not None
        self.assertLessEqual(imported.expires, now + 30.0)

    def test_persist_failure_keeps_in_memory_ban(self) -> None:
        blocker = Path(self._temp.name) / "blocker"
        blocker.write_text("not a directory", encoding="utf-8")
        store = BanStore(blocker / "offenders.json", max_entries=10, prefix_v4=32, prefix_v6=128)
        address = ipaddress.ip_address("203.0.113.44")
        self.assertFalse(store.ban(address, "test", 60))
        self.assertIsNotNone(store.check(address))
        self.assertGreaterEqual(store.persist_errors, 1)


class FakeRedisServer:
    def __init__(self, response: bytes, *, delay: float = 0.0) -> None:
        self.response = response
        self.delay = delay
        self.server: asyncio.AbstractServer | None = None
        self.port = 0
        self.tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        socket = self.server.sockets[0]
        self.port = int(socket.getsockname()[1])

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.tasks.add(task)
        try:
            while True:
                command = await _read_command(reader)
                if command is None:
                    return
                if self.delay:
                    await asyncio.sleep(self.delay)
                name = command[0].upper()
                if name in {"AUTH", "SELECT"}:
                    writer.write(b"+OK\r\n")
                elif name == "GET":
                    writer.write(self.response)
                else:
                    writer.write(b"-ERR unsupported\r\n")
                await writer.drain()
        except (asyncio.CancelledError, ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            if task is not None:
                self.tasks.discard(task)


async def _read_command(reader: asyncio.StreamReader) -> list[str] | None:
    line = await reader.readline()
    if not line:
        return None
    if not line.startswith(b"*"):
        raise ValueError("expected RESP array")
    count = int(line[1:-2])
    parts: list[str] = []
    for _ in range(count):
        header = await reader.readline()
        length = int(header[1:-2])
        parts.append((await reader.readexactly(length)).decode("utf-8"))
        await reader.readexactly(2)
    return parts


def bulk(data: bytes) -> bytes:
    return f"${len(data)}\r\n".encode("ascii") + data + b"\r\n"


class SharedRedisSourceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name)
        self.servers: list[FakeRedisServer] = []

    async def asyncTearDown(self) -> None:
        for server in self.servers:
            await server.stop()
        self._temp.cleanup()

    async def source(self, response: bytes, *, delay: float = 0.0, **updates: Any) -> SharedRedisSource:
        server = FakeRedisServer(response, delay=delay)
        await server.start()
        self.servers.append(server)
        values = {
            "enabled": True,
            "port": server.port,
            "connect_timeout": 0.2,
            "read_timeout": 0.2,
            "max_payload_bytes": 4096,
        }
        values.update(updates)
        config = shared_config(**values)
        return SharedRedisSource(config, max_entries=100)

    async def test_valid_payload_is_fetched(self) -> None:
        now = time.time()
        source = await self.source(bulk(payload([entry("203.0.113.7/32", now=now)])))
        result = await source.fetch(now)
        self.assertEqual(len(result.entries), 1)

    async def test_missing_key_is_a_failure_not_an_empty_clear(self) -> None:
        source = await self.source(b"$-1\r\n")
        with self.assertRaisesRegex(SharedStateError, "missing"):
            await source.fetch(time.time())

    async def test_corrupt_json_is_a_failure(self) -> None:
        source = await self.source(bulk(b"{not-json"))
        with self.assertRaisesRegex(SharedStateError, "invalid shared ban payload"):
            await source.fetch(time.time())

    async def test_oversized_response_is_rejected_before_reading_body(self) -> None:
        source = await self.source(b"$5000\r\n")
        with self.assertRaisesRegex(SharedStateError, "exceeds"):
            await source.fetch(time.time())

    async def test_read_timeout_is_bounded(self) -> None:
        source = await self.source(bulk(b"{}"), delay=5.0, connect_timeout=0.1, read_timeout=0.1)
        started = time.monotonic()
        with self.assertRaisesRegex(SharedStateError, "timed out"):
            await source.fetch(time.time())
        self.assertLess(time.monotonic() - started, 2.0)


class SyncLoopTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name)
        self.audit = AuditWriter(self.directory / "audit.jsonl")
        self.metrics = Metrics(True)
        self.bans = BanStore(self.directory / "offenders.json", max_entries=10, prefix_v4=32, prefix_v6=128)

    async def asyncTearDown(self) -> None:
        self.audit.close()
        self._temp.cleanup()

    async def stop_task(self, task: asyncio.Task[None]) -> None:
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1.0)

    async def test_source_failure_does_not_remove_local_ban_or_end_task(self) -> None:
        address = ipaddress.ip_address("203.0.113.70")
        self.bans.ban(address, "local", 60)

        class FailingSource:
            async def fetch(self, now: float) -> SharedFetchResult:
                raise OSError("redis down")

        task: asyncio.Task[None]
        with self.assertLogs("l4wall.shared", level="WARNING"):
            task = asyncio.create_task(
                run_shared_ban_sync(FailingSource(), self.bans, self.audit, self.metrics, interval=0.05)
            )
            await asyncio.sleep(0.15)
        self.assertFalse(task.done())
        self.assertIsNotNone(self.bans.check(address))
        self.assertGreaterEqual(self.metrics.get("l4wall_shared_sync_failures_total"), 1)
        self.assertIn("shared_sync_failed", (self.directory / "audit.jsonl").read_text(encoding="utf-8"))
        await self.stop_task(task)

    async def test_repeated_rejections_do_not_flood_audit(self) -> None:
        class RejectingSource:
            async def fetch(self, now: float) -> SharedFetchResult:
                return SharedFetchResult((), 1)

        task = asyncio.create_task(
            run_shared_ban_sync(RejectingSource(), self.bans, self.audit, self.metrics, interval=0.02)
        )
        await asyncio.sleep(0.2)
        await self.stop_task(task)
        text = (self.directory / "audit.jsonl").read_text(encoding="utf-8")
        self.assertEqual(text.count("shared_sync_rejected"), 1)

    async def test_empty_success_does_not_clear_local_bans(self) -> None:
        address = ipaddress.ip_address("203.0.113.71")
        self.bans.ban(address, "local", 60)

        class EmptySource:
            async def fetch(self, now: float) -> SharedFetchResult:
                return SharedFetchResult((), 0)

        task = asyncio.create_task(run_shared_ban_sync(EmptySource(), self.bans, self.audit, self.metrics, interval=0.05))
        await asyncio.sleep(0.12)
        self.assertIsNotNone(self.bans.check(address))
        self.assertEqual(self.metrics.get("l4wall_shared_connected"), 1)
        await self.stop_task(task)

    async def test_success_imports_and_persists_remote_ban(self) -> None:
        now = time.time()
        remote = BanEntry(
            network=ipaddress.ip_network("198.51.100.90/32"),
            reason="shared:agent",
            created=now,
            expires=now + 60,
            source="remote",
        )

        class GoodSource:
            async def fetch(self, current: float) -> SharedFetchResult:
                return SharedFetchResult((remote,), 0)

        task = asyncio.create_task(run_shared_ban_sync(GoodSource(), self.bans, self.audit, self.metrics, interval=0.05))
        await asyncio.sleep(0.12)
        self.assertIsNotNone(self.bans.check(ipaddress.ip_address("198.51.100.90")))
        reloaded = BanStore(self.bans.path, max_entries=10, prefix_v4=32, prefix_v6=128)
        self.assertIsNotNone(reloaded.check(ipaddress.ip_address("198.51.100.90")))
        await self.stop_task(task)


if __name__ == "__main__":
    unittest.main()
