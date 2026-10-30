from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import tempfile
import unittest
from pathlib import Path

from l4wall.admin import AdminServer
from l4wall.audit import AuditWriter
from l4wall.config import AdminConfig
from l4wall.metrics import Metrics


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class AdminTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name)
        self.token_env = "L4WALL_TEST_ADMIN_TOKEN"
        os.environ[self.token_env] = "test-secret"
        self.audit = AuditWriter(self.directory / "audit.jsonl")
        self.audit.write("connection_allowed", client_ip="127.0.0.1", listener="web")
        self.metrics = Metrics(True)
        self.metrics.inc("l4wall_connections_total")
        self.config = AdminConfig(
            enabled=True,
            listen_host="127.0.0.1",
            listen_port=free_port(),
            token_env=self.token_env,
            audit_tail_max_lines=10,
            request_timeout=2.0,
        )
        self.admin = AdminServer(self.config, audit=self.audit, metrics=self.metrics)
        await self.admin.start()

    async def asyncTearDown(self) -> None:
        await self.admin.stop()
        self.audit.close()
        os.environ.pop(self.token_env, None)
        self._temp.cleanup()

    async def request(self, path: str, token: str | None = None) -> tuple[int, str]:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.config.listen_port)
        headers = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
        if token is not None:
            headers += f"Authorization: Bearer {token}\r\n"
        headers += "\r\n"
        writer.write(headers.encode("ascii"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout=2.0)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        text = data.decode("utf-8", errors="replace")
        status = int(text.split(" ", 2)[1]) if text else 0
        return status, text

    async def test_missing_token_is_401(self) -> None:
        status, _ = await self.request("/healthz")
        self.assertEqual(status, 401)

    async def test_wrong_token_is_401(self) -> None:
        status, _ = await self.request("/healthz", "wrong")
        self.assertEqual(status, 401)

    async def test_healthz_and_metrics(self) -> None:
        status, body = await self.request("/healthz", "test-secret")
        self.assertEqual(status, 200)
        self.assertIn('"ok":true', body)
        status, body = await self.request("/metrics", "test-secret")
        self.assertEqual(status, 200)
        self.assertIn("l4wall_connections_total 1", body)

    async def test_audit_tail(self) -> None:
        status, body = await self.request("/audit/tail?lines=1", "test-secret")
        self.assertEqual(status, 200)
        self.assertIn("connection_allowed", body)

    async def test_post_is_405(self) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.config.listen_port)
        writer.write(b"POST /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout=2.0)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        self.assertIn(b" 405 ", data)


if __name__ == "__main__":
    unittest.main()

