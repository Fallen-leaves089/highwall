"""Minimal loopback-only admin plane."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
from urllib.parse import parse_qs, urlsplit

from .audit import AuditWriter
from .config import AdminConfig
from .metrics import Metrics

_MAX_REQUEST_BYTES = 8192


class AdminServer:
    def __init__(self, config: AdminConfig, *, audit: AuditWriter, metrics: Metrics) -> None:
        self.config = config
        self.audit = audit
        self.metrics = metrics
        self._token = ""
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        token = os.environ.get(self.config.token_env, "")
        if not token:
            raise RuntimeError(f"admin token environment variable {self.config.token_env} is empty")
        self._token = token
        self._server = await asyncio.start_server(
            self._spawn,
            host=self.config.listen_host,
            port=self.config.listen_port,
            backlog=16,
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _spawn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                method, target, headers = await asyncio.wait_for(
                    _read_request(reader), timeout=self.config.request_timeout
                )
            except asyncio.TimeoutError:
                await _respond(writer, 408, "Request Timeout", b"timeout\n")
                return
            except (ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError):
                await _respond(writer, 400, "Bad Request", b"bad request\n")
                return
            if method != "GET":
                await _respond(writer, 405, "Method Not Allowed", b"method not allowed\n")
                return
            provided = headers.get("authorization", "")
            expected = f"Bearer {self._token}"
            if not hmac.compare_digest(provided, expected):
                await _respond(writer, 401, "Unauthorized", b"unauthorized\n")
                return
            split = urlsplit(target)
            if split.path == "/healthz":
                body = json.dumps(
                    {
                        "ok": self.audit.healthy,
                        "audit_errors": self.audit.error_count,
                        "metrics": self.metrics.snapshot(),
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                await _respond(writer, 200 if self.audit.healthy else 503, "OK", body, "application/json")
                return
            if split.path == "/metrics":
                body = self.metrics.to_prometheus().encode("utf-8")
                await _respond(writer, 200, "OK", body, "text/plain; version=0.0.4")
                return
            if split.path == "/audit/tail":
                query = parse_qs(split.query)
                try:
                    lines = int(query.get("lines", ["50"])[0])
                except ValueError:
                    lines = 50
                lines = max(1, min(lines, self.config.audit_tail_max_lines))
                body = ("\n".join(self.audit.tail(lines)) + "\n").encode("utf-8")
                await _respond(writer, 200, "OK", body, "text/plain; charset=utf-8")
                return
            await _respond(writer, 404, "Not Found", b"not found\n")
        except Exception:
            with contextlib.suppress(Exception):
                await _respond(writer, 500, "Internal Server Error", b"internal error\n")
        finally:
            await _close_writer(writer)


async def _read_request(reader: asyncio.StreamReader) -> tuple[str, str, dict[str, str]]:
    data = await reader.readuntil(b"\r\n\r\n")
    if len(data) > _MAX_REQUEST_BYTES:
        raise ValueError("request headers too large")
    text = data.decode("latin-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ValueError("missing request line")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ValueError("malformed request line")
    method, target, version = parts
    if not version.startswith("HTTP/1."):
        raise ValueError("unsupported HTTP version")
    headers: dict[str, str] = {}
    seen: set[str] = set()
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ValueError("malformed header")
        name, value = line.split(":", 1)
        key = name.strip().casefold()
        if not key or key in seen:
            raise ValueError("duplicate header")
        seen.add(key)
        headers[key] = value.strip()
    return method, target, headers


async def _respond(
    writer: asyncio.StreamWriter, status: int, reason: str, body: bytes, content_type: str = "text/plain; charset=utf-8"
) -> None:
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    writer.write(head + body)
    await writer.drain()


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()

