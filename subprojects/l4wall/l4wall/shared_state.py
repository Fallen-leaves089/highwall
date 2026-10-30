"""Fail-isolated ingestion of shared bans.

The local BanStore remains authoritative. Redis is a secondary, read-only
source: a timeout, bad payload, missing key, or full store must never clear a
local ban or block the data plane.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import math
import os
import socket
import time
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol, Sequence

from .audit import AuditWriter
from .config import SharedBansConfig
from .metrics import Metrics
from .tracker import BanEntry, BanStore

LOGGER = logging.getLogger("l4wall.shared")
_MAX_REDIS_LINE = 4096
_FAILURE_AUDIT_INTERVAL = 60.0


class SharedStateError(RuntimeError):
    """A recoverable shared-state failure that must not stop the gateway."""


@dataclass(frozen=True)
class SharedFetchResult:
    entries: tuple[BanEntry, ...]
    rejected: int
    updated: float | None = None


class SharedBanSource(Protocol):
    async def fetch(self, now: float) -> SharedFetchResult:
        ...


def parse_shared_bans(
    payload: bytes,
    *,
    now: float,
    config: SharedBansConfig,
    prefix_v4: int,
    prefix_v6: int,
    max_entries: int,
) -> SharedFetchResult:
    """Parse a versioned shared-ban document with bounded, fail-closed rules."""
    if len(payload) > config.max_payload_bytes:
        raise SharedStateError("shared ban payload exceeds max_payload_bytes")
    try:
        text = payload.decode("utf-8")
        raw = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_strict_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SharedStateError(f"invalid shared ban payload: {_safe_error(exc)}") from exc
    if not isinstance(raw, dict):
        raise SharedStateError("shared ban payload root must be an object")
    unknown = set(raw) - {"version", "updated", "entries"}
    if unknown:
        raise SharedStateError("shared ban payload has unknown root fields")
    version = raw.get("version")
    if isinstance(version, bool) or version != 1:
        raise SharedStateError("unsupported shared ban payload version")
    entries_raw = raw.get("entries")
    if not isinstance(entries_raw, list):
        raise SharedStateError("shared ban entries must be an array")
    updated = _optional_finite_number(raw.get("updated"), "updated")
    rejected = max(0, len(entries_raw) - max_entries)
    entries: list[BanEntry] = []
    for item in entries_raw[:max_entries]:
        parsed = _parse_entry(item, now=now, config=config, prefix_v4=prefix_v4, prefix_v6=prefix_v6)
        if parsed is None:
            rejected += 1
        else:
            entries.append(parsed)
    return SharedFetchResult(entries=tuple(entries), rejected=rejected, updated=updated)


def _parse_entry(
    item: Any,
    *,
    now: float,
    config: SharedBansConfig,
    prefix_v4: int,
    prefix_v6: int,
) -> BanEntry | None:
    if not isinstance(item, dict) or set(item) != {"network", "reason", "created", "expires"}:
        return None
    network_raw = item.get("network")
    reason_raw = item.get("reason")
    if not isinstance(network_raw, str) or not isinstance(reason_raw, str):
        return None
    try:
        network = ipaddress.ip_network(network_raw.strip(), strict=False)
    except ValueError:
        return None
    required_prefix = prefix_v4 if network.version == 4 else prefix_v6
    if network.prefixlen < required_prefix:
        return None
    reason = _clean_reason(reason_raw)
    if not reason:
        return None
    try:
        created = _finite_number(item.get("created"), "created")
        expires = _finite_number(item.get("expires"), "expires")
    except ValueError:
        return None
    if expires <= now:
        return None
    expires = min(expires, now + config.max_ttl_seconds)
    created = min(created, now)
    return BanEntry(network=network, reason=f"shared:{reason}", created=created, expires=expires, source="remote")


class SharedRedisSource:
    """Minimal Redis GET client using RESP over asyncio streams."""

    def __init__(
        self,
        config: SharedBansConfig,
        *,
        prefix_v4: int = 32,
        prefix_v6: int = 128,
        max_entries: int = 10000,
    ) -> None:
        self.config = config
        self.prefix_v4 = prefix_v4
        self.prefix_v6 = prefix_v6
        self.max_entries = max_entries

    async def fetch(self, now: float) -> SharedFetchResult:
        # DNS, connect, response reads, and writer close each have their own
        # bounded timeout. Wrapping the whole coroutine in another wait_for can
        # leave an orphan _fetch task when the outer deadline wins the race,
        # which in turn produces "Task exception was never retrieved" warnings.
        try:
            return await self._fetch(now)
        except SharedStateError:
            raise
        except asyncio.TimeoutError as exc:
            raise SharedStateError("shared ban fetch timed out") from exc
        except (OSError, asyncio.IncompleteReadError, UnicodeError, ValueError) as exc:
            raise SharedStateError(f"shared ban fetch failed: {_safe_error(exc)}") from exc

    async def _fetch(self, now: float) -> SharedFetchResult:
        reader, writer = await self._connect()
        try:
            if self.config.password_env:
                password = os.environ.get(self.config.password_env)
                if not password:
                    raise SharedStateError(
                        f"shared ban password environment variable {self.config.password_env} is empty"
                    )
                await self._command(reader, writer, "AUTH", password)
            await self._command(reader, writer, "SELECT", str(self.config.db))
            response = await self._command(reader, writer, "GET", self.config.key)
            if response is None:
                raise SharedStateError("shared ban key is missing")
            if not isinstance(response, bytes):
                raise SharedStateError("shared ban GET returned an unexpected Redis type")
            return parse_shared_bans(
                response,
                now=now,
                config=self.config,
                prefix_v4=self.prefix_v4,
                prefix_v6=self.prefix_v6,
                max_entries=self.max_entries,
            )
        finally:
            await _close_writer(writer)

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(self.config.host, self.config.port, type=socket.SOCK_STREAM),
                timeout=self.config.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise SharedStateError(f"cannot resolve shared ban host: {_safe_error(exc)}") from exc
        safe: list[tuple[int, int, int, tuple[Any, ...]]] = []
        for family, _socktype, proto, _canonname, sockaddr in infos:
            raw_host = str(sockaddr[0]).split("%", 1)[0]
            try:
                address = ipaddress.ip_address(raw_host)
            except ValueError:
                continue
            if address.is_unspecified or address.is_multicast:
                continue
            if not (address.is_loopback or address.is_private or address.is_link_local):
                continue
            safe.append((family, _socktype, proto, sockaddr))
        if not safe:
            raise SharedStateError("shared ban host must resolve only to loopback or private addresses")
        last_error: Exception | None = None
        for safe_family, _safe_socktype, proto, sockaddr in safe:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(
                        str(sockaddr[0]),
                        int(sockaddr[1]),
                        family=safe_family,
                        proto=proto,
                        limit=65536,
                    ),
                    timeout=self.config.connect_timeout,
                )
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc
        raise SharedStateError(f"cannot connect to shared ban store: {_safe_error(last_error)}")

    async def _command(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *parts: str
    ) -> str | int | bytes | None:
        writer.write(_encode_command(parts))
        await writer.drain()
        return await asyncio.wait_for(
            _read_redis_response(reader, self.config.max_payload_bytes),
            timeout=self.config.read_timeout,
        )


async def run_shared_ban_sync(
    source: SharedBanSource,
    bans: BanStore,
    audit: AuditWriter,
    metrics: Metrics,
    *,
    interval: float,
) -> None:
    """Poll a shared source forever without propagating failures to the data plane."""
    healthy: bool | None = None
    last_failure_audit = 0.0
    last_rejected_audit = 0.0
    last_rejected_count = 0
    failure_count = 0
    while True:
        metrics.inc("l4wall_shared_sync_total")
        now = time.time()
        persist_errors_before = bans.persist_errors
        try:
            result = await source.fetch(now)
            imported = bans.merge_remote(result.entries, now)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failure_count += 1
            metrics.inc("l4wall_shared_sync_failures_total")
            metrics.set_gauge("l4wall_shared_connected", 0)
            metrics.set_gauge("l4wall_shared_last_failure_timestamp", now)
            if healthy is not False or now - last_failure_audit >= _FAILURE_AUDIT_INTERVAL:
                audit.write(
                    "shared_sync_failed",
                    backend="redis",
                    error=_safe_error(exc),
                    consecutive_failures=failure_count,
                )
                LOGGER.warning("shared ban sync failed: %s", _safe_error(exc))
                last_failure_audit = now
            healthy = False
        else:
            recovered = healthy is False
            healthy = True
            failure_count = 0
            metrics.set_gauge("l4wall_shared_connected", 1)
            metrics.set_gauge("l4wall_shared_last_success_timestamp", now)
            metrics.inc("l4wall_shared_entries_imported_total", imported)
            metrics.inc("l4wall_shared_rejected_entries_total", result.rejected)
            persist_failed = bans.persist_errors > persist_errors_before
            if persist_failed:
                metrics.inc("l4wall_shared_persist_errors_total")
            if recovered or imported or persist_failed:
                audit.write(
                    "shared_sync_ok",
                    backend="redis",
                    recovered=recovered,
                    imported=imported,
                    rejected=result.rejected,
                    persisted=not persist_failed,
                )
            if result.rejected and (
                result.rejected != last_rejected_count or now - last_rejected_audit >= _FAILURE_AUDIT_INTERVAL
            ):
                audit.write("shared_sync_rejected", count=result.rejected)
                last_rejected_audit = now
            last_rejected_count = result.rejected
            if persist_failed:
                audit.write("shared_persist_failed", error_count=bans.persist_errors)
            if recovered:
                LOGGER.info("shared ban sync recovered")
        await asyncio.sleep(interval)


def _encode_command(parts: Sequence[str]) -> bytes:
    encoded = [str(part).encode("utf-8") for part in parts]
    chunks = [f"*{len(encoded)}\r\n".encode("ascii")]
    for part in encoded:
        chunks.append(f"${len(part)}\r\n".encode("ascii"))
        chunks.append(part)
        chunks.append(b"\r\n")
    return b"".join(chunks)


async def _read_redis_response(reader: asyncio.StreamReader, max_payload: int) -> str | int | bytes | None:
    line = await reader.readline()
    if not line or len(line) > _MAX_REDIS_LINE or not line.endswith(b"\r\n"):
        raise SharedStateError("invalid or truncated Redis response")
    prefix = line[:1]
    body = line[1:-2]
    if prefix == b"+":
        return body.decode("utf-8", errors="replace")
    if prefix == b"-":
        raise SharedStateError(f"Redis error: {_clean_reason(body.decode('utf-8', errors='replace'))}")
    if prefix == b":":
        try:
            return int(body)
        except ValueError as exc:
            raise SharedStateError("invalid Redis integer response") from exc
    if prefix == b"$":
        try:
            length = int(body)
        except ValueError as exc:
            raise SharedStateError("invalid Redis bulk length") from exc
        if length < 0:
            return None
        if length > max_payload:
            raise SharedStateError("shared ban payload exceeds max_payload_bytes")
        payload = await reader.readexactly(length)
        trailer = await reader.readexactly(2)
        if trailer != b"\r\n":
            raise SharedStateError("invalid Redis bulk trailer")
        return payload
    raise SharedStateError("unsupported Redis response type")


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def _finite_number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{where} must be finite")
    return number


def _optional_finite_number(value: Any, where: str) -> float | None:
    if value is None:
        return None
    return _finite_number(value, where)


def _clean_reason(value: str) -> str:
    text = "".join(" " if ch < " " or ch == "\x7f" else ch for ch in value)
    return " ".join(text.split())[:180]


def _safe_error(exc: Exception | None) -> str:
    if exc is None:
        return "unknown error"
    text = _clean_reason(f"{type(exc).__name__}: {exc}")
    return text[:200] or type(exc).__name__
