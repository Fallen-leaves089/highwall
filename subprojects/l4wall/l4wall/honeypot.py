"""Bounded TCP decoy dialogue engine."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .config import HoneypotConfig
from .honeypot_templates import HoneypotRule


class HoneypotError(Exception):
    """A deterministic, audit-safe honeypot failure reason."""


@dataclass
class HoneypotResult:
    bytes_in: int = 0
    bytes_out: int = 0
    reason: str = "honeypot_closed"
    backend_connected: bool = False


def _match_rule(rules: tuple[HoneypotRule, ...], buffer: bytearray) -> tuple[HoneypotRule, int] | None:
    for rule in rules:
        if not rule.expect:
            return rule, 0
        index = buffer.find(rule.expect)
        if index >= 0:
            return rule, index + len(rule.expect)
    return None


async def _send(writer: asyncio.StreamWriter, data: bytes, result: HoneypotResult, limit: int) -> None:
    if not data:
        return
    if result.bytes_out + len(data) > limit:
        raise HoneypotError("byte_limit")
    writer.write(data)
    await writer.drain()
    result.bytes_out += len(data)


async def run_honeypot_session(
    config: HoneypotConfig,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    result: HoneypotResult | None = None,
) -> HoneypotResult:
    """Serve one bounded synthetic dialogue and return byte counters."""

    if result is None:
        result = HoneypotResult()
    await _send(writer, config.banner, result, config.max_bytes_out)
    if config.close_after_banner:
        result.reason = "banner_sent"
        return result
    if config.max_exchanges <= 0:
        result.reason = "banner_sent"
        return result

    buffer = bytearray()
    exchanges = 0
    first = True
    while exchanges < config.max_exchanges:
        if not buffer:
            timeout = config.first_byte_timeout if first else config.idle_timeout
            remaining = config.max_bytes_in - result.bytes_in
            if remaining <= 0:
                raise HoneypotError("byte_limit")
            try:
                data = await asyncio.wait_for(
                    reader.read(min(config.read_chunk_bytes, remaining)),
                    timeout=timeout,
                )
            except asyncio.TimeoutError as exc:
                raise HoneypotError("first_byte_timeout" if first else "idle_timeout") from exc
            if not data:
                result.reason = "client_closed"
                return result
            first = False
            result.bytes_in += len(data)
            if result.bytes_in > config.max_bytes_in:
                raise HoneypotError("byte_limit")
            buffer.extend(data)

        matched = _match_rule(config.rules, buffer)
        if matched is not None:
            rule, consumed = matched
            if consumed:
                del buffer[:consumed]
            await _send(writer, rule.reply, result, config.max_bytes_out)
            exchanges += 1
            if config.close_after_reply or exchanges >= config.max_exchanges:
                result.reason = "honeypot_reply"
                return result
            continue

        if config.default_reply:
            buffer.clear()
            await _send(writer, config.default_reply, result, config.max_bytes_out)
            exchanges += 1
            if config.close_after_reply or exchanges >= config.max_exchanges:
                result.reason = "honeypot_reply"
                return result
            continue

        if not config.rules:
            result.reason = "client_input"
            return result

    result.reason = "max_exchanges"
    return result
