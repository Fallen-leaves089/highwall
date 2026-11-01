"""Encoding helpers for the optional PROXY protocol v2 upstream header."""

from __future__ import annotations

import ipaddress
import struct

from .policy import IPAddress, normalize_ip

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
PROXY_COMMAND_VERSION = 0x21
TCP_OVER_IPV4 = 0x11
TCP_OVER_IPV6 = 0x21


def _source_address(value: str | IPAddress) -> IPAddress:
    address = normalize_ip(str(value))
    if address is None:
        raise ValueError("source address is invalid")
    if address.is_unspecified or address.is_multicast:
        raise ValueError("source address must be a concrete unicast address")
    if isinstance(address, ipaddress.IPv4Address) and address == ipaddress.IPv4Address("255.255.255.255"):
        raise ValueError("source address must not be limited broadcast")
    return address


def _destination_address(value: object, source_version: int) -> tuple[IPAddress, int]:
    if not isinstance(value, tuple) or len(value) < 2:
        return (_unspecified(source_version), 0)
    destination = normalize_ip(str(value[0]))
    if destination is None or destination.version != source_version:
        return (_unspecified(source_version), 0)
    try:
        port = int(value[1])
    except (TypeError, ValueError):
        return (_unspecified(source_version), 0)
    if not 0 <= port <= 65535:
        return (_unspecified(source_version), 0)
    return (destination, port)


def _unspecified(version: int) -> IPAddress:
    if version == 4:
        return ipaddress.IPv4Address("0.0.0.0")
    return ipaddress.IPv6Address("::")


def encode_proxy_v2(
    source: str | IPAddress,
    source_port: int,
    destination: object = None,
) -> bytes:
    """Build a PROXY v2 TCP header without optional TLVs."""
    address = _source_address(source)
    try:
        port = int(source_port)
    except (TypeError, ValueError) as exc:
        raise ValueError("source port is invalid") from exc
    if not 1 <= port <= 65535:
        raise ValueError("source port must be between 1 and 65535")

    destination_address, destination_port = _destination_address(destination, address.version)
    payload = (
        address.packed
        + destination_address.packed
        + struct.pack("!HH", port, destination_port)
    )
    family = TCP_OVER_IPV4 if address.version == 4 else TCP_OVER_IPV6
    return (
        SIGNATURE
        + bytes((PROXY_COMMAND_VERSION, family))
        + struct.pack("!H", len(payload))
        + payload
    )
