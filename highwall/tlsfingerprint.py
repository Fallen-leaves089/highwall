"""Bounded TLS ClientHello profiling without third-party dependencies.

The profile is a defensive fingerprint, not an identity guarantee.  It is a
stable hash of fields the client sends during the TLS handshake and may be
spoofed by a determined attacker.
"""

from __future__ import annotations

import hashlib
import socket
from dataclasses import dataclass

_MAX_CLIENT_HELLO_BYTES = 16384
_MAX_LIST_ITEMS = 512
_MAX_ALPN_BYTES = 255


@dataclass(frozen=True)
class TLSProfile:
    version: str
    ciphers: tuple[int, ...]
    extensions: tuple[int, ...]
    groups: tuple[int, ...]
    signature_algorithms: tuple[int, ...]
    alpn: str
    sni_present: bool
    digest: str

    def label(self) -> str:
        return f"{self.version}:{self.digest[:16]}"


def _u8(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset + 1 > len(data):
        return None
    return data[offset], offset + 1


def _u16(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 2], "big"), offset + 2


def _u24(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset + 3 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 3], "big"), offset + 3


def _version_name(value: int) -> str:
    return {
        0x0304: "TLS1.3",
        0x0303: "TLS1.2",
        0x0302: "TLS1.1",
        0x0301: "TLS1.0",
        0x0300: "SSL3",
    }.get(value, f"0x{value:04x}")


def _unique_limited(values: list[int]) -> tuple[int, ...]:
    result: list[int] = []
    seen: set[int] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
        if len(result) >= _MAX_LIST_ITEMS:
            break
    return tuple(result)


def _parse_extensions(data: bytes) -> dict[int, bytes]:
    extensions: dict[int, bytes] = {}
    offset = 0
    count = 0
    while offset < len(data) and count < _MAX_LIST_ITEMS:
        item = _u16(data, offset)
        if item is None:
            break
        extension_type, offset = item
        item = _u16(data, offset)
        if item is None:
            break
        length, offset = item
        end = offset + length
        if end > len(data):
            break
        extensions.setdefault(extension_type, data[offset:end])
        offset = end
        count += 1
    return extensions


def _parse_sni(data: bytes) -> bool:
    item = _u16(data, 0)
    if item is None:
        return False
    list_length, offset = item
    end = min(len(data), offset + list_length)
    while offset < end:
        item = _u8(data, offset)
        if item is None:
            return False
        name_type, offset = item
        item = _u16(data, offset)
        if item is None:
            return False
        name_length, offset = item
        name_end = offset + name_length
        if name_end > end:
            return False
        if name_type == 0 and name_length > 0:
            return True
        offset = name_end
    return False


def _parse_supported_versions(data: bytes) -> tuple[int, ...]:
    item = _u8(data, 0)
    if item is None:
        return ()
    length, offset = item
    end = min(len(data), offset + length)
    versions: list[int] = []
    while offset + 2 <= end:
        versions.append(int.from_bytes(data[offset : offset + 2], "big"))
        offset += 2
    return _unique_limited(versions)


def _parse_u16_list(data: bytes) -> tuple[int, ...]:
    item = _u16(data, 0)
    if item is None:
        return ()
    length, offset = item
    end = min(len(data), offset + length)
    values: list[int] = []
    while offset + 2 <= end:
        values.append(int.from_bytes(data[offset : offset + 2], "big"))
        offset += 2
    return _unique_limited(values)


def _parse_alpn(data: bytes) -> str:
    item = _u16(data, 0)
    if item is None:
        return ""
    length, offset = item
    end = min(len(data), offset + length)
    while offset < end:
        item = _u8(data, offset)
        if item is None:
            return ""
        item_length, offset = item
        protocol_end = offset + item_length
        if protocol_end > end or item_length > _MAX_ALPN_BYTES:
            return ""
        try:
            return data[offset:protocol_end].decode("ascii", errors="replace")[:64]
        except Exception:
            return ""
    return ""


def parse_client_hello(data: bytes) -> TLSProfile | None:
    """Parse the first TLS ClientHello record, returning None on ambiguity."""

    if len(data) < 5 or len(data) > _MAX_CLIENT_HELLO_BYTES:
        return None
    if data[0] != 22:
        return None
    record_length = int.from_bytes(data[3:5], "big")
    record_end = 5 + record_length
    if record_length <= 0 or record_end > len(data) or record_end > _MAX_CLIENT_HELLO_BYTES:
        return None
    handshake = data[5:record_end]
    if len(handshake) < 4 or handshake[0] != 1:
        return None
    handshake_length = int.from_bytes(handshake[1:4], "big")
    body_end = 4 + handshake_length
    if body_end > len(handshake):
        return None
    body = handshake[4:body_end]
    offset = 0
    version_item = _u16(body, offset)
    if version_item is None:
        return None
    legacy_version, offset = version_item
    if offset + 32 > len(body):
        return None
    offset += 32
    item = _u8(body, offset)
    if item is None:
        return None
    session_length, offset = item
    offset += session_length
    if offset > len(body):
        return None
    item = _u16(body, offset)
    if item is None:
        return None
    cipher_length, offset = item
    cipher_end = offset + cipher_length
    if cipher_end > len(body) or cipher_length % 2:
        return None
    ciphers: list[int] = []
    while offset < cipher_end and len(ciphers) < _MAX_LIST_ITEMS:
        ciphers.append(int.from_bytes(body[offset : offset + 2], "big"))
        offset += 2
    item = _u8(body, offset)
    if item is None:
        return None
    compression_length, offset = item
    offset += compression_length
    if offset > len(body):
        return None
    extension_data = b""
    if offset < len(body):
        item = _u16(body, offset)
        if item is None:
            return None
        extension_length, offset = item
        extension_end = offset + extension_length
        if extension_end > len(body):
            return None
        extension_data = body[offset:extension_end]
    extensions = _parse_extensions(extension_data)
    supported_versions = _parse_supported_versions(extensions.get(43, b""))
    version_value = max(supported_versions) if supported_versions else legacy_version
    groups = _parse_u16_list(extensions.get(10, b""))
    signature_algorithms = _parse_u16_list(extensions.get(13, b""))
    alpn = _parse_alpn(extensions.get(16, b""))
    sni_present = _parse_sni(extensions.get(0, b""))
    extension_ids = tuple(extensions.keys())
    material = "|".join(
        [
            "tls-profile-v1",
            f"{version_value:04x}",
            ",".join(f"{value:04x}" for value in _unique_limited(ciphers)),
            ",".join(f"{value:04x}" for value in extension_ids),
            ",".join(f"{value:04x}" for value in groups),
            ",".join(f"{value:04x}" for value in signature_algorithms),
            alpn,
            "1" if sni_present else "0",
        ]
    )
    digest = hashlib.sha256(material.encode("ascii", errors="replace")).hexdigest()
    return TLSProfile(
        version=_version_name(version_value),
        ciphers=_unique_limited(ciphers),
        extensions=extension_ids,
        groups=groups,
        signature_algorithms=signature_algorithms,
        alpn=alpn,
        sni_present=sni_present,
        digest=digest,
    )


def peek_tls_profile(sock: socket.socket, timeout: float) -> TLSProfile | None:
    """Peek at a ClientHello without consuming bytes from the socket."""

    previous = sock.gettimeout()
    try:
        sock.settimeout(max(0.05, min(0.75, float(timeout))))
        try:
            data = sock.recv(_MAX_CLIENT_HELLO_BYTES, socket.MSG_PEEK)
        except (OSError, TimeoutError, socket.timeout):
            return None
        return parse_client_hello(data)
    finally:
        try:
            sock.settimeout(previous)
        except OSError:
            pass