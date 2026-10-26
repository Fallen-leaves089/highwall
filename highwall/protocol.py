"""Strict HTTP/1.x request parsing.

Only origin-form requests with an explicit Content-Length are accepted. All
Transfer-Encoding forms are rejected, which removes the classic CL.TE/TE.CL
smuggling ambiguity instead of trying to repair it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import BinaryIO

from .config import PolicyConfig
from .errors import (
    BadRequest,
    ExpectationFailed,
    PayloadTooLarge,
    RequestHeaderFieldsTooLarge,
    URITooLong,
)

_METHOD_RE = re.compile(r"^[A-Z]{1,16}$")
_ALLOWED_VERSIONS = {b"HTTP/1.0", b"HTTP/1.1"}


@dataclass(frozen=True)
class RequestHead:
    method: str
    target: str
    version: str
    headers: tuple[tuple[str, str], ...]
    content_length: int
    client_ip: str


def _read_crlf_line(reader: BinaryIO, limit: int, too_long_error: type[Exception]) -> bytes | None:
    line = reader.readline(limit + 1)
    if not line:
        return None
    if len(line) > limit:
        raise too_long_error("line exceeds configured limit", rule_id="HW-PROTO-1001")
    if not line.endswith(b"\r\n"):
        raise BadRequest("request lines must end with CRLF", rule_id="HW-PROTO-1002")
    return line[:-2]


def _validate_header_value(name: str, value: str) -> None:
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F or ord(ch) > 0x7E for ch in value):
        raise BadRequest(f"invalid value in header {name}", rule_id="HW-PROTO-1003")


def _parse_content_length(values: list[str]) -> int:
    if not values:
        return 0
    if len(values) != 1:
        raise BadRequest("multiple Content-Length headers are not allowed", rule_id="HW-SMUGGLE-1001")
    value = values[0]
    if not value or len(value) > 20 or not value.isascii() or not value.isdigit():
        raise BadRequest("invalid Content-Length", rule_id="HW-SMUGGLE-1002")
    length = int(value, 10)
    if length < 0:
        raise BadRequest("invalid Content-Length", rule_id="HW-SMUGGLE-1002")
    return length


def read_request_head(reader: BinaryIO, client_ip: str, policy: PolicyConfig) -> RequestHead | None:
    """Read and validate a request head without reading the body."""

    raw_line = _read_crlf_line(reader, policy.max_request_line, URITooLong)
    if raw_line is None:
        return None
    if any(byte < 0x20 or byte > 0x7E for byte in raw_line):
        raise BadRequest("request line must be visible ASCII", rule_id="HW-PROTO-1004")
    parts = raw_line.split(b" ")
    if len(parts) != 3 or not all(parts):
        raise BadRequest("malformed request line", rule_id="HW-PROTO-1005")
    method_raw, target_raw, version_raw = parts
    if not _METHOD_RE.fullmatch(method_raw.decode("ascii")):
        raise BadRequest("unsupported method token", rule_id="HW-PROTO-1006")
    if version_raw not in _ALLOWED_VERSIONS:
        raise BadRequest("unsupported HTTP version", rule_id="HW-PROTO-1007")
    target = target_raw.decode("ascii")
    if not target.startswith("/"):
        raise BadRequest("only origin-form request targets are accepted", rule_id="HW-PROTO-1008")
    if "#" in target:
        raise BadRequest("fragments are not allowed in request targets", rule_id="HW-PROTO-1009")

    headers: list[tuple[str, str]] = []
    seen_names: set[str] = set()
    header_bytes = 0
    while True:
        remaining = policy.max_header_bytes - header_bytes
        if remaining <= 0:
            raise RequestHeaderFieldsTooLarge("header block exceeds configured limit", rule_id="HW-PROTO-1101")
        line = _read_crlf_line(reader, min(remaining, 65537), RequestHeaderFieldsTooLarge)
        if line is None:
            raise BadRequest("unexpected end of headers", rule_id="HW-PROTO-1010")
        header_bytes += len(line) + 2
        if not line:
            break
        if line[:1] in (b" ", b"\t"):
            raise BadRequest("obsolete header folding is not allowed", rule_id="HW-PROTO-1011")
        if b":" not in line:
            raise BadRequest("malformed header line", rule_id="HW-PROTO-1012")
        name_raw, value_raw = line.split(b":", 1)
        if not name_raw or any(byte < 0x21 or byte > 0x7E for byte in name_raw):
            raise BadRequest("invalid header name", rule_id="HW-PROTO-1013")
        name = name_raw.decode("ascii")
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name):
            raise BadRequest("invalid header name", rule_id="HW-PROTO-1013")
        value_bytes = value_raw.strip(b" \t")
        if any(byte < 0x20 or byte > 0x7E for byte in value_bytes):
            raise BadRequest("invalid header value", rule_id="HW-PROTO-1015")
        value = value_bytes.decode("ascii")
        _validate_header_value(name, value)
        lower_name = name.lower()
        if policy.reject_duplicate_headers and lower_name in seen_names:
            raise BadRequest(f"duplicate header {name} is not allowed", rule_id="HW-PROTO-1014")
        seen_names.add(lower_name)
        if len(headers) >= policy.max_header_count:
            raise RequestHeaderFieldsTooLarge("too many header fields", rule_id="HW-PROTO-1102")
        headers.append((name, value))

    lowered = [(name.lower(), value) for name, value in headers]
    names = [name for name, _ in lowered]
    if "transfer-encoding" in names or "te" in names:
        raise BadRequest("Transfer-Encoding and TE are not accepted", rule_id="HW-SMUGGLE-1003")
    if "trailer" in names:
        raise BadRequest("Trailer is not accepted", rule_id="HW-SMUGGLE-1004")
    if "expect" in names:
        raise ExpectationFailed("Expect is not accepted", rule_id="HW-PROTO-1103")
    if "upgrade" in names:
        raise BadRequest("protocol upgrades are not accepted", rule_id="HW-PROTO-1104")
    if "content-encoding" in names:
        raise BadRequest("encoded request bodies are not accepted", rule_id="HW-PROTO-1105")

    content_length = _parse_content_length([value for name, value in lowered if name == "content-length"])
    if content_length > policy.max_body_bytes:
        raise PayloadTooLarge("request body exceeds configured limit", rule_id="HW-PROTO-1106")
    return RequestHead(
        method=method_raw.decode("ascii"),
        target=target,
        version=version_raw.decode("ascii"),
        headers=tuple(headers),
        content_length=content_length,
        client_ip=client_ip,
    )


def read_request_body(reader: BinaryIO, head: RequestHead) -> bytes:
    if head.content_length == 0:
        return b""
    body = reader.read(head.content_length)
    if body is None or len(body) != head.content_length:
        raise BadRequest("request body ended before Content-Length", rule_id="HW-PROTO-1107")
    return body


def discard_request_body(reader: BinaryIO, head: RequestHead, chunk_size: int = 65536) -> int:
    """Drain a declared body without retaining it, returning the byte count."""

    remaining = head.content_length
    total = 0
    size = max(1, min(int(chunk_size), 65536))
    while remaining > 0:
        chunk = reader.read(min(size, remaining))
        if not chunk:
            raise BadRequest("request body ended before Content-Length", rule_id="HW-PROTO-1107")
        remaining -= len(chunk)
        total += len(chunk)
    return total


def header_values(headers: tuple[tuple[str, str], ...], name: str) -> list[str]:
    lowered = name.lower()
    return [value for header_name, value in headers if header_name.lower() == lowered]


def single_header(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    values = header_values(headers, name)
    if len(values) > 1:
        raise BadRequest(f"multiple {name} headers are not allowed", rule_id="HW-PROTO-1201")
    return values[0] if values else None
