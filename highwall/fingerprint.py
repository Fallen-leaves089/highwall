"""Stable, privacy-minimized request fingerprints.

Fingerprints are hashes of protocol shape and selected non-secret headers.  They
are useful for correlating repeated automation, but cannot prove who a client
is and must not be treated as authentication.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

from .protocol import RequestHead
from .tlsfingerprint import TLSProfile

_SECRET_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}
_STABLE_VALUE_HEADERS = {
    "accept",
    "accept-language",
    "accept-encoding",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "upgrade-insecure-requests",
    "user-agent",
}
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_value(value: str) -> str:
    return _WHITESPACE_RE.sub(" ", value.strip())[:256]


def source_prefix(client_ip: str) -> str:
    """Return a coarse source prefix without retaining the full address."""

    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return "unknown"
    if isinstance(address, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{address}/24", strict=False))
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(ipaddress.ip_network(f"{address.ipv4_mapped}/24", strict=False))
    return str(ipaddress.ip_network(f"{address}/64", strict=False))


def header_shape(head: RequestHead) -> str:
    tokens: list[str] = []
    for name, value in head.headers:
        lower = name.lower()
        if lower in _SECRET_HEADERS:
            tokens.append(f"{lower}=<redacted>")
        elif lower in _STABLE_VALUE_HEADERS:
            tokens.append(f"{lower}={_normalize_value(value)}")
        else:
            tokens.append(lower)
    return "\n".join(tokens)


def _digest(material: str) -> str:
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def shape_fingerprint(head: RequestHead, tls_profile: TLSProfile | None = None) -> str:
    tls = tls_profile.digest if tls_profile is not None else ""
    return _digest("highwall-shape-v1\n" + header_shape(head) + "\n" + tls)[:32]


def request_fingerprint(
    head: RequestHead,
    client_ip: str,
    tls_profile: TLSProfile | None = None,
) -> tuple[str, str]:
    """Return (actor fingerprint, shape fingerprint)."""

    shape = shape_fingerprint(head, tls_profile)
    actor = _digest(
        "highwall-actor-v1\n"
        + source_prefix(client_ip)
        + "\n"
        + shape
    )[:32]
    return actor, shape