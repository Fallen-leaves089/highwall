"""Machine-readable protocol coverage declarations.

The manifest exists to prevent documentation, marketing text and runtime
behavior from drifting apart.  A surface is marked complete only when its
declared C-level includes parsing, policy, resource bounds, audit and tests.
"""

from __future__ import annotations

from typing import Any

CAPABILITY_LEVELS = ("C0", "C1", "C2", "C3", "C4")
_SURFACES: tuple[dict[str, Any], ...] = (
    {
        "name": "http1",
        "layer": "L7",
        "level": "C3",
        "complete": True,
        "declared": "Strict HTTP/1.0 and HTTP/1.1 parsing, routing, WAF/DLP, bounded bodies, audit.",
        "limitations": "Buffered response bodies; no HTTP/1.1 upgrade, WebSocket, h2c or streaming proxy.",
    },
    {
        "name": "tls",
        "layer": "L5",
        "level": "C1",
        "complete": False,
        "declared": "TLS 1.2/1.3 termination, certificate loading and bounded ClientHello profiling.",
        "limitations": "No SNI policy, ALPN policy, mTLS, revocation, 0-RTT policy or standardized JA3/JA4.",
    },
    {
        "name": "http2",
        "layer": "L7",
        "level": "C0",
        "complete": False,
        "declared": "Not terminated or inspected by the native HighWall data plane.",
        "limitations": "An edge proxy may pass normalized HTTP/1.1, but that is not H2 coverage.",
    },
    {
        "name": "http3",
        "layer": "L7",
        "level": "C0",
        "complete": False,
        "declared": "Not terminated or inspected by HighWall.",
        "limitations": "No QUIC, QPACK, 0-RTT, connection migration or UDP resource policy.",
    },
    {
        "name": "websocket",
        "layer": "L7",
        "level": "C0",
        "complete": False,
        "declared": "Upgrade is rejected by the HTTP/1.1 data plane.",
        "limitations": "No explicit route, Origin policy, frame limits or message inspection.",
    },
    {
        "name": "grpc",
        "layer": "L7",
        "level": "C0",
        "complete": False,
        "declared": "No native gRPC handling.",
        "limitations": "HTTP/2 transport, trailers, compression, deadline and binary payload policy are absent.",
    },
)


def capability_manifest() -> dict[str, Any]:
    """Return an immutable-by-convention copy of the current coverage claims."""

    return {
        "schema": "highwall.capabilities.v1",
        "levels": {
            "C0": "Encrypted or opaque transport; no semantic policy.",
            "C1": "Termination and basic metadata only.",
            "C2": "Strict parsing, state validation, resource bounds and routing.",
            "C3": "C2 plus header/body policy, WAF/DLP and audit for declared routes.",
            "C4": "C3 plus streaming, trailers, WebSocket/gRPC and long-lived connection policy.",
        },
        "surfaces": [dict(surface) for surface in _SURFACES],
        "not_a_certification": True,
        "undocumented_capability_is_unsupported": True,
    }
