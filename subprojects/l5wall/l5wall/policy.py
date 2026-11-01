"""Pure TLS session policy for L5Wall."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .config import L5Config

_TLS_RANK = {"TLS1.0": 0, "TLS1.1": 1, "TLS1.2": 2, "TLS1.3": 3}


@dataclass(frozen=True)
class ClientMetadata:
    tls_version: str
    cipher: str
    alpn: str
    sni: str
    peer_cert_sha256: str = ""
    handshake_ms: int = 0

    def as_public(self) -> dict[str, Any]:
        return {
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "alpn": self.alpn,
            "sni": self.sni,
            "peer_cert_sha256": self.peer_cert_sha256,
            "handshake_ms": self.handshake_ms,
        }


@dataclass(frozen=True)
class L5Decision:
    allowed: bool
    metadata: ClientMetadata
    reasons: tuple[str, ...]

    def as_public(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "metadata": self.metadata.as_public(),
            "reasons": list(self.reasons),
        }


class L5Policy:
    """Deny-by-default policy over the TLS session metadata available to Python."""

    def __init__(self, config: L5Config) -> None:
        self.config = config

    def evaluate(self, metadata: ClientMetadata) -> L5Decision:
        reasons: list[str] = []
        min_rank = _TLS_RANK.get(_normalize_tls_version(self.config.min_version), -1)
        version_rank = _TLS_RANK.get(metadata.tls_version, -1)
        if version_rank < 0:
            reasons.append("unknown TLS version")
        elif version_rank < min_rank:
            reasons.append("TLS version is below the configured minimum")

        if metadata.alpn not in self.config.allowed_alpn:
            reasons.append("ALPN is not explicitly allowed")

        sni = metadata.sni.strip().rstrip(".").lower()
        if not sni:
            if not self.config.allow_missing_sni:
                reasons.append("SNI is required")
        elif not any(_sni_matches(pattern, sni) for pattern in self.config.allowed_sni):
            reasons.append("SNI is not explicitly allowed")

        if metadata.peer_cert_sha256 and not _is_sha256(metadata.peer_cert_sha256):
            reasons.append("client certificate fingerprint is malformed")
        if self.config.mtls_mode == "required" and not metadata.peer_cert_sha256:
            reasons.append("mTLS client certificate is required")

        return L5Decision(
            allowed=not reasons,
            metadata=metadata,
            reasons=tuple(dict.fromkeys(reasons)),
        )


def certificate_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _sni_matches(pattern: str, hostname: str) -> bool:
    if pattern == hostname:
        return True
    if not pattern.startswith("*."):
        return False
    suffix = pattern[1:]
    return hostname.endswith(suffix) and hostname.count(".") >= pattern.count(".")


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _normalize_tls_version(value: str) -> str:
    return value.replace("TLSv", "TLS").replace("_", ".")
