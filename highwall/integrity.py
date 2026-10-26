"""Opt-in response integrity pinning for critical static responses."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .config import PolicyConfig


@dataclass(frozen=True)
class IntegrityHit:
    rule_id: str
    reason: str


def inspect_integrity(
    method: str,
    path: str,
    status: int,
    body: bytes,
    policy: PolicyConfig,
) -> IntegrityHit | None:
    if method != "GET" or policy.response_integrity_mode == "off":
        return None
    folded_path = path.casefold()
    pin = next(
        (candidate for candidate in policy.integrity_pins if candidate.path.casefold() == folded_path),
        None,
    )
    if pin is None:
        return None
    if status != pin.status:
        return IntegrityHit(rule_id="HW-INTEGRITY-1001", reason="status")
    actual = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(actual, pin.sha256):
        return IntegrityHit(rule_id="HW-INTEGRITY-1001", reason="digest")
    return None
