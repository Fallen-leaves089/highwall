"""Small monotonic token bucket used for connection admission."""

from __future__ import annotations

import time


class TokenBucket:
    """A token bucket that allows at most ``burst`` immediate events."""

    __slots__ = ("rate", "burst", "tokens", "updated")

    def __init__(self, rate: float, burst: int, *, now: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        if burst < 1:
            raise ValueError("burst must be at least 1")
        self.rate = float(rate)
        self.burst = int(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic() if now is None else now

    def _refill(self, now: float) -> None:
        if now < self.updated:
            self.updated = now
        elapsed = max(0.0, now - self.updated)
        if elapsed:
            self.tokens = min(float(self.burst), self.tokens + elapsed * self.rate)
            self.updated = now

    def allow(self, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        self._refill(current)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def retry_after(self, now: float | None = None) -> float:
        current = time.monotonic() if now is None else now
        self._refill(current)
        if self.tokens >= 1.0:
            return 0.0
        return max(0.0, (1.0 - self.tokens) / self.rate)

