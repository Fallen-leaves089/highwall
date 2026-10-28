"""Thread-safe circuit breaker for repeated upstream failures."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class CircuitDecision:
    allowed: bool
    state: str
    token: int = 0
    retry_after: float = 0.0

    @property
    def state_code(self) -> int:
        return {"closed": 0, "half_open": 1, "open": 2}[self.state]


class CircuitBreaker:
    """Open after repeated failures, then admit bounded half-open probes."""

    def __init__(
        self,
        failure_threshold: int,
        window: float,
        open_seconds: float,
        *,
        half_open_max_requests: int = 1,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if half_open_max_requests < 1:
            raise ValueError("half_open_max_requests must be at least 1")
        self.failure_threshold = int(failure_threshold)
        self.window = max(1.0, float(window))
        self.open_seconds = max(1.0, float(open_seconds))
        self.half_open_max_requests = int(half_open_max_requests)
        self._clock = clock
        self._lock = threading.Lock()
        self._state = "closed"
        self._generation = 0
        self._opened_at = 0.0
        self._half_open_inflight = 0
        self._failures: deque[float] = deque()
        self.open_events = 0
        self.half_open_events = 0

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()

    def _open(self, now: float) -> None:
        self._state = "open"
        self._opened_at = now
        self._half_open_inflight = 0
        self._failures.clear()
        self._generation += 1
        self.open_events += 1

    def allow(self) -> CircuitDecision:
        now = self._clock()
        with self._lock:
            if self._state == "closed":
                return CircuitDecision(True, "closed", self._generation)
            if self._state == "open":
                remaining = self._opened_at + self.open_seconds - now
                if remaining > 0:
                    return CircuitDecision(False, "open", self._generation, remaining)
                self._state = "half_open"
                self._half_open_inflight = 0
                self._generation += 1
                self.half_open_events += 1
            if self._half_open_inflight >= self.half_open_max_requests:
                return CircuitDecision(False, "half_open", self._generation, 1.0)
            self._half_open_inflight += 1
            return CircuitDecision(True, "half_open", self._generation)

    def record_success(self, token: int) -> bool:
        with self._lock:
            if token != self._generation:
                return False
            if self._state == "half_open":
                self._state = "closed"
                self._generation += 1
                self._half_open_inflight = 0
                self._failures.clear()
                return True
            if self._state == "closed":
                self._failures.clear()
            return False

    def record_failure(self, token: int) -> bool:
        now = self._clock()
        with self._lock:
            if token != self._generation:
                return False
            if self._state == "half_open":
                self._open(now)
                return True
            if self._state != "closed":
                return False
            self._prune(now)
            self._failures.append(now)
            if len(self._failures) >= self.failure_threshold:
                self._open(now)
                return True
            return False

    def current_state(self) -> str:
        with self._lock:
            return self._state
