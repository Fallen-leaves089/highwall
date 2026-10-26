"""Small, thread-safe token-bucket limiter with bounded client state."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    retry_after: float = 0.0


@dataclass
class _Bucket:
    tokens: float
    last_refill: float
    last_seen: float


class TokenBucketLimiter:
    def __init__(
        self,
        rate: float,
        burst: int,
        *,
        max_entries: int = 10000,
        idle_ttl: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if burst < 1:
            raise ValueError("burst must be at least 1")
        self.rate = max(0.0, float(rate))
        self.burst = int(burst)
        self.max_entries = max(1, int(max_entries))
        self.idle_ttl = max(1.0, float(idle_ttl))
        self._clock = clock
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._lock = threading.Lock()
        self._operations = 0
        self.evictions = 0

    def _cleanup(self, now: float) -> None:
        while self._buckets:
            key, bucket = next(iter(self._buckets.items()))
            if now - bucket.last_seen <= self.idle_ttl:
                break
            del self._buckets[key]

    def consume(self, key: str, *, cost: float = 1.0) -> LimitDecision:
        if self.rate <= 0.0:
            return LimitDecision(True)
        if cost <= 0:
            return LimitDecision(True)
        now = self._clock()
        with self._lock:
            self._operations += 1
            if self._operations % 256 == 0 or len(self._buckets) >= self.max_entries:
                self._cleanup(now)
            bucket = self._buckets.get(key)
            if bucket is None:
                while len(self._buckets) >= self.max_entries:
                    self._buckets.popitem(last=False)
                    self.evictions += 1
                bucket = _Bucket(tokens=float(self.burst), last_refill=now, last_seen=now)
                self._buckets[key] = bucket
            else:
                self._buckets.move_to_end(key)

            elapsed = max(0.0, now - bucket.last_refill)
            bucket.tokens = min(float(self.burst), bucket.tokens + elapsed * self.rate)
            bucket.last_refill = now
            bucket.last_seen = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return LimitDecision(True)
            retry_after = max(0.001, (cost - bucket.tokens) / self.rate)
            return LimitDecision(False, retry_after)

    def size(self) -> int:
        with self._lock:
            return len(self._buckets)


def retry_after_seconds(value: float) -> int:
    return max(1, int(math.ceil(value)))


@dataclass
class _BanRecord:
    violations: deque[float]
    last_seen: float
    banned_until: float = 0.0


class AdaptiveBanner:
    """Temporarily block sources that repeatedly trigger gateway violations."""

    def __init__(
        self,
        threshold: int,
        window: float,
        ban_seconds: float,
        *,
        max_entries: int = 10000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        self.threshold = int(threshold)
        self.window = max(1.0, float(window))
        self.ban_seconds = max(1.0, float(ban_seconds))
        self.max_entries = max(1, int(max_entries))
        self.idle_ttl = max(self.window, self.ban_seconds) * 2.0
        self._clock = clock
        self._records: OrderedDict[str, _BanRecord] = OrderedDict()
        self._lock = threading.Lock()
        self.bans = 0
        self.evictions = 0

    def _prune_violations(self, record: _BanRecord, now: float) -> None:
        cutoff = now - self.window
        while record.violations and record.violations[0] < cutoff:
            record.violations.popleft()

    def _cleanup(self, now: float) -> None:
        while self._records:
            key, record = next(iter(self._records.items()))
            idle = now - record.last_seen
            if record.banned_until > now or idle <= self.idle_ttl:
                break
            del self._records[key]

    def check(self, key: str) -> LimitDecision:
        now = self._clock()
        with self._lock:
            self._cleanup(now)
            record = self._records.get(key)
            if record is None:
                return LimitDecision(True)
            record.last_seen = now
            self._records.move_to_end(key)
            if record.banned_until > now:
                return LimitDecision(False, record.banned_until - now)
            if record.banned_until:
                record.banned_until = 0.0
                record.violations.clear()
            self._prune_violations(record, now)
            if not record.violations:
                del self._records[key]
            return LimitDecision(True)

    def record_violation(self, key: str) -> LimitDecision:
        now = self._clock()
        with self._lock:
            self._cleanup(now)
            record = self._records.get(key)
            if record is None:
                while len(self._records) >= self.max_entries:
                    self._records.popitem(last=False)
                    self.evictions += 1
                record = _BanRecord(violations=deque(), last_seen=now)
                self._records[key] = record
            else:
                record.last_seen = now
                self._records.move_to_end(key)
            if record.banned_until > now:
                return LimitDecision(False, record.banned_until - now)
            if record.banned_until:
                record.banned_until = 0.0
                record.violations.clear()
            self._prune_violations(record, now)
            record.violations.append(now)
            if len(record.violations) >= self.threshold:
                record.violations.clear()
                record.banned_until = now + self.ban_seconds
                self.bans += 1
                return LimitDecision(False, self.ban_seconds)
            return LimitDecision(True)

    def force_ban(self, key: str, seconds: float | None = None) -> LimitDecision:
        """Immediately ban a key for the configured or supplied duration."""

        duration = self.ban_seconds if seconds is None else float(seconds)
        if duration <= 0:
            return LimitDecision(True)
        now = self._clock()
        with self._lock:
            self._cleanup(now)
            record = self._records.get(key)
            if record is None:
                while len(self._records) >= self.max_entries:
                    self._records.popitem(last=False)
                    self.evictions += 1
                record = _BanRecord(violations=deque(), last_seen=now)
                self._records[key] = record
            else:
                self._records.move_to_end(key)
            record.last_seen = now
            record.violations.clear()
            record.banned_until = max(record.banned_until, now + duration)
            self.bans += 1
            return LimitDecision(False, record.banned_until - now)

    def active_bans(self) -> int:
        now = self._clock()
        with self._lock:
            return sum(1 for record in self._records.values() if record.banned_until > now)

    def size(self) -> int:
        with self._lock:
            return len(self._records)
