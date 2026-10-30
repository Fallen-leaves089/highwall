"""Connection-behavior tracking and agent-like traffic scoring.

At L4 there is no User-Agent, cookie, or request path. The only durable
signals are connection timing, fan-out across protected listeners, rejected
attempts, and how little data a connection exchanged before closing. This
module scores those signals; it does not claim to identify an agent.
"""

from __future__ import annotations

import heapq
import ipaddress
import json
import math
import os
import tempfile
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .config import IPNetwork, ThreatConfig
from .policy import IPAddress


@dataclass(frozen=True)
class ConnectionRecord:
    ts: float
    listener: str
    accepted: bool
    reason: str
    bytes_in: int = 0
    bytes_out: int = 0
    duration: float = 0.0


@dataclass(frozen=True)
class Assessment:
    score: int
    signals: tuple[str, ...]
    agent_like: bool
    suspected: bool
    confirmed: bool
    action: str
    throttle_ms: int
    reason: str


@dataclass
class ClientState:
    events: deque[ConnectionRecord] = field(default_factory=deque)
    intervals: deque[float] = field(default_factory=deque)
    last_event_ts: float | None = None
    suspected_since: float | None = None
    confirmed_until: float = 0.0
    total_events: int = 0


@dataclass(frozen=True)
class BanEntry:
    network: IPNetwork
    reason: str
    created: float
    expires: float
    source: str = "local"


class BanStore:
    """Persistent, bounded source bans.

    The file is written atomically. A corrupt offender file is a startup error:
    silently discarding a deny list would fail open.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        max_entries: int = 10000,
        prefix_v4: int = 32,
        prefix_v6: int = 128,
        max_remote_ttl: float = 86400.0,
    ) -> None:
        self.path = Path(path) if str(path) else None
        self.max_entries = max_entries
        self.prefix_v4 = prefix_v4
        self.prefix_v6 = prefix_v6
        self.max_remote_ttl = max_remote_ttl
        self._entries: list[BanEntry] = []
        self.persist_errors = 0
        self.load()

    def load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"cannot read offender file {self.path}: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(raw.get("entries"), list):
            raise RuntimeError(f"offender file {self.path} has an unsupported format")
        entries: list[BanEntry] = []
        for item in raw["entries"]:
            if not isinstance(item, dict):
                continue
            try:
                network = ipaddress.ip_network(str(item["network"]), strict=False)
                reason = str(item["reason"])[:200]
                created = float(item["created"])
                expires = float(item["expires"])
                source = item.get("source", "local")
            except (KeyError, TypeError, ValueError):
                continue
            if not math.isfinite(created) or not math.isfinite(expires):
                continue
            if source not in {"local", "remote"}:
                source = "local"
            entries.append(
                BanEntry(network=network, reason=reason, created=created, expires=expires, source=source)
            )
        self._entries = entries
        self._prune(time.time())

    def _prune(self, now: float) -> None:
        self._entries = [entry for entry in self._entries if entry.expires > now]
        if len(self._entries) > self.max_entries:
            local = sorted((entry for entry in self._entries if entry.source == "local"), key=lambda entry: entry.created)
            remote = sorted((entry for entry in self._entries if entry.source != "local"), key=lambda entry: entry.created)
            if len(local) >= self.max_entries:
                self._entries = local[-self.max_entries :]
            else:
                self._entries = local + remote[-(self.max_entries - len(local)) :]

    def check(self, address: IPAddress, now: float | None = None) -> BanEntry | None:
        current = time.time() if now is None else now
        self._prune(current)
        for entry in self._entries:
            if address.version == entry.network.version and address in entry.network:
                return entry
        return None

    def ban(self, address: IPAddress, reason: str, seconds: float) -> bool:
        current = time.time()
        network = self._network_for(address)
        for index, entry in enumerate(self._entries):
            if entry.network == network:
                self._entries[index] = BanEntry(
                    network=network,
                    reason=reason,
                    created=entry.created,
                    expires=max(entry.expires, current + seconds),
                    source="local",
                )
                break
        else:
            self._entries.append(
                BanEntry(network=network, reason=reason, created=current, expires=current + seconds, source="local")
            )
        self._prune(current)
        return self.save()

    def merge_remote(self, entries: Sequence[BanEntry], now: float) -> int:
        """Add remote entries without weakening or replacing local decisions.

        Remote data is a secondary source of truth. A malformed prefix, expired
        item, or full store cannot remove a local ban. Successful imports are
        persisted so the last known shared deny list survives a restart during a
        Redis outage.
        """
        working = {entry.network: entry for entry in self._entries}
        remote_heap: list[tuple[float, IPNetwork]] = [
            (entry.created, entry.network) for entry in self._entries if entry.source != "local"
        ]
        heapq.heapify(remote_heap)
        changed = 0
        for incoming in entries:
            if incoming.expires <= now:
                continue
            required_prefix = self.prefix_v4 if incoming.network.version == 4 else self.prefix_v6
            if incoming.network.prefixlen < required_prefix:
                continue
            created = min(incoming.created, now)
            expires = min(incoming.expires, now + self.max_remote_ttl)
            if expires <= now:
                continue
            reason = _clean_reason(incoming.reason)
            current = working.get(incoming.network)
            if current is not None:
                merged_expires = max(current.expires, expires)
                if current.source == "local":
                    merged_reason = current.reason
                elif expires > current.expires:
                    merged_reason = reason
                else:
                    merged_reason = current.reason
                if merged_expires != current.expires or merged_reason != current.reason:
                    working[current.network] = BanEntry(
                        network=current.network,
                        reason=merged_reason,
                        created=current.created,
                        expires=merged_expires,
                        source=current.source,
                    )
                    changed += 1
                continue
            if len(working) >= self.max_entries:
                evicted = False
                while remote_heap:
                    created_at, network = heapq.heappop(remote_heap)
                    candidate = working.get(network)
                    if candidate is None or candidate.source == "local" or candidate.created != created_at:
                        continue
                    del working[network]
                    evicted = True
                    break
                if not evicted:
                    continue
            entry = BanEntry(network=incoming.network, reason=reason, created=created, expires=expires, source="remote")
            working[incoming.network] = entry
            heapq.heappush(remote_heap, (entry.created, entry.network))
            changed += 1
        self._entries = list(working.values())
        self._prune(now)
        if changed:
            self.save()
        return changed

    def _network_for(self, address: IPAddress) -> IPNetwork:
        prefix = self.prefix_v4 if address.version == 4 else self.prefix_v6
        return ipaddress.ip_network(f"{address}/{prefix}", strict=False)

    def save(self) -> bool:
        if self.path is None:
            return True
        payload = {
            "version": 1,
            "entries": [
                {
                    "network": str(entry.network),
                    "reason": entry.reason,
                    "created": entry.created,
                    "expires": entry.expires,
                    "source": entry.source,
                }
                for entry in self._entries
            ],
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                newline="\n",
                delete=False,
                dir=str(self.path.parent),
                prefix=f".{self.path.name}.",
                suffix=".tmp",
            )
            with handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, self.path)
            return True
        except OSError:
            self.persist_errors += 1
            return False

    def snapshot(self) -> list[dict[str, Any]]:
        self._prune(time.time())
        return [
            {
                "network": str(entry.network),
                "reason": entry.reason,
                "created": entry.created,
                "expires": entry.expires,
                "source": entry.source,
            }
            for entry in self._entries
        ]


def _clean_reason(reason: str) -> str:
    text = "".join(" " if ch < " " or ch == "\x7f" else ch for ch in reason)
    return " ".join(text.split())[:200]


class ThreatTracker:
    def __init__(self, config: ThreatConfig, bans: BanStore | None = None) -> None:
        self.config = config
        self.bans = bans or BanStore(
            config.offender_path,
            max_entries=config.max_ban_entries,
            prefix_v4=config.ban_prefix_v4,
            prefix_v6=config.ban_prefix_v6,
            max_remote_ttl=config.shared_bans.max_ttl_seconds,
        )
        self._states: OrderedDict[str, ClientState] = OrderedDict()

    def _state(self, key: str) -> ClientState:
        state = self._states.get(key)
        if state is None:
            state = ClientState()
            self._states[key] = state
            if len(self._states) > self.config.max_tracked_clients:
                self._states.popitem(last=False)
        else:
            self._states.move_to_end(key)
        return state

    def _max_events(self) -> int:
        return max(256, self.config.max_listeners_per_client * 8)

    def _purge(self, state: ClientState, now: float) -> list[ConnectionRecord]:
        cutoff = now - self.config.window_seconds
        while state.events and state.events[0].ts < cutoff:
            state.events.popleft()
        max_events = self._max_events()
        while len(state.events) > max_events:
            state.events.popleft()
        return list(state.events)

    def assess(self, address: IPAddress, now: float) -> Assessment:
        # An explicit deny list is authoritative even when heuristic scoring is
        # disabled. Turning off scoring must not silently release known offenders.
        if self.bans.check(address) is not None:
            return Assessment(100, ("banned",), True, True, True, "deny", 0, "banned")
        if not self.config.enabled:
            return _allow()
        state = self._state(str(address))
        return self._score(state, now)

    def _score(self, state: ClientState, now: float) -> Assessment:
        if state.confirmed_until > now:
            action = _action_for(self.config.mode)
            throttle = self.config.max_throttle_ms if action == "throttle" else 0
            return Assessment(100, ("confirmed_containment",), True, True, True, action, throttle, "agent_confirmed")
        events = self._purge(state, now)
        signals: list[str] = []
        score = 0
        if len(events) >= self.config.min_connections:
            signals.append("connection_burst")
            score += 15
        distinct = {event.listener for event in events}
        if len(distinct) >= self.config.min_distinct_listeners:
            signals.append("listener_fanout")
            score += 20
        short = sum(
            1
            for event in events
            if event.duration <= self.config.short_connection_seconds
            and event.bytes_in + event.bytes_out <= self.config.short_connection_bytes
        )
        if short >= self.config.min_short_connections:
            signals.append("short_connections")
            score += 20
        zero = sum(1 for event in events if event.accepted and event.bytes_in == 0 and event.bytes_out == 0)
        if zero >= self.config.min_zero_byte_connections:
            signals.append("zero_byte_probes")
            score += 15
        rejections = sum(1 for event in events if not event.accepted)
        if rejections >= self.config.min_rejections:
            signals.append("rejection_burst")
            score += 20
        if self._regular_timing(state):
            signals.append("regular_timing")
            score += 10
        score = min(100, score)
        agent_like = len(signals) >= self.config.agent_min_signals and score >= self.config.agent_score
        suspected = score >= self.config.score_threshold or agent_like
        confirmed = False
        if suspected:
            if state.suspected_since is None:
                state.suspected_since = now
            suspicious_for = now - state.suspected_since >= self.config.confirm_after_seconds
            confirmed = score >= self.config.confirm_score or suspicious_for
            if confirmed:
                state.confirmed_until = now + self.config.confirmed_containment_seconds
        else:
            state.suspected_since = None
        action = _action_for(self.config.mode, suspected=suspected)
        throttle = 0
        if action == "throttle":
            if confirmed:
                throttle = self.config.max_throttle_ms
            else:
                bump = max(0, score - self.config.score_threshold) * 20
                throttle = min(self.config.max_throttle_ms, self.config.throttle_ms + bump)
        reason = "agent_confirmed" if confirmed else ("agent_suspected" if suspected else "allowed")
        return Assessment(score, tuple(signals), agent_like, suspected, confirmed, action, throttle, reason)

    def _regular_timing(self, state: ClientState) -> bool:
        intervals = list(state.intervals)
        if len(intervals) < 5:
            return False
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            return False
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        coefficient = math.sqrt(variance) / mean
        return coefficient <= self.config.regular_timing_max_cv

    def pre_connection(self, address: IPAddress, now: float) -> Assessment:
        assessment = self.assess(address, now)
        if assessment.action == "deny" and assessment.reason == "agent_confirmed":
            self.bans.ban(address, assessment.reason, self.config.confirmed_containment_seconds)
        return assessment

    def record(self, address: IPAddress, record: ConnectionRecord, now: float) -> Assessment:
        if not self.config.enabled:
            return _allow()
        state = self._state(str(address))
        state.events.append(record)
        state.total_events += 1
        if state.last_event_ts is not None:
            delta = max(0.0, record.ts - state.last_event_ts)
            state.intervals.append(delta)
            while len(state.intervals) > 64:
                state.intervals.popleft()
        state.last_event_ts = record.ts
        assessment = self._score(state, now)
        if (
            assessment.confirmed
            and self.config.mode == "block"
            and self.bans.check(address) is None
        ):
            self.bans.ban(address, assessment.reason, min(self.config.confirmed_containment_seconds, self.config.mark_ttl_seconds))
        return assessment


def _allow() -> Assessment:
    return Assessment(0, (), False, False, False, "allow", 0, "allowed")


def _action_for(mode: str, *, suspected: bool = True) -> str:
    if not suspected:
        return "allow"
    if mode == "score":
        return "allow"
    if mode == "throttle":
        return "throttle"
    return "deny"

