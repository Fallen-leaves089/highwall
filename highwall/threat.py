"""Per-actor attack detection, containment and aggregate DDoS signals."""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .config import DdosDetectionConfig, ThreatDetectionConfig
from .fingerprint import request_fingerprint, source_prefix
from .metrics import Metrics
from .offenders import OffenderMatch, OffenderRecord, OffenderRegistry
from .protocol import RequestHead
from .tlsfingerprint import TLSProfile

_EVENT_RULE_IDS = {
    "suspected": "HW-THREAT-1001",
    "confirmed": "HW-THREAT-1002",
}

_AGENT_MIN_REQUESTS = 6
_AUTOMATION_UA_RE = re.compile(
    r"(?:^|[\s/])(?:curl|wget|httpie|python-requests|python-urllib|httpx|aiohttp|requests|"
    r"go-http-client|okhttp|java|libwww-perl|node-fetch|axios|undici|postmanruntime|"
    r"insomnia|powershell|headlesschrome)(?:[/\s-]|$)",
    re.I,
)
_BROWSER_HEADERS = {
    "accept-language",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-ch-ua",
    "upgrade-insecure-requests",
}


def _utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class ThreatAssessment:
    fingerprint: str
    shape_fingerprint: str
    score: int
    confidence: str
    signals: tuple[str, ...]
    request_count: int
    distinct_paths: int
    violation_count: int
    action: str
    delay_ms: int
    hold_seconds: float
    retry_after: float
    ban_ip: bool = False
    ban_seconds: float = 0.0
    alert: dict[str, Any] | None = None
    offender: OffenderRecord | None = None


@dataclass
class _ActorState:
    requests: deque[float] = field(default_factory=deque)
    agent_events: deque[tuple[float, bool, bool, bool, str]] = field(default_factory=deque)
    paths: OrderedDict[str, float] = field(default_factory=OrderedDict)
    query_variants: OrderedDict[str, set[str]] = field(default_factory=OrderedDict)
    violations: deque[tuple[float, str]] = field(default_factory=deque)
    last_seen: float = 0.0
    first_trigger: float = 0.0
    containment_until: float = 0.0
    confirmed_at: float = 0.0
    confidence: str = "none"
    last_alert_at: float = 0.0
    last_alert_event: str = ""
    marked_at: float = 0.0
    marked_confidence: str = ""


class ThreatDetector:
    """Bounded sliding-window detector with two-stage confirmation."""

    def __init__(
        self,
        config: ThreatDetectionConfig,
        metrics: Metrics,
        offenders: OffenderRegistry,
        *,
        include_client_ip: bool = False,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.metrics = metrics
        self.offenders = offenders
        self.include_client_ip = include_client_ip
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.Lock()
        self._states: OrderedDict[str, _ActorState] = OrderedDict()
        self._tarpit_counts: dict[str, int] = {}
        self._tarpit_global = 0
        self._delay_global = 0

    def _path_key(self, target: str) -> str:
        path = target.split("?", 1)[0]
        return hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _prune_actor(self, state: _ActorState, now: float) -> None:
        cutoff = now - self.config.window_seconds
        while state.requests and state.requests[0] < cutoff:
            state.requests.popleft()
        while state.agent_events and state.agent_events[0][0] < cutoff:
            state.agent_events.popleft()
        while state.paths:
            _, seen = next(iter(state.paths.items()))
            if seen >= cutoff:
                break
            state.paths.popitem(last=False)
        while state.query_variants:
            key, _ = next(iter(state.query_variants.items()))
            if state.paths.get(key, 0) >= cutoff:
                break
            state.query_variants.popitem(last=False)
        while state.violations and state.violations[0][0] < cutoff:
            state.violations.popleft()
        while len(state.paths) > self.config.max_paths_per_actor:
            state.paths.popitem(last=False)
        while len(state.query_variants) > self.config.max_paths_per_actor:
            state.query_variants.popitem(last=False)

    def _state_for(self, fingerprint: str, now: float) -> _ActorState:
        state = self._states.get(fingerprint)
        if state is None:
            while len(self._states) >= self.config.max_tracked_actors:
                self._states.popitem(last=False)
            state = _ActorState()
            self._states[fingerprint] = state
        else:
            self._states.move_to_end(fingerprint)
        state.last_seen = now
        return state

    def _score(self, state: _ActorState) -> tuple[int, tuple[str, ...], int, int, int]:
        request_count = len(state.requests)
        distinct_paths = len(state.paths)
        violation_count = len(state.violations)
        rate_ratio = min(1.0, request_count / max(1, self.config.min_requests))
        breadth_ratio = min(1.0, distinct_paths / max(1, self.config.min_distinct_paths))
        violation_ratio = min(1.0, violation_count / max(1, self.config.min_violations))
        score = int(round(100.0 * (0.35 * rate_ratio + 0.35 * breadth_ratio + 0.30 * violation_ratio)))
        signals: list[str] = []
        if rate_ratio >= 1.0:
            signals.append("request_rate")
        if breadth_ratio >= 1.0:
            signals.append("path_breadth")
        if violation_ratio >= 1.0:
            signals.append("policy_violations")
        return score, tuple(signals), request_count, distinct_paths, violation_count

    def _agent_signals(self, state: _ActorState) -> tuple[int, tuple[str, ...]]:
        events = list(state.agent_events)
        count = len(events)
        if count < _AGENT_MIN_REQUESTS:
            return 0, ()
        automation = sum(1 for event in events if event[1])
        browser = sum(1 for event in events if event[2])
        cookies = sum(1 for event in events if event[3])
        signals: list[str] = []
        if automation >= max(3, count // 2):
            signals.append("agent_user_agent")
        if browser == 0:
            signals.append("agent_no_browser_headers")
        if cookies == 0:
            signals.append("agent_no_cookies")
        intervals = [later[0] - earlier[0] for earlier, later in zip(events, events[1:])]
        if len(intervals) >= 5:
            mean = sum(intervals) / len(intervals)
            if mean > 0:
                deviation = (sum((value - mean) ** 2 for value in intervals) / len(intervals)) ** 0.5
                if deviation / mean <= 0.25:
                    signals.append("agent_regular_timing")
        path_counts: dict[str, int] = {}
        for event in events:
            path_counts[event[4]] = path_counts.get(event[4], 0) + 1
        if max(path_counts.values(), default=0) / count >= 0.6:
            signals.append("agent_path_focus")
        if max((len(values) for values in state.query_variants.values()), default=0) >= 6:
            signals.append("agent_query_fuzzing")
        return len(signals), tuple(signals)

    def _alert_due(self, state: _ActorState, now: float, event: str) -> bool:
        if state.last_alert_event != event:
            return True
        return now - state.last_alert_at >= self.config.alert_cooldown_seconds

    def _payload(
        self,
        *,
        fingerprint: str,
        shape: str,
        score: int,
        confidence: str,
        signals: tuple[str, ...],
        request_count: int,
        distinct_paths: int,
        violation_count: int,
        action: str,
        delay_ms: int,
        hold_seconds: float,
        containment_until: float,
        client_ip: str,
        request_id: str,
    ) -> dict[str, Any]:
        event = "threat_confirmed" if confidence == "confirmed" else "threat_suspected"
        now_wall = self._wall_clock()
        remaining = max(0.0, containment_until - self._clock())
        payload: dict[str, Any] = {
            "schema": "highwall.alert.v1",
            "event": event,
            "severity": "high" if confidence == "confirmed" else "medium",
            "detected_at": _utc_iso(now_wall),
            "fingerprint": fingerprint,
            "shape_fingerprint": shape,
            "score": score,
            "confidence": confidence,
            "signals": list(signals),
            "request_count": request_count,
            "distinct_paths": distinct_paths,
            "violation_count": violation_count,
            "action": action,
            "delay_ms": delay_ms,
            "hold_seconds": hold_seconds,
            "containment_until": _utc_iso(now_wall + remaining),
            "rule_id": _EVENT_RULE_IDS[confidence],
            "request_id": request_id,
            "recommended_actions": [
                "notify_security_operations",
                "review_upstream_and_edge_logs",
                "preserve_audit_evidence",
            ],
        }
        if self.include_client_ip:
            payload["client_ip"] = client_ip
        return payload

    def _action_for(self, confidence: str, score: int) -> tuple[str, int, float]:
        if not self.config.enabled or confidence == "none":
            return "none", 0, 0.0
        if confidence == "confirmed":
            if self.config.mode == "tarpit":
                hold = min(
                    self.config.max_tarpit_hold_seconds,
                    self.config.tarpit_hold_seconds * max(1.0, score / max(1, self.config.confirm_score)),
                )
                return "tarpit", 0, hold
            if self.config.mode == "block":
                return "block", 0, 0.0
            if self.config.mode == "throttle":
                return "throttle", self.config.max_throttle_ms, 0.0
            return "monitor", 0, 0.0
        if self.config.mode in {"throttle", "tarpit"}:
            delay = int(round(self.config.throttle_ms * max(0.5, min(1.0, score / max(1, self.config.score_threshold)))))
            return "throttle", min(self.config.max_throttle_ms, max(0, delay)), 0.0
        return "monitor", 0, 0.0

    def _evaluate(
        self,
        state: _ActorState,
        *,
        fingerprint: str,
        shape: str,
        client_ip: str,
        request_id: str,
        now: float,
        allow_confirm: bool = True,
    ) -> ThreatAssessment:
        self._prune_actor(state, now)
        score, signals, request_count, distinct_paths, violation_count = self._score(state)
        agent_count, agent_signals = self._agent_signals(state)
        agent_like = agent_count >= self.config.agent_min_signals
        if agent_like:
            score = min(100, score + self.config.agent_score)
            signals = signals + ("agent_like",) + agent_signals
        match: OffenderMatch | None = self.offenders.get(fingerprint, shape)
        exact_match = match if match is not None and match.exact else None
        if exact_match is not None:
            score = max(
                score,
                exact_match.record.score if exact_match.record.confidence == "confirmed" else 75,
            )
            if "persisted_mark" not in signals:
                signals = signals + ("persisted_mark",)
        elif match is not None:
            if "shape_match" not in signals:
                signals = signals + ("shape_match",)
        exact_confirmed = (
            exact_match is not None and exact_match.record.confidence == "confirmed"
        )
        agent_contain = agent_like and self.config.agent_mode in {"block", "throttle"}
        triggered = score >= self.config.score_threshold or exact_confirmed or agent_contain
        if triggered:
            if state.first_trigger <= 0:
                state.first_trigger = now
            state.containment_until = max(
                state.containment_until,
                now + self.config.containment_seconds,
            )
            confirm = agent_contain or (
                allow_confirm
                and (
                    score >= self.config.confirm_score
                    or exact_confirmed
                    or (state.first_trigger > 0 and now - state.first_trigger >= self.config.confirm_after_seconds)
                )
            )
            if confirm:
                state.confidence = "confirmed"
                if state.confirmed_at <= 0:
                    state.confirmed_at = now
                state.containment_until = max(
                    state.containment_until,
                    now + self.config.confirmed_containment_seconds,
                )
            elif state.confidence != "confirmed":
                state.confidence = "suspected"
        elif state.containment_until <= now:
            state.confidence = "none"
            state.first_trigger = 0.0
            state.confirmed_at = 0.0

        confidence = state.confidence
        action, delay_ms, hold_seconds = self._action_for(confidence, score)
        if agent_contain and confidence == "confirmed":
            action = self.config.agent_mode
            delay_ms = self.config.max_throttle_ms if action == "throttle" else 0
            hold_seconds = 0.0
        alert: dict[str, Any] | None = None
        if confidence in {"suspected", "confirmed"}:
            event = "threat_confirmed" if confidence == "confirmed" else "threat_suspected"
            if self._alert_due(state, now, event):
                alert = self._payload(
                    fingerprint=fingerprint,
                    shape=shape,
                    score=score,
                    confidence=confidence,
                    signals=signals,
                    request_count=request_count,
                    distinct_paths=distinct_paths,
                    violation_count=violation_count,
                    action=action,
                    delay_ms=delay_ms,
                    hold_seconds=hold_seconds,
                    containment_until=state.containment_until,
                    client_ip=client_ip,
                    request_id=request_id,
                )
                state.last_alert_at = now
                state.last_alert_event = event

        should_mark = confidence == "confirmed" and (
            state.marked_at <= 0
            or state.marked_confidence != "confirmed"
            or now - state.marked_at >= 60.0
        )
        if should_mark:
            state.marked_at = now
            state.marked_confidence = "confirmed"
            self.offenders.mark(
                fingerprint=fingerprint,
                shape_fingerprint_value=shape,
                tag="confirmed_fast_attack",
                confidence="confirmed",
                score=score,
                signals=signals,
                action=action,
                source_prefix_value=source_prefix(client_ip),
                client_ip=client_ip,
            )
            self.metrics.set("offender_marks", float(self.offenders.size()))

        retry_after = max(0.0, state.containment_until - now) if action == "block" else 0.0
        ban_ip = agent_contain and self.config.agent_mode == "block"
        return ThreatAssessment(
            fingerprint=fingerprint,
            shape_fingerprint=shape,
            score=score,
            confidence=confidence,
            signals=signals,
            request_count=request_count,
            distinct_paths=distinct_paths,
            violation_count=violation_count,
            action=action,
            delay_ms=delay_ms,
            hold_seconds=hold_seconds,
            retry_after=retry_after,
            ban_ip=ban_ip,
            ban_seconds=max(1.0, retry_after) if ban_ip else 0.0,
            alert=alert,
            offender=exact_match.record if exact_match is not None else None,
        )

    def assess(
        self,
        head: RequestHead,
        client_ip: str,
        tls_profile: TLSProfile | None = None,
        *,
        request_id: str = "",
    ) -> ThreatAssessment:
        fingerprint, shape = request_fingerprint(head, client_ip, tls_profile)
        if not self.config.enabled:
            return ThreatAssessment(
                fingerprint=fingerprint,
                shape_fingerprint=shape,
                score=0,
                confidence="none",
                signals=(),
                request_count=0,
                distinct_paths=0,
                violation_count=0,
                action="none",
                delay_ms=0,
                hold_seconds=0.0,
                retry_after=0.0,
            )
        now = self._clock()
        with self._lock:
            state = self._state_for(fingerprint, now)
            path_key = self._path_key(head.target)
            user_agent = next(
                (value for name, value in head.headers if name.lower() == "user-agent"),
                "",
            )
            state.requests.append(now)
            state.agent_events.append(
                (
                    now,
                    _AUTOMATION_UA_RE.search(user_agent) is not None,
                    any(name.lower() in _BROWSER_HEADERS for name, _ in head.headers),
                    any(name.lower() == "cookie" for name, _ in head.headers),
                    path_key,
                )
            )
            state.paths[path_key] = now
            state.paths.move_to_end(path_key)
            query = head.target.partition("?")[2]
            variants = state.query_variants.setdefault(path_key, set())
            if len(variants) < 32:
                variants.add(query)
            state.query_variants.move_to_end(path_key)
            return self._evaluate(
                state,
                fingerprint=fingerprint,
                shape=shape,
                client_ip=client_ip,
                request_id=request_id,
                now=now,
            )

    def record_violation(
        self,
        fingerprint: str,
        shape: str,
        rule_id: str,
        status: int,
        *,
        client_ip: str = "",
        request_id: str = "",
    ) -> ThreatAssessment | None:
        if not self.config.enabled:
            return None
        if not (rule_id.startswith("HW-WAF-") or status in {400, 403, 405, 413, 414, 415, 417, 431}):
            return None
        now = self._clock()
        with self._lock:
            state = self._states.get(fingerprint)
            if state is None:
                state = self._state_for(fingerprint, now)
            state.violations.append((now, rule_id))
            return self._evaluate(
                state,
                fingerprint=fingerprint,
                shape=shape,
                client_ip=client_ip,
                request_id=request_id,
                now=now,
            )

    def acquire_tarpit(self, fingerprint: str) -> bool:
        with self._lock:
            if self._tarpit_global >= self.config.global_tarpit_slots:
                return False
            current = self._tarpit_counts.get(fingerprint, 0)
            if current >= self.config.per_actor_tarpit_slots:
                return False
            self._tarpit_counts[fingerprint] = current + 1
            self._tarpit_global += 1
            self.metrics.set("tarpit_active", float(self._tarpit_global))
            return True

    def release_tarpit(self, fingerprint: str) -> None:
        with self._lock:
            current = self._tarpit_counts.get(fingerprint, 0)
            if current <= 1:
                self._tarpit_counts.pop(fingerprint, None)
            else:
                self._tarpit_counts[fingerprint] = current - 1
            if self._tarpit_global > 0:
                self._tarpit_global -= 1
            self.metrics.set("tarpit_active", float(self._tarpit_global))

    def acquire_delay(self) -> bool:
        with self._lock:
            if self._delay_global >= self.config.global_tarpit_slots:
                return False
            self._delay_global += 1
            return True

    def release_delay(self) -> None:
        with self._lock:
            if self._delay_global > 0:
                self._delay_global -= 1

    def active_marks(self) -> list[OffenderRecord]:
        return self.offenders.active()


@dataclass
class _DdosBucket:
    requests: float = 0.0
    global_rejections: float = 0.0
    connection_rejections: float = 0.0
    tls_failures: float = 0.0
    upstream_errors: float = 0.0
    max_connection_load: float = 0.0


@dataclass(frozen=True)
class DdosAssessment:
    triggered: bool
    signals: dict[str, float]
    alerts: tuple[dict[str, Any], ...]
    severity: str


class DdosDetector:
    """Aggregate L7 saturation signals.

    This is an alerting heuristic only.  It cannot detect or mitigate bandwidth
    exhaustion before packets reach HighWall, and it is not a DDoS scrubber.
    """

    def __init__(
        self,
        config: DdosDetectionConfig,
        metrics: Metrics,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.metrics = metrics
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.Lock()
        self._buckets: dict[int, _DdosBucket] = {}
        self._triggered_at = 0.0
        self._last_trigger_at = 0.0
        self._escalated = False
        self._last_alert = 0.0

    def _bucket(self, now: float) -> _DdosBucket:
        key = int(now)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _DdosBucket()
            self._buckets[key] = bucket
        return bucket

    def _prune(self, now: float) -> None:
        cutoff = int(now - max(self.config.window_seconds, self.config.cooldown_seconds) - 2)
        for key in [key for key in self._buckets if key < cutoff]:
            self._buckets.pop(key, None)

    def record_request(self, *, connection_load: float = 0.0) -> None:
        if not self.config.enabled:
            return
        with self._lock:
            now = self._clock()
            self._prune(now)
            bucket = self._bucket(now)
            bucket.requests += 1.0
            bucket.max_connection_load = max(bucket.max_connection_load, max(0.0, min(1.0, connection_load)))

    def record_global_rejection(self) -> None:
        if not self.config.enabled:
            return
        with self._lock:
            now = self._clock()
            self._bucket(now).global_rejections += 1.0

    def record_connection_rejection(self) -> None:
        if not self.config.enabled:
            return
        with self._lock:
            now = self._clock()
            self._bucket(now).connection_rejections += 1.0

    def record_tls_failure(self) -> None:
        if not self.config.enabled:
            return
        with self._lock:
            now = self._clock()
            self._bucket(now).tls_failures += 1.0

    def record_upstream_error(self) -> None:
        if not self.config.enabled:
            return
        with self._lock:
            now = self._clock()
            self._bucket(now).upstream_errors += 1.0

    def _signals(self, now: float) -> tuple[dict[str, float], int]:
        self._prune(now)
        start = int(now - self.config.window_seconds)
        requests = 0.0
        global_rejections = 0.0
        connection_rejections = 0.0
        tls_failures = 0.0
        upstream_errors = 0.0
        max_load = 0.0
        for key, bucket in self._buckets.items():
            if key < start:
                continue
            requests += bucket.requests
            global_rejections += bucket.global_rejections
            connection_rejections += bucket.connection_rejections
            tls_failures += bucket.tls_failures
            upstream_errors += bucket.upstream_errors
            max_load = max(max_load, bucket.max_connection_load)
        denominator = max(1.0, requests + global_rejections + connection_rejections)
        signals: dict[str, float] = {}
        if requests / max(1.0, self.config.window_seconds) >= self.config.request_rate_threshold:
            signals["request_rate"] = requests / max(1.0, self.config.window_seconds)
        rejection_ratio = (global_rejections + connection_rejections) / denominator
        if rejection_ratio >= self.config.global_rejection_ratio:
            signals["rejection_ratio"] = rejection_ratio
        if max_load >= self.config.connection_saturation:
            signals["connection_saturation"] = max_load
        if tls_failures >= self.config.tls_failure_threshold:
            signals["tls_failure_count"] = tls_failures
        upstream_ratio = upstream_errors / max(1.0, requests)
        if upstream_ratio >= self.config.upstream_error_ratio:
            signals["upstream_error_ratio"] = upstream_ratio
        return signals, len(signals)

    def evaluate(self) -> DdosAssessment:
        if not self.config.enabled:
            return DdosAssessment(False, {}, (), "info")
        now = self._clock()
        with self._lock:
            signals, count = self._signals(now)
            triggered = count >= self.config.min_signals
            alerts: list[dict[str, Any]] = []
            severity = "info"
            if triggered:
                self._last_trigger_at = now
                severity = "high"
                if self._triggered_at <= 0:
                    self._triggered_at = now
                    alerts.append(self._payload("ddos_suspected", "high", signals))
                    self.metrics.inc("ddos_detected_total")
                elif not self._escalated and now - self._triggered_at >= self.config.escalation_seconds:
                    self._escalated = True
                    severity = "critical"
                    alerts.append(self._payload("ddos_escalated", "critical", signals))
                    self.metrics.inc("ddos_escalated_total")
            elif self._triggered_at > 0 and now - self._last_trigger_at >= self.config.recovery_seconds:
                self._triggered_at = 0.0
                self._escalated = False
                alerts.append(self._payload("ddos_recovered", "info", signals))
                self.metrics.inc("ddos_recovered_total")
            return DdosAssessment(triggered, signals, tuple(alerts), severity)

    def _payload(self, event: str, severity: str, signals: dict[str, float]) -> dict[str, Any]:
        action = {
            "ddos_suspected": "alert_and_check_l7_capacity",
            "ddos_escalated": "escalate_to_noc_and_check_edge_scrubbing",
            "ddos_recovered": "monitor_and_preserve_evidence",
        }[event]
        return {
            "schema": "highwall.alert.v1",
            "event": event,
            "severity": severity,
            "detected_at": _utc_iso(self._wall_clock()),
            "layer": "L7",
            "signals": {name: round(value, 3) for name, value in signals.items()},
            "action": action,
            "containment_window_seconds": 300,
            "recommended_actions": [
                "notify_noc",
                "check_edge_scrubbing",
                "verify_upstream_capacity",
                "preserve_audit_logs",
            ],
        }
