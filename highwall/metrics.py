"""Minimal thread-safe counters for the loopback management endpoint."""

from __future__ import annotations

import threading
from typing import Mapping


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, float] = {
            "requests_total": 0,
            "allowed_total": 0,
            "blocked_total": 0,
            "parse_errors_total": 0,
            "waf_blocked_total": 0,
            "rate_limited_total": 0,
            "upstream_errors_total": 0,
            "admin_requests_total": 0,
            "audit_write_failures_total": 0,
            "ip_connection_rejections_total": 0,
            "inflight_rejections_total": 0,
            "route_rate_limit_rejections_total": 0,
            "route_concurrency_rejections_total": 0,
            "tls_handshake_failures_total": 0,
            "auto_bans_total": 0,
            "auto_ban_rejections_total": 0,
            "auto_ban_entries": 0,
            "dlp_detected_total": 0,
            "dlp_blocked_total": 0,
            "integrity_detected_total": 0,
            "integrity_blocked_total": 0,
            "circuit_state": 0,
            "circuit_open_total": 0,
            "circuit_recovered_total": 0,
            "circuit_rejections_total": 0,
            "honeypot_hits_total": 0,
            "honeypot_bans_total": 0,
            "honeypot_ban_rejections_total": 0,
            "honeypot_ban_entries": 0,
            "response_bytes_total": 0,
            "request_bytes_total": 0,
            "active_requests": 0,
            "active_connections": 0,
            "threat_detected_total": 0,
            "threat_tarpitted_total": 0,
            "threat_blocked_total": 0,
            "threat_throttled_total": 0,
            "threat_tarpit_shed_total": 0,
            "threat_delay_shed_total": 0,
            "offender_marks": 0,
            "tarpit_active": 0,
            "ddos_detected_total": 0,
            "ddos_escalated_total": 0,
            "ddos_recovered_total": 0,
            "alert_sent_total": 0,
            "alert_failed_total": 0,
            "alert_dropped_total": 0,
            "alert_queue_depth": 0,
            "config_reloads_total": 0,
            "config_reload_failures_total": 0,
            "drain_rejections_total": 0,
            "config_generation": 0,
        }

    def inc(self, name: str, amount: float = 1.0) -> None:
        with self._lock:
            self._values[name] = self._values.get(name, 0.0) + amount

    def set(self, name: str, value: float) -> None:
        with self._lock:
            self._values[name] = value

    def add(self, name: str, amount: float) -> None:
        self.inc(name, amount)

    def snapshot(self) -> Mapping[str, float]:
        with self._lock:
            return dict(self._values)

    def prometheus(self, extra: Mapping[str, float] | None = None) -> str:
        values = dict(self.snapshot())
        if extra:
            values.update(extra)
        lines: list[str] = []
        descriptions = {
            "requests_total": "Parsed requests received.",
            "allowed_total": "Requests forwarded upstream.",
            "blocked_total": "Requests rejected by policy or parsing.",
            "parse_errors_total": "Malformed requests rejected during parsing.",
            "waf_blocked_total": "Requests blocked by WAF rules.",
            "rate_limited_total": "Requests rejected by rate limits.",
            "upstream_errors_total": "Upstream connection or response failures.",
            "admin_requests_total": "Management endpoint requests.",
            "audit_write_failures_total": "Failed audit writes.",
            "ip_connection_rejections_total": "Connections rejected by the per-client connection limit.",
            "inflight_rejections_total": "Requests rejected by the global in-flight request limit.",
            "route_rate_limit_rejections_total": "Requests rejected by a route rate limit.",
            "route_concurrency_rejections_total": "Requests rejected by a route concurrency limit.",
            "tls_handshake_failures_total": "TLS handshakes that failed or timed out.",
            "auto_bans_total": "Clients temporarily banned after repeated violations.",
            "auto_ban_rejections_total": "Requests rejected because the client is temporarily banned.",
            "auto_ban_entries": "Current adaptive-ban state entries.",
            "dlp_detected_total": "Responses with sensitive-data or debug leakage detected.",
            "dlp_blocked_total": "Responses blocked by sensitive-data or debug leakage policy.",
            "integrity_detected_total": "Responses that failed configured integrity pins.",
            "integrity_blocked_total": "Responses blocked by configured integrity pins.",
            "circuit_state": "Upstream circuit state: 0 closed, 1 half-open, 2 open.",
            "circuit_open_total": "Times the upstream circuit opened.",
            "circuit_recovered_total": "Times the upstream circuit recovered from half-open.",
            "circuit_rejections_total": "Requests rejected while the upstream circuit was open.",
            "honeypot_hits_total": "Requests served by a configured honeypot route.",
            "honeypot_bans_total": "Clients immediately banned after a honeypot hit.",
            "honeypot_ban_rejections_total": "Requests rejected by a honeypot ban.",
            "honeypot_ban_entries": "Current active honeypot bans.",
            "active_requests": "Requests currently being handled.",
            "request_bytes_total": "Request bodies accepted in bytes.",
            "response_bytes_total": "Response bodies sent in bytes.",
            "active_connections": "Connections currently admitted by the gateway.",
            "threat_detected_total": "Suspected or confirmed attacker events.",
            "threat_tarpitted_total": "Requests held in the bounded slow-response lane.",
            "threat_blocked_total": "Requests rejected by attacker containment mode.",
            "threat_throttled_total": "Requests delayed by attacker containment.",
            "threat_tarpit_shed_total": "Requests rejected because slow-lane capacity was full.",
            "threat_delay_shed_total": "Requests that skipped delay because delay capacity was full.",
            "offender_marks": "Current persisted confirmed attacker marks.",
            "tarpit_active": "Requests currently held in slow-response lanes.",
            "ddos_detected_total": "Aggregate L7 DDoS suspicion events.",
            "ddos_escalated_total": "DDoS events escalated after the containment window.",
            "ddos_recovered_total": "DDoS events that returned below threshold.",
            "alert_sent_total": "Alerts delivered to the configured webhook.",
            "alert_failed_total": "Alerts that could not be delivered.",
            "alert_dropped_total": "Alerts dropped because the queue was full.",
            "alert_queue_depth": "Alerts waiting for delivery.",
            "config_reloads_total": "Configuration reloads applied successfully.",
            "config_reload_failures_total": "Configuration reload attempts rejected.",
            "drain_rejections_total": "Connections rejected while the gateway was draining.",
            "config_generation": "Monotonic configuration generation applied to the listener.",
        }
        for name in sorted(values):
            metric = f"highwall_{name}"
            description = descriptions.get(name, name.replace("_", " "))
            lines.extend(
                [
                    f"# HELP {metric} {description}",
                    f"# TYPE {metric} gauge",
                    f"{metric} {float(values[name]):.0f}",
                ]
            )
        return "\n".join(lines) + "\n"
