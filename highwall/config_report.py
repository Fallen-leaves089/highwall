"""Describe the effective HighWall configuration without exposing secrets."""

from __future__ import annotations

from typing import Any

from .config import Config


def _networks(values: tuple[Any, ...]) -> list[str]:
    return [str(value) for value in values]


def build_config_report(config: Config) -> dict[str, Any]:
    """Return an audit-friendly view of the values HighWall will actually use."""

    routes: list[dict[str, Any]] = []
    for route in config.policy.routes:
        routes.append(
            {
                "path_prefix": route.path_prefix,
                "methods": list(route.methods) if route.methods is not None else None,
                "read_only": route.read_only,
                "max_body_bytes": route.max_body_bytes,
                "max_concurrent": route.max_concurrent,
                "rate": route.rate,
                "rate_burst": route.rate_burst,
                "allowed_client_networks": (
                    _networks(route.allowed_client_networks)
                    if route.allowed_client_networks is not None
                    else None
                ),
            }
        )

    honeypot_routes = [
        {
            "id": route.id,
            "path": route.path,
            "status": route.status,
            "content_type": route.content_type,
            "body_bytes": len(route.body),
            "headers": [{"name": name, "value": value} for name, value in route.headers],
            "server_header": route.server_header,
            "delay_ms": route.delay_ms,
        }
        for route in config.policy.honeypot.routes
    ]
    integrity_pins = [
        {"path": pin.path, "status": pin.status, "sha256": pin.sha256}
        for pin in config.policy.integrity_pins
    ]
    configured_headers = dict(config.policy.security_headers)
    effective_hsts = next(
        (value for name, value in configured_headers.items() if name.casefold() == "strict-transport-security"),
        None,
    )
    if effective_hsts is None and config.server.tls.enabled:
        effective_hsts = "max-age=31536000"

    return {
        "source": str(config.source) if config.source is not None else None,
        "version": config.version,
        "server": {
            "listen_host": config.server.listen_host,
            "listen_port": config.server.listen_port,
            "max_connections": config.server.max_connections,
            "max_connections_per_ip": config.server.max_connections_per_ip,
            "max_inflight_requests": config.server.max_inflight_requests,
            "header_timeout": config.server.header_timeout,
            "body_timeout": config.server.body_timeout,
            "shutdown_timeout": config.server.shutdown_timeout,
            "tls_enabled": config.server.tls.enabled,
            "tls": {
                "enabled": config.server.tls.enabled,
                "min_version": config.server.tls.min_version,
                "handshake_timeout": config.server.tls.handshake_timeout,
                "cert_file": (
                    str(config.server.tls.cert_file)
                    if config.server.tls.cert_file is not None
                    else None
                ),
                "key_file": (
                    str(config.server.tls.key_file)
                    if config.server.tls.key_file is not None
                    else None
                ),
                "certificate_configured": config.server.tls.cert_file is not None,
                "key_configured": config.server.tls.key_file is not None,
            },
        },
        "upstream": {
            "scheme": config.upstream.scheme,
            "host": config.upstream.host,
            "port": config.upstream.port,
            "host_header": config.upstream.host_header,
            "connect_timeout": config.upstream.connect_timeout,
            "read_timeout": config.upstream.read_timeout,
            "total_timeout": config.upstream.total_timeout,
            "max_response_bytes": config.upstream.max_response_bytes,
            "circuit_breaker": {
                "enabled": config.upstream.circuit_breaker.enabled,
                "failure_threshold": config.upstream.circuit_breaker.failure_threshold,
                "window": config.upstream.circuit_breaker.window,
                "open_seconds": config.upstream.circuit_breaker.open_seconds,
                "half_open_max_requests": config.upstream.circuit_breaker.half_open_max_requests,
            },
        },
        "policy": {
            "allowed_hosts": list(config.policy.allowed_hosts),
            "allowed_methods": list(config.policy.allowed_methods),
            "allowed_path_prefixes": list(config.policy.allowed_path_prefixes),
            "deny_path_prefixes": list(config.policy.deny_path_prefixes),
            "allowed_client_networks": _networks(config.policy.allowed_client_networks),
            "denied_client_networks": _networks(config.policy.denied_client_networks),
            "trusted_proxies": _networks(config.policy.trusted_proxies),
            "allowed_origins": list(config.policy.allowed_origins),
            "read_only": config.policy.read_only,
            "routes": routes,
            "reject_encoded_separators": config.policy.reject_encoded_separators,
            "allow_path_parameters": config.policy.allow_path_parameters,
            "allow_trailing_dot_or_space": config.policy.allow_trailing_dot_or_space,
            "reject_duplicate_headers": config.policy.reject_duplicate_headers,
            "reject_get_body": config.policy.reject_get_body,
            "allowed_body_content_types": list(config.policy.allowed_body_content_types),
            "max_request_line": config.policy.max_request_line,
            "max_header_count": config.policy.max_header_count,
            "max_header_bytes": config.policy.max_header_bytes,
            "max_body_bytes": config.policy.max_body_bytes,
            "max_xff_hops": config.policy.max_xff_hops,
            "waf_enabled": config.policy.waf_enabled,
            "waf_mode": config.policy.waf_mode,
            "waf_rules": list(config.policy.waf_rules),
            "response_scan_mode": config.policy.response_scan_mode,
            "response_scan_max_bytes": config.policy.response_scan_max_bytes,
            "response_scan_headers": config.policy.response_scan_headers,
            "response_integrity_mode": config.policy.response_integrity_mode,
            "integrity_pins": integrity_pins,
            "security_headers": configured_headers,
            "effective_hsts": effective_hsts,
            "honeypot": {
                "enabled": config.policy.honeypot.enabled,
                "ban_seconds": config.policy.honeypot.ban_seconds,
                "routes": honeypot_routes,
            },
        },
        "rate_limit": {
            "enabled": config.rate_limit.enabled,
            "per_ip_rate": config.rate_limit.per_ip_rate,
            "per_ip_burst": config.rate_limit.per_ip_burst,
            "global_rate": config.rate_limit.global_rate,
            "global_burst": config.rate_limit.global_burst,
            "max_tracked_clients": config.rate_limit.max_tracked_clients,
            "client_idle_ttl": config.rate_limit.client_idle_ttl,
            "auto_ban_threshold": config.rate_limit.auto_ban_threshold,
            "auto_ban_window": config.rate_limit.auto_ban_window,
            "auto_ban_seconds": config.rate_limit.auto_ban_seconds,
            "max_ban_entries": config.rate_limit.max_ban_entries,
        },
        "audit": {
            "path": str(config.audit.path),
            "max_bytes": config.audit.max_bytes,
            "backup_count": config.audit.backup_count,
            "include_client_ip": config.audit.include_client_ip,
            "path_mode": config.audit.path_mode,
            "on_write_failure": config.audit.on_write_failure,
        },
        "admin": {
            "enabled": config.admin.enabled,
            "listen_host": config.admin.listen_host,
            "listen_port": config.admin.listen_port,
            "token_env": config.admin.token_env,
            "audit_tail_max_lines": config.admin.audit_tail_max_lines,
        },
        "threat_detection": {
            "enabled": config.threat_detection.enabled,
            "mode": config.threat_detection.mode,
            "agent_mode": config.threat_detection.agent_mode,
            "agent_min_signals": config.threat_detection.agent_min_signals,
            "agent_score": config.threat_detection.agent_score,
            "window_seconds": config.threat_detection.window_seconds,
            "min_requests": config.threat_detection.min_requests,
            "min_distinct_paths": config.threat_detection.min_distinct_paths,
            "min_violations": config.threat_detection.min_violations,
            "score_threshold": config.threat_detection.score_threshold,
            "confirm_score": config.threat_detection.confirm_score,
            "confirm_after_seconds": config.threat_detection.confirm_after_seconds,
            "containment_seconds": config.threat_detection.containment_seconds,
            "confirmed_containment_seconds": config.threat_detection.confirmed_containment_seconds,
            "throttle_ms": config.threat_detection.throttle_ms,
            "max_throttle_ms": config.threat_detection.max_throttle_ms,
            "tarpit_hold_seconds": config.threat_detection.tarpit_hold_seconds,
            "max_tarpit_hold_seconds": config.threat_detection.max_tarpit_hold_seconds,
            "per_actor_tarpit_slots": config.threat_detection.per_actor_tarpit_slots,
            "global_tarpit_slots": config.threat_detection.global_tarpit_slots,
            "max_tracked_actors": config.threat_detection.max_tracked_actors,
            "max_paths_per_actor": config.threat_detection.max_paths_per_actor,
            "alert_cooldown_seconds": config.threat_detection.alert_cooldown_seconds,
            "mark_ttl_seconds": config.threat_detection.mark_ttl_seconds,
            "offender_path": str(config.threat_detection.offender_path),
        },
        "ddos_detection": {
            "enabled": config.ddos_detection.enabled,
            "window_seconds": config.ddos_detection.window_seconds,
            "request_rate_threshold": config.ddos_detection.request_rate_threshold,
            "global_rejection_ratio": config.ddos_detection.global_rejection_ratio,
            "connection_saturation": config.ddos_detection.connection_saturation,
            "tls_failure_threshold": config.ddos_detection.tls_failure_threshold,
            "upstream_error_ratio": config.ddos_detection.upstream_error_ratio,
            "min_signals": config.ddos_detection.min_signals,
            "cooldown_seconds": config.ddos_detection.cooldown_seconds,
            "escalation_seconds": config.ddos_detection.escalation_seconds,
            "recovery_seconds": config.ddos_detection.recovery_seconds,
        },
        "alerting": {
            "enabled": config.alerting.enabled,
            "webhook_url_env": config.alerting.webhook_url_env,
            "auth_token_env": config.alerting.auth_token_env,
            "timeout_seconds": config.alerting.timeout_seconds,
            "max_queue": config.alerting.max_queue,
            "cooldown_seconds": config.alerting.cooldown_seconds,
            "include_client_ip": config.alerting.include_client_ip,
            "allow_http": config.alerting.allow_http,
        },
    }
