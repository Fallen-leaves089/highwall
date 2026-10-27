"""Shared runtime objects and startup validation."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

from .alerting import (
    AlertConfigurationError,
    AlertDispatcher,
    validate_alert_token,
    validate_webhook_url,
)
from .audit import AuditLogger
from .circuit import CircuitBreaker
from .config import Config, ConfigError
from .metrics import Metrics
from .offenders import OffenderRegistry
from .ratelimit import AdaptiveBanner, TokenBucketLimiter
from .threat import DdosDetector, ThreatDetector

_TOKEN_RE = re.compile(r"^[!-~]{32,512}$")


def validate_admin_token(value: str) -> str:
    if not _TOKEN_RE.fullmatch(value):
        raise ConfigError("admin token must be 32-512 printable non-space ASCII characters")
    return value


def load_admin_token(config: Config, environ: dict[str, str] | None = None) -> str | None:
    if not config.admin.enabled:
        return None
    source = os.environ if environ is None else environ
    token = source.get(config.admin.token_env)
    if token is None or token == "":
        raise ConfigError(f"admin is enabled but environment variable {config.admin.token_env} is empty")
    return validate_admin_token(token)


@dataclass
class Runtime:
    config: Config
    audit: AuditLogger
    metrics: Metrics
    per_ip_limiter: TokenBucketLimiter | None
    global_limiter: TokenBucketLimiter | None
    route_limiters: dict[str, TokenBucketLimiter]
    auto_ban: AdaptiveBanner | None
    circuit_breaker: CircuitBreaker | None
    honeypot_ban: AdaptiveBanner | None
    admin_token: str | None = field(repr=False)
    alert_dispatcher: AlertDispatcher | None = None
    threat_detector: ThreatDetector | None = None
    ddos_detector: DdosDetector | None = None
    offenders: OffenderRegistry | None = None
    started_epoch: float = field(default_factory=time.time)
    started_monotonic: float = field(default_factory=time.monotonic)

    def emit_alert(self, payload: dict, dedupe_key: str, *, cooldown_seconds: float | None = None) -> bool:
        if self.alert_dispatcher is None:
            return False
        return self.alert_dispatcher.emit(
            payload,
            dedupe_key,
            cooldown_seconds=self.config.alerting.cooldown_seconds
            if cooldown_seconds is None
            else cooldown_seconds,
        )

    def close(self) -> None:
        if self.alert_dispatcher is not None:
            self.alert_dispatcher.close()

    @classmethod
    def build(cls, config: Config, admin_token: str | None = None) -> "Runtime":
        resolved_token = validate_admin_token(admin_token) if admin_token is not None else load_admin_token(config)
        try:
            audit = AuditLogger(config.audit)
        except OSError as exc:
            raise ConfigError("audit log path is not usable") from exc
        metrics = Metrics()
        per_ip: TokenBucketLimiter | None = None
        global_limiter: TokenBucketLimiter | None = None
        auto_ban: AdaptiveBanner | None = None
        circuit_breaker: CircuitBreaker | None = None
        honeypot_ban: AdaptiveBanner | None = None
        route_limiters: dict[str, TokenBucketLimiter] = {}
        if config.rate_limit.enabled:
            per_ip = TokenBucketLimiter(
                config.rate_limit.per_ip_rate,
                config.rate_limit.per_ip_burst,
                max_entries=config.rate_limit.max_tracked_clients,
                idle_ttl=config.rate_limit.client_idle_ttl,
            )
            global_limiter = TokenBucketLimiter(
                config.rate_limit.global_rate,
                config.rate_limit.global_burst,
                max_entries=1,
                idle_ttl=config.rate_limit.client_idle_ttl,
            )
            if config.rate_limit.auto_ban_threshold > 0:
                auto_ban = AdaptiveBanner(
                    config.rate_limit.auto_ban_threshold,
                    config.rate_limit.auto_ban_window,
                    config.rate_limit.auto_ban_seconds,
                    max_entries=config.rate_limit.max_ban_entries,
                )
        for route in config.policy.routes:
            if route.rate > 0:
                route_limiters[route.path_prefix] = TokenBucketLimiter(
                    route.rate,
                    route.rate_burst,
                    max_entries=config.rate_limit.max_tracked_clients,
                    idle_ttl=config.rate_limit.client_idle_ttl,
                )
        if config.upstream.circuit_breaker.enabled:
            breaker_config = config.upstream.circuit_breaker
            circuit_breaker = CircuitBreaker(
                breaker_config.failure_threshold,
                breaker_config.window,
                breaker_config.open_seconds,
                half_open_max_requests=breaker_config.half_open_max_requests,
            )
        if config.policy.honeypot.enabled and config.policy.honeypot.ban_seconds > 0:
            honeypot_ban = AdaptiveBanner(
                1,
                1.0,
                config.policy.honeypot.ban_seconds,
                max_entries=config.rate_limit.max_ban_entries,
            )

        alert_dispatcher: AlertDispatcher | None = None
        if config.alerting.enabled:
            webhook_url = os.environ.get(config.alerting.webhook_url_env, "")
            if not webhook_url:
                raise ConfigError(
                    f"alerting is enabled but environment variable {config.alerting.webhook_url_env} is empty"
                )
            try:
                webhook_url = validate_webhook_url(
                    webhook_url,
                    allow_http=config.alerting.allow_http,
                )
                alert_token = validate_alert_token(
                    os.environ.get(config.alerting.auth_token_env, "")
                )
            except AlertConfigurationError as exc:
                raise ConfigError(str(exc)) from exc
            alert_dispatcher = AlertDispatcher(
                url=webhook_url,
                token=alert_token,
                timeout=config.alerting.timeout_seconds,
                max_queue=config.alerting.max_queue,
                cooldown_seconds=config.alerting.cooldown_seconds,
                metrics=metrics,
            )

        offenders: OffenderRegistry | None = None
        threat_detector: ThreatDetector | None = None
        if config.threat_detection.enabled:
            offenders = OffenderRegistry(
                config.threat_detection.offender_path,
                max_entries=config.threat_detection.max_tracked_actors,
                ttl_seconds=config.threat_detection.mark_ttl_seconds,
                include_client_ip=config.alerting.include_client_ip,
            )
            threat_detector = ThreatDetector(
                config.threat_detection,
                metrics,
                offenders,
                include_client_ip=config.alerting.include_client_ip,
            )

        ddos_detector: DdosDetector | None = None
        if config.ddos_detection.enabled:
            ddos_detector = DdosDetector(config.ddos_detection, metrics)

        return cls(
            config=config,
            audit=audit,
            metrics=metrics,
            per_ip_limiter=per_ip,
            global_limiter=global_limiter,
            route_limiters=route_limiters,
            auto_ban=auto_ban,
            circuit_breaker=circuit_breaker,
            honeypot_ban=honeypot_ban,
            admin_token=resolved_token,
            alert_dispatcher=alert_dispatcher,
            threat_detector=threat_detector,
            ddos_detector=ddos_detector,
            offenders=offenders,
        )

    def uptime_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_monotonic)
