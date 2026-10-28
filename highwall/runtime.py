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

    def close(self, *, close_alerts: bool = True) -> None:
        dispatcher = self.alert_dispatcher
        if close_alerts:
            self.alert_dispatcher = None
            if dispatcher is not None:
                dispatcher.close()

    @classmethod
    def build(
        cls,
        config: Config,
        admin_token: str | None = None,
        *,
        previous: "Runtime | None" = None,
    ) -> "Runtime":
        resolved_token = validate_admin_token(admin_token) if admin_token is not None else load_admin_token(config)
        if previous is not None and previous.config.audit == config.audit:
            audit = previous.audit
        else:
            try:
                audit = AuditLogger(config.audit)
            except OSError as exc:
                raise ConfigError("audit log path is not usable") from exc
        metrics = previous.metrics if previous is not None else Metrics()
        per_ip: TokenBucketLimiter | None = None
        global_limiter: TokenBucketLimiter | None = None
        auto_ban: AdaptiveBanner | None = None
        circuit_breaker: CircuitBreaker | None = None
        honeypot_ban: AdaptiveBanner | None = None
        route_limiters: dict[str, TokenBucketLimiter] = {}
        needs_agent_ip_ban = (
            config.threat_detection.enabled
            and config.threat_detection.agent_mode == "block"
        )
        reuse_rate_state = (
            previous is not None
            and config.rate_limit == previous.config.rate_limit
            and config.policy.routes == previous.config.policy.routes
        )
        if reuse_rate_state:
            assert previous is not None
            per_ip = previous.per_ip_limiter
            global_limiter = previous.global_limiter
            auto_ban = previous.auto_ban
            route_limiters = previous.route_limiters
        else:
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
            for route in config.policy.routes:
                if route.rate > 0:
                    route_limiters[route.path_prefix] = TokenBucketLimiter(
                        route.rate,
                        route.rate_burst,
                        max_entries=config.rate_limit.max_tracked_clients,
                        idle_ttl=config.rate_limit.client_idle_ttl,
                    )
        auto_ban_enabled = (
            config.rate_limit.enabled
            and config.rate_limit.auto_ban_threshold > 0
        ) or needs_agent_ip_ban
        if auto_ban_enabled and auto_ban is None:
            auto_ban = AdaptiveBanner(
                max(1, config.rate_limit.auto_ban_threshold),
                config.rate_limit.auto_ban_window,
                config.rate_limit.auto_ban_seconds,
                max_entries=config.rate_limit.max_ban_entries,
            )
        elif not auto_ban_enabled:
            auto_ban = None
        same_upstream_target = (
            previous is not None
            and config.upstream.scheme == previous.config.upstream.scheme
            and config.upstream.host == previous.config.upstream.host
            and config.upstream.port == previous.config.upstream.port
        )
        if (
            same_upstream_target
            and previous is not None
            and config.upstream.circuit_breaker == previous.config.upstream.circuit_breaker
        ):
            circuit_breaker = previous.circuit_breaker
        elif config.upstream.circuit_breaker.enabled:
            breaker_config = config.upstream.circuit_breaker
            circuit_breaker = CircuitBreaker(
                breaker_config.failure_threshold,
                breaker_config.window,
                breaker_config.open_seconds,
                half_open_max_requests=breaker_config.half_open_max_requests,
            )
        if (
            previous is not None
            and config.policy.honeypot == previous.config.policy.honeypot
            and config.rate_limit.max_ban_entries == previous.config.rate_limit.max_ban_entries
        ):
            honeypot_ban = previous.honeypot_ban
        elif config.policy.honeypot.enabled and config.policy.honeypot.ban_seconds > 0:
            honeypot_ban = AdaptiveBanner(
                1,
                1.0,
                config.policy.honeypot.ban_seconds,
                max_entries=config.rate_limit.max_ban_entries,
            )
        reuse_threat_state = (
            previous is not None
            and config.threat_detection == previous.config.threat_detection
            and config.alerting.include_client_ip == previous.config.alerting.include_client_ip
        )
        offenders: OffenderRegistry | None = None
        threat_detector: ThreatDetector | None = None
        if reuse_threat_state:
            assert previous is not None
            offenders = previous.offenders
            threat_detector = previous.threat_detector
        elif config.threat_detection.enabled:
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
        if previous is not None and config.ddos_detection == previous.config.ddos_detection:
            ddos_detector = previous.ddos_detector
        elif config.ddos_detection.enabled:
            ddos_detector = DdosDetector(config.ddos_detection, metrics)

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
            if (
                previous is not None
                and previous.alert_dispatcher is not None
                and config.alerting == previous.config.alerting
                and previous.alert_dispatcher.url == webhook_url
                and previous.alert_dispatcher.token == alert_token
            ):
                alert_dispatcher = previous.alert_dispatcher
            else:
                alert_dispatcher = AlertDispatcher(
                    url=webhook_url,
                    token=alert_token,
                    timeout=config.alerting.timeout_seconds,
                    max_queue=config.alerting.max_queue,
                    cooldown_seconds=config.alerting.cooldown_seconds,
                    metrics=metrics,
                )

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
            started_epoch=previous.started_epoch if previous is not None else time.time(),
            started_monotonic=previous.started_monotonic if previous is not None else time.monotonic(),
        )

    def uptime_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_monotonic)
