"""Shared runtime objects and startup validation."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

from .audit import AuditLogger
from .circuit import CircuitBreaker
from .config import Config, ConfigError
from .metrics import Metrics
from .ratelimit import AdaptiveBanner, TokenBucketLimiter

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
    started_epoch: float = field(default_factory=time.time)
    started_monotonic: float = field(default_factory=time.monotonic)

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
        )

    def uptime_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_monotonic)
