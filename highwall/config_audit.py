"""Surface high-risk configuration choices without changing startup behavior."""

from __future__ import annotations

from dataclasses import dataclass

from .config import Config

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class ConfigWarning:
    path: str
    severity: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "severity": self.severity,
            "message": self.message,
        }


def audit_config(config: Config) -> tuple[ConfigWarning, ...]:
    """Return warnings for switches that widen the exposed trust boundary."""

    warnings: list[ConfigWarning] = []

    def add(path: str, severity: str, message: str) -> None:
        warnings.append(ConfigWarning(path, severity, message))

    policy = config.policy
    if policy.proxy_networks:
        add(
            "policy.trusted_proxies",
            "high",
            "X-Forwarded-For is trusted from configured proxies; enable only behind a trusted load balancer",
        )
    if not policy.allowed_origins and any(method in _UNSAFE_METHODS for method in policy.allowed_methods):
        add(
            "policy.allowed_origins",
            "medium",
            "unsafe methods are allowed without an Origin allowlist; CSRF checks are not enforced",
        )
    if (
        policy.allowed_origins
        and any(method in _UNSAFE_METHODS for method in policy.allowed_methods)
        and "OPTIONS" not in policy.allowed_methods
    ):
        add(
            "policy.allowed_origins",
            "medium",
            "allowed_origins is set but OPTIONS is not allowed; browser preflight requests will be rejected",
        )
    if not policy.allowed_client_networks:
        add(
            "policy.allowed_client_networks",
            "medium",
            "no client CIDR allowlist is configured; any network that can reach the listener is accepted",
        )
    for route in policy.routes:
        if route.allowed_client_networks is None:
            add(
                f"policy.routes[{route.path_prefix}].allowed_client_networks",
                "medium",
                "route has no client CIDR restriction",
            )
    if policy.allow_path_parameters:
        add(
            "policy.allow_path_parameters",
            "high",
            "semicolon path parameters are accepted; this reopens path-interpretation ambiguity",
        )
    if policy.allow_trailing_dot_or_space:
        add(
            "policy.allow_trailing_dot_or_space",
            "high",
            "trailing dots and spaces are accepted; this reopens path-normalization ambiguity",
        )
    if not policy.reject_encoded_separators:
        add(
            "policy.reject_encoded_separators",
            "high",
            "encoded path separators are accepted; traversal and route checks may disagree with the upstream",
        )
    if not policy.reject_duplicate_headers:
        add(
            "policy.reject_duplicate_headers",
            "high",
            "duplicate headers are accepted; framing and authorization ambiguity can be reintroduced",
        )
    if not policy.waf_enabled:
        add("policy.waf_enabled", "high", "WAF inspection is disabled")
    elif policy.waf_mode != "block":
        add("policy.waf_mode", "medium", "WAF is in detect mode; matching requests are not blocked")
    if policy.response_scan_mode == "off":
        add("policy.response_scan_mode", "medium", "response DLP scanning is disabled")
    if policy.integrity_pins and policy.response_integrity_mode == "off":
        add(
            "policy.response_integrity_mode",
            "high",
            "integrity pins are configured but response integrity enforcement is off",
        )
    if "/" in policy.allowed_path_prefixes:
        add("policy.allowed_path_prefixes", "medium", "the root path is allowed; narrow prefixes to real endpoints")
    if not config.rate_limit.enabled:
        add("rate_limit.enabled", "medium", "request rate limiting is disabled")
    if config.audit.on_write_failure != "fail_closed":
        add(
            "audit.on_write_failure",
            "high",
            "audit write failures do not stop request processing",
        )
    return tuple(warnings)
