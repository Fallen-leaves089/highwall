"""Strict JSON configuration for HighWall.

The configuration is intentionally fail-closed: unknown fields, ambiguous
authorities, unsafe methods, and non-loopback management listeners are errors.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import stat
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .honeypot_templates import HONEYPOT_TEMPLATES, expand_honeypot_presets

_ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SAFE_WAF_RULES = {"sqli", "xss", "traversal", "cmdi", "jndi", "ssrf"}
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MEDIA_TYPE_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+/[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 64
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
_FORBIDDEN_SECURITY_HEADERS = {
    "connection",
    "content-length",
    "date",
    "server",
    "set-cookie",
    "transfer-encoding",
    "x-request-id",
}
_HONEYPOT_RESERVED_HEADERS = {
    "cache-control",
    "connection",
    "content-length",
    "content-security-policy",
    "content-security-policy-report-only",
    "content-type",
    "date",
    "keep-alive",
    "permissions-policy",
    "proxy-authenticate",
    "proxy-authorization",
    "referrer-policy",
    "server",
    "set-cookie",
    "strict-transport-security",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-content-type-options",
    "x-frame-options",
    "x-request-id",
}
_MAX_HONEYPOT_BODY_BYTES = 64 * 1024


class ConfigError(ValueError):
    """A safe, actionable configuration error."""


@dataclass(frozen=True)
class TLSConfig:
    enabled: bool
    cert_file: Path | None
    key_file: Path | None
    min_version: str
    handshake_timeout: float


@dataclass(frozen=True)
class ServerConfig:
    listen_host: str
    listen_port: int
    max_connections: int
    max_connections_per_ip: int
    max_inflight_requests: int
    header_timeout: float
    body_timeout: float
    shutdown_timeout: float
    tls: TLSConfig


@dataclass(frozen=True)
class CircuitBreakerConfig:
    enabled: bool
    failure_threshold: int
    window: float
    open_seconds: float
    half_open_max_requests: int


@dataclass(frozen=True)
class UpstreamConfig:
    scheme: str
    host: str
    port: int
    connect_timeout: float
    read_timeout: float
    total_timeout: float
    max_response_bytes: int
    host_header: str | None
    circuit_breaker: CircuitBreakerConfig


@dataclass(frozen=True)
class RouteConfig:
    path_prefix: str
    methods: tuple[str, ...] | None
    read_only: bool
    max_body_bytes: int | None
    max_concurrent: int
    allowed_client_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] | None
    rate: float = 0.0
    rate_burst: int = 1


@dataclass(frozen=True)
class IntegrityPin:
    path: str
    status: int
    sha256: str


@dataclass(frozen=True)
class HoneypotRoute:
    id: str
    path: str
    status: int
    content_type: str
    body: bytes
    headers: tuple[tuple[str, str], ...]
    server_header: str
    delay_ms: int


@dataclass(frozen=True)
class HoneypotConfig:
    enabled: bool
    ban_seconds: float
    routes: tuple[HoneypotRoute, ...]


def _default_honeypot() -> HoneypotConfig:
    return HoneypotConfig(enabled=False, ban_seconds=0.0, routes=())


@dataclass(frozen=True)
class PolicyConfig:
    allowed_hosts: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    deny_path_prefixes: tuple[str, ...]
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_client_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    denied_client_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_origins: tuple[str, ...]
    read_only: bool
    routes: tuple[RouteConfig, ...]
    reject_encoded_separators: bool
    allow_path_parameters: bool
    allow_trailing_dot_or_space: bool
    reject_duplicate_headers: bool
    reject_get_body: bool
    allowed_body_content_types: tuple[str, ...]
    max_request_line: int
    max_header_count: int
    max_header_bytes: int
    max_body_bytes: int
    max_xff_hops: int
    waf_enabled: bool
    waf_mode: str
    waf_rules: tuple[str, ...]
    response_scan_mode: str
    response_scan_max_bytes: int
    response_scan_headers: bool
    response_integrity_mode: str
    integrity_pins: tuple[IntegrityPin, ...]
    security_headers: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    honeypot: HoneypotConfig = field(default_factory=_default_honeypot)


@dataclass(frozen=True)
class RateLimitConfig:
    enabled: bool
    per_ip_rate: float
    per_ip_burst: int
    global_rate: float
    global_burst: int
    max_tracked_clients: int
    client_idle_ttl: float
    auto_ban_threshold: int
    auto_ban_window: float
    auto_ban_seconds: float
    max_ban_entries: int


@dataclass(frozen=True)
class AuditConfig:
    path: Path
    max_bytes: int
    backup_count: int
    include_client_ip: bool
    path_mode: str


@dataclass(frozen=True)
class AdminConfig:
    enabled: bool
    listen_host: str
    listen_port: int
    token_env: str
    audit_tail_max_lines: int


@dataclass(frozen=True)
class ThreatDetectionConfig:
    enabled: bool
    mode: str
    window_seconds: float
    min_requests: int
    min_distinct_paths: int
    min_violations: int
    score_threshold: int
    confirm_score: int
    confirm_after_seconds: float
    containment_seconds: float
    confirmed_containment_seconds: float
    throttle_ms: int
    max_throttle_ms: int
    tarpit_hold_seconds: float
    max_tarpit_hold_seconds: float
    per_actor_tarpit_slots: int
    global_tarpit_slots: int
    max_tracked_actors: int
    max_paths_per_actor: int
    alert_cooldown_seconds: float
    mark_ttl_seconds: float
    offender_path: Path


@dataclass(frozen=True)
class DdosDetectionConfig:
    enabled: bool
    window_seconds: float
    request_rate_threshold: float
    global_rejection_ratio: float
    connection_saturation: float
    tls_failure_threshold: int
    upstream_error_ratio: float
    min_signals: int
    cooldown_seconds: float
    escalation_seconds: float
    recovery_seconds: float


@dataclass(frozen=True)
class AlertingConfig:
    enabled: bool
    webhook_url_env: str
    auth_token_env: str
    timeout_seconds: float
    max_queue: int
    cooldown_seconds: float
    include_client_ip: bool
    allow_http: bool


@dataclass(frozen=True)
class Config:
    version: int
    source: Path | None
    server: ServerConfig
    upstream: UpstreamConfig
    policy: PolicyConfig
    rate_limit: RateLimitConfig
    audit: AuditConfig
    admin: AdminConfig
    threat_detection: ThreatDetectionConfig
    ddos_detection: DdosDetectionConfig
    alerting: AlertingConfig


def canonicalize_host(value: str) -> str:
    """Return a lowercase, unambiguous HTTP authority or raise ConfigError."""

    if not isinstance(value, str):
        raise ConfigError("host authority must be a string")
    host = value.strip().lower()
    if not host or len(host) > 255:
        raise ConfigError("host authority is empty or too long")
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in host):
        raise ConfigError("host authority contains forbidden characters")
    if any(ch in host for ch in ("@", "/", "\\", "?", "#", ",", ";")):
        raise ConfigError("host authority contains forbidden delimiters")

    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            raise ConfigError("unterminated IPv6 authority")
        address = host[1:end]
        remainder = host[end + 1 :]
        try:
            ipaddress.IPv6Address(address)
        except ValueError as exc:
            raise ConfigError("invalid IPv6 authority") from exc
        if remainder:
            if not remainder.startswith(":") or not remainder[1:].isdigit():
                raise ConfigError("invalid port in authority")
            port = int(remainder[1:])
            if not 1 <= port <= 65535:
                raise ConfigError("authority port is out of range")
            return f"[{address}]:{port}"
        return f"[{address}]"

    if host.count(":") > 1:
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise ConfigError("IPv6 authorities must use brackets") from exc
        return host

    host_part = host
    port: int | None = None
    if ":" in host:
        host_part, port_text = host.rsplit(":", 1)
        if not port_text.isdigit() or not host_part:
            raise ConfigError("invalid authority port")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ConfigError("authority port is out of range")

    if host_part.endswith("."):
        host_part = host_part[:-1]
    if not host_part:
        raise ConfigError("host is empty")
    try:
        ipaddress.ip_address(host_part)
    except ValueError:
        labels = host_part.split(".")
        if len(host_part) > 253 or any(not _LABEL_RE.fullmatch(label) for label in labels):
            raise ConfigError("invalid host name")
    return f"{host_part}:{port}" if port is not None else host_part


def host_without_port(value: str) -> str:
    canonical = canonicalize_host(value)
    if canonical.startswith("["):
        return canonical[1 : canonical.index("]")]
    if canonical.count(":") == 1:
        return canonical.rsplit(":", 1)[0]
    return canonical


def canonicalize_origin(value: str) -> str:
    """Return a canonical HTTP Origin value or raise ConfigError."""

    if not isinstance(value, str):
        raise ConfigError("origin must be a string")
    text = value.strip()
    if not text or len(text) > 512 or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in text):
        raise ConfigError("origin contains forbidden characters")
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError as exc:
        raise ConfigError("origin is malformed") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ConfigError("origin scheme must be http or https")
    if not parsed.netloc:
        raise ConfigError("origin authority is required")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("origin must not contain user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ConfigError("origin must not contain a path, query, or fragment")
    try:
        authority = canonicalize_host(parsed.netloc)
    except (TypeError, ValueError) as exc:
        raise ConfigError("origin is malformed") from exc

    if authority.startswith("["):
        end = authority.index("]")
        host_part = authority[: end + 1]
        port_part = authority[end + 1 :]
        port = int(port_part[1:]) if port_part else None
    elif authority.count(":") == 1:
        host_part, port_text = authority.rsplit(":", 1)
        port = int(port_text)
    else:
        host_part = authority
        port = None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        authority = host_part
    return f"{scheme}://{authority}"


def _map(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be an object")
    return value


def _check_keys(value: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"{where} has unknown keys: {', '.join(unknown)}")


def _bool(value: Any, where: str, default: bool) -> bool:
    if value is None:
        return default
    if type(value) is not bool:
        raise ConfigError(f"{where} must be true or false")
    return value


def _int(value: Any, where: str, default: int, low: int, high: int) -> int:
    if value is None:
        return default
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"{where} must be an integer in [{low}, {high}]")
    return value


def _number(value: Any, where: str, default: float, low: float, high: float) -> float:
    if value is None:
        return default
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        raise ConfigError(f"{where} must be a finite number")
    result = float(value)
    if not low <= result <= high:
        raise ConfigError(f"{where} must be in [{low}, {high}]")
    return result


def _string(value: Any, where: str, default: str | None, low: int, high: int) -> str:
    if value is None:
        if default is None:
            raise ConfigError(f"{where} is required")
        value = default
    if not isinstance(value, str):
        raise ConfigError(f"{where} must be a string")
    if not low <= len(value) <= high:
        raise ConfigError(f"{where} length must be in [{low}, {high}]")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ConfigError(f"{where} contains control characters")
    return value


def _string_list(
    value: Any,
    where: str,
    default: list[str] | None,
    *,
    allow_empty: bool = False,
    low: int = 1,
    high: int = 255,
) -> tuple[str, ...]:
    if value is None:
        if default is None:
            raise ConfigError(f"{where} is required")
        items = default
    else:
        if not isinstance(value, list):
            raise ConfigError(f"{where} must be an array")
        items = value
    if not items and not allow_empty:
        raise ConfigError(f"{where} must not be empty")
    result: list[str] = []
    for index, item in enumerate(items):
        result.append(_string(item, f"{where}[{index}]", None, low, high))
    if len(set(result)) != len(result):
        raise ConfigError(f"{where} contains duplicates")
    return tuple(result)


def _object(value: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    result = _map(value, where)
    _check_keys(result, allowed, where)
    return result


def _resolve_path(value: str, base_dir: Path, where: str, *, reject_symlink: bool = False) -> Path:
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raw = base_dir / raw
    if reject_symlink:
        try:
            info = raw.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ConfigError(f"{where} cannot be inspected") from exc
        else:
            if stat.S_ISLNK(info.st_mode) or _has_reparse_attribute(info):
                raise ConfigError(f"{where} must not be a symbolic link")
    try:
        return raw.resolve(strict=False)
    except OSError as exc:
        raise ConfigError(f"{where} cannot be resolved") from exc


def _parse_tls(value: Any, base_dir: Path, where: str) -> TLSConfig:
    raw = _object(value, where, {"enabled", "cert_file", "key_file", "min_version", "handshake_timeout"})
    enabled = _bool(raw.get("enabled"), f"{where}.enabled", False)
    cert_file: Path | None = None
    key_file: Path | None = None
    if enabled:
        cert_text = _string(raw.get("cert_file"), f"{where}.cert_file", None, 1, 4096)
        key_text = _string(raw.get("key_file"), f"{where}.key_file", None, 1, 4096)
        cert_file = _resolve_path(cert_text, base_dir, f"{where}.cert_file")
        key_file = _resolve_path(key_text, base_dir, f"{where}.key_file")
        if not cert_file.is_file():
            raise ConfigError(f"{where}.cert_file does not exist")
        if not key_file.is_file():
            raise ConfigError(f"{where}.key_file does not exist")
    min_version = _string(raw.get("min_version"), f"{where}.min_version", "TLSv1_2", 1, 32)
    if min_version not in {"TLSv1_2", "TLSv1_3"}:
        raise ConfigError(f"{where}.min_version must be TLSv1_2 or TLSv1_3")
    return TLSConfig(
        enabled=enabled,
        cert_file=cert_file,
        key_file=key_file,
        min_version=min_version,
        handshake_timeout=_number(raw.get("handshake_timeout"), f"{where}.handshake_timeout", 5.0, 0.1, 60.0),
    )


def _parse_server(value: Any, base_dir: Path) -> ServerConfig:
    where = "server"
    raw = _object(
        value,
        where,
        {
            "listen_host",
            "listen_port",
            "max_connections",
            "max_connections_per_ip",
            "max_inflight_requests",
            "header_timeout",
            "body_timeout",
            "shutdown_timeout",
            "tls",
        },
    )
    listen_host = _string(raw.get("listen_host"), "server.listen_host", "127.0.0.1", 1, 255)
    try:
        listen_ip = ipaddress.ip_address(listen_host)
    except ValueError as exc:
        raise ConfigError("server.listen_host must be an IP address") from exc
    max_connections = _int(raw.get("max_connections"), "server.max_connections", 64, 1, 4096)
    max_connections_per_ip = _int(
        raw.get("max_connections_per_ip"),
        "server.max_connections_per_ip",
        min(16, max_connections),
        0,
        4096,
    )
    if max_connections_per_ip > max_connections:
        raise ConfigError("server.max_connections_per_ip must not exceed max_connections")
    max_inflight_requests = _int(
        raw.get("max_inflight_requests"),
        "server.max_inflight_requests",
        0,
        0,
        max_connections,
    )
    return ServerConfig(
        listen_host=str(listen_ip),
        listen_port=_int(raw.get("listen_port"), "server.listen_port", 18090, 1, 65535),
        max_connections=max_connections,
        max_connections_per_ip=max_connections_per_ip,
        max_inflight_requests=max_inflight_requests,
        header_timeout=_number(raw.get("header_timeout"), "server.header_timeout", 5.0, 0.1, 120.0),
        body_timeout=_number(raw.get("body_timeout"), "server.body_timeout", 15.0, 0.1, 300.0),
        shutdown_timeout=_number(raw.get("shutdown_timeout"), "server.shutdown_timeout", 30.0, 0.0, 300.0),
        tls=_parse_tls(raw.get("tls", {}), base_dir, "server.tls"),
    )


def _parse_circuit_breaker(value: Any) -> CircuitBreakerConfig:
    where = "upstream.circuit_breaker"
    raw = _object(
        value,
        where,
        {"enabled", "failure_threshold", "window", "open_seconds", "half_open_max_requests"},
    )
    return CircuitBreakerConfig(
        enabled=_bool(raw.get("enabled"), f"{where}.enabled", False),
        failure_threshold=_int(raw.get("failure_threshold"), f"{where}.failure_threshold", 5, 1, 1000),
        window=_number(raw.get("window"), f"{where}.window", 30.0, 1.0, 3600.0),
        open_seconds=_number(raw.get("open_seconds"), f"{where}.open_seconds", 30.0, 1.0, 3600.0),
        half_open_max_requests=_int(
            raw.get("half_open_max_requests"),
            f"{where}.half_open_max_requests",
            1,
            1,
            64,
        ),
    )


def _parse_upstream(value: Any) -> UpstreamConfig:
    where = "upstream"
    raw = _object(
        value,
        where,
        {
            "scheme",
            "host",
            "port",
            "connect_timeout",
            "read_timeout",
            "total_timeout",
            "max_response_bytes",
            "host_header",
            "circuit_breaker",
        },
    )
    scheme = _string(raw.get("scheme"), "upstream.scheme", "http", 4, 5).lower()
    if scheme not in {"http", "https"}:
        raise ConfigError("upstream.scheme must be http or https")
    host_text = _string(raw.get("host"), "upstream.host", None, 1, 255)
    try:
        host_canonical = str(ipaddress.ip_address(host_text))
    except ValueError:
        host_canonical = canonicalize_host(host_text)
        if ":" in host_canonical:
            raise ConfigError("upstream.host must not include a port")
    default_port = 443 if scheme == "https" else 80
    host_header_raw = raw.get("host_header")
    host_header = None
    if host_header_raw is not None:
        host_header = canonicalize_host(_string(host_header_raw, "upstream.host_header", None, 1, 255))
    return UpstreamConfig(
        scheme=scheme,
        host=host_canonical,
        port=_int(raw.get("port"), "upstream.port", default_port, 1, 65535),
        connect_timeout=_number(raw.get("connect_timeout"), "upstream.connect_timeout", 3.0, 0.1, 60.0),
        read_timeout=_number(raw.get("read_timeout"), "upstream.read_timeout", 15.0, 0.1, 300.0),
        total_timeout=_number(raw.get("total_timeout"), "upstream.total_timeout", 30.0, 0.5, 3600.0),
        max_response_bytes=_int(raw.get("max_response_bytes"), "upstream.max_response_bytes", 8 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
        host_header=host_header,
        circuit_breaker=_parse_circuit_breaker(raw.get("circuit_breaker", {})),
    )


def _parse_prefix(value: str, where: str) -> str:
    if not value.startswith("/"):
        raise ConfigError(f"{where} must start with /")
    if value.startswith("//") or "\\" in value or "?" in value or "#" in value:
        raise ConfigError(f"{where} contains ambiguous path syntax")
    if "%" in value:
        raise ConfigError(f"{where} must not contain percent escapes")
    segments = value.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise ConfigError(f"{where} must not contain dot segments")
    return value


def _parse_network_list(
    value: Any,
    where: str,
    default: list[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    raw = _string_list(value, where, default, allow_empty=True, high=64)
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in raw:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ConfigError(f"{where} contains an invalid network") from exc
        if network.prefixlen == 0:
            raise ConfigError(f"{where} must not contain a whole-address-space network")
        networks.append(network)
    if len(set(networks)) != len(networks):
        raise ConfigError(f"{where} contains duplicate networks")
    return tuple(networks)


def _parse_routes(
    value: Any,
    allowed_methods: tuple[str, ...],
    max_body_bytes: int,
) -> tuple[RouteConfig, ...]:
    where = "policy.routes"
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"{where} must be an array")
    if len(value) > 512:
        raise ConfigError(f"{where} must not contain more than 512 entries")
    routes: list[RouteConfig] = []
    seen: set[str] = set()
    seen_folded: set[str] = set()
    for index, item in enumerate(value):
        item_where = f"{where}[{index}]"
        raw = _object(
            item,
            item_where,
            {
                "path_prefix",
                "methods",
                "read_only",
                "max_body_bytes",
                "max_concurrent",
                "allowed_client_networks",
                "rate",
                "rate_burst",
            },
        )
        prefix_text = _string(raw.get("path_prefix"), f"{item_where}.path_prefix", None, 1, 1024)
        prefix = unicodedata.normalize("NFKC", _parse_prefix(prefix_text, f"{item_where}.path_prefix"))
        _parse_prefix(prefix, f"{item_where}.path_prefix")
        folded_prefix = prefix.casefold()
        if prefix in seen or folded_prefix in seen_folded:
            raise ConfigError(f"{where} contains a duplicate path_prefix")
        seen.add(prefix)
        seen_folded.add(folded_prefix)

        route_methods: tuple[str, ...] | None = None
        if raw.get("methods") is not None:
            method_items = _string_list(
                raw.get("methods"),
                f"{item_where}.methods",
                None,
                low=3,
                high=16,
            )
            route_methods = tuple(method.upper() for method in method_items)
            if len(set(route_methods)) != len(route_methods):
                raise ConfigError(f"{item_where}.methods contains duplicate methods")
            invalid = set(route_methods) - set(allowed_methods)
            if invalid:
                raise ConfigError(f"{item_where}.methods must be a subset of policy.allowed_methods")
        read_only = _bool(raw.get("read_only"), f"{item_where}.read_only", False)
        if read_only and route_methods is not None and set(route_methods) & _UNSAFE_METHODS:
            raise ConfigError(f"{item_where}.methods must not contain unsafe methods when read_only is true")

        route_body: int | None = None
        if raw.get("max_body_bytes") is not None:
            route_body = _int(
                raw.get("max_body_bytes"),
                f"{item_where}.max_body_bytes",
                max_body_bytes,
                1,
                max_body_bytes,
            )
        route_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] | None = None
        if raw.get("allowed_client_networks") is not None:
            parsed_networks = _parse_network_list(
                raw.get("allowed_client_networks"),
                f"{item_where}.allowed_client_networks",
                [],
            )
            if not parsed_networks:
                raise ConfigError(f"{item_where}.allowed_client_networks must not be empty")
            route_networks = parsed_networks
        route_rate = _number(raw.get("rate"), f"{item_where}.rate", 0.0, 0.0, 100000.0)
        default_burst = max(1, int(route_rate + 0.999)) if route_rate > 0 else 1
        route_burst = _int(raw.get("rate_burst"), f"{item_where}.rate_burst", default_burst, 1, 1000000)
        if route_rate == 0.0 and raw.get("rate_burst") is not None:
            raise ConfigError(f"{item_where}.rate_burst requires rate > 0")
        routes.append(
            RouteConfig(
                path_prefix=prefix,
                methods=route_methods,
                read_only=read_only,
                max_body_bytes=route_body,
                max_concurrent=_int(
                    raw.get("max_concurrent"),
                    f"{item_where}.max_concurrent",
                    0,
                    0,
                    4096,
                ),
                allowed_client_networks=route_networks,
                rate=route_rate,
                rate_burst=route_burst,
            )
        )
    routes.sort(key=lambda route: (-len(route.path_prefix), route.path_prefix.casefold()))
    return tuple(routes)


def _parse_integrity_pins(value: Any) -> tuple[IntegrityPin, ...]:
    where = "policy.integrity_pins"
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"{where} must be an array")
    if len(value) > 512:
        raise ConfigError(f"{where} must not contain more than 512 entries")
    pins: list[IntegrityPin] = []
    seen: set[str] = set()
    seen_folded: set[str] = set()
    for index, item in enumerate(value):
        item_where = f"{where}[{index}]"
        raw = _object(item, item_where, {"path", "status", "sha256"})
        path_text = _string(raw.get("path"), f"{item_where}.path", None, 1, 1024)
        path = unicodedata.normalize("NFKC", _parse_prefix(path_text, f"{item_where}.path"))
        _parse_prefix(path, f"{item_where}.path")
        if path in seen or path.casefold() in seen_folded:
            raise ConfigError(f"{where} contains a duplicate path")
        seen.add(path)
        seen_folded.add(path.casefold())
        digest = _string(raw.get("sha256"), f"{item_where}.sha256", None, 64, 64).lower()
        if not _SHA256_RE.fullmatch(digest):
            raise ConfigError(f"{item_where}.sha256 must be 64 hexadecimal characters")
        pins.append(
            IntegrityPin(
                path=path,
                status=_int(raw.get("status"), f"{item_where}.status", 200, 100, 599),
                sha256=digest,
            )
        )
    return tuple(pins)


def _parse_honeypot_route(item: Any, item_where: str) -> HoneypotRoute:
    route_raw = _object(
        item,
        item_where,
        {"id", "path", "status", "content_type", "body", "headers", "server_header", "delay_ms"},
    )
    route_id = _string(route_raw.get("id"), f"{item_where}.id", None, 1, 63)
    if not _LABEL_RE.fullmatch(route_id):
        raise ConfigError(f"{item_where}.id must be a lowercase DNS-style label")

    path_text = _string(route_raw.get("path"), f"{item_where}.path", None, 1, 1024)
    path = unicodedata.normalize("NFKC", _parse_prefix(path_text, f"{item_where}.path"))
    _parse_prefix(path, f"{item_where}.path")

    status = _int(route_raw.get("status"), f"{item_where}.status", 200, 200, 499)
    if status in {204, 304}:
        raise ConfigError(f"{item_where}.status must not be 204 or 304")

    content_type = _string(
        route_raw.get("content_type"),
        f"{item_where}.content_type",
        "text/plain; charset=utf-8",
        3,
        255,
    )
    media_type = content_type.split(";", 1)[0].strip().lower()
    if not _MEDIA_TYPE_RE.fullmatch(media_type):
        raise ConfigError(f"{item_where}.content_type must begin with a valid media type")
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in content_type):
        raise ConfigError(f"{item_where}.content_type must be printable ASCII")

    body_text = route_raw.get("body", "")
    if not isinstance(body_text, str):
        raise ConfigError(f"{item_where}.body must be a string")
    if any((ord(ch) < 0x20 and ch not in "\t\r\n") or ord(ch) == 0x7F for ch in body_text):
        raise ConfigError(f"{item_where}.body contains unsupported control characters")
    body = body_text.encode("utf-8")
    if len(body) > _MAX_HONEYPOT_BODY_BYTES:
        raise ConfigError(f"{item_where}.body must not exceed 64 KiB as UTF-8")

    headers_raw = _map(route_raw.get("headers", {}), f"{item_where}.headers")
    if len(headers_raw) > 16:
        raise ConfigError(f"{item_where}.headers must not contain more than 16 entries")
    headers: list[tuple[str, str]] = []
    seen_headers: set[str] = set()
    for name, header_value in headers_raw.items():
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise ConfigError(f"{item_where}.headers contains an invalid header name")
        lower_name = name.lower()
        if lower_name in _HONEYPOT_RESERVED_HEADERS:
            raise ConfigError(f"{item_where}.headers must not set {name}")
        if lower_name in seen_headers:
            raise ConfigError(f"{item_where}.headers contains duplicate names")
        seen_headers.add(lower_name)
        text = _string(header_value, f"{item_where}.headers.{name}", None, 0, 2048)
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in text):
            raise ConfigError(f"{item_where}.headers.{name} must be printable ASCII")
        headers.append((name, text))

    server_header = _string(
        route_raw.get("server_header"),
        f"{item_where}.server_header",
        "HighWall",
        1,
        128,
    )
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in server_header):
        raise ConfigError(f"{item_where}.server_header must be printable ASCII")

    return HoneypotRoute(
        id=route_id,
        path=path,
        status=status,
        content_type=content_type,
        body=body,
        headers=tuple(headers),
        server_header=server_header,
        delay_ms=_int(route_raw.get("delay_ms"), f"{item_where}.delay_ms", 0, 0, 5000),
    )


def _parse_honeypot(value: Any) -> HoneypotConfig:
    where = "policy.honeypot"
    if value is None:
        return _default_honeypot()
    raw = _object(value, where, {"enabled", "ban_seconds", "presets", "routes"})
    enabled = _bool(raw.get("enabled"), f"{where}.enabled", False)
    ban_seconds = _number(raw.get("ban_seconds"), f"{where}.ban_seconds", 900.0, 0.0, 86400.0)

    preset_items = raw.get("presets")
    if preset_items is None:
        preset_items = []
    if not isinstance(preset_items, list):
        raise ConfigError(f"{where}.presets must be an array")
    if len(preset_items) > 32:
        raise ConfigError(f"{where}.presets must not contain more than 32 entries")
    preset_names: list[str] = []
    for index, item in enumerate(preset_items):
        name = _string(item, f"{where}.presets[{index}]", None, 1, 64)
        if not _LABEL_RE.fullmatch(name):
            raise ConfigError(f"{where}.presets[{index}] must be a lowercase DNS-style label")
        preset_names.append(name)
    try:
        expanded_presets = expand_honeypot_presets(preset_names)
    except ValueError as exc:
        raise ConfigError(f"{where}.presets contains {exc}") from exc

    route_items = raw.get("routes")
    if route_items is None:
        route_items = []
    if not isinstance(route_items, list):
        raise ConfigError(f"{where}.routes must be an array")
    if len(route_items) > 128:
        raise ConfigError(f"{where}.routes must not contain more than 128 entries")

    explicit_routes: list[HoneypotRoute] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_paths_folded: set[str] = set()
    for index, item in enumerate(route_items):
        route = _parse_honeypot_route(item, f"{where}.routes[{index}]")
        if route.id in seen_ids:
            raise ConfigError(f"{where}.routes contains a duplicate id")
        if route.path in seen_paths or route.path.casefold() in seen_paths_folded:
            raise ConfigError(f"{where}.routes contains a duplicate exact path")
        seen_ids.add(route.id)
        seen_paths.add(route.path)
        seen_paths_folded.add(route.path.casefold())
        explicit_routes.append(route)

    preset_routes: list[HoneypotRoute] = []
    for index, template_name in enumerate(expanded_presets):
        preset_routes.append(
            _parse_honeypot_route(
                HONEYPOT_TEMPLATES[template_name],
                f"{where}.presets[{index}]({template_name})",
            )
        )

    routes_by_path = {route.path.casefold(): route for route in preset_routes}
    for route in explicit_routes:
        routes_by_path[route.path.casefold()] = route
    routes = list(routes_by_path.values())
    if len(routes) > 128:
        raise ConfigError(f"{where} expands to more than 128 routes")

    final_ids: dict[str, str] = {}
    for route in routes:
        previous_path = final_ids.get(route.id)
        if previous_path is not None and previous_path != route.path:
            raise ConfigError(f"{where} contains a duplicate id across presets and routes")
        final_ids[route.id] = route.path

    if enabled and not routes:
        raise ConfigError(f"{where}.routes or {where}.presets must not be empty when honeypot is enabled")
    routes.sort(key=lambda route: (route.path, route.id))
    return HoneypotConfig(enabled=enabled, ban_seconds=ban_seconds, routes=tuple(routes))


def _parse_policy(value: Any) -> PolicyConfig:
    where = "policy"
    raw = _object(
        value,
        where,
        {
            "allowed_hosts",
            "allowed_methods",
            "allowed_path_prefixes",
            "deny_path_prefixes",
            "trusted_proxies",
            "allowed_client_networks",
            "denied_client_networks",
            "allowed_origins",
            "read_only",
            "routes",
            "reject_encoded_separators",
            "allow_path_parameters",
            "allow_trailing_dot_or_space",
            "reject_duplicate_headers",
            "reject_get_body",
            "allowed_body_content_types",
            "max_request_line",
            "max_header_count",
            "max_header_bytes",
            "max_body_bytes",
            "max_xff_hops",
            "waf_enabled",
            "waf_mode",
            "waf_rules",
            "response_scan_mode",
            "response_scan_max_bytes",
            "response_scan_headers",
            "response_integrity_mode",
            "integrity_pins",
            "security_headers",
            "honeypot",
        },
    )
    allowed_hosts_raw = _string_list(raw.get("allowed_hosts"), "policy.allowed_hosts", None)
    allowed_hosts = tuple(canonicalize_host(host) for host in allowed_hosts_raw)
    if len(set(allowed_hosts)) != len(allowed_hosts):
        raise ConfigError("policy.allowed_hosts contains duplicate canonical authorities")

    methods_raw = _string_list(raw.get("allowed_methods"), "policy.allowed_methods", ["GET", "HEAD"], low=3, high=16)
    methods = tuple(method.upper() for method in methods_raw)
    if len(set(methods)) != len(methods):
        raise ConfigError("policy.allowed_methods contains duplicate methods")
    invalid_methods = set(methods) - _ALLOWED_METHODS
    if invalid_methods:
        raise ConfigError("policy.allowed_methods contains unsafe or unsupported methods")

    prefixes_raw = _string_list(raw.get("allowed_path_prefixes"), "policy.allowed_path_prefixes", ["/"])
    allowed_prefixes = tuple(_parse_prefix(prefix, "policy.allowed_path_prefixes") for prefix in prefixes_raw)
    deny_raw = _string_list(
        raw.get("deny_path_prefixes"),
        "policy.deny_path_prefixes",
        ["/.git", "/.svn", "/.hg", "/.env", "/server-status", "/actuator/heapdump", "/actuator/env"],
        allow_empty=True,
    )
    deny_prefixes = tuple(_parse_prefix(prefix, "policy.deny_path_prefixes") for prefix in deny_raw)

    trusted_raw = _string_list(raw.get("trusted_proxies"), "policy.trusted_proxies", [], allow_empty=True, high=64)
    trusted: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in trusted_raw:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ConfigError("policy.trusted_proxies contains an invalid network") from exc
        if network.prefixlen == 0:
            raise ConfigError("policy.trusted_proxies must not trust the entire internet")
        trusted.append(network)

    allowed_client_networks = _parse_network_list(
        raw.get("allowed_client_networks"),
        "policy.allowed_client_networks",
        [],
    )
    denied_client_networks = _parse_network_list(
        raw.get("denied_client_networks"),
        "policy.denied_client_networks",
        [],
    )
    origins_raw = _string_list(raw.get("allowed_origins"), "policy.allowed_origins", [], allow_empty=True, high=512)
    allowed_origins = tuple(canonicalize_origin(origin) for origin in origins_raw)
    if len(set(allowed_origins)) != len(allowed_origins):
        raise ConfigError("policy.allowed_origins contains duplicate canonical origins")

    max_body = _int(raw.get("max_body_bytes"), "policy.max_body_bytes", 1024 * 1024, 1, 16 * 1024 * 1024)
    read_only = _bool(raw.get("read_only"), "policy.read_only", False)
    routes = _parse_routes(raw.get("routes"), methods, max_body)

    body_types_raw = _string_list(
        raw.get("allowed_body_content_types"),
        "policy.allowed_body_content_types",
        ["application/x-www-form-urlencoded", "application/json", "text/plain"],
        allow_empty=True,
        high=255,
    )
    body_types = tuple(item.lower() for item in body_types_raw)
    for media_type in body_types:
        if not _MEDIA_TYPE_RE.fullmatch(media_type):
            raise ConfigError("policy.allowed_body_content_types contains an invalid media type")
    if len(set(body_types)) != len(body_types):
        raise ConfigError("policy.allowed_body_content_types contains duplicates")

    waf_rules_raw = _string_list(raw.get("waf_rules"), "policy.waf_rules", ["sqli", "xss", "traversal", "cmdi", "jndi"], allow_empty=True, low=2, high=32)
    waf_rules = tuple(item.lower() for item in waf_rules_raw)
    unknown_rules = set(waf_rules) - _SAFE_WAF_RULES
    if unknown_rules:
        raise ConfigError(f"policy.waf_rules contains unknown rules: {', '.join(sorted(unknown_rules))}")
    waf_mode = _string(raw.get("waf_mode"), "policy.waf_mode", "block", 5, 6).lower()
    if waf_mode not in {"block", "detect"}:
        raise ConfigError("policy.waf_mode must be block or detect")
    response_scan_mode = _string(raw.get("response_scan_mode"), "policy.response_scan_mode", "block", 3, 6).lower()
    if response_scan_mode not in {"off", "detect", "block"}:
        raise ConfigError("policy.response_scan_mode must be off, detect, or block")
    response_scan_headers = _bool(raw.get("response_scan_headers"), "policy.response_scan_headers", True)
    response_integrity_mode = _string(
        raw.get("response_integrity_mode"),
        "policy.response_integrity_mode",
        "off",
        3,
        6,
    ).lower()
    if response_integrity_mode not in {"off", "detect", "block"}:
        raise ConfigError("policy.response_integrity_mode must be off, detect, or block")
    integrity_pins = _parse_integrity_pins(raw.get("integrity_pins"))
    honeypot = _parse_honeypot(raw.get("honeypot"))

    custom_security = _map(raw.get("security_headers", {}), "policy.security_headers")
    merged_security: dict[str, tuple[str, str]] = {
        name.lower(): (name, value) for name, value in _DEFAULT_SECURITY_HEADERS.items()
    }
    seen_custom: set[str] = set()
    for name, value in custom_security.items():
        lower_name = name.lower() if isinstance(name, str) else ""
        if not lower_name or lower_name in seen_custom:
            raise ConfigError("policy.security_headers contains duplicate or invalid names")
        seen_custom.add(lower_name)
        merged_security[lower_name] = (name, value)
    security_headers: list[tuple[str, str]] = []
    for name, header_value in merged_security.values():
        if not _HEADER_NAME_RE.fullmatch(name):
            raise ConfigError("policy.security_headers contains an invalid header name")
        if name.lower() in _FORBIDDEN_SECURITY_HEADERS:
            raise ConfigError(f"policy.security_headers must not set {name}")
        text = _string(header_value, f"policy.security_headers.{name}", None, 0, 2048)
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in text):
            raise ConfigError(f"policy.security_headers.{name} must be printable ASCII")
        security_headers.append((name, text))

    return PolicyConfig(
        allowed_hosts=allowed_hosts,
        allowed_methods=methods,
        allowed_path_prefixes=allowed_prefixes,
        deny_path_prefixes=deny_prefixes,
        trusted_proxies=tuple(trusted),
        allowed_client_networks=allowed_client_networks,
        denied_client_networks=denied_client_networks,
        allowed_origins=allowed_origins,
        read_only=read_only,
        routes=routes,
        reject_encoded_separators=_bool(raw.get("reject_encoded_separators"), "policy.reject_encoded_separators", True),
        allow_path_parameters=_bool(raw.get("allow_path_parameters"), "policy.allow_path_parameters", False),
        allow_trailing_dot_or_space=_bool(
            raw.get("allow_trailing_dot_or_space"),
            "policy.allow_trailing_dot_or_space",
            False,
        ),
        reject_duplicate_headers=_bool(raw.get("reject_duplicate_headers"), "policy.reject_duplicate_headers", True),
        reject_get_body=_bool(raw.get("reject_get_body"), "policy.reject_get_body", True),
        allowed_body_content_types=body_types,
        max_request_line=_int(raw.get("max_request_line"), "policy.max_request_line", 8192, 128, 65536),
        max_header_count=_int(raw.get("max_header_count"), "policy.max_header_count", 64, 1, 200),
        max_header_bytes=_int(raw.get("max_header_bytes"), "policy.max_header_bytes", 16384, 256, 65536),
        max_body_bytes=max_body,
        max_xff_hops=_int(raw.get("max_xff_hops"), "policy.max_xff_hops", 8, 1, 32),
        waf_enabled=_bool(raw.get("waf_enabled"), "policy.waf_enabled", True),
        waf_mode=waf_mode,
        waf_rules=waf_rules,
        response_scan_mode=response_scan_mode,
        response_scan_max_bytes=_int(
            raw.get("response_scan_max_bytes"),
            "policy.response_scan_max_bytes",
            1024 * 1024,
            1024,
            16 * 1024 * 1024,
        ),
        response_scan_headers=response_scan_headers,
        response_integrity_mode=response_integrity_mode,
        integrity_pins=integrity_pins,
        security_headers=tuple(security_headers),
        honeypot=honeypot,
    )


def _parse_rate_limit(value: Any) -> RateLimitConfig:
    where = "rate_limit"
    raw = _object(
        value,
        where,
        {
            "enabled",
            "per_ip_rate",
            "per_ip_burst",
            "global_rate",
            "global_burst",
            "max_tracked_clients",
            "client_idle_ttl",
            "auto_ban_threshold",
            "auto_ban_window",
            "auto_ban_seconds",
            "max_ban_entries",
        },
    )
    enabled = _bool(raw.get("enabled"), f"{where}.enabled", True)
    per_ip_rate = _number(raw.get("per_ip_rate"), f"{where}.per_ip_rate", 20.0, 0.01, 100000.0)
    per_ip_burst = _int(raw.get("per_ip_burst"), f"{where}.per_ip_burst", 40, 1, 1000000)
    global_rate = _number(raw.get("global_rate"), f"{where}.global_rate", 200.0, 0.01, 1000000.0)
    global_burst = _int(raw.get("global_burst"), f"{where}.global_burst", 400, 1, 1000000)
    return RateLimitConfig(
        enabled=enabled,
        per_ip_rate=per_ip_rate if enabled else 0.0,
        per_ip_burst=per_ip_burst if enabled else 1,
        global_rate=global_rate if enabled else 0.0,
        global_burst=global_burst if enabled else 1,
        max_tracked_clients=_int(raw.get("max_tracked_clients"), f"{where}.max_tracked_clients", 10000, 16, 1000000),
        client_idle_ttl=_number(raw.get("client_idle_ttl"), f"{where}.client_idle_ttl", 300.0, 1.0, 86400.0),
        auto_ban_threshold=_int(raw.get("auto_ban_threshold"), f"{where}.auto_ban_threshold", 20, 0, 100000),
        auto_ban_window=_number(raw.get("auto_ban_window"), f"{where}.auto_ban_window", 60.0, 1.0, 86400.0),
        auto_ban_seconds=_number(raw.get("auto_ban_seconds"), f"{where}.auto_ban_seconds", 300.0, 1.0, 604800.0),
        max_ban_entries=_int(raw.get("max_ban_entries"), f"{where}.max_ban_entries", 10000, 16, 1000000),
    )


def _parse_audit(value: Any, base_dir: Path) -> AuditConfig:
    where = "audit"
    raw = _object(value, where, {"path", "max_bytes", "backup_count", "include_client_ip", "path_mode"})
    path_text = _string(raw.get("path"), f"{where}.path", "highwall-audit.jsonl", 1, 4096)
    path_mode = _string(raw.get("path_mode"), f"{where}.path_mode", "redact", 4, 6).lower()
    if path_mode not in {"exact", "redact", "hash"}:
        raise ConfigError("audit.path_mode must be exact, redact, or hash")
    return AuditConfig(
        path=_resolve_path(path_text, base_dir, f"{where}.path", reject_symlink=True),
        max_bytes=_int(raw.get("max_bytes"), f"{where}.max_bytes", 10 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
        backup_count=_int(raw.get("backup_count"), f"{where}.backup_count", 5, 0, 50),
        include_client_ip=_bool(raw.get("include_client_ip"), f"{where}.include_client_ip", True),
        path_mode=path_mode,
    )


def _parse_admin(value: Any) -> AdminConfig:
    where = "admin"
    raw = _object(value, where, {"enabled", "listen_host", "listen_port", "token_env", "audit_tail_max_lines"})
    enabled = _bool(raw.get("enabled"), f"{where}.enabled", False)
    listen_host = _string(raw.get("listen_host"), f"{where}.listen_host", "127.0.0.1", 1, 255)
    try:
        admin_ip = ipaddress.ip_address(listen_host)
    except ValueError as exc:
        raise ConfigError("admin.listen_host must be an IP address") from exc
    if not admin_ip.is_loopback:
        raise ConfigError("admin.listen_host must be a loopback address")
    token_env = _string(raw.get("token_env"), f"{where}.token_env", "HIGHWALL_ADMIN_TOKEN", 1, 128)
    if not _ENV_NAME_RE.fullmatch(token_env):
        raise ConfigError("admin.token_env must be a valid environment variable name")
    return AdminConfig(
        enabled=enabled,
        listen_host=str(admin_ip),
        listen_port=_int(raw.get("listen_port"), f"{where}.listen_port", 18091, 1, 65535),
        token_env=token_env,
        audit_tail_max_lines=_int(raw.get("audit_tail_max_lines"), f"{where}.audit_tail_max_lines", 200, 1, 1000),
    )


def _parse_threat_detection(value: Any, base_dir: Path) -> ThreatDetectionConfig:
    where = "threat_detection"
    raw = _object(
        value,
        where,
        {
            "enabled",
            "mode",
            "window_seconds",
            "min_requests",
            "min_distinct_paths",
            "min_violations",
            "score_threshold",
            "confirm_score",
            "confirm_after_seconds",
            "containment_seconds",
            "confirmed_containment_seconds",
            "throttle_ms",
            "max_throttle_ms",
            "tarpit_hold_seconds",
            "max_tarpit_hold_seconds",
            "per_actor_tarpit_slots",
            "global_tarpit_slots",
            "max_tracked_actors",
            "max_paths_per_actor",
            "alert_cooldown_seconds",
            "mark_ttl_seconds",
            "offender_path",
        },
    )
    enabled = _bool(raw.get("enabled"), f"{where}.enabled", False)
    mode = _string(raw.get("mode"), f"{where}.mode", "monitor", 6, 8).lower()
    if mode not in {"monitor", "throttle", "tarpit", "block"}:
        raise ConfigError(f"{where}.mode must be monitor, throttle, tarpit, or block")
    score_threshold = _int(raw.get("score_threshold"), f"{where}.score_threshold", 70, 1, 100)
    confirm_score = _int(raw.get("confirm_score"), f"{where}.confirm_score", 85, 1, 100)
    if confirm_score < score_threshold:
        raise ConfigError(f"{where}.confirm_score must not be below score_threshold")
    containment = _number(raw.get("containment_seconds"), f"{where}.containment_seconds", 300.0, 1.0, 86400.0)
    confirmed_containment = _number(
        raw.get("confirmed_containment_seconds"),
        f"{where}.confirmed_containment_seconds",
        900.0,
        1.0,
        86400.0,
    )
    if confirmed_containment < containment:
        raise ConfigError(f"{where}.confirmed_containment_seconds must not be below containment_seconds")
    throttle_ms = _int(raw.get("throttle_ms"), f"{where}.throttle_ms", 750, 0, 60000)
    max_throttle_ms = _int(raw.get("max_throttle_ms"), f"{where}.max_throttle_ms", 3000, 0, 60000)
    if max_throttle_ms < throttle_ms:
        raise ConfigError(f"{where}.max_throttle_ms must not be below throttle_ms")
    tarpit_hold = _number(raw.get("tarpit_hold_seconds"), f"{where}.tarpit_hold_seconds", 15.0, 1.0, 120.0)
    max_tarpit_hold = _number(
        raw.get("max_tarpit_hold_seconds"),
        f"{where}.max_tarpit_hold_seconds",
        30.0,
        1.0,
        300.0,
    )
    if max_tarpit_hold < tarpit_hold:
        raise ConfigError(f"{where}.max_tarpit_hold_seconds must not be below tarpit_hold_seconds")
    per_actor_slots = _int(raw.get("per_actor_tarpit_slots"), f"{where}.per_actor_tarpit_slots", 4, 1, 64)
    global_slots = _int(raw.get("global_tarpit_slots"), f"{where}.global_tarpit_slots", 16, 1, 256)
    if global_slots < per_actor_slots:
        raise ConfigError(f"{where}.global_tarpit_slots must not be below per_actor_tarpit_slots")
    return ThreatDetectionConfig(
        enabled=enabled,
        mode=mode,
        window_seconds=_number(raw.get("window_seconds"), f"{where}.window_seconds", 10.0, 1.0, 3600.0),
        min_requests=_int(raw.get("min_requests"), f"{where}.min_requests", 10, 1, 100000),
        min_distinct_paths=_int(raw.get("min_distinct_paths"), f"{where}.min_distinct_paths", 6, 1, 10000),
        min_violations=_int(raw.get("min_violations"), f"{where}.min_violations", 3, 1, 10000),
        score_threshold=score_threshold,
        confirm_score=confirm_score,
        confirm_after_seconds=_number(
            raw.get("confirm_after_seconds"),
            f"{where}.confirm_after_seconds",
            300.0,
            1.0,
            86400.0,
        ),
        containment_seconds=containment,
        confirmed_containment_seconds=confirmed_containment,
        throttle_ms=throttle_ms,
        max_throttle_ms=max_throttle_ms,
        tarpit_hold_seconds=tarpit_hold,
        max_tarpit_hold_seconds=max_tarpit_hold,
        per_actor_tarpit_slots=per_actor_slots,
        global_tarpit_slots=global_slots,
        max_tracked_actors=_int(raw.get("max_tracked_actors"), f"{where}.max_tracked_actors", 10000, 16, 1000000),
        max_paths_per_actor=_int(raw.get("max_paths_per_actor"), f"{where}.max_paths_per_actor", 64, 4, 1024),
        alert_cooldown_seconds=_number(
            raw.get("alert_cooldown_seconds"),
            f"{where}.alert_cooldown_seconds",
            60.0,
            1.0,
            86400.0,
        ),
        mark_ttl_seconds=_number(raw.get("mark_ttl_seconds"), f"{where}.mark_ttl_seconds", 86400.0, 60.0, 604800.0),
        offender_path=_resolve_path(
            _string(raw.get("offender_path"), f"{where}.offender_path", "offenders.json", 1, 4096),
            base_dir,
            f"{where}.offender_path",
            reject_symlink=True,
        ),
    )


def _parse_ddos_detection(value: Any) -> DdosDetectionConfig:
    where = "ddos_detection"
    raw = _object(
        value,
        where,
        {
            "enabled",
            "window_seconds",
            "request_rate_threshold",
            "global_rejection_ratio",
            "connection_saturation",
            "tls_failure_threshold",
            "upstream_error_ratio",
            "min_signals",
            "cooldown_seconds",
            "escalation_seconds",
            "recovery_seconds",
        },
    )
    return DdosDetectionConfig(
        enabled=_bool(raw.get("enabled"), f"{where}.enabled", False),
        window_seconds=_number(raw.get("window_seconds"), f"{where}.window_seconds", 10.0, 1.0, 300.0),
        request_rate_threshold=_number(
            raw.get("request_rate_threshold"),
            f"{where}.request_rate_threshold",
            500.0,
            0.1,
            1000000.0,
        ),
        global_rejection_ratio=_number(
            raw.get("global_rejection_ratio"),
            f"{where}.global_rejection_ratio",
            0.2,
            0.0,
            1.0,
        ),
        connection_saturation=_number(
            raw.get("connection_saturation"),
            f"{where}.connection_saturation",
            0.85,
            0.0,
            1.0,
        ),
        tls_failure_threshold=_int(
            raw.get("tls_failure_threshold"),
            f"{where}.tls_failure_threshold",
            20,
            1,
            1000000,
        ),
        upstream_error_ratio=_number(
            raw.get("upstream_error_ratio"),
            f"{where}.upstream_error_ratio",
            0.05,
            0.0,
            1.0,
        ),
        min_signals=_int(raw.get("min_signals"), f"{where}.min_signals", 2, 1, 5),
        cooldown_seconds=_number(raw.get("cooldown_seconds"), f"{where}.cooldown_seconds", 60.0, 1.0, 3600.0),
        escalation_seconds=_number(
            raw.get("escalation_seconds"),
            f"{where}.escalation_seconds",
            300.0,
            1.0,
            86400.0,
        ),
        recovery_seconds=_number(
            raw.get("recovery_seconds"),
            f"{where}.recovery_seconds",
            30.0,
            1.0,
            86400.0,
        ),
    )


def _parse_alerting(value: Any) -> AlertingConfig:
    where = "alerting"
    raw = _object(
        value,
        where,
        {
            "enabled",
            "webhook_url_env",
            "auth_token_env",
            "timeout_seconds",
            "max_queue",
            "cooldown_seconds",
            "include_client_ip",
            "allow_http",
        },
    )
    webhook_url_env = _string(
        raw.get("webhook_url_env"),
        f"{where}.webhook_url_env",
        "HIGHWALL_ALERT_WEBHOOK",
        1,
        128,
    )
    auth_token_env = _string(
        raw.get("auth_token_env"),
        f"{where}.auth_token_env",
        "HIGHWALL_ALERT_TOKEN",
        1,
        128,
    )
    if not _ENV_NAME_RE.fullmatch(webhook_url_env):
        raise ConfigError(f"{where}.webhook_url_env must be a valid environment variable name")
    if not _ENV_NAME_RE.fullmatch(auth_token_env):
        raise ConfigError(f"{where}.auth_token_env must be a valid environment variable name")
    return AlertingConfig(
        enabled=_bool(raw.get("enabled"), f"{where}.enabled", False),
        webhook_url_env=webhook_url_env,
        auth_token_env=auth_token_env,
        timeout_seconds=_number(raw.get("timeout_seconds"), f"{where}.timeout_seconds", 3.0, 0.1, 60.0),
        max_queue=_int(raw.get("max_queue"), f"{where}.max_queue", 256, 1, 65536),
        cooldown_seconds=_number(raw.get("cooldown_seconds"), f"{where}.cooldown_seconds", 60.0, 1.0, 86400.0),
        include_client_ip=_bool(raw.get("include_client_ip"), f"{where}.include_client_ip", False),
        allow_http=_bool(raw.get("allow_http"), f"{where}.allow_http", False),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ConfigError(f"duplicate JSON key: {key}")
        result[key] = item
    return result


def _reject_constant(value: str) -> None:
    raise ConfigError(f"invalid JSON number: {value}")


def _reject_deep_json(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_JSON_DEPTH:
            raise ConfigError("configuration nesting is too deep")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def parse_config(data: Any, base_dir: Path | str = ".", source: Path | None = None) -> Config:
    raw = _object(
        data,
        "root",
        {
            "version",
            "server",
            "upstream",
            "policy",
            "rate_limit",
            "audit",
            "admin",
            "threat_detection",
            "ddos_detection",
            "alerting",
        },
    )
    if raw.get("version") != 1:
        raise ConfigError("root.version must be 1")
    base = Path(base_dir).resolve(strict=False)
    server = _parse_server(raw.get("server", {}), base)
    upstream = _parse_upstream(raw.get("upstream", {}))
    policy = _parse_policy(raw.get("policy", {}))
    rate_limit = _parse_rate_limit(raw.get("rate_limit", {}))
    audit = _parse_audit(raw.get("audit", {}), base)
    admin = _parse_admin(raw.get("admin", {}))
    threat_detection = _parse_threat_detection(raw.get("threat_detection", {}), base)
    ddos_detection = _parse_ddos_detection(raw.get("ddos_detection", {}))
    alerting = _parse_alerting(raw.get("alerting", {}))
    if admin.enabled and admin.listen_port == server.listen_port:
        raise ConfigError("admin listener must not reuse the proxy port")
    for route in policy.routes:
        if route.max_concurrent > server.max_connections:
            raise ConfigError("policy.routes.max_concurrent must not exceed server.max_connections")
    if server.max_connections * upstream.max_response_bytes > 512 * 1024 * 1024:
        raise ConfigError("max_connections * max_response_bytes must not exceed 512 MiB")
    return Config(
        version=1,
        source=source,
        server=server,
        upstream=upstream,
        policy=policy,
        rate_limit=rate_limit,
        audit=audit,
        admin=admin,
        threat_detection=threat_detection,
        ddos_detection=ddos_detection,
        alerting=alerting,
    )


def _has_reparse_attribute(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _read_regular_file(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ConfigError(f"cannot inspect configuration: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or _has_reparse_attribute(info):
        raise ConfigError("configuration must not be a symbolic link or reparse point")
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError(f"configuration is not a regular file: {path}")
    if info.st_size > _MAX_CONFIG_BYTES:
        raise ConfigError("configuration file exceeds 1 MiB")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ConfigError(f"cannot read configuration: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _has_reparse_attribute(opened):
            raise ConfigError("configuration changed into a non-regular file")
        if opened.st_size > _MAX_CONFIG_BYTES:
            raise ConfigError("configuration file exceeds 1 MiB")
        remaining = _MAX_CONFIG_BYTES + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_bytes = b"".join(chunks)
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError(f"cannot read configuration: {path}") from exc
    finally:
        os.close(descriptor)
    if len(raw_bytes) > _MAX_CONFIG_BYTES:
        raise ConfigError("configuration file exceeds 1 MiB")
    return raw_bytes


def load_config_data(path: str | Path) -> tuple[dict[str, Any], Path]:
    """Load a validated JSON object and its resolved source path."""

    config_input = Path(path).expanduser()
    raw_bytes = _read_regular_file(config_input)
    try:
        config_path = config_input.resolve(strict=True)
    except OSError as exc:
        raise ConfigError(f"cannot resolve configuration: {config_input}") from exc
    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError("configuration must be UTF-8") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ConfigError:
        raise
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    except RecursionError as exc:
        raise ConfigError("configuration nesting is too deep") from exc
    _reject_deep_json(data)
    if not isinstance(data, dict):
        raise ConfigError("configuration root must be an object")
    return data, config_path


def load_config(path: str | Path) -> Config:
    data, config_path = load_config_data(path)
    try:
        return parse_config(data, config_path.parent, source=config_path)
    except RecursionError as exc:
        raise ConfigError("configuration nesting is too deep") from exc
