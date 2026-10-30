"""Strict configuration loading for L4Wall.

The configuration is deliberately boring: JSON, explicit keys, no implicit
defaults that widen exposure. Unknown keys are rejected so a typo cannot
silently turn a deny rule into an allow rule.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from .errors import ConfigError

CONFIG_VERSION = 1
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be an object")
    return value


def _check_keys(raw: dict[str, Any], allowed: Iterable[str], where: str) -> None:
    extra = sorted(set(raw) - set(allowed))
    if extra:
        names = ", ".join(extra)
        raise ConfigError(f"{where} has unknown key(s): {names}")


def _string(value: Any, where: str, *, min_length: int = 1, max_length: int = 255) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{where} must be a string")
    text = value.strip()
    if len(text) < min_length:
        raise ConfigError(f"{where} must not be empty")
    if len(text) > max_length:
        raise ConfigError(f"{where} is too long")
    return text


def _int(value: Any, where: str, default: int, *, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where} must be an integer")
    if value < minimum or value > maximum:
        raise ConfigError(f"{where} must be between {minimum} and {maximum}")
    return value


def _float(value: Any, where: str, default: float, *, minimum: float, maximum: float) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ConfigError(f"{where} must be finite")
    if number < minimum or number > maximum:
        raise ConfigError(f"{where} must be between {minimum} and {maximum}")
    return number


def _bool(value: Any, where: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false")
    return value


def _networks(value: Any, where: str) -> tuple[IPNetwork, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"{where} must be an array of CIDR strings")
    result: list[IPNetwork] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"{where}[{index}] must be a non-empty CIDR string")
        text = item.strip()
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ConfigError(f"{where}[{index}] is not a valid CIDR: {text}") from exc
        canonical = str(network)
        if canonical not in seen:
            seen.add(canonical)
            result.append(network)
    return tuple(result)


def _is_loopback_host(host: str) -> bool:
    lowered = host.casefold()
    if lowered in {"localhost", "localhost.localdomain"}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_loopback


@dataclass(frozen=True)
class ServerConfig:
    listen_host: str
    max_connections: int
    max_connections_per_ip: int
    accept_backlog: int
    shutdown_timeout: float
    require_client_allowlist: bool


@dataclass(frozen=True)
class ListenerConfig:
    name: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    allowed_client_networks: tuple[IPNetwork, ...]
    denied_client_networks: tuple[IPNetwork, ...]
    connect_timeout: float
    first_byte_timeout: float
    idle_timeout: float
    max_connection_seconds: float
    max_bytes_per_direction: int
    max_connections_per_ip: int
    new_connections_per_second: float
    new_connections_burst: int
    read_chunk_bytes: int


@dataclass(frozen=True)
class SharedBansConfig:
    enabled: bool
    backend: str
    host: str
    port: int
    db: int
    key: str
    connect_timeout: float
    read_timeout: float
    sync_interval_seconds: float
    password_env: str
    max_payload_bytes: int
    max_ttl_seconds: float


@dataclass(frozen=True)
class ThreatConfig:
    enabled: bool
    mode: str
    window_seconds: float
    min_connections: int
    min_distinct_listeners: int
    min_short_connections: int
    min_zero_byte_connections: int
    min_rejections: int
    short_connection_seconds: float
    short_connection_bytes: int
    regular_timing_max_cv: float
    agent_min_signals: int
    agent_score: int
    score_threshold: int
    confirm_score: int
    confirm_after_seconds: float
    containment_seconds: float
    confirmed_containment_seconds: float
    throttle_ms: int
    max_throttle_ms: int
    max_tracked_clients: int
    max_listeners_per_client: int
    mark_ttl_seconds: float
    offender_path: str
    ban_prefix_v4: int
    ban_prefix_v6: int
    max_ban_entries: int
    shared_bans: SharedBansConfig


@dataclass(frozen=True)
class AuditConfig:
    path: str
    max_bytes: int
    backup_count: int
    include_client_ip: bool
    on_write_failure: str


@dataclass(frozen=True)
class AdminConfig:
    enabled: bool
    listen_host: str
    listen_port: int
    token_env: str
    audit_tail_max_lines: int
    request_timeout: float


@dataclass(frozen=True)
class GatewayConfig:
    version: int
    server: ServerConfig
    listeners: tuple[ListenerConfig, ...]
    threat: ThreatConfig
    audit: AuditConfig
    admin: AdminConfig
    metrics_enabled: bool


_TOP_KEYS = {"version", "server", "listeners", "threat_detection", "audit", "admin", "metrics"}
_SERVER_KEYS = {
    "listen_host",
    "max_connections",
    "max_connections_per_ip",
    "accept_backlog",
    "shutdown_timeout",
    "require_client_allowlist",
}
_LISTENER_KEYS = {
    "name",
    "listen_port",
    "upstream_host",
    "upstream_port",
    "allowed_client_networks",
    "denied_client_networks",
    "connect_timeout",
    "first_byte_timeout",
    "idle_timeout",
    "max_connection_seconds",
    "max_bytes_per_direction",
    "max_connections_per_ip",
    "new_connections_per_second",
    "new_connections_burst",
    "read_chunk_bytes",
}
_THREAT_KEYS = {
    "enabled",
    "mode",
    "window_seconds",
    "min_connections",
    "min_distinct_listeners",
    "min_short_connections",
    "min_zero_byte_connections",
    "min_rejections",
    "short_connection_seconds",
    "short_connection_bytes",
    "regular_timing_max_cv",
    "agent_min_signals",
    "agent_score",
    "score_threshold",
    "confirm_score",
    "confirm_after_seconds",
    "containment_seconds",
    "confirmed_containment_seconds",
    "throttle_ms",
    "max_throttle_ms",
    "max_tracked_clients",
    "max_listeners_per_client",
    "mark_ttl_seconds",
    "offender_path",
    "ban_prefix_v4",
    "ban_prefix_v6",
    "max_ban_entries",
    "shared_bans",
}
_SHARED_BANS_KEYS = {
    "enabled",
    "backend",
    "host",
    "port",
    "db",
    "key",
    "connect_timeout",
    "read_timeout",
    "sync_interval_seconds",
    "password_env",
    "max_payload_bytes",
    "max_ttl_seconds",
}
_AUDIT_KEYS = {"path", "max_bytes", "backup_count", "include_client_ip", "on_write_failure"}
_ADMIN_KEYS = {"enabled", "listen_host", "listen_port", "token_env", "audit_tail_max_lines", "request_timeout"}
_METRICS_KEYS = {"enabled"}
_SHARED_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_SHARED_KEY_RE = re.compile(r"^[A-Za-z0-9:._-]{1,128}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _parse_server(raw: Any) -> ServerConfig:
    data = _mapping(raw, "server")
    _check_keys(data, _SERVER_KEYS, "server")
    listen_host = _string(data.get("listen_host", "127.0.0.1"), "server.listen_host")
    max_connections = _int(data.get("max_connections"), "server.max_connections", 512, minimum=1, maximum=100000)
    max_connections_per_ip = _int(
        data.get("max_connections_per_ip"), "server.max_connections_per_ip", 32, minimum=1, maximum=100000
    )
    if max_connections_per_ip > max_connections:
        raise ConfigError("server.max_connections_per_ip must not exceed server.max_connections")
    return ServerConfig(
        listen_host=listen_host,
        max_connections=max_connections,
        max_connections_per_ip=max_connections_per_ip,
        accept_backlog=_int(data.get("accept_backlog"), "server.accept_backlog", 128, minimum=1, maximum=65535),
        shutdown_timeout=_float(
            data.get("shutdown_timeout"), "server.shutdown_timeout", 30.0, minimum=0.1, maximum=3600.0
        ),
        require_client_allowlist=_bool(
            data.get("require_client_allowlist"), "server.require_client_allowlist", False
        ),
    )


def _parse_listener(raw: Any, server: ServerConfig, index: int) -> ListenerConfig:
    where = f"listeners[{index}]"
    data = _mapping(raw, where)
    _check_keys(data, _LISTENER_KEYS, where)
    name = _string(data.get("name"), f"{where}.name", max_length=64)
    listen_port = _int(data.get("listen_port"), f"{where}.listen_port", 0, minimum=1, maximum=65535)
    upstream_host = _string(data.get("upstream_host"), f"{where}.upstream_host")
    upstream_port = _int(data.get("upstream_port"), f"{where}.upstream_port", 0, minimum=1, maximum=65535)
    allowed = _networks(data.get("allowed_client_networks"), f"{where}.allowed_client_networks")
    denied = _networks(data.get("denied_client_networks"), f"{where}.denied_client_networks")
    if server.require_client_allowlist and not allowed:
        raise ConfigError(f"{where}.allowed_client_networks must not be empty when require_client_allowlist is true")
    if listen_port == upstream_port and _is_loopback_host(upstream_host):
        raise ConfigError(f"{where} would forward to itself; change listen_port or upstream_port")
    max_connections_per_ip = _int(
        data.get("max_connections_per_ip"),
        f"{where}.max_connections_per_ip",
        server.max_connections_per_ip,
        minimum=1,
        maximum=100000,
    )
    if max_connections_per_ip > server.max_connections:
        raise ConfigError(f"{where}.max_connections_per_ip must not exceed server.max_connections")
    return ListenerConfig(
        name=name,
        listen_port=listen_port,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        allowed_client_networks=allowed,
        denied_client_networks=denied,
        connect_timeout=_float(data.get("connect_timeout"), f"{where}.connect_timeout", 3.0, minimum=0.1, maximum=300.0),
        first_byte_timeout=_float(
            data.get("first_byte_timeout"), f"{where}.first_byte_timeout", 5.0, minimum=0.1, maximum=3600.0
        ),
        idle_timeout=_float(data.get("idle_timeout"), f"{where}.idle_timeout", 60.0, minimum=0.1, maximum=86400.0),
        max_connection_seconds=_float(
            data.get("max_connection_seconds"),
            f"{where}.max_connection_seconds",
            300.0,
            minimum=1.0,
            maximum=86400.0,
        ),
        max_bytes_per_direction=_int(
            data.get("max_bytes_per_direction"),
            f"{where}.max_bytes_per_direction",
            10 * 1024 * 1024,
            minimum=1,
            maximum=10 * 1024 * 1024 * 1024,
        ),
        max_connections_per_ip=max_connections_per_ip,
        new_connections_per_second=_float(
            data.get("new_connections_per_second"),
            f"{where}.new_connections_per_second",
            10.0,
            minimum=0.01,
            maximum=1000000.0,
        ),
        new_connections_burst=_int(
            data.get("new_connections_burst"),
            f"{where}.new_connections_burst",
            20,
            minimum=1,
            maximum=1000000,
        ),
        read_chunk_bytes=_int(
            data.get("read_chunk_bytes"), f"{where}.read_chunk_bytes", 65536, minimum=512, maximum=1024 * 1024
        ),
    )


def _parse_threat(raw: Any) -> ThreatConfig:
    data = _mapping(raw, "threat_detection")
    _check_keys(data, _THREAT_KEYS, "threat_detection")
    mode = _string(data.get("mode", "score"), "threat_detection.mode").casefold()
    if mode not in {"score", "throttle", "block"}:
        raise ConfigError("threat_detection.mode must be score, throttle, or block")
    score_threshold = _int(data.get("score_threshold"), "threat_detection.score_threshold", 70, minimum=0, maximum=100)
    confirm_score = _int(data.get("confirm_score"), "threat_detection.confirm_score", 85, minimum=0, maximum=100)
    if confirm_score < score_threshold:
        raise ConfigError("threat_detection.confirm_score must be greater than or equal to score_threshold")
    return ThreatConfig(
        enabled=_bool(data.get("enabled"), "threat_detection.enabled", True),
        mode=mode,
        window_seconds=_float(
            data.get("window_seconds"), "threat_detection.window_seconds", 10.0, minimum=1.0, maximum=86400.0
        ),
        min_connections=_int(data.get("min_connections"), "threat_detection.min_connections", 20, minimum=1, maximum=1000000),
        min_distinct_listeners=_int(
            data.get("min_distinct_listeners"), "threat_detection.min_distinct_listeners", 2, minimum=1, maximum=256
        ),
        min_short_connections=_int(
            data.get("min_short_connections"), "threat_detection.min_short_connections", 10, minimum=1, maximum=1000000
        ),
        min_zero_byte_connections=_int(
            data.get("min_zero_byte_connections"),
            "threat_detection.min_zero_byte_connections",
            5,
            minimum=1,
            maximum=1000000,
        ),
        min_rejections=_int(data.get("min_rejections"), "threat_detection.min_rejections", 5, minimum=1, maximum=1000000),
        short_connection_seconds=_float(
            data.get("short_connection_seconds"),
            "threat_detection.short_connection_seconds",
            1.0,
            minimum=0.01,
            maximum=3600.0,
        ),
        short_connection_bytes=_int(
            data.get("short_connection_bytes"),
            "threat_detection.short_connection_bytes",
            64,
            minimum=0,
            maximum=1048576,
        ),
        regular_timing_max_cv=_float(
            data.get("regular_timing_max_cv"),
            "threat_detection.regular_timing_max_cv",
            0.25,
            minimum=0.0,
            maximum=10.0,
        ),
        agent_min_signals=_int(
            data.get("agent_min_signals"), "threat_detection.agent_min_signals", 3, minimum=1, maximum=8
        ),
        agent_score=_int(data.get("agent_score"), "threat_detection.agent_score", 30, minimum=0, maximum=100),
        score_threshold=score_threshold,
        confirm_score=confirm_score,
        confirm_after_seconds=_float(
            data.get("confirm_after_seconds"),
            "threat_detection.confirm_after_seconds",
            300.0,
            minimum=1.0,
            maximum=86400.0,
        ),
        containment_seconds=_float(
            data.get("containment_seconds"),
            "threat_detection.containment_seconds",
            300.0,
            minimum=1.0,
            maximum=86400.0,
        ),
        confirmed_containment_seconds=_float(
            data.get("confirmed_containment_seconds"),
            "threat_detection.confirmed_containment_seconds",
            900.0,
            minimum=1.0,
            maximum=86400.0,
        ),
        throttle_ms=_int(data.get("throttle_ms"), "threat_detection.throttle_ms", 500, minimum=0, maximum=60000),
        max_throttle_ms=_int(
            data.get("max_throttle_ms"), "threat_detection.max_throttle_ms", 3000, minimum=0, maximum=60000
        ),
        max_tracked_clients=_int(
            data.get("max_tracked_clients"), "threat_detection.max_tracked_clients", 10000, minimum=1, maximum=1000000
        ),
        max_listeners_per_client=_int(
            data.get("max_listeners_per_client"),
            "threat_detection.max_listeners_per_client",
            64,
            minimum=1,
            maximum=65535,
        ),
        mark_ttl_seconds=_float(
            data.get("mark_ttl_seconds"), "threat_detection.mark_ttl_seconds", 86400.0, minimum=60.0, maximum=31536000.0
        ),
        offender_path=_string(
            data.get("offender_path", "offenders.json"), "threat_detection.offender_path", max_length=1024
        ),
        ban_prefix_v4=_int(data.get("ban_prefix_v4"), "threat_detection.ban_prefix_v4", 32, minimum=24, maximum=32),
        ban_prefix_v6=_int(data.get("ban_prefix_v6"), "threat_detection.ban_prefix_v6", 128, minimum=48, maximum=128),
        max_ban_entries=_int(
            data.get("max_ban_entries"), "threat_detection.max_ban_entries", 10000, minimum=1, maximum=1000000
        ),
        shared_bans=_parse_shared_bans(data.get("shared_bans", {})),
    )


def _parse_shared_bans(raw: Any) -> SharedBansConfig:
    data = _mapping(raw, "threat_detection.shared_bans")
    _check_keys(data, _SHARED_BANS_KEYS, "threat_detection.shared_bans")
    backend = _string(
        data.get("backend", "redis"), "threat_detection.shared_bans.backend", max_length=32
    ).casefold()
    if backend != "redis":
        raise ConfigError("threat_detection.shared_bans.backend must be redis")
    host = _string(data.get("host", "127.0.0.1"), "threat_detection.shared_bans.host", max_length=253).casefold()
    if not _SHARED_HOST_RE.fullmatch(host):
        raise ConfigError("threat_detection.shared_bans.host contains invalid characters")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if address.is_unspecified or address.is_multicast or (not address.is_private and not address.is_loopback):
            raise ConfigError(
                "threat_detection.shared_bans.host must be loopback or a private address; "
                "put Redis on a private management network"
            )
    key = _string(data.get("key", "l4wall:bans:v1"), "threat_detection.shared_bans.key", max_length=128)
    if not _SHARED_KEY_RE.fullmatch(key):
        raise ConfigError("threat_detection.shared_bans.key must use only letters, digits, ':', '.', '_' or '-'")
    password_env = _string(
        data.get("password_env", ""),
        "threat_detection.shared_bans.password_env",
        min_length=0,
        max_length=128,
    )
    if password_env and not _ENV_NAME_RE.fullmatch(password_env):
        raise ConfigError("threat_detection.shared_bans.password_env must be a valid environment variable name")
    return SharedBansConfig(
        enabled=_bool(data.get("enabled"), "threat_detection.shared_bans.enabled", False),
        backend=backend,
        host=host,
        port=_int(data.get("port"), "threat_detection.shared_bans.port", 6379, minimum=1, maximum=65535),
        db=_int(data.get("db"), "threat_detection.shared_bans.db", 0, minimum=0, maximum=15),
        key=key,
        connect_timeout=_float(
            data.get("connect_timeout"),
            "threat_detection.shared_bans.connect_timeout",
            0.5,
            minimum=0.05,
            maximum=10.0,
        ),
        read_timeout=_float(
            data.get("read_timeout"),
            "threat_detection.shared_bans.read_timeout",
            0.5,
            minimum=0.05,
            maximum=10.0,
        ),
        sync_interval_seconds=_float(
            data.get("sync_interval_seconds"),
            "threat_detection.shared_bans.sync_interval_seconds",
            1.0,
            minimum=0.1,
            maximum=3600.0,
        ),
        password_env=password_env,
        max_payload_bytes=_int(
            data.get("max_payload_bytes"),
            "threat_detection.shared_bans.max_payload_bytes",
            1048576,
            minimum=1024,
            maximum=16 * 1024 * 1024,
        ),
        max_ttl_seconds=_float(
            data.get("max_ttl_seconds"),
            "threat_detection.shared_bans.max_ttl_seconds",
            86400.0,
            minimum=1.0,
            maximum=31536000.0,
        ),
    )


def _parse_audit(raw: Any) -> AuditConfig:
    data = _mapping(raw, "audit")
    _check_keys(data, _AUDIT_KEYS, "audit")
    on_write_failure = _string(data.get("on_write_failure", "fail_closed"), "audit.on_write_failure").casefold()
    if on_write_failure not in {"fail_closed", "continue"}:
        raise ConfigError("audit.on_write_failure must be fail_closed or continue")
    return AuditConfig(
        path=_string(data.get("path", "audit.jsonl"), "audit.path", max_length=1024),
        max_bytes=_int(data.get("max_bytes"), "audit.max_bytes", 10 * 1024 * 1024, minimum=4096, maximum=10 * 1024 * 1024 * 1024),
        backup_count=_int(data.get("backup_count"), "audit.backup_count", 5, minimum=1, maximum=100),
        include_client_ip=_bool(data.get("include_client_ip"), "audit.include_client_ip", True),
        on_write_failure=on_write_failure,
    )


def _parse_admin(raw: Any) -> AdminConfig:
    data = _mapping(raw, "admin")
    _check_keys(data, _ADMIN_KEYS, "admin")
    listen_host = _string(data.get("listen_host", "127.0.0.1"), "admin.listen_host")
    if not _is_loopback_host(listen_host):
        raise ConfigError("admin.listen_host must be a loopback address")
    return AdminConfig(
        enabled=_bool(data.get("enabled"), "admin.enabled", False),
        listen_host=listen_host,
        listen_port=_int(data.get("listen_port"), "admin.listen_port", 18091, minimum=1, maximum=65535),
        token_env=_string(data.get("token_env", "L4WALL_ADMIN_TOKEN"), "admin.token_env", max_length=128),
        audit_tail_max_lines=_int(
            data.get("audit_tail_max_lines"), "admin.audit_tail_max_lines", 200, minimum=1, maximum=10000
        ),
        request_timeout=_float(
            data.get("request_timeout"), "admin.request_timeout", 5.0, minimum=0.1, maximum=60.0
        ),
    )


def parse_config(raw: Any) -> GatewayConfig:
    """Validate and normalize a configuration object."""
    data = _mapping(raw, "config")
    _check_keys(data, _TOP_KEYS, "config")
    version = _int(data.get("version"), "version", CONFIG_VERSION, minimum=CONFIG_VERSION, maximum=CONFIG_VERSION)
    server = _parse_server(data.get("server", {}))
    listeners_raw = data.get("listeners")
    if not isinstance(listeners_raw, list) or not listeners_raw:
        raise ConfigError("listeners must be a non-empty array")
    if len(listeners_raw) > 256:
        raise ConfigError("listeners must contain at most 256 entries")
    listeners = tuple(_parse_listener(item, server, index) for index, item in enumerate(listeners_raw))
    names: set[str] = set()
    ports: set[int] = set()
    for listener in listeners:
        if listener.name in names:
            raise ConfigError(f"duplicate listener name: {listener.name}")
        if listener.listen_port in ports:
            raise ConfigError(f"duplicate listen_port: {listener.listen_port}")
        names.add(listener.name)
        ports.add(listener.listen_port)
    metrics_raw = _mapping(data.get("metrics", {}), "metrics")
    _check_keys(metrics_raw, _METRICS_KEYS, "metrics")
    return GatewayConfig(
        version=version,
        server=server,
        listeners=listeners,
        threat=_parse_threat(data.get("threat_detection", {})),
        audit=_parse_audit(data.get("audit", {})),
        admin=_parse_admin(data.get("admin", {})),
        metrics_enabled=_bool(metrics_raw.get("enabled"), "metrics.enabled", True),
    )


def load_config(path: str | Path) -> GatewayConfig:
    """Load and validate a JSON configuration file."""
    config_path = Path(path)
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {config_path}: {exc}") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config {config_path} is not valid JSON: {exc}") from exc
    return parse_config(raw)


def resolve_runtime_paths(config: GatewayConfig, base_dir: str | Path) -> GatewayConfig:
    """Resolve relative audit/offender paths against the config file directory."""
    base = Path(base_dir)

    def resolve(value: str) -> str:
        candidate = Path(value)
        return str(candidate if candidate.is_absolute() else base / candidate)

    return replace(
        config,
        audit=replace(config.audit, path=resolve(config.audit.path)),
        threat=replace(config.threat, offender_path=resolve(config.threat.offender_path)),
    )


def config_to_dict(config: GatewayConfig) -> dict[str, Any]:
    """Return a JSON-serializable effective configuration without secret references."""
    return {
        "version": config.version,
        "server": {
            "listen_host": config.server.listen_host,
            "max_connections": config.server.max_connections,
            "max_connections_per_ip": config.server.max_connections_per_ip,
            "accept_backlog": config.server.accept_backlog,
            "shutdown_timeout": config.server.shutdown_timeout,
            "require_client_allowlist": config.server.require_client_allowlist,
        },
        "listeners": [
            {
                "name": listener.name,
                "listen_port": listener.listen_port,
                "upstream_host": listener.upstream_host,
                "upstream_port": listener.upstream_port,
                "allowed_client_networks": [str(network) for network in listener.allowed_client_networks],
                "denied_client_networks": [str(network) for network in listener.denied_client_networks],
                "connect_timeout": listener.connect_timeout,
                "first_byte_timeout": listener.first_byte_timeout,
                "idle_timeout": listener.idle_timeout,
                "max_connection_seconds": listener.max_connection_seconds,
                "max_bytes_per_direction": listener.max_bytes_per_direction,
                "max_connections_per_ip": listener.max_connections_per_ip,
                "new_connections_per_second": listener.new_connections_per_second,
                "new_connections_burst": listener.new_connections_burst,
                "read_chunk_bytes": listener.read_chunk_bytes,
            }
            for listener in config.listeners
        ],
        "threat_detection": {
            "enabled": config.threat.enabled,
            "mode": config.threat.mode,
            "window_seconds": config.threat.window_seconds,
            "min_connections": config.threat.min_connections,
            "min_distinct_listeners": config.threat.min_distinct_listeners,
            "min_short_connections": config.threat.min_short_connections,
            "min_zero_byte_connections": config.threat.min_zero_byte_connections,
            "min_rejections": config.threat.min_rejections,
            "short_connection_seconds": config.threat.short_connection_seconds,
            "short_connection_bytes": config.threat.short_connection_bytes,
            "regular_timing_max_cv": config.threat.regular_timing_max_cv,
            "agent_min_signals": config.threat.agent_min_signals,
            "agent_score": config.threat.agent_score,
            "score_threshold": config.threat.score_threshold,
            "confirm_score": config.threat.confirm_score,
            "confirm_after_seconds": config.threat.confirm_after_seconds,
            "containment_seconds": config.threat.containment_seconds,
            "confirmed_containment_seconds": config.threat.confirmed_containment_seconds,
            "throttle_ms": config.threat.throttle_ms,
            "max_throttle_ms": config.threat.max_throttle_ms,
            "max_tracked_clients": config.threat.max_tracked_clients,
            "max_listeners_per_client": config.threat.max_listeners_per_client,
            "mark_ttl_seconds": config.threat.mark_ttl_seconds,
            "offender_path": config.threat.offender_path,
            "ban_prefix_v4": config.threat.ban_prefix_v4,
            "ban_prefix_v6": config.threat.ban_prefix_v6,
            "max_ban_entries": config.threat.max_ban_entries,
            "shared_bans": {
                "enabled": config.threat.shared_bans.enabled,
                "backend": config.threat.shared_bans.backend,
                "host": config.threat.shared_bans.host,
                "port": config.threat.shared_bans.port,
                "db": config.threat.shared_bans.db,
                "key": config.threat.shared_bans.key,
                "connect_timeout": config.threat.shared_bans.connect_timeout,
                "read_timeout": config.threat.shared_bans.read_timeout,
                "sync_interval_seconds": config.threat.shared_bans.sync_interval_seconds,
                "max_payload_bytes": config.threat.shared_bans.max_payload_bytes,
                "max_ttl_seconds": config.threat.shared_bans.max_ttl_seconds,
            },
        },
        "audit": {
            "path": config.audit.path,
            "max_bytes": config.audit.max_bytes,
            "backup_count": config.audit.backup_count,
            "include_client_ip": config.audit.include_client_ip,
            "on_write_failure": config.audit.on_write_failure,
        },
        "admin": {
            "enabled": config.admin.enabled,
            "listen_host": config.admin.listen_host,
            "listen_port": config.admin.listen_port,
            "audit_tail_max_lines": config.admin.audit_tail_max_lines,
            "request_timeout": config.admin.request_timeout,
        },
        "metrics": {"enabled": config.metrics_enabled},
    }


def example_config() -> dict[str, Any]:
    """Return a conservative, loopback-only example configuration."""
    listener = {
        "name": "web",
        "listen_port": 18080,
        "upstream_host": "127.0.0.1",
        "upstream_port": 18082,
        "allowed_client_networks": ["127.0.0.1/32", "::1/128"],
        "denied_client_networks": [],
        "connect_timeout": 3.0,
        "first_byte_timeout": 5.0,
        "idle_timeout": 60.0,
        "max_connection_seconds": 300.0,
        "max_bytes_per_direction": 10485760,
        "max_connections_per_ip": 16,
        "new_connections_per_second": 10.0,
        "new_connections_burst": 20,
        "read_chunk_bytes": 65536,
    }
    api = dict(listener)
    api.update({"name": "api", "listen_port": 18081, "upstream_port": 18083})
    return {
        "version": CONFIG_VERSION,
        "server": {
            "listen_host": "127.0.0.1",
            "max_connections": 512,
            "max_connections_per_ip": 32,
            "accept_backlog": 128,
            "shutdown_timeout": 30.0,
            "require_client_allowlist": False,
        },
        "listeners": [listener, api],
        "threat_detection": {
            "enabled": True,
            "mode": "score",
            "window_seconds": 10.0,
            "min_connections": 20,
            "min_distinct_listeners": 2,
            "min_short_connections": 10,
            "min_zero_byte_connections": 5,
            "min_rejections": 5,
            "short_connection_seconds": 1.0,
            "short_connection_bytes": 64,
            "regular_timing_max_cv": 0.25,
            "agent_min_signals": 3,
            "agent_score": 30,
            "score_threshold": 70,
            "confirm_score": 85,
            "confirm_after_seconds": 300.0,
            "containment_seconds": 300.0,
            "confirmed_containment_seconds": 900.0,
            "throttle_ms": 500,
            "max_throttle_ms": 3000,
            "max_tracked_clients": 10000,
            "max_listeners_per_client": 64,
            "mark_ttl_seconds": 86400.0,
            "offender_path": "offenders.json",
            "ban_prefix_v4": 32,
            "ban_prefix_v6": 128,
            "max_ban_entries": 10000,
            "shared_bans": {
                "enabled": False,
                "backend": "redis",
                "host": "127.0.0.1",
                "port": 6379,
                "db": 0,
                "key": "l4wall:bans:v1",
                "connect_timeout": 0.5,
                "read_timeout": 0.5,
                "sync_interval_seconds": 1.0,
                "password_env": "",
                "max_payload_bytes": 1048576,
                "max_ttl_seconds": 86400.0,
            },
        },
        "audit": {
            "path": "audit.jsonl",
            "max_bytes": 10485760,
            "backup_count": 5,
            "include_client_ip": True,
            "on_write_failure": "fail_closed",
        },
        "admin": {
            "enabled": False,
            "listen_host": "127.0.0.1",
            "listen_port": 18091,
            "token_env": "L4WALL_ADMIN_TOKEN",
            "audit_tail_max_lines": 200,
            "request_timeout": 5.0,
        },
        "metrics": {"enabled": True},
    }


def write_example(path: str | Path, *, force: bool = False) -> None:
    """Write the example config, refusing to clobber an existing file by default."""
    target = Path(path)
    if target.exists() and not force:
        raise ConfigError(f"refusing to overwrite existing config: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(example_config(), indent=2) + "\n", encoding="utf-8")

