"""Strict L5Wall configuration."""

from __future__ import annotations

import ipaddress
import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_CONFIG_BYTES = 1024 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_ALPN_RE = re.compile(r"^[\x21-\x7e]{1,255}$")


class ConfigError(ValueError):
    """A safe, actionable configuration error."""


@dataclass(frozen=True)
class L5Config:
    cert_file: Path
    key_file: Path
    min_version: str = "TLSv1_2"
    allowed_alpn: tuple[str, ...] = ("http/1.1",)
    allowed_sni: tuple[str, ...] = ("localhost",)
    allow_missing_sni: bool = False
    mtls_mode: str = "off"
    client_ca_file: Path | None = None
    handshake_timeout: float = 5.0
    listen_host: str = "127.0.0.1"
    listen_port: int = 18443
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 18080
    max_connections: int = 128
    connect_timeout: float = 5.0
    idle_timeout: float = 30.0
    max_bytes_per_direction: int = 64 * 1024 * 1024
    max_request_head_bytes: int = 32 * 1024
    require_sni_host_match: bool = True

    def as_public(self) -> dict[str, Any]:
        return {
            "cert_file": str(self.cert_file),
            "key_file": str(self.key_file),
            "min_version": self.min_version,
            "allowed_alpn": list(self.allowed_alpn),
            "allowed_sni": list(self.allowed_sni),
            "allow_missing_sni": self.allow_missing_sni,
            "mtls_mode": self.mtls_mode,
            "client_ca_file": str(self.client_ca_file) if self.client_ca_file is not None else None,
            "handshake_timeout": self.handshake_timeout,
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "upstream_host": self.upstream_host,
            "upstream_port": self.upstream_port,
            "max_connections": self.max_connections,
            "connect_timeout": self.connect_timeout,
            "idle_timeout": self.idle_timeout,
            "max_bytes_per_direction": self.max_bytes_per_direction,
            "max_request_head_bytes": self.max_request_head_bytes,
            "require_sni_host_match": self.require_sni_host_match,
        }


def load_config(path: str | Path) -> L5Config:
    config_path = Path(path)
    try:
        info = config_path.lstat()
    except OSError as exc:
        raise ConfigError("configuration file cannot be inspected") from exc
    attributes = getattr(info, "st_file_attributes", 0)
    if stat.S_ISLNK(info.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise ConfigError("configuration file must not be a symbolic link or reparse point")
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError("configuration file must be a regular file")
    if info.st_size > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file is too large")
    try:
        raw = config_path.read_bytes()
    except OSError as exc:
        raise ConfigError("configuration file cannot be read") from exc
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError("configuration file is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ConfigError("configuration must be a JSON object")
    return parse_config(value, config_path.parent)


def parse_config(value: Any, base_dir: Path) -> L5Config:
    if not isinstance(value, dict):
        raise ConfigError("configuration must be a JSON object")
    allowed = {
        "cert_file",
        "key_file",
        "min_version",
        "allowed_alpn",
        "allowed_sni",
        "allow_missing_sni",
        "mtls_mode",
        "client_ca_file",
        "handshake_timeout",
        "listen_host",
        "listen_port",
        "upstream_host",
        "upstream_port",
        "max_connections",
        "connect_timeout",
        "idle_timeout",
        "max_bytes_per_direction",
        "max_request_head_bytes",
        "require_sni_host_match",
    }
    unknown = set(value) - allowed
    if unknown:
        raise ConfigError("configuration contains an unknown field")

    cert_file = _path_field(value.get("cert_file"), "cert_file", base_dir, required=True)
    key_file = _path_field(value.get("key_file"), "key_file", base_dir, required=True)
    assert cert_file is not None and key_file is not None
    client_ca_file = _path_field(value.get("client_ca_file"), "client_ca_file", base_dir, required=False)

    min_version = value.get("min_version", "TLSv1_2")
    if min_version not in {"TLSv1_2", "TLSv1_3"}:
        raise ConfigError("min_version must be TLSv1_2 or TLSv1_3")

    alpn_value = value.get("allowed_alpn", ["http/1.1"])
    if not isinstance(alpn_value, list) or not 1 <= len(alpn_value) <= 16:
        raise ConfigError("allowed_alpn must contain 1 to 16 entries")
    allowed_alpn: list[str] = []
    for item in alpn_value:
        if not isinstance(item, str) or not _ALPN_RE.fullmatch(item):
            raise ConfigError("allowed_alpn contains an invalid protocol token")
        if item in allowed_alpn:
            raise ConfigError("allowed_alpn contains a duplicate protocol")
        allowed_alpn.append(item)

    sni_value = value.get("allowed_sni", ["localhost"])
    if not isinstance(sni_value, list) or not 1 <= len(sni_value) <= 64:
        raise ConfigError("allowed_sni must contain 1 to 64 entries")
    allowed_sni: list[str] = []
    for item in sni_value:
        if not isinstance(item, str):
            raise ConfigError("allowed_sni contains a non-string value")
        normalized = _normalize_sni_pattern(item)
        if normalized in allowed_sni:
            raise ConfigError("allowed_sni contains a duplicate name")
        allowed_sni.append(normalized)

    allow_missing_sni = value.get("allow_missing_sni", False)
    if not isinstance(allow_missing_sni, bool):
        raise ConfigError("allow_missing_sni must be a boolean")

    mtls_mode = value.get("mtls_mode", "off")
    if mtls_mode not in {"off", "optional", "required"}:
        raise ConfigError("mtls_mode must be off, optional, or required")
    if mtls_mode == "off" and client_ca_file is not None:
        raise ConfigError("client_ca_file requires mtls_mode optional or required")
    if mtls_mode != "off" and client_ca_file is None:
        raise ConfigError("client_ca_file is required when mTLS is enabled")

    timeout_value = value.get("handshake_timeout", 5.0)
    if not isinstance(timeout_value, (int, float)) or isinstance(timeout_value, bool):
        raise ConfigError("handshake_timeout must be a number")
    handshake_timeout = float(timeout_value)
    if not 0.1 <= handshake_timeout <= 60.0:
        raise ConfigError("handshake_timeout must be between 0.1 and 60 seconds")

    listen_host = _loopback_host(value.get("listen_host", "127.0.0.1"), "listen_host")
    upstream_host = _loopback_host(value.get("upstream_host", "127.0.0.1"), "upstream_host")
    listen_port = _integer(value.get("listen_port", 18443), "listen_port", 0, 65535)
    upstream_port = _integer(value.get("upstream_port", 18080), "upstream_port", 1, 65535)
    max_connections = _integer(value.get("max_connections", 128), "max_connections", 1, 4096)
    connect_timeout = _number(value.get("connect_timeout", 5.0), "connect_timeout", 0.1, 30.0)
    idle_timeout = _number(value.get("idle_timeout", 30.0), "idle_timeout", 0.1, 300.0)
    max_bytes_per_direction = _integer(
        value.get("max_bytes_per_direction", 64 * 1024 * 1024),
        "max_bytes_per_direction",
        1024,
        1024 * 1024 * 1024,
    )
    max_request_head_bytes = _integer(
        value.get("max_request_head_bytes", 32 * 1024),
        "max_request_head_bytes",
        1024,
        64 * 1024,
    )
    require_sni_host_match = value.get("require_sni_host_match", True)
    if not isinstance(require_sni_host_match, bool):
        raise ConfigError("require_sni_host_match must be a boolean")

    return L5Config(
        cert_file=cert_file,
        key_file=key_file,
        min_version=min_version,
        allowed_alpn=tuple(allowed_alpn),
        allowed_sni=tuple(allowed_sni),
        allow_missing_sni=allow_missing_sni,
        mtls_mode=mtls_mode,
        client_ca_file=client_ca_file,
        handshake_timeout=handshake_timeout,
        listen_host=listen_host,
        listen_port=listen_port,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        max_connections=max_connections,
        connect_timeout=connect_timeout,
        idle_timeout=idle_timeout,
        max_bytes_per_direction=max_bytes_per_direction,
        max_request_head_bytes=max_request_head_bytes,
        require_sni_host_match=require_sni_host_match,
    )


def _path_field(value: Any, name: str, base_dir: Path, *, required: bool) -> Path | None:
    if value is None:
        if required:
            raise ConfigError(f"{name} is required")
        return None
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ConfigError(f"{name} must be a non-empty path string")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError as exc:
        raise ConfigError(f"{name} must exist and be readable") from exc
    attributes = getattr(info, "st_file_attributes", 0)
    if stat.S_ISLNK(info.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise ConfigError(f"{name} must not be a symbolic link or reparse point")
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError(f"{name} must be a regular file")
    return resolved


def _normalize_sni_pattern(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    wildcard = candidate.startswith("*.")
    host = candidate[2:] if wildcard else candidate
    if not host or len(host) > 253 or not _LABEL_RE.fullmatch(host):
        raise ConfigError("allowed_sni contains an invalid DNS name")
    if any(label.startswith("-") or label.endswith("-") or not label for label in host.split(".")):
        raise ConfigError("allowed_sni contains an invalid DNS label")
    return f"*.{host}" if wildcard else host


def _loopback_host(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ConfigError(f"{name} must be an IP address string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a literal IP address") from exc
    if not address.is_loopback:
        raise ConfigError(f"{name} must be a loopback address in this preview")
    return str(address)


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"{name} must be a number")
    number = float(value)
    if not minimum <= number <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return number


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("configuration contains a duplicate key")
        result[key] = value
    return result
