"""Generate compact deployment configurations without hidden overwrites."""

from __future__ import annotations

import copy
import json
import os
import stat
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Iterable

from .config import ConfigError, parse_config
from .honeypot_templates import expand_honeypot_presets

_ALLOWED_UPSTREAM_SCHEMES = {"http", "https"}
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def parse_upstream_url(value: str) -> tuple[str, str, int]:
    """Parse an HTTP upstream URL into scheme, host, and port."""

    if not isinstance(value, str) or not value.strip():
        raise ConfigError("upstream URL must not be empty")
    text = value.strip()
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError as exc:
        raise ConfigError("upstream URL is malformed") from exc
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_UPSTREAM_SCHEMES:
        raise ConfigError("upstream URL scheme must be http or https")
    if parts.username is not None or parts.password is not None:
        raise ConfigError("upstream URL must not contain user information")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ConfigError("upstream URL must not contain a path, query, or fragment")
    host = parts.hostname
    if not host:
        raise ConfigError("upstream URL must include a host")
    try:
        port = parts.port
    except ValueError as exc:
        raise ConfigError("upstream URL contains an invalid port") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def build_initial_config(
    *,
    upstream_scheme: str,
    upstream_host: str,
    upstream_port: int,
    listen_host: str,
    listen_port: int,
    allowed_hosts: Iterable[str],
    allowed_methods: Iterable[str],
    honeypot_presets: Iterable[str],
    audit_path: str = "audit.jsonl",
    base_dir: Path | str = ".",
) -> dict[str, Any]:
    """Build and validate a small fail-closed deployment configuration."""

    hosts = tuple(allowed_hosts)
    if not hosts:
        raise ConfigError("at least one allowed host is required")
    methods = tuple(method.upper() for method in allowed_methods)
    presets = tuple(honeypot_presets)
    if presets:
        try:
            expanded = expand_honeypot_presets(presets)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        honeypot: dict[str, Any] = {
            "enabled": True,
            "ban_seconds": 0,
            "presets": list(presets),
        }
        if not expanded:
            honeypot["enabled"] = False
    else:
        honeypot = {"enabled": False}

    data: dict[str, Any] = {
        "version": 1,
        "server": {
            "listen_host": listen_host,
            "listen_port": listen_port,
            "max_connections": 64,
            "max_connections_per_ip": 16,
            "max_inflight_requests": 32,
        },
        "upstream": {
            "scheme": upstream_scheme,
            "host": upstream_host,
            "port": upstream_port,
            "circuit_breaker": {
                "enabled": True,
                "failure_threshold": 5,
                "window": 30.0,
                "open_seconds": 30.0,
                "half_open_max_requests": 1,
            },
        },
        "policy": {
            "allowed_hosts": list(hosts),
            "allowed_methods": list(methods),
            "allowed_path_prefixes": ["/"],
            "allow_path_parameters": False,
            "allow_trailing_dot_or_space": False,
            "read_only": False,
            "waf_enabled": True,
            "waf_mode": "block",
            "waf_rules": ["sqli", "xss", "traversal", "cmdi", "jndi", "ssrf"],
            "response_scan_mode": "block",
            "response_scan_headers": True,
            "honeypot": honeypot,
        },
        "audit": {"path": audit_path, "path_mode": "redact"},
        "admin": {"enabled": False},
    }
    parse_config(data, base_dir)
    return data


def update_config_data(
    base: dict[str, Any],
    *,
    upstream_scheme: str | None = None,
    upstream_host: str | None = None,
    upstream_port: int | None = None,
    listen_host: str | None = None,
    listen_port: int | None = None,
    allowed_hosts: Iterable[str] | None = None,
    allowed_methods: Iterable[str] | None = None,
    honeypot_presets: Iterable[str] | None = None,
    disable_honeypot: bool = False,
    audit_path: str | None = None,
    base_dir: Path | str = ".",
) -> dict[str, Any]:
    """Merge explicit deployment fields into an existing configuration."""

    data = copy.deepcopy(base)
    upstream_values = (upstream_scheme, upstream_host, upstream_port)
    if any(value is not None for value in upstream_values):
        if any(value is None for value in upstream_values):
            raise ConfigError("upstream scheme, host, and port must be updated together")
        upstream = data.setdefault("upstream", {})
        upstream["scheme"] = upstream_scheme
        upstream["host"] = upstream_host
        upstream["port"] = upstream_port

    server = data.setdefault("server", {})
    if listen_host is not None:
        server["listen_host"] = listen_host
    if listen_port is not None:
        server["listen_port"] = listen_port
    policy = data.setdefault("policy", {})
    if allowed_hosts is not None:
        hosts = tuple(allowed_hosts)
        if not hosts:
            raise ConfigError("at least one allowed host is required")
        policy["allowed_hosts"] = list(hosts)
    if allowed_methods is not None:
        policy["allowed_methods"] = [method.upper() for method in allowed_methods]

    if disable_honeypot and honeypot_presets is not None:
        raise ConfigError("disable_honeypot and honeypot_presets are mutually exclusive")
    if disable_honeypot:
        honeypot = policy.get("honeypot")
        if not isinstance(honeypot, dict):
            honeypot = {}
        honeypot["enabled"] = False
        policy["honeypot"] = honeypot
    elif honeypot_presets is not None:
        presets = tuple(honeypot_presets)
        try:
            expanded = expand_honeypot_presets(presets)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        honeypot = policy.get("honeypot")
        if not isinstance(honeypot, dict):
            honeypot = {}
        honeypot["enabled"] = bool(expanded)
        honeypot["presets"] = list(presets)
        honeypot.setdefault("ban_seconds", 0)
        policy["honeypot"] = honeypot

    if audit_path is not None:
        data.setdefault("audit", {})["path"] = audit_path

    parse_config(data, base_dir)
    return data


def ensure_stable_relative_paths(
    data: dict[str, Any],
    *,
    base_path: Path,
    output_path: Path,
) -> None:
    """Reject moves that would silently retarget relative configuration paths."""

    try:
        same_directory = base_path.parent.resolve(strict=False) == output_path.parent.resolve(strict=False)
    except OSError as exc:
        raise ConfigError("cannot compare configuration directories") from exc
    if same_directory:
        return

    relative_fields: list[str] = []
    audit = data.get("audit")
    if isinstance(audit, dict) and isinstance(audit.get("path"), str):
        if not Path(audit["path"]).expanduser().is_absolute():
            relative_fields.append("audit.path")
    server = data.get("server")
    if isinstance(server, dict):
        tls = server.get("tls")
        if isinstance(tls, dict):
            for field in ("cert_file", "key_file"):
                value = tls.get(field)
                if isinstance(value, str) and not Path(value).expanduser().is_absolute():
                    relative_fields.append(f"server.tls.{field}")
    if relative_fields:
        raise ConfigError(
            "cannot move a configuration with relative paths to another directory "
            f"({', '.join(relative_fields)}); use the same directory or absolute paths"
        )


def _has_reparse_attribute(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_unsafe_existing_target(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ConfigError(f"cannot inspect output path: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or _has_reparse_attribute(info):
        raise ConfigError("output must not be a symbolic link or reparse point")
    if stat.S_ISDIR(info.st_mode):
        raise ConfigError("output path is a directory")


def write_initial_config(path: str | Path, data: dict[str, Any], *, force: bool = False) -> Path:
    """Write a validated configuration atomically without implicit replacement."""

    target = Path(path).expanduser()
    if not target.is_absolute():
        target = Path.cwd() / target
    _reject_unsafe_existing_target(target)
    if target.exists() and not force:
        raise ConfigError("output already exists; use --force to replace it")

    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f"cannot create output directory: {parent}") from exc

    payload = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if force:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".highwall-config-", dir=str(parent)
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        except OSError as exc:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise ConfigError(f"cannot write configuration: {target}") from exc
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags, 0o600)
        except FileExistsError as exc:
            raise ConfigError("output already exists; use --force to replace it") from exc
        except OSError as exc:
            raise ConfigError(f"cannot create configuration: {target}") from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(target, 0o600)
        except OSError as exc:
            try:
                target.unlink()
            except OSError:
                pass
            raise ConfigError(f"cannot write configuration: {target}") from exc
    try:
        return target.resolve(strict=True)
    except OSError:
        return target
