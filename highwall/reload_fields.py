"""Shared definition of configuration fields that require a restart."""

from __future__ import annotations

from typing import Any

from .config import Config

IMMUTABLE_RELOAD_FIELDS: tuple[str, ...] = (
    "server.listen_host",
    "server.listen_port",
    "server.max_connections",
    "server.max_inflight_requests",
    "server.tls.enabled",
    "admin.enabled",
    "admin.listen_host",
    "admin.listen_port",
)

IMMUTABLE_RELOAD_FIELD_SET = frozenset(IMMUTABLE_RELOAD_FIELDS)


def _field_value(config: Config, path: str) -> Any:
    value: Any = config
    for part in path.split("."):
        value = getattr(value, part)
    return value


def changed_immutable_fields(old: Config, new: Config) -> tuple[str, ...]:
    """Return listener fields that changed and therefore need a restart."""

    return tuple(
        path
        for path in IMMUTABLE_RELOAD_FIELDS
        if _field_value(old, path) != _field_value(new, path)
    )


def reload_error(old: Config, new: Config) -> str | None:
    changed = changed_immutable_fields(old, new)
    if not changed:
        return None
    return "reload cannot change listener fields: " + ", ".join(changed) + "; restart required"
