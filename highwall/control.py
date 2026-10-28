"""Atomic, fail-closed configuration reload for a running gateway."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config, ConfigError, load_config
from .proxy import GatewayServer, build_tls_context
from .runtime import Runtime

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReloadResult:
    status: str
    generation: int
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": self.status,
            "generation": self.generation,
        }
        if self.error:
            result["error"] = self.error
        return result


def _reloadable_error(old: Config, new: Config) -> str | None:
    immutable = (
        ("server.listen_host", old.server.listen_host, new.server.listen_host),
        ("server.listen_port", old.server.listen_port, new.server.listen_port),
        ("server.max_connections", old.server.max_connections, new.server.max_connections),
        (
            "server.max_inflight_requests",
            old.server.max_inflight_requests,
            new.server.max_inflight_requests,
        ),
        ("server.tls.enabled", old.server.tls.enabled, new.server.tls.enabled),
        ("admin.enabled", old.admin.enabled, new.admin.enabled),
        ("admin.listen_host", old.admin.listen_host, new.admin.listen_host),
        ("admin.listen_port", old.admin.listen_port, new.admin.listen_port),
    )
    changed = [name for name, old_value, new_value in immutable if old_value != new_value]
    if not changed:
        return None
    return "reload cannot change listener fields: " + ", ".join(changed) + "; restart required"


def _safe_reload_error(exc: Exception) -> str:
    if isinstance(exc, ConfigError):
        return str(exc)[:512]
    return f"configuration reload failed ({type(exc).__name__})"


class ServerController:
    """Apply validated configuration changes without dropping in-flight requests."""

    def __init__(self, config_path: Path, gateway: GatewayServer) -> None:
        self.config_path = config_path
        self.gateway = gateway
        self.admin: Any = None
        self._lock = threading.Lock()

    def attach_admin(self, admin: Any) -> None:
        self.admin = admin

    def reload(self) -> ReloadResult:
        with self._lock:
            old_runtime = self.gateway.runtime
            try:
                new_config = load_config(self.config_path)
                problem = _reloadable_error(old_runtime.config, new_config)
                if problem is not None:
                    raise ConfigError(problem)
                new_tls_context = build_tls_context(new_config)
                new_runtime = Runtime.build(new_config, previous=old_runtime)
            except Exception as exc:
                old_runtime.metrics.inc("config_reload_failures_total")
                message = _safe_reload_error(exc)
                _LOG.error("configuration reload rejected: %s", message)
                return ReloadResult("rejected", self.gateway.generation, message)

            try:
                generation = self.gateway.reload(new_runtime, new_tls_context)
            except Exception:
                new_runtime.close()
                raise
            if self.admin is not None:
                self.admin.set_runtime(new_runtime, generation)
            new_runtime.metrics.inc("config_reloads_total")
            new_runtime.metrics.set("config_generation", float(generation))
            _LOG.info("configuration reloaded (generation %d)", generation)
            return ReloadResult("reloaded", generation)
