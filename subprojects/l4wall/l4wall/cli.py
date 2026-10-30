"""Command line entry points for L4Wall."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Callable, Sequence

from . import __version__
from .admin import AdminServer
from .audit import AuditWriter
from .config import config_to_dict, load_config, resolve_runtime_paths, write_example
from .errors import ConfigError
from .gateway import Gateway
from .metrics import Metrics
from .shared_state import SharedRedisSource, run_shared_ban_sync
from .tracker import ThreatTracker


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="l4wall", description="Fail-closed TCP gateway with connection-level defense")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run the gateway")
    run_parser.add_argument("--config", required=True, help="path to config.json")
    run_parser.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR")

    check_parser = subparsers.add_parser("check", help="validate a configuration")
    check_parser.add_argument("--config", default="config.json", help="path to config.json")

    inspect_parser = subparsers.add_parser("inspect", help="print the effective configuration")
    inspect_parser.add_argument("--config", default="config.json", help="path to config.json")

    init_parser = subparsers.add_parser("init", help="write an example configuration")
    init_parser.add_argument("--path", default="config.json", help="target path")
    init_parser.add_argument("--force", action="store_true", help="overwrite an existing file")

    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return asyncio.run(_run(args.config, args.log_level))
        if args.command == "check":
            config = load_config(args.config)
            print(f"ok: {len(config.listeners)} listener(s), version {config.version}")
            return 0
        if args.command == "inspect":
            config = load_config(args.config)
            print(json.dumps(config_to_dict(config), indent=2, ensure_ascii=False))
            return 0
        if args.command == "init":
            write_example(args.path, force=args.force)
            print(f"wrote {args.path}")
            return 0
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"runtime error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"startup error: {exc}", file=sys.stderr)
        return 1
    return 2


async def _run(config_path: str, log_level: str) -> int:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config(config_path)
    config = resolve_runtime_paths(config, Path(config_path).resolve().parent)
    if config.admin.enabled and not os.environ.get(config.admin.token_env):
        raise RuntimeError(f"admin is enabled but {config.admin.token_env} is empty")
    audit = AuditWriter(
        config.audit.path,
        max_bytes=config.audit.max_bytes,
        backup_count=config.audit.backup_count,
        on_write_failure=config.audit.on_write_failure,
        include_client_ip=config.audit.include_client_ip,
    )
    metrics = Metrics(config.metrics_enabled)
    tracker = ThreatTracker(config.threat)
    gateway = Gateway(config, audit=audit, metrics=metrics, tracker=tracker)
    admin = AdminServer(config.admin, audit=audit, metrics=metrics) if config.admin.enabled else None
    shared_source = (
        SharedRedisSource(
            config.threat.shared_bans,
            prefix_v4=config.threat.ban_prefix_v4,
            prefix_v6=config.threat.ban_prefix_v6,
            max_entries=config.threat.max_ban_entries,
        )
        if config.threat.shared_bans.enabled
        else None
    )
    sync_task: asyncio.Task[None] | None = None
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def request_stop() -> None:
        stop_event.set()

    try:
        await gateway.start()
        for listener in config.listeners:
            port = gateway.listener_ports.get(listener.name, listener.listen_port)
            print(
                f"listener {listener.name}: {config.server.listen_host}:{port} -> "
                f"{listener.upstream_host}:{listener.upstream_port}"
            )
        if admin is not None:
            await admin.start()
            print(f"admin: http://{config.admin.listen_host}:{config.admin.listen_port}/healthz")
        if shared_source is not None:
            sync_task = asyncio.create_task(
                run_shared_ban_sync(
                    shared_source,
                    tracker.bans,
                    audit,
                    metrics,
                    interval=config.threat.shared_bans.sync_interval_seconds,
                ),
                name="l4wall-shared-bans",
            )
            print(
                "shared bans: redis "
                f"{config.threat.shared_bans.host}:{config.threat.shared_bans.port}"
                f"/{config.threat.shared_bans.db} key={config.threat.shared_bans.key}"
            )
        _install_signal_handlers(loop, request_stop)
        await stop_event.wait()
        logging.getLogger("l4wall").info("shutdown requested")
    finally:
        if sync_task is not None:
            sync_task.cancel()
            await asyncio.gather(sync_task, return_exceptions=True)
        if admin is not None:
            await admin.stop()
        await gateway.stop()
    return 0


def _install_signal_handlers(loop: asyncio.AbstractEventLoop, callback: Callable[[], None]) -> None:
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, callback)
        except (NotImplementedError, RuntimeError):
            try:
                signal.signal(sig, lambda _signum, _frame: loop.call_soon_threadsafe(callback))
            except (ValueError, OSError):
                pass

