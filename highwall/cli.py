"""Command-line entry point for HighWall."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from pathlib import Path

from . import __version__
from .admin import build_admin_server
from .config_report import build_config_report
from .config import Config, ConfigError, load_config, load_config_data
from .control import ServerController
from .init_config import (
    build_initial_config,
    ensure_stable_relative_paths,
    parse_upstream_url,
    update_config_data,
    write_initial_config,
)
from .proxy import GatewayServer, build_tls_context
from .runtime import Runtime, load_admin_token, validate_admin_token

_LOG = logging.getLogger("highwall")


def _configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def _endpoint(scheme: str, host: str, port: int) -> str:
    display_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{display_host}:{port}"


def _check_config(config: Config) -> str:
    token = load_admin_token(config)
    if token is not None:
        validate_admin_token(token)
    build_tls_context(config)
    return "configuration OK"


def _serve(config: Config, config_path: Path) -> int:
    runtime = Runtime.build(config)
    tls_context = build_tls_context(config)
    gateway: GatewayServer | None = None
    admin = None
    try:
        gateway = GatewayServer((config.server.listen_host, config.server.listen_port), runtime, tls_context)
        controller = ServerController(config_path, gateway)
        admin = build_admin_server(runtime, reload_callback=controller.reload)
        if admin is not None:
            controller.attach_admin(admin)
    except OSError as exc:
        if gateway is not None:
            gateway.server_close()
        runtime.close()
        _LOG.error("listener bind failed (%s)", type(exc).__name__)
        return 1
    except Exception as exc:
        if gateway is not None:
            gateway.server_close()
        runtime.close()
        _LOG.error("startup failed (%s)", type(exc).__name__)
        return 1

    stop = threading.Event()
    reload_event = threading.Event()
    gateway_thread = threading.Thread(target=gateway.serve_forever, name="highwall-proxy", kwargs={"poll_interval": 0.2})
    admin_thread = None
    if admin is not None:
        admin_thread = threading.Thread(target=admin.serve_forever, name="highwall-admin", kwargs={"poll_interval": 0.2})

    def request_stop(signum: int, frame: object) -> None:
        _LOG.info("shutdown requested")
        stop.set()

    def request_reload(signum: int, frame: object) -> None:
        reload_event.set()

    previous_handlers: dict[int, object] = {}
    for signal_name, handler in (
        ("SIGINT", request_stop),
        ("SIGTERM", request_stop),
        ("SIGBREAK", request_stop),
        ("SIGHUP", request_reload),
    ):
        signal_value = getattr(signal, signal_name, None)
        if signal_value is None:
            continue
        try:
            previous_handlers[signal_value] = signal.getsignal(signal_value)
            signal.signal(signal_value, handler)
        except (ValueError, OSError):
            pass

    proxy_scheme = "https" if tls_context is not None else "http"
    _LOG.info(
        "HighWall %s listening on %s -> %s://%s:%d",
        __version__,
        _endpoint(proxy_scheme, config.server.listen_host, gateway.server_address[1]),
        config.upstream.scheme,
        config.upstream.host,
        config.upstream.port,
    )
    if admin is not None:
        _LOG.info(
            "management endpoint on %s (loopback only)",
            _endpoint("http", admin.server_address[0], admin.server_address[1]),
        )
    gateway_thread.start()
    if admin_thread is not None:
        admin_thread.start()

    try:
        while not stop.wait(0.5):
            if reload_event.is_set():
                reload_event.clear()
                result = controller.reload()
                if result.status != "reloaded":
                    _LOG.error("configuration reload rejected: %s", result.error)
            if not gateway_thread.is_alive() or (admin_thread is not None and not admin_thread.is_alive()):
                _LOG.error("a server thread stopped unexpectedly")
                break
    except KeyboardInterrupt:
        stop.set()
    finally:
        gateway.begin_drain()
        if admin is not None:
            try:
                admin.shutdown()
            except Exception:
                pass
            admin.server_close()
        try:
            gateway.shutdown()
        except Exception:
            pass
        gateway.server_close()
        drain_timeout = gateway.runtime.config.server.shutdown_timeout
        if not gateway.wait_for_drain(drain_timeout):
            _LOG.warning("shutdown drain timed out; closing active connections")
            gateway.abort_connections()
            gateway.wait_for_drain(1.0)
        gateway_thread.join(timeout=5.0)
        if admin_thread is not None:
            admin_thread.join(timeout=5.0)
        gateway.close_all_runtimes()
        for signal_value, handler in previous_handlers.items():
            try:
                signal.signal(signal_value, handler)
            except (ValueError, OSError):
                pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="highwall", description="Fail-closed HTTP application firewall and reverse proxy.")
    parser.add_argument("--version", action="version", version=f"highwall {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve", help="start the proxy")
    serve.add_argument("-c", "--config", required=True, help="path to the JSON configuration")
    serve.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    check = subparsers.add_parser("check", help="validate configuration without listening")
    check.add_argument("-c", "--config", required=True, help="path to the JSON configuration")
    check.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    inspect = subparsers.add_parser("inspect", help="print the effective configuration as JSON")
    inspect.add_argument("-c", "--config", required=True, help="path to the JSON configuration")
    init = subparsers.add_parser("init", help="write a compact deployment configuration")
    init.add_argument(
        "--base",
        help="merge explicitly provided fields into an existing configuration",
    )
    init.add_argument(
        "--upstream",
        help="upstream HTTP(S) URL without path (default without --base: http://127.0.0.1:8080)",
    )
    init.add_argument("--listen-host", help="proxy bind address (default without --base: 127.0.0.1)")
    init.add_argument("--listen-port", type=int, help="proxy bind port (default without --base: 18090)")
    init.add_argument(
        "--allowed-host",
        action="append",
        dest="allowed_hosts",
        help="allowed HTTP Host authority; repeat for multiple values",
    )
    init.add_argument(
        "--method",
        action="append",
        dest="methods",
        help="allowed HTTP method; repeat for multiple values",
    )
    init.add_argument(
        "--honeypot-preset",
        action="append",
        dest="honeypot_presets",
        help="built-in honeypot preset or template; repeat for multiple values",
    )
    init.add_argument("--no-honeypot", action="store_true", help="disable built-in honeypot templates")
    init.add_argument("--audit-path", help="audit path relative to the config")
    init.add_argument("-o", "--output", help="output path (default: config.json, or the --base path)")
    init.add_argument("--force", action="store_true", help="replace an existing output file")
    init.add_argument("--print-config", action="store_true", help="also print the generated JSON")
    return parser


def _init(args: argparse.Namespace) -> int:
    try:
        if args.no_honeypot and args.honeypot_presets:
            raise ConfigError("--no-honeypot and --honeypot-preset are mutually exclusive")

        base_data = None
        if args.base:
            base_data, base_path = load_config_data(Path(args.base))
            load_config(base_path)
            output = Path(args.output).expanduser() if args.output else base_path
        else:
            output = Path(args.output).expanduser() if args.output else Path("config.json")
        if not output.is_absolute():
            output = Path.cwd() / output

        if base_data is None:
            scheme, host, port = parse_upstream_url(args.upstream or "http://127.0.0.1:8080")
            allowed_hosts = tuple(args.allowed_hosts or ("app.internal",))
            methods = tuple(method.upper() for method in (args.methods or ("GET", "HEAD", "POST")))
            if args.no_honeypot:
                presets: tuple[str, ...] = ()
            else:
                presets = tuple(args.honeypot_presets or ("common",))
            data = build_initial_config(
                upstream_scheme=scheme,
                upstream_host=host,
                upstream_port=port,
                listen_host=args.listen_host or "127.0.0.1",
                listen_port=args.listen_port if args.listen_port is not None else 18090,
                allowed_hosts=allowed_hosts,
                allowed_methods=methods,
                honeypot_presets=presets,
                audit_path=args.audit_path or "audit.jsonl",
                base_dir=output.parent,
            )
        else:
            if args.upstream is None:
                scheme = host = None
                port = None
            else:
                scheme, host, port = parse_upstream_url(args.upstream)
            presets = tuple(args.honeypot_presets) if args.honeypot_presets is not None else None
            data = update_config_data(
                base_data,
                upstream_scheme=scheme,
                upstream_host=host,
                upstream_port=port,
                listen_host=args.listen_host,
                listen_port=args.listen_port,
                allowed_hosts=tuple(args.allowed_hosts) if args.allowed_hosts is not None else None,
                allowed_methods=(
                    tuple(method.upper() for method in args.methods)
                    if args.methods is not None
                    else None
                ),
                honeypot_presets=presets,
                disable_honeypot=args.no_honeypot,
                audit_path=args.audit_path,
                base_dir=output.parent,
            )
            ensure_stable_relative_paths(
                data,
                base_path=base_path,
                output_path=output,
            )
        written = write_initial_config(output, data, force=args.force)
        config = load_config(written)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"configuration error ({type(exc).__name__})", file=sys.stderr)
        return 2

    print(f"configuration written: {written}")
    print(f"  upstream: {config.upstream.scheme}://{config.upstream.host}:{config.upstream.port}")
    print(f"  listen: {config.server.listen_host}:{config.server.listen_port}")
    print(f"  allowed hosts: {', '.join(config.policy.allowed_hosts)}")
    print(f"  methods: {', '.join(config.policy.allowed_methods)}")
    honeypot = config.policy.honeypot
    if honeypot.enabled:
        print(f"  honeypot: {len(honeypot.routes)} routes, ban_seconds={honeypot.ban_seconds:g}")
    else:
        print("  honeypot: disabled")
    print(f"next: python -m highwall check -c \"{written}\"")
    if args.print_config:
        print(json.dumps(data, indent=2, ensure_ascii=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", False))
    if args.command == "init":
        return _init(args)
    try:
        config = load_config(Path(args.config))
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.command == "inspect":
        print(json.dumps(build_config_report(config), indent=2, ensure_ascii=True))
        return 0
    if args.command == "check":
        try:
            print(_check_config(config))
        except ConfigError as exc:
            print(f"configuration error: {exc}", file=sys.stderr)
            return 2
        except (OSError, ValueError) as exc:
            print(f"configuration error ({type(exc).__name__})", file=sys.stderr)
            return 2
        return 0
    if args.command == "serve":
        try:
            return _serve(config, Path(args.config))
        except ConfigError as exc:
            print(f"configuration error: {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"startup error ({type(exc).__name__})", file=sys.stderr)
            return 1
    parser.error("unknown command")
    return 2
