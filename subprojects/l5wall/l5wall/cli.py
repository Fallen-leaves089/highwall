"""Command-line checks and the bounded L5 proxy entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .gateway import build_tls_context
from .proxy import L5ProxyServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="l5wall", description="Fail-closed TLS session policy.")
    parser.add_argument("--version", action="version", version=f"l5wall {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="validate configuration and certificate material")
    check.add_argument("-c", "--config", required=True, help="path to the JSON configuration")
    inspect = subparsers.add_parser("inspect", help="print the effective non-secret configuration")
    inspect.add_argument("-c", "--config", required=True, help="path to the JSON configuration")
    serve = subparsers.add_parser("serve", help="terminate TLS and forward HTTP/1.1 to a local HighWall listener")
    serve.add_argument("-c", "--config", required=True, help="path to the JSON configuration")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(Path(args.config))
        build_tls_context(config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"configuration error ({type(exc).__name__})", file=sys.stderr)
        return 2
    if args.command == "serve":
        server = None
        try:
            server = L5ProxyServer(config)
            address = server.bind()
            print(
                f"L5Wall listening on {address[0]}:{address[1]} -> "
                f"{config.upstream_host}:{config.upstream_port} (HTTP/1.1 only)",
                flush=True,
            )
            print(
                "WARNING: this loopback bridge does not forward the original client IP; "
                "do not enable per-IP bans or ACLs behind it without a trusted identity channel.",
                flush=True,
            )
            server.serve_forever()
        except KeyboardInterrupt:
            return 0
        except (OSError, ValueError) as exc:
            print(f"listener error ({type(exc).__name__})", file=sys.stderr)
            return 2
        finally:
            if server is not None:
                server.stop()
        return 0
    if args.command == "inspect":
        payload = {
            "version": __version__,
            "config": config.as_public(),
            "coverage": {
                "level": "C1",
                "complete": False,
                "limitations": [
                    "L5 metadata and bounded HTTP/1.1 bridge only",
                    "serve mode adds SNI/Host cross-check and resource bounds",
                    "no standard JA3/JA4, 0-RTT policy, QUIC, or H2/H3 inspection",
                ],
            },
        }
        print(json.dumps(payload, indent=2, ensure_ascii=True))
    else:
        print("L5Wall configuration OK")
        print("coverage: C1 (incomplete; TLS metadata and bounded HTTP/1.1 bridge only)")
    return 0
