#!/usr/bin/env python3
"""Attack-surface checks for the standard deployment skeleton."""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

COMPOSE_FILE = Path(__file__).resolve().parent / "docker-compose.yml"
STARTUP_RETRIES = 5
STARTUP_RETRY_DELAY = 1.0


def fail(message: str) -> None:
    print(f"[FAIL] {message}")
    raise SystemExit(1)


def pass_(message: str) -> None:
    print(f"[PASS] {message}")


def request_json(url: str, headers: dict[str, str]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=8) as response:
        payload = response.read()
        return response.status, json.loads(payload.decode("utf-8"))


def header_value(headers: dict[str, object], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value)
    return ""


def check_edge(edge: str, forged_ip: str) -> None:
    headers = {
        "Host": "app.internal",
        "X-Forwarded-For": forged_ip,
        "User-Agent": "highwall-standard-verify/1",
    }
    for attempt in range(1, STARTUP_RETRIES + 1):
        try:
            status, payload = request_json(
                f"{edge.rstrip('/')}/api/echo",
                headers,
            )
        except urllib.error.HTTPError as exc:
            if exc.code in {502, 503, 504} and attempt < STARTUP_RETRIES:
                time.sleep(STARTUP_RETRY_DELAY)
                continue
            fail(f"edge returned HTTP {exc.code}: {exc.read()[:200]!r}")
        except OSError as exc:
            if attempt < STARTUP_RETRIES:
                time.sleep(STARTUP_RETRY_DELAY)
                continue
            fail(f"edge request failed: {type(exc).__name__}: {exc}")
        except Exception as exc:
            fail(f"edge request failed: {type(exc).__name__}: {exc}")
        break
    else:
        fail("edge request failed after startup retries")

    if status != 200:
        fail(f"edge returned {status}, expected 200")
    pass_("edge reaches upstream")

    headers = payload.get("headers")
    if not isinstance(headers, dict):
        fail("upstream response did not include a headers object")
    seen_xff = header_value(headers, "X-Forwarded-For")
    if not seen_xff:
        fail("upstream did not receive X-Forwarded-For")
    if forged_ip in seen_xff:
        fail(f"forged X-Forwarded-For reached upstream: {seen_xff}")
    pass_(f"forged X-Forwarded-For was replaced (upstream saw {seen_xff})")


def check_closed(host: str, port: int, label: str) -> None:
    try:
        with socket.create_connection((host, port), timeout=2):
            fail(f"{label} is reachable on {host}:{port}; it should not be published")
    except OSError:
        pass_(f"{label} is not reachable on {host}:{port}")


def docker_output(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        fail("docker is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        fail(f"docker command timed out: {' '.join(arguments)}")
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        fail(f"docker command failed: {' '.join(arguments)}: {detail}")
    return result.stdout.strip()


def check_not_published(service: str, label: str, compose_file: Path) -> None:
    container_ids = docker_output(
        ["docker", "compose", "-f", str(compose_file), "ps", "-q", service]
    ).split()
    if not container_ids:
        fail(f"{service} container is not running; start the standard stack first")
    for container_id in container_ids:
        raw_bindings = docker_output(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .HostConfig.PortBindings}}",
                container_id,
            ]
        )
        try:
            bindings = json.loads(raw_bindings)
        except json.JSONDecodeError as exc:
            fail(f"could not parse Docker port bindings for {service}: {exc}")
        if bindings is None:
            bindings = {}
        if not isinstance(bindings, dict):
            fail(f"unexpected Docker port bindings for {service}: {raw_bindings}")
        published = {
            container_port: host_bindings
            for container_port, host_bindings in bindings.items()
            if isinstance(host_bindings, list) and host_bindings
        }
        if published:
            fail(f"{label} has published host ports: {published}")
    pass_(f"{label} has no published host ports")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--edge", default="http://127.0.0.1:8080")
    parser.add_argument("--forged-ip", default="203.0.113.9")
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=COMPOSE_FILE,
        help="Compose file used to identify the standard stack containers",
    )
    parser.add_argument(
        "--highwall-port",
        type=int,
        help="deprecated: also probe this host port for a direct HighWall listener",
    )
    parser.add_argument(
        "--upstream-port",
        type=int,
        help="deprecated: also probe this host port for a direct upstream listener",
    )
    parser.add_argument("--skip-direct", action="store_true")
    args = parser.parse_args()

    check_edge(args.edge, args.forged_ip)
    if not args.skip_direct:
        check_not_published("highwall", "HighWall", args.compose_file)
        check_not_published("upstream", "upstream", args.compose_file)
        if args.highwall_port is not None:
            check_closed("127.0.0.1", args.highwall_port, "HighWall")
        if args.upstream_port is not None:
            check_closed("127.0.0.1", args.upstream_port, "upstream")
    print("all standard deployment checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
