#!/usr/bin/env python3
"""Attack-surface checks for the standard deployment skeleton."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import urllib.error
import urllib.request


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
    try:
        status, payload = request_json(
            f"{edge.rstrip('/')}/api/echo",
            {
                "Host": "app.internal",
                "X-Forwarded-For": forged_ip,
                "User-Agent": "highwall-standard-verify/1",
            },
        )
    except urllib.error.HTTPError as exc:
        fail(f"edge returned HTTP {exc.code}: {exc.read()[:200]!r}")
    except Exception as exc:
        fail(f"edge request failed: {type(exc).__name__}: {exc}")

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--edge", default="http://127.0.0.1:8080")
    parser.add_argument("--forged-ip", default="203.0.113.9")
    parser.add_argument("--highwall-port", type=int, default=18090)
    parser.add_argument("--upstream-port", type=int, default=18080)
    parser.add_argument("--skip-direct", action="store_true")
    args = parser.parse_args()

    check_edge(args.edge, args.forged_ip)
    if not args.skip_direct:
        check_closed("127.0.0.1", args.highwall_port, "HighWall")
        check_closed("127.0.0.1", args.upstream_port, "upstream")
    print("all standard deployment checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
