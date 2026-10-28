#!/usr/bin/env python3
"""Record a local loopback performance baseline for HighWall.

This is a measurement tool, not a capacity guarantee. It starts a stub
upstream and a HighWall instance on ephemeral loopback ports, then reports
latency percentiles and throughput for allowed and WAF-blocked traffic.
"""

from __future__ import annotations

import argparse
import http.client
import json
import platform
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from highwall.config import Config, parse_config
from highwall.proxy import GatewayServer
from highwall.runtime import Runtime

_HOST = "bench.local"
_HEADERS = {
    "Host": _HOST,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Connection": "close",
    "Cookie": "benchmark=1",
}


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def _build_config(base_dir: Path, upstream_port: int) -> Config:
    data: dict[str, Any] = {
        "version": 1,
        "server": {
            "listen_host": "127.0.0.1",
            "listen_port": 18090,
            "max_connections": 256,
            "max_connections_per_ip": 0,
            "max_inflight_requests": 0,
            "header_timeout": 5.0,
            "body_timeout": 15.0,
            "shutdown_timeout": 10.0,
        },
        "upstream": {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": upstream_port,
            "connect_timeout": 1.0,
            "read_timeout": 5.0,
            "total_timeout": 10.0,
            "max_response_bytes": 65536,
            "circuit_breaker": {"enabled": False},
        },
        "policy": {
            "allowed_hosts": [_HOST],
            "allowed_methods": ["GET", "HEAD"],
            "allowed_path_prefixes": ["/"],
            "deny_path_prefixes": ["/.git", "/.env"],
            "reject_encoded_separators": True,
            "allow_path_parameters": False,
            "allow_trailing_dot_or_space": False,
            "reject_duplicate_headers": True,
            "reject_get_body": True,
            "max_request_line": 8192,
            "max_header_count": 64,
            "max_header_bytes": 16384,
            "max_body_bytes": 65536,
            "waf_enabled": True,
            "waf_mode": "block",
            "waf_rules": ["sqli", "xss", "traversal", "cmdi", "jndi", "ssrf"],
            "response_scan_mode": "block",
            "honeypot": {"enabled": False},
        },
        "rate_limit": {"enabled": False},
        "threat_detection": {"enabled": False},
        "audit": {
            "path": "audit.jsonl",
            "max_bytes": 10485760,
            "backup_count": 2,
            "include_client_ip": False,
            "on_write_failure": "fail_closed",
        },
        "admin": {"enabled": False},
    }
    return parse_config(data, base_dir)


def _request(port: int, path: str, timeout: float) -> tuple[float, int]:
    started = time.perf_counter()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", path, headers=_HEADERS)
        response = connection.getresponse()
        response.read()
        status = response.status
    finally:
        connection.close()
    return time.perf_counter() - started, status


@dataclass(frozen=True)
class Scenario:
    name: str
    port: int
    path: str
    expected_status: int


@dataclass(frozen=True)
class Result:
    name: str
    requests: int
    concurrency: int
    failures: int
    wall_seconds: float
    throughput: float
    p50_ms: float
    p95_ms: float
    p99_ms: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "requests": self.requests,
            "concurrency": self.concurrency,
            "failures": self.failures,
            "wall_seconds": round(self.wall_seconds, 4),
            "throughput_rps": round(self.throughput, 2),
            "p50_ms": round(self.p50_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "p99_ms": round(self.p99_ms, 3),
        }


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def _run(scenario: Scenario, requests: int, concurrency: int, timeout: float) -> Result:
    durations: list[float] = []
    failures = 0

    def one() -> tuple[float, int]:
        return _request(scenario.port, scenario.path, timeout)

    started = time.perf_counter()
    if concurrency <= 1:
        for _ in range(requests):
            elapsed, status = one()
            durations.append(elapsed)
            failures += status != scenario.expected_status
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            for elapsed, status in pool.map(lambda _: one(), range(requests)):
                durations.append(elapsed)
                failures += status != scenario.expected_status
    wall = time.perf_counter() - started

    return Result(
        name=scenario.name,
        requests=requests,
        concurrency=concurrency,
        failures=failures,
        wall_seconds=wall,
        throughput=requests / wall if wall else 0.0,
        p50_ms=_percentile(durations, 0.50) * 1000.0,
        p95_ms=_percentile(durations, 0.95) * 1000.0,
        p99_ms=_percentile(durations, 0.99) * 1000.0,
    )


def _warm_up(scenarios: tuple[Scenario, ...], count: int, timeout: float) -> None:
    for scenario in scenarios:
        for _ in range(count):
            _request(scenario.port, scenario.path, timeout)


def benchmark(args: argparse.Namespace) -> tuple[Result, ...]:
    with tempfile.TemporaryDirectory(prefix="highwall-bench-") as directory:
        base_dir = Path(directory)
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        upstream.daemon_threads = True
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()

        runtime = Runtime.build(_build_config(base_dir, int(upstream.server_address[1])))
        gateway = GatewayServer(("127.0.0.1", 0), runtime)
        gateway_thread = threading.Thread(
            target=lambda: gateway.serve_forever(poll_interval=0.02),
            daemon=True,
        )
        gateway_thread.start()
        gateway_port = int(gateway.server_address[1])

        scenarios = (
            Scenario("direct-upstream", int(upstream.server_address[1]), "/", 200),
            Scenario("highwall-allowed", gateway_port, "/", 200),
            Scenario(
                "highwall-waf-blocked",
                gateway_port,
                "/search?q=%27%20OR%201%3D1--",
                403,
            ),
        )

        try:
            _warm_up(scenarios, args.warmup, args.timeout)
            results: list[Result] = []
            for scenario in scenarios:
                results.append(_run(scenario, args.sequential_requests, 1, args.timeout))
            for scenario in scenarios:
                results.append(
                    _run(scenario, args.concurrent_requests, args.concurrency, args.timeout)
                )
            return tuple(results)
        finally:
            gateway.shutdown()
            gateway.server_close()
            gateway_thread.join(timeout=3.0)
            runtime.close()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3.0)


def _print_report(results: tuple[Result, ...], args: argparse.Namespace) -> None:
    print(
        f"highwall benchmark: python={platform.python_version()} platform={platform.platform()}"
    )
    print(
        f"config: warmup={args.warmup} sequential={args.sequential_requests} "
        f"concurrent={args.concurrent_requests} concurrency={args.concurrency}"
    )
    print(
        "note: loopback measurements only; results depend on host load and are not a capacity SLA"
    )
    print(
        f"{'scenario':<24}{'mode':<12}{'n':>7}{'fail':>7}"
        f"{'rps':>10}{'p50ms':>9}{'p95ms':>9}{'p99ms':>9}"
    )
    for result in results:
        mode = "sequential" if result.concurrency == 1 else f"c{result.concurrency}"
        print(
            f"{result.name:<24}{mode:<12}{result.requests:>7}{result.failures:>7}"
            f"{result.throughput:>10.1f}{result.p50_ms:>9.2f}"
            f"{result.p95_ms:>9.2f}{result.p99_ms:>9.2f}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure a local HighWall performance baseline.")
    parser.add_argument("--sequential-requests", type=int, default=200)
    parser.add_argument("--concurrent-requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    args = parser.parse_args(argv)
    if args.sequential_requests < 1 or args.concurrent_requests < 1:
        parser.error("request counts must be at least 1")
    if args.concurrency < 2:
        parser.error("--concurrency must be at least 2")
    if args.warmup < 0:
        parser.error("--warmup must not be negative")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    results = benchmark(args)
    if args.json:
        print(
            json.dumps(
                {
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                    "config": {
                        "warmup": args.warmup,
                        "sequential_requests": args.sequential_requests,
                        "concurrent_requests": args.concurrent_requests,
                        "concurrency": args.concurrency,
                    },
                    "results": [result.as_dict() for result in results],
                },
                indent=2,
            )
        )
    else:
        _print_report(results, args)
    return 1 if any(result.failures for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
