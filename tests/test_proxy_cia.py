from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tests.support import (
    GatewayHarness,
    StubUpstream,
    base_config,
    build_request,
    header_values,
    parse_response,
    send_raw,
)


class ProxyCiaIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stub = StubUpstream()
        self.stub.__enter__()
        self.addCleanup(self.stub.__exit__, None, None, None)

    def request(
        self,
        gateway: GatewayHarness,
        payload: bytes,
        *,
        timeout: float = 3.0,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        return parse_response(send_raw(gateway.port, payload, timeout=timeout))

    def wait_for_upstream(self, path: str, *, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(item["path"].split("?", 1)[0] == path for item in self.stub.state.snapshot()):
                return
            time.sleep(0.01)
        self.fail(f"upstream did not receive {path}")

    def start_held_request(
        self,
        gateway: GatewayHarness,
        path: str = "/hold",
    ) -> tuple[threading.Thread, dict[str, object]]:
        result: dict[str, object] = {}

        def worker() -> None:
            try:
                result["response"] = parse_response(
                    send_raw(gateway.port, build_request(path=path), timeout=5.0)
                )
            except Exception as exc:  # pragma: no cover - surfaced by assertions
                result["error"] = exc

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.wait_for_upstream(path)
        return thread, result

    def test_route_concurrency_limit_returns_503(self) -> None:
        config = base_config(
            Path(self.temp.name),
            self.stub.port,
            overrides={
                "policy": {
                    "routes": [{"path_prefix": "/hold", "max_concurrent": 1}],
                }
            },
        )
        with GatewayHarness(config) as gateway:
            thread, result = self.start_held_request(gateway)
            try:
                status, headers, _ = self.request(
                    gateway,
                    build_request(path="/hold"),
                    timeout=2.0,
                )
                self.assertEqual(status, 503)
                self.assertTrue(header_values(headers, "Retry-After"))
                metrics = gateway.runtime.metrics.snapshot()
                self.assertEqual(metrics["route_concurrency_rejections_total"], 1)
            finally:
                self.stub.hold_release.set()
                thread.join(timeout=5.0)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", result)
        self.assertEqual(result["response"][0], 200)

    def test_global_inflight_limit_returns_503(self) -> None:
        config = base_config(
            Path(self.temp.name),
            self.stub.port,
            overrides={"server": {"max_inflight_requests": 1}},
        )
        with GatewayHarness(config) as gateway:
            thread, result = self.start_held_request(gateway)
            try:
                status, _, _ = self.request(gateway, build_request(path="/ok"), timeout=2.0)
                self.assertEqual(status, 503)
                self.assertEqual(gateway.runtime.metrics.snapshot()["inflight_rejections_total"], 1)
            finally:
                self.stub.hold_release.set()
                thread.join(timeout=5.0)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", result)
        self.assertEqual(result["response"][0], 200)

    def test_integrity_detect_allows_response_and_audits_hit(self) -> None:
        pin = {
            "path": "/ok",
            "status": 200,
            "sha256": hashlib.sha256(b"different expected body").hexdigest(),
        }
        directory = Path(self.temp.name)
        config = base_config(
            directory,
            self.stub.port,
            overrides={
                "policy": {
                    "response_integrity_mode": "detect",
                    "integrity_pins": [pin],
                }
            },
        )
        with GatewayHarness(config) as gateway:
            status, _, body = self.request(gateway, build_request(path="/ok"))
            metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from upstream")
        self.assertEqual(metrics["integrity_detected_total"], 1)
        self.assertEqual(metrics["integrity_blocked_total"], 0)
        event = json.loads((directory / "audit.jsonl").read_text("utf-8").splitlines()[-1])
        self.assertEqual(event["event"], "response_allowed_with_integrity_detection")
        self.assertEqual(event["rule_id"], "HW-INTEGRITY-1001")

    def test_integrity_block_returns_502_without_upstream_body(self) -> None:
        pin = {
            "path": "/ok",
            "status": 200,
            "sha256": hashlib.sha256(b"different expected body").hexdigest(),
        }
        directory = Path(self.temp.name)
        config = base_config(
            directory,
            self.stub.port,
            overrides={
                "policy": {
                    "response_integrity_mode": "block",
                    "integrity_pins": [pin],
                }
            },
        )
        with GatewayHarness(config) as gateway:
            status, _, body = self.request(gateway, build_request(path="/ok"))
            metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(status, 502)
        self.assertNotIn(b"hello from upstream", body)
        self.assertIn(b"HW-INTEGRITY-1001", body)
        self.assertEqual(metrics["integrity_detected_total"], 1)
        self.assertEqual(metrics["integrity_blocked_total"], 1)
        event = json.loads((directory / "audit.jsonl").read_text("utf-8").splitlines()[-1])
        self.assertEqual(event["event"], "response_integrity_blocked")
        self.assertEqual(event["rule_id"], "HW-INTEGRITY-1001")

    def test_global_read_only_blocks_writes_end_to_end(self) -> None:
        config = base_config(
            Path(self.temp.name),
            self.stub.port,
            overrides={"policy": {"read_only": True}},
        )
        with GatewayHarness(config) as gateway:
            write_status, _, _ = self.request(
                gateway,
                build_request(
                    method="POST",
                    path="/echo",
                    headers=[("Content-Type", "application/json")],
                    body=b"{}",
                ),
            )
            read_status, _, _ = self.request(gateway, build_request(path="/ok"))
        self.assertEqual(write_status, 403)
        self.assertEqual(read_status, 200)
        self.assertEqual(len(self.stub.state.snapshot()), 1)

    def test_circuit_opens_after_repeated_upstream_5xx(self) -> None:
        config = base_config(
            Path(self.temp.name),
            self.stub.port,
            overrides={
                "upstream": {
                    "circuit_breaker": {
                        "enabled": True,
                        "failure_threshold": 2,
                        "window": 60.0,
                        "open_seconds": 60.0,
                        "half_open_max_requests": 1,
                    }
                }
            },
        )
        with GatewayHarness(config) as gateway:
            first = self.request(gateway, build_request(path="/status/500"))
            second = self.request(gateway, build_request(path="/status/500"))
            third = self.request(gateway, build_request(path="/status/500"))
            metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(first[0], 500)
        self.assertEqual(second[0], 500)
        self.assertEqual(third[0], 503)
        self.assertTrue(header_values(third[1], "Retry-After"))
        self.assertEqual(metrics["circuit_state"], 2)
        self.assertEqual(metrics["circuit_open_total"], 1)
        self.assertEqual(metrics["circuit_rejections_total"], 1)
        self.assertEqual(len(self.stub.state.snapshot()), 2)

    def test_circuit_does_not_open_for_upstream_4xx(self) -> None:
        config = base_config(
            Path(self.temp.name),
            self.stub.port,
            overrides={
                "upstream": {
                    "circuit_breaker": {
                        "enabled": True,
                        "failure_threshold": 1,
                        "window": 60.0,
                        "open_seconds": 60.0,
                    }
                }
            },
        )
        with GatewayHarness(config) as gateway:
            not_found = self.request(gateway, build_request(path="/status/404"))
            healthy = self.request(gateway, build_request(path="/ok"))
            metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(not_found[0], 404)
        self.assertEqual(healthy[0], 200)
        self.assertEqual(metrics["circuit_state"], 0)
        self.assertEqual(metrics["circuit_open_total"], 0)


if __name__ == "__main__":
    unittest.main()
