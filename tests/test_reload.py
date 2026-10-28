from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from highwall.config import load_config
from highwall.control import ServerController
from highwall.proxy import GatewayServer
from highwall.runtime import Runtime
from tests.support import StubUpstream, build_request, free_port, parse_response, send_raw


def _config_data(upstream_port: int, hosts: list[str], *, listen_port: int = 18090) -> dict:
    return {
        "version": 1,
        "server": {
            "listen_host": "127.0.0.1",
            "listen_port": listen_port,
            "max_connections": 16,
            "max_connections_per_ip": 8,
            "max_inflight_requests": 8,
            "header_timeout": 1.0,
            "body_timeout": 2.0,
            "shutdown_timeout": 0.5,
        },
        "upstream": {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": upstream_port,
            "connect_timeout": 0.3,
            "read_timeout": 1.0,
            "max_response_bytes": 65536,
        },
        "policy": {
            "allowed_hosts": hosts,
            "allowed_methods": ["GET", "HEAD"],
            "allowed_path_prefixes": ["/"],
            "waf_enabled": False,
        },
        "rate_limit": {
            "enabled": True,
            "per_ip_rate": 100.0,
            "per_ip_burst": 100,
            "global_rate": 1000.0,
            "global_burst": 1000,
        },
        "audit": {"path": "audit.jsonl"},
        "admin": {"enabled": False},
    }


class ReloadIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config_path = self.directory / "config.json"
        self.stub = StubUpstream()
        self.stub.__enter__()
        self.addCleanup(self.stub.__exit__, None, None, None)
        self._write_config(_config_data(self.stub.port, ["test.local"], listen_port=free_port()))
        config = load_config(self.config_path)
        self.runtime = Runtime.build(config)
        self.server = GatewayServer(("127.0.0.1", 0), self.runtime)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )
        self.thread.start()
        self.addCleanup(self._stop)
        self.controller = ServerController(self.config_path, self.server)

    def _write_config(self, data: dict) -> None:
        self.config_path.write_text(json.dumps(data), encoding="utf-8")

    def _stop(self) -> None:
        self.stub.hold_release.set()
        self.server.begin_drain()
        try:
            self.server.shutdown()
        except Exception:
            pass
        self.server.server_close()
        self.server.wait_for_drain(2.0)
        self.thread.join(timeout=2.0)
        self.server.close_all_runtimes()

    def request(self, host: str, path: str = "/ok") -> tuple[int, list[tuple[str, str]], bytes]:
        return parse_response(send_raw(self.port, build_request(path=path, host=host)))

    def test_reload_swaps_policy_and_preserves_metrics(self) -> None:
        self.assertEqual(self.request("test.local")[0], 200)
        old_metrics = self.server.runtime.metrics
        old_limiter = self.server.runtime.per_ip_limiter

        self._write_config(_config_data(self.stub.port, ["new.local"], listen_port=self.runtime.config.server.listen_port))
        result = self.controller.reload()

        self.assertEqual(result.status, "reloaded")
        self.assertEqual(result.generation, 1)
        self.assertEqual(self.server.runtime.config.policy.allowed_hosts, ("new.local",))
        self.assertIs(self.server.runtime.metrics, old_metrics)
        self.assertIs(self.server.runtime.per_ip_limiter, old_limiter)
        self.assertGreaterEqual(self.server.runtime.metrics.snapshot()["requests_total"], 1)
        self.assertEqual(self.request("new.local")[0], 200)
        self.assertEqual(self.request("test.local")[0], 403)

    def test_invalid_reload_keeps_the_old_configuration(self) -> None:
        self.config_path.write_text("{not json", encoding="utf-8")
        result = self.controller.reload()

        self.assertEqual(result.status, "rejected")
        self.assertEqual(self.server.runtime.config.policy.allowed_hosts, ("test.local",))
        self.assertEqual(self.request("test.local")[0], 200)

    def test_reload_rejects_listener_changes(self) -> None:
        new_port = free_port()
        self._write_config(
            _config_data(self.stub.port, ["new.local"], listen_port=new_port)
        )
        result = self.controller.reload()

        self.assertEqual(result.status, "rejected")
        self.assertIn("restart required", result.error)
        self.assertEqual(self.server.runtime.config.policy.allowed_hosts, ("test.local",))
        self.assertEqual(self.request("test.local")[0], 200)

    def test_reload_swaps_tls_context_for_new_handshakes(self) -> None:
        replacement = object()
        generation = self.server.reload(self.server.runtime, replacement)  # type: ignore[arg-type]

        self.assertEqual(generation, 1)
        self.assertIs(self.server.tls_context, replacement)
        self.assertTrue(self.server.tls_enabled)

    def test_multiple_reloads_advance_generation_and_reuse_metrics(self) -> None:
        old_metrics = self.server.runtime.metrics

        for generation, host in enumerate(("one.local", "two.local", "three.local"), start=1):
            self._write_config(
                _config_data(
                    self.stub.port,
                    [host],
                    listen_port=self.runtime.config.server.listen_port,
                )
            )
            result = self.controller.reload()

            self.assertEqual(result.status, "reloaded")
            self.assertEqual(result.generation, generation)
            self.assertIs(self.server.runtime.metrics, old_metrics)
            self.assertEqual(self.request(host)[0], 200)

        self.assertEqual(self.server._runtime_refs, {})
        self.assertEqual(self.server._retired_runtimes, {})

    def test_inflight_request_keeps_old_runtime_across_reload(self) -> None:
        result: list[bytes] = []
        request_thread = threading.Thread(
            target=lambda: result.append(
                send_raw(self.port, build_request(path="/hold", host="test.local"))
            ),
            daemon=True,
        )
        request_thread.start()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not self.stub.state.snapshot():
            time.sleep(0.01)
        self.assertTrue(self.stub.state.snapshot())
        old_runtime = self.server.runtime

        self._write_config(
            _config_data(
                self.stub.port,
                ["new.local"],
                listen_port=self.runtime.config.server.listen_port,
            )
        )
        reload_result = self.controller.reload()

        self.assertEqual(reload_result.status, "reloaded")
        self.assertIsNot(self.server.runtime, old_runtime)
        self.assertIn(id(old_runtime), self.server._retired_runtimes)
        self.stub.hold_release.set()
        request_thread.join(timeout=2.0)
        self.assertEqual(parse_response(result[0])[0], 200)
        self.assertEqual(self.request("test.local")[0], 403)
        self.assertEqual(self.request("new.local")[0], 200)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and id(old_runtime) in self.server._retired_runtimes:
            time.sleep(0.01)
        self.assertNotIn(id(old_runtime), self.server._retired_runtimes)

    def test_connection_admission_key_survives_policy_reload(self) -> None:
        original_process_request_thread = self.server.process_request_thread
        entered = threading.Event()
        proceed = threading.Event()

        def delayed_process_request_thread(
            request: object,
            client_address: tuple[str, int],
        ) -> None:
            entered.set()
            self.assertTrue(proceed.wait(2.0))
            original_process_request_thread(request, client_address)  # type: ignore[arg-type]

        self.server.process_request_thread = delayed_process_request_thread  # type: ignore[method-assign]
        try:
            result: list[bytes] = []
            request_thread = threading.Thread(
                target=lambda: result.append(
                    send_raw(self.port, build_request(path="/ok", host="test.local"))
                ),
                daemon=True,
            )
            request_thread.start()
            self.assertTrue(entered.wait(2.0))

            data = _config_data(
                self.stub.port,
                ["test.local"],
                listen_port=self.runtime.config.server.listen_port,
            )
            data["policy"]["trusted_proxies"] = ["127.0.0.1/32"]
            self._write_config(data)
            self.assertEqual(self.controller.reload().status, "reloaded")

            proceed.set()
            request_thread.join(timeout=2.0)
            self.assertEqual(parse_response(result[0])[0], 200)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and self.server._ip_counts:
                time.sleep(0.01)
            self.assertEqual(self.server._ip_counts, {})
        finally:
            proceed.set()
            self.server.process_request_thread = original_process_request_thread  # type: ignore[method-assign]

    def test_shared_alert_dispatcher_survives_reload_until_shutdown(self) -> None:
        data = _config_data(
            self.stub.port,
            ["test.local"],
            listen_port=self.runtime.config.server.listen_port,
        )
        data["alerting"] = {
            "enabled": True,
            "webhook_url_env": "HIGHWALL_TEST_WEBHOOK",
            "auth_token_env": "HIGHWALL_TEST_TOKEN",
            "allow_http": True,
        }
        environment = {
            "HIGHWALL_TEST_WEBHOOK": "http://127.0.0.1:9/alert",
            "HIGHWALL_TEST_TOKEN": "T" * 16,
        }
        with patch.dict(os.environ, environment, clear=False):
            self._write_config(data)
            self.assertEqual(self.controller.reload().status, "reloaded")
            dispatcher = self.server.runtime.alert_dispatcher
            assert dispatcher is not None and dispatcher._thread is not None

            self._write_config(data)
            self.assertEqual(self.controller.reload().status, "reloaded")

        self.assertIs(self.server.runtime.alert_dispatcher, dispatcher)
        self.assertTrue(dispatcher._thread is not None and dispatcher._thread.is_alive())

    def test_upstream_target_change_resets_circuit_breaker(self) -> None:
        data = _config_data(
            self.stub.port,
            ["test.local"],
            listen_port=self.runtime.config.server.listen_port,
        )
        data["upstream"]["circuit_breaker"] = {
            "enabled": True,
            "failure_threshold": 2,
            "window": 30.0,
            "open_seconds": 30.0,
        }
        first_path = self.directory / "first.json"
        first_path.write_text(json.dumps(data), encoding="utf-8")
        first_runtime = Runtime.build(load_config(first_path))
        breaker = first_runtime.circuit_breaker
        assert breaker is not None
        token = breaker.allow().token
        breaker.record_failure(token)
        breaker.record_failure(token)
        self.assertEqual(breaker.current_state(), "open")

        data["upstream"]["port"] = free_port()
        second_path = self.directory / "second.json"
        second_path.write_text(json.dumps(data), encoding="utf-8")
        second_runtime = Runtime.build(load_config(second_path), previous=first_runtime)
        try:
            self.assertIsNot(second_runtime.circuit_breaker, breaker)
            assert second_runtime.circuit_breaker is not None
            self.assertEqual(second_runtime.circuit_breaker.current_state(), "closed")
        finally:
            first_runtime.close()
            second_runtime.close()

    def test_drain_rejects_new_requests_and_waits_for_active_requests(self) -> None:
        result: list[bytes] = []
        request_thread = threading.Thread(
            target=lambda: result.append(send_raw(self.port, build_request(path="/hold", host="test.local"))),
            daemon=True,
        )
        request_thread.start()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not self.stub.state.snapshot():
            time.sleep(0.01)
        self.assertTrue(self.stub.state.snapshot())

        self.server.begin_drain()
        drained = self.request("test.local")
        self.assertEqual(drained[0], 503)
        self.assertFalse(self.server.wait_for_drain(0.1))
        self.stub.hold_release.set()
        self.assertTrue(self.server.wait_for_drain(2.0))
        request_thread.join(timeout=2.0)
        self.assertEqual(parse_response(result[0])[0], 200)


if __name__ == "__main__":
    unittest.main()
