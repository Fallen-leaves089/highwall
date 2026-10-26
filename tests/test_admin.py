from __future__ import annotations

import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from highwall.admin import AdminServer
from highwall.runtime import Runtime
from tests.support import base_config


class AdminIntegrationTests(unittest.TestCase):
    token = "B" * 32

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "admin": {
                    "enabled": True,
                    "listen_host": "127.0.0.1",
                    "listen_port": 18091,
                    "token_env": "HIGHWALL_ADMIN_TOKEN",
                    "audit_tail_max_lines": 50,
                },
                "policy": {
                    "honeypot": {
                        "enabled": True,
                        "ban_seconds": 30,
                        "routes": [
                            {
                                "id": "env_probe",
                                "path": "/.env",
                                "status": 200,
                                "body": "DECOY=1\n",
                            }
                        ],
                    }
                },
            },
        )
        self.runtime = Runtime.build(config, admin_token=self.token)
        self.server = AdminServer(("127.0.0.1", 0), self.runtime)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.01)
        else:
            self.fail("admin server did not start")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        host: str | None = None,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2.0)
        headers: dict[str, str] = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if host is not None:
            headers["Host"] = host
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            connection.close()

    def test_health_does_not_require_token(self) -> None:
        status, headers, body = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")
        self.assertIn("default-src 'none'", dict(headers)["Content-Security-Policy"])
        self.assertEqual(dict(headers)["Cache-Control"], "no-store")

    def test_metrics_requires_token(self) -> None:
        status, headers, _ = self.request("GET", "/metrics")
        self.assertEqual(status, 401)
        self.assertIn("Bearer", dict(headers)["WWW-Authenticate"])

        status, _, _ = self.request("GET", "/metrics", token="C" * 32)
        self.assertEqual(status, 401)

        status, _, body = self.request("GET", "/metrics", token=self.token)
        self.assertEqual(status, 200)
        self.assertIn(b"highwall_requests_total", body)
        self.assertIn(b"highwall_route_rate_limit_rejections_total 0", body)
        self.assertIn(b"highwall_tls_handshake_failures_total 0", body)
        self.assertIn(b"highwall_uptime_seconds", body)
        assert self.runtime.honeypot_ban is not None
        self.runtime.honeypot_ban.force_ban("203.0.113.9")
        status, _, body = self.request("GET", "/metrics", token=self.token)
        self.assertEqual(status, 200)
        self.assertIn(b"highwall_honeypot_ban_entries 1", body)

    def test_audit_tail_requires_token_and_returns_events(self) -> None:
        status, _, _ = self.request("GET", "/audit/tail?lines=2")
        self.assertEqual(status, 401)
        self.request("GET", "/healthz")
        status, _, body = self.request("GET", "/audit/tail?lines=10", token=self.token)
        self.assertEqual(status, 200)
        events = json.loads(body)["events"]
        self.assertTrue(any(event["event"] == "admin_access" for event in events))

    def test_audit_tail_rejects_bad_limits(self) -> None:
        for path in ("/audit/tail?lines=0", "/audit/tail?lines=9999", "/audit/tail?other=1", "/audit/tail?lines=x"):
            with self.subTest(path=path):
                status, _, _ = self.request("GET", path, token=self.token)
                self.assertEqual(status, 400)

    def test_unknown_path_is_404(self) -> None:
        status, _, _ = self.request("GET", "/nope", token=self.token)
        self.assertEqual(status, 404)

    def test_post_is_rejected(self) -> None:
        status, _, _ = self.request("POST", "/metrics", token=self.token)
        self.assertEqual(status, 405)

    def test_post_with_non_loopback_host_is_rejected_before_method_handling(self) -> None:
        status, _, _ = self.request("POST", "/metrics", token=self.token, host="evil.local")
        self.assertEqual(status, 400)

    def test_runtime_repr_does_not_expose_admin_token(self) -> None:
        self.assertNotIn(self.token, repr(self.runtime))

    def test_non_loopback_host_header_is_rejected(self) -> None:
        status, _, _ = self.request("GET", "/healthz", host="evil.local")
        self.assertEqual(status, 400)

    def test_head_has_headers_but_no_body(self) -> None:
        status, headers, body = self.request("HEAD", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertGreater(int(dict(headers)["Content-Length"]), 0)

    def test_audit_never_contains_token_or_authorization(self) -> None:
        self.request("GET", "/metrics", token=self.token)
        raw = (Path(self.temp.name) / "audit.jsonl").read_text("utf-8")
        self.assertNotIn(self.token, raw)
        self.assertNotIn("Authorization", raw)
        self.assertNotIn("Bearer", raw)


if __name__ == "__main__":
    unittest.main()
