from __future__ import annotations

import json
import hashlib
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from highwall.config import Config
from highwall.proxy import GatewayServer, _effective_security_headers
from highwall.runtime import Runtime
from tests.support import (
    GatewayHarness,
    RawUpstream,
    StubUpstream,
    audit_text,
    base_config,
    build_request,
    free_port,
    header_values,
    parse_response,
    send_raw,
)


class _BlockingTLSContext:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.block_next = True

    def wrap_socket(self, sock: socket.socket, *, server_side: bool = False) -> socket.socket:
        if self.block_next:
            self.block_next = False
            self.started.set()
            if not self.release.wait(2.0):
                raise OSError("test TLS handshake timed out")
        return sock


class _FailingOnceTLSContext:
    def __init__(self) -> None:
        self.failed = threading.Event()
        self.fail_next = True

    def wrap_socket(self, sock: socket.socket, *, server_side: bool = False) -> socket.socket:
        if self.fail_next:
            self.fail_next = False
            self.failed.set()
            raise OSError("test TLS handshake failure")
        return sock


class ProxyIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stub = StubUpstream()
        self.stub.__enter__()
        self.addCleanup(self.stub.__exit__, None, None, None)
        self.config = base_config(Path(self.temp.name), self.stub.port)
        self.gateway = GatewayHarness(self.config)
        self.gateway.__enter__()
        self.addCleanup(self.gateway.__exit__, None, None, None)

    def request(self, payload: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        return parse_response(send_raw(self.gateway.port, payload))

    def start_tls_gateway(
        self,
        context: object,
        config: Config | None = None,
    ) -> tuple[GatewayServer, Runtime]:
        runtime = Runtime.build(config or self.config)
        server = GatewayServer(("127.0.0.1", 0), runtime, tls_context=context)
        ready = threading.Event()

        def serve() -> None:
            ready.set()
            server.serve_forever(poll_interval=0.02)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(1.0))

        def stop() -> None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

        self.addCleanup(stop)
        return server, runtime

    def test_valid_request_is_forwarded_and_response_is_cleaned(self) -> None:
        payload = build_request(
            headers=[
                ("X-Forwarded-For", "203.0.113.9"),
                ("Cookie", "session=topsecret"),
                ("Authorization", "Bearer topsecret"),
                ("Connection", "keep-alive, X-Drop"),
                ("X-Drop", "remove-me"),
                ("Proxy-Connection", "keep-alive"),
                ("X-HTTP-Method-Override", "DELETE"),
                ("X-Original-URL", "/.git/config"),
                ("Accept-Encoding", "gzip, br"),
            ]
        )
        status, headers, body = self.request(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from upstream")
        self.assertEqual(header_values(headers, "Server"), ["HighWall"])
        self.assertEqual(header_values(headers, "X-Custom"), ["keep-me"])
        self.assertEqual(header_values(headers, "X-Powered-By"), [])
        self.assertEqual(header_values(headers, "Set-Cookie"), ["a=1; Path=/", "b=2; Path=/"])
        self.assertIn("default-src 'self'", header_values(headers, "Content-Security-Policy")[0])
        self.assertEqual(header_values(headers, "X-Content-Type-Options"), ["nosniff"])
        self.assertEqual(header_values(headers, "Strict-Transport-Security"), [])
        self.assertTrue(header_values(headers, "X-Request-ID"))
        self.assertEqual(len(header_values(headers, "Date")), 1)
        self.assertEqual(header_values(headers, "Connection"), ["close"])

        received = self.stub.state.snapshot()[-1]
        upstream_headers = {name.lower(): value for name, value in received["headers"]}
        self.assertEqual(upstream_headers["host"], "test.local")
        self.assertEqual(upstream_headers["x-forwarded-for"], "127.0.0.1")
        self.assertEqual(upstream_headers["cookie"], "session=topsecret")
        self.assertEqual(upstream_headers["authorization"], "Bearer topsecret")
        self.assertNotIn("x-drop", upstream_headers)
        self.assertNotIn("proxy-connection", upstream_headers)
        self.assertNotIn("x-http-method-override", upstream_headers)
        self.assertNotIn("x-original-url", upstream_headers)
        self.assertEqual(upstream_headers["accept-encoding"], "identity")
        self.assertIn("x-request-id", upstream_headers)

        logged = audit_text(Path(self.temp.name))
        self.assertNotIn("topsecret", logged)
        self.assertNotIn("session=", logged)
        self.assertNotIn("Authorization", logged)
        event = json.loads(logged.splitlines()[-1])
        self.assertEqual(event["event"], "request_allowed")
        self.assertEqual(event["path"], "/ok")

    def test_post_body_is_forwarded(self) -> None:
        body = b'{"name":"alice"}'
        payload = build_request(
            method="POST",
            path="/echo",
            headers=[("Content-Type", "application/json")],
            body=body,
        )
        status, _, response_body = self.request(payload)
        self.assertEqual(status, 200)
        echoed = json.loads(response_body)
        self.assertEqual(echoed["body"], body.decode("utf-8"))
        self.assertEqual(echoed["path"], "/echo")
        received = self.stub.state.snapshot()[-1]
        self.assertEqual(received["body"], body)

    def test_query_encoding_is_preserved_for_upstream(self) -> None:
        target = "/echo?a=%2526b&c=hello+world"
        status, _, body = self.request(build_request(path=target))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["path"], target)
        self.assertEqual(self.stub.state.snapshot()[-1]["path"], target)

    def test_head_has_no_body(self) -> None:
        status, headers, body = self.request(build_request(method="HEAD"))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(header_values(headers, "Content-Length"), ["19"])

    def test_upstream_404_is_forwarded(self) -> None:
        status, _, body = self.request(build_request(path="/status/404"))
        self.assertEqual(status, 404)
        self.assertEqual(body, b"not found")
        event = json.loads(audit_text(Path(self.temp.name)).splitlines()[-1])
        self.assertEqual(event["event"], "request_allowed")
        self.assertEqual(event["status"], 404)

    def test_duplicate_content_length_rejected(self) -> None:
        raw = (
            b"POST /ok HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 1\r\nContent-Length: 1\r\n\r\nA"
        )
        status, headers, _ = self.request(raw)
        self.assertEqual(status, 400)
        self.assertEqual(header_values(headers, "Connection"), ["close"])
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_content_length_and_transfer_encoding_rejected(self) -> None:
        raw = (
            b"POST /ok HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        status, _, _ = self.request(raw)
        self.assertEqual(status, 400)

    def test_transfer_encoding_alone_rejected(self) -> None:
        raw = (
            b"POST /ok HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        status, _, _ = self.request(raw)
        self.assertEqual(status, 400)

    def test_untrusted_forwarding_header_is_replaced(self) -> None:
        status, _, body = self.request(build_request(path="/echo", headers=[("X-Forwarded-For", "198.51.100.8")]))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["xff"], "127.0.0.1")

    def test_invalid_host_rejected(self) -> None:
        status, _, _ = self.request(build_request(host="evil.local"))
        self.assertEqual(status, 403)

    def test_missing_host_rejected(self) -> None:
        status, _, _ = self.request(build_request(host=None))
        self.assertEqual(status, 400)

    def test_disallowed_method_rejected(self) -> None:
        status, _, _ = self.request(build_request(method="PUT"))
        self.assertEqual(status, 405)

    def test_absolute_uri_rejected(self) -> None:
        raw = b"GET http://evil.local/ HTTP/1.1\r\nHost: test.local\r\n\r\n"
        status, _, _ = self.request(raw)
        self.assertEqual(status, 400)

    def test_path_traversal_rejected(self) -> None:
        for path in ("/a/../b", "/%2e%2e/etc/passwd", "/a%2fb", "/a%252e%252e%252fb"):
            with self.subTest(path=path):
                status, _, _ = self.request(build_request(path=path))
                self.assertIn(status, {400, 403})

    def test_denied_path_rejected(self) -> None:
        status, _, _ = self.request(build_request(path="/.git/config"))
        self.assertEqual(status, 403)

    def test_oversized_body_rejected_before_read(self) -> None:
        raw = (
            b"POST /ok HTTP/1.1\r\nHost: test.local\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 5000\r\n\r\n"
        )
        status, _, _ = self.request(raw)
        self.assertEqual(status, 413)

    def test_oversized_request_line_rejected(self) -> None:
        status, _, _ = self.request(build_request(path="/" + "a" * 5000))
        self.assertEqual(status, 414)

    def test_oversized_header_block_rejected(self) -> None:
        headers = [(f"X-Long-{index}", "a" * 800) for index in range(12)]
        status, _, _ = self.request(build_request(headers=headers))
        self.assertEqual(status, 431)

    def test_duplicate_header_rejected(self) -> None:
        status, _, _ = self.request(build_request(headers=[("X-Test", "one"), ("X-Test", "two")]))
        self.assertEqual(status, 400)

    def test_obsolete_header_folding_rejected(self) -> None:
        raw = b"GET /ok HTTP/1.1\r\nHost: test.local\r\n X-Folded: yes\r\n\r\n"
        status, _, _ = self.request(raw)
        self.assertEqual(status, 400)

    def test_waf_blocks_sql_injection_in_query(self) -> None:
        status, _, _ = self.request(build_request(path="/ok?q=%27%20OR%201%3D1"))
        self.assertEqual(status, 403)

    def test_waf_blocks_xss_in_json_body(self) -> None:
        body = b'{"comment":"<script>alert(1)</script>"}'
        payload = build_request(
            method="POST",
            path="/ok",
            headers=[("Content-Type", "application/json")],
            body=body,
        )
        status, _, _ = self.request(payload)
        self.assertEqual(status, 403)

    def test_get_body_rejected(self) -> None:
        payload = build_request(
            method="GET",
            headers=[("Content-Type", "text/plain")],
            body=b"A",
        )
        status, _, _ = self.request(payload)
        self.assertEqual(status, 400)

    def test_unsupported_content_type_rejected(self) -> None:
        payload = build_request(
            method="POST",
            headers=[("Content-Type", "application/octet-stream")],
            body=b"A",
        )
        status, _, _ = self.request(payload)
        self.assertEqual(status, 415)

    def test_rate_limit_returns_429_and_retry_after(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={
                    "rate_limit": {
                        "enabled": True,
                        "per_ip_rate": 1.0,
                        "per_ip_burst": 1,
                        "global_rate": 100.0,
                        "global_burst": 100,
                    }
                },
            )
            with GatewayHarness(config) as gateway:
                first = parse_response(send_raw(gateway.port, build_request()))
                second = parse_response(send_raw(gateway.port, build_request()))
            self.assertEqual(first[0], 200)
            self.assertEqual(second[0], 429)
            self.assertTrue(header_values(second[1], "Retry-After"))
            self.assertEqual(len(self.stub.state.snapshot()), 1)

    def test_route_rate_limit_works_with_global_rate_limit_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={
                    "policy": {
                        "routes": [{"path_prefix": "/ok", "rate": 1.0, "rate_burst": 1}],
                    }
                },
            )
            with GatewayHarness(config) as gateway:
                first = parse_response(send_raw(gateway.port, build_request(path="/ok")))
                second = parse_response(send_raw(gateway.port, build_request(path="/ok")))
                metrics = gateway.runtime.metrics.snapshot()
            self.assertEqual(first[0], 200)
            self.assertEqual(second[0], 429)
            self.assertTrue(header_values(second[1], "Retry-After"))
            self.assertEqual(metrics["route_rate_limit_rejections_total"], 1)
            self.assertEqual(len(self.stub.state.snapshot()), 1)

    def test_sensitive_upstream_response_is_blocked(self) -> None:
        status, _, body = self.request(build_request(path="/leak-secret"))
        self.assertEqual(status, 502)
        self.assertNotIn(b"PRIVATE KEY", body)
        time.sleep(0.05)
        event = json.loads(audit_text(Path(self.temp.name)).splitlines()[-1])
        self.assertEqual(event["event"], "response_blocked")
        self.assertEqual(event["rule_id"], "HW-DLP-SECRET-1001")
        metrics = self.gateway.runtime.metrics.snapshot()
        self.assertEqual(metrics["dlp_detected_total"], 1)
        self.assertEqual(metrics["dlp_blocked_total"], 1)

    def test_sensitive_upstream_response_can_be_detected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={"policy": {"response_scan_mode": "detect"}},
            )
            with GatewayHarness(config) as gateway:
                status, _, body = parse_response(send_raw(gateway.port, build_request(path="/leak-secret")))
                metrics = gateway.runtime.metrics.snapshot()
            time.sleep(0.05)
            event = json.loads((Path(directory) / "audit.jsonl").read_text("utf-8").splitlines()[-1])
        self.assertEqual(status, 200)
        self.assertIn(b"PRIVATE KEY", body)
        self.assertEqual(event["event"], "response_allowed_with_detection")
        self.assertEqual(event["rule_id"], "HW-DLP-SECRET-1001")
        self.assertEqual(metrics["dlp_detected_total"], 1)
        self.assertEqual(metrics["dlp_blocked_total"], 0)

    def test_octet_stream_and_utf16_secret_responses_are_blocked(self) -> None:
        bodies = [
            b"\x00\x01-----BEGIN RSA PRIVATE KEY-----",
            "dump\n-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAK\n".encode("utf-16-le"),
        ]
        for body in bodies:
            with self.subTest(prefix=body[:8]):
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
                with tempfile.TemporaryDirectory() as directory:
                    with RawUpstream(response) as upstream:
                        config = base_config(Path(directory), upstream.port)
                        with GatewayHarness(config) as gateway:
                            status, _, response_body = parse_response(
                                send_raw(gateway.port, build_request())
                            )
                self.assertEqual(status, 502)
                self.assertNotIn(b"PRIVATE KEY", response_body)

    def test_secret_in_response_header_is_blocked(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Api-Key: AKIAIOSFODNN7EXAMPLE\r\n"
            b"Content-Length: 2\r\n\r\nok"
        )
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(Path(directory), upstream.port)
                with GatewayHarness(config) as gateway:
                    status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 502)

    def test_jwt_in_set_cookie_does_not_trigger_dlp(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Set-Cookie: session={jwt}; HttpOnly; Secure; Path=/\r\n".encode("ascii")
            + b"Content-Length: 2\r\n\r\nok"
        )
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(Path(directory), upstream.port)
                with GatewayHarness(config) as gateway:
                    status, headers, body = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        self.assertEqual(len(header_values(headers, "Set-Cookie")), 1)

    def test_hsts_defaults_only_when_tls_is_enabled(self) -> None:
        policy = SimpleNamespace(security_headers=(("X-Test", "1"),))
        plain = SimpleNamespace(
            config=SimpleNamespace(
                server=SimpleNamespace(tls=SimpleNamespace(enabled=False)),
                policy=policy,
            )
        )
        self.assertNotIn("strict-transport-security", {name.casefold() for name, _ in _effective_security_headers(plain)})

        secure = SimpleNamespace(
            config=SimpleNamespace(
                server=SimpleNamespace(tls=SimpleNamespace(enabled=True)),
                policy=policy,
            )
        )
        secure_headers = _effective_security_headers(secure)
        self.assertEqual(
            [value for name, value in secure_headers if name.casefold() == "strict-transport-security"],
            ["max-age=31536000"],
        )

        explicit_policy = SimpleNamespace(
            security_headers=(("Strict-Transport-Security", "max-age=42"),)
        )
        explicit = SimpleNamespace(
            config=SimpleNamespace(
                server=SimpleNamespace(tls=SimpleNamespace(enabled=True)),
                policy=explicit_policy,
            )
        )
        hsts = [value for name, value in _effective_security_headers(explicit) if name.casefold() == "strict-transport-security"]
        self.assertEqual(hsts, ["max-age=42"])

    def test_tls_handshake_does_not_block_accept_loop(self) -> None:
        context = _BlockingTLSContext()
        server, _ = self.start_tls_gateway(context)
        self.addCleanup(context.release.set)
        first = socket.create_connection(("127.0.0.1", int(server.server_address[1])), timeout=1.0)
        self.addCleanup(first.close)
        self.assertTrue(context.started.wait(1.0))

        status, _, body = parse_response(
            send_raw(int(server.server_address[1]), build_request(), timeout=1.0)
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from upstream")
        context.release.set()

    def test_tls_handshake_failure_releases_all_slots(self) -> None:
        config = base_config(
            Path(self.temp.name),
            self.stub.port,
            overrides={
                "server": {
                    "max_connections": 1,
                    "max_connections_per_ip": 1,
                    "max_inflight_requests": 1,
                }
            },
        )
        context = _FailingOnceTLSContext()
        server, runtime = self.start_tls_gateway(context, config)
        first = socket.create_connection(("127.0.0.1", int(server.server_address[1])), timeout=1.0)
        self.addCleanup(first.close)
        self.assertTrue(context.failed.wait(1.0))

        status, _, body = parse_response(
            send_raw(int(server.server_address[1]), build_request(), timeout=1.0)
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from upstream")
        self.assertEqual(runtime.metrics.snapshot()["tls_handshake_failures_total"], 1)

    def test_utf16_request_body_and_non_utf8_charset_are_rejected(self) -> None:
        body = "{\"q\":\"UNION SELECT\"}".encode("utf-16-le")
        payload = build_request(
            method="POST",
            path="/ok",
            headers=[("Content-Type", "application/json")],
            body=body,
        )
        status, _, _ = self.request(payload)
        self.assertEqual(status, 415)

        declared = build_request(
            method="POST",
            path="/ok",
            headers=[("Content-Type", "application/json; charset=utf-16")],
            body=b"{}",
        )
        status, _, _ = self.request(declared)
        self.assertEqual(status, 415)
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_confirmed_request_waf_bypasses_do_not_reach_upstream(self) -> None:
        payloads = [
            build_request(path="/ok?q=UNION/**/SELECT"),
            build_request(path="/ok?q=;%20cat%20/etc/passwd"),
            build_request(
                method="POST",
                path="/ok",
                headers=[("Content-Type", "application/json")],
                body=b'{"x":"onpointerover=alert(1)"}',
            ),
        ]
        for payload in payloads:
            with self.subTest(payload=payload.split(b"\r\n", 1)[0]):
                status, _, _ = self.request(payload)
                self.assertEqual(status, 403)
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_route_obfuscation_cannot_bypass_method_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={
                    "policy": {
                        "routes": [{"path_prefix": "/admin", "methods": ["GET"]}],
                    }
                },
            )
            with GatewayHarness(config) as gateway:
                for target in ("/admin;foo", "/admin%3Bfoo", "/admin.", "/admin%20"):
                    with self.subTest(target=target):
                        status, _, _ = parse_response(
                            send_raw(gateway.port, build_request(method="POST", path=target))
                        )
                        self.assertEqual(status, 400)
                upper = parse_response(send_raw(gateway.port, build_request(method="POST", path="/ADMIN")))
        self.assertEqual(upper[0], 405)
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_integrity_pin_uses_routing_path_after_compatibility_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={
                    "policy": {
                        "allow_trailing_dot_or_space": True,
                        "response_integrity_mode": "block",
                        "integrity_pins": [
                            {
                                "path": "/ok",
                                "status": 200,
                                "sha256": hashlib.sha256(b"different expected body").hexdigest(),
                            }
                        ],
                    }
                },
            )
            with GatewayHarness(config) as gateway:
                status, _, body = parse_response(
                    send_raw(gateway.port, build_request(path="/ok."))
                )
        self.assertEqual(status, 502)
        self.assertIn(b"HW-INTEGRITY-1001", body)

    def test_sensitive_path_is_redacted_from_audit(self) -> None:
        status, _, _ = self.request(build_request(path="/token/SUPERSECRET"))
        self.assertEqual(status, 200)
        logged = audit_text(Path(self.temp.name))
        self.assertNotIn("SUPERSECRET", logged)
        event = json.loads(logged.splitlines()[-1])
        self.assertEqual(event["path"], "/token/<redacted>")

    def test_encoded_upstream_response_is_rejected(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nabcd"
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(Path(directory), upstream.port)
                with GatewayHarness(config) as gateway:
                    status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 502)

    def test_origin_policy_is_enforced_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={"policy": {"allowed_origins": ["https://test.local"]}},
            )
            with GatewayHarness(config) as gateway:
                valid = build_request(
                    method="POST",
                    path="/echo",
                    headers=[("Content-Type", "application/json"), ("Origin", "https://TEST.local:443")],
                    body=b"{}",
                )
                missing = build_request(
                    method="POST",
                    path="/echo",
                    headers=[("Content-Type", "application/json")],
                    body=b"{}",
                )
                wrong = build_request(
                    method="POST",
                    path="/echo",
                    headers=[("Content-Type", "application/json"), ("Origin", "https://evil.test")],
                    body=b"{}",
                )
                valid_status = parse_response(send_raw(gateway.port, valid))[0]
                missing_status = parse_response(send_raw(gateway.port, missing))[0]
                wrong_status = parse_response(send_raw(gateway.port, wrong))[0]
        self.assertEqual((valid_status, missing_status, wrong_status), (200, 403, 403))

    def test_client_network_deny_list_is_enforced_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={"policy": {"denied_client_networks": ["127.0.0.1/32"]}},
            )
            with GatewayHarness(config) as gateway:
                status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 403)

    def test_repeated_violations_trigger_adaptive_ban(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={
                    "rate_limit": {
                        "enabled": True,
                        "per_ip_rate": 100.0,
                        "per_ip_burst": 100,
                        "global_rate": 1000.0,
                        "global_burst": 1000,
                        "auto_ban_threshold": 2,
                        "auto_ban_window": 60.0,
                        "auto_ban_seconds": 30.0,
                    }
                },
            )
            with GatewayHarness(config) as gateway:
                first = parse_response(send_raw(gateway.port, build_request(host="bad.local")))
                time.sleep(0.1)
                second = parse_response(send_raw(gateway.port, build_request(host="bad.local")))
                time.sleep(0.1)
                third = parse_response(send_raw(gateway.port, build_request(host="bad.local")))
            time.sleep(0.05)
            event = json.loads((Path(directory) / "audit.jsonl").read_text("utf-8").splitlines()[-1])
        self.assertEqual(first[0], 403)
        self.assertEqual(second[0], 403)
        self.assertEqual(third[0], 429)
        self.assertTrue(header_values(third[1], "Retry-After"))
        self.assertEqual(event["rule_id"], "HW-RATE-1003")

    def test_per_ip_connection_limit_rejects_excess_connections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={"server": {"max_connections_per_ip": 1}},
            )
            with GatewayHarness(config) as gateway:
                time.sleep(0.2)
                first = socket.create_connection(("127.0.0.1", gateway.port), timeout=2.0)
                try:
                    first.sendall(build_request(path="/slow"))
                    time.sleep(0.2)
                    second = socket.create_connection(("127.0.0.1", gateway.port), timeout=2.0)
                    try:
                        second.settimeout(2.0)
                        chunks: list[bytes] = []
                        while True:
                            chunk = second.recv(65536)
                            if not chunk:
                                break
                            chunks.append(chunk)
                    finally:
                        second.close()
                    first.settimeout(2.0)
                    while first.recv(65536):
                        pass
                finally:
                    first.close()
        self.assertEqual(parse_response(b"".join(chunks))[0], 503)

    def test_upstream_connect_timeout_returns_504(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                free_port(),
                overrides={"upstream": {"connect_timeout": 0.1}},
            )
            with GatewayHarness(config) as gateway:
                status, _, _ = parse_response(send_raw(gateway.port, build_request()))
            self.assertEqual(status, 504)

    def test_upstream_protocol_failure_returns_502(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = int(listener.getsockname()[1])

        def close_once() -> None:
            try:
                connection, _ = listener.accept()
                connection.close()
            finally:
                listener.close()

        thread = threading.Thread(target=close_once, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), port)
            with GatewayHarness(config) as gateway:
                status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        thread.join(timeout=1.0)
        self.assertEqual(status, 502)

    def test_upstream_timeout_returns_504(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={"upstream": {"read_timeout": 0.1}},
            )
            with GatewayHarness(config) as gateway:
                status, _, _ = parse_response(send_raw(gateway.port, build_request(path="/slow")))
            self.assertEqual(status, 504)

    def test_oversized_upstream_response_returns_502(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={"upstream": {"max_response_bytes": 1024}},
            )
            with GatewayHarness(config) as gateway:
                status, _, _ = parse_response(send_raw(gateway.port, build_request(path="/big")))
            self.assertEqual(status, 502)

    def test_trusted_proxy_chain_reaches_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={"policy": {"trusted_proxies": ["127.0.0.1/32"]}},
            )
            with GatewayHarness(config) as gateway:
                payload = build_request(
                    path="/echo",
                    headers=[("X-Forwarded-For", "198.51.100.7, 127.0.0.1")],
                )
                status, _, body = parse_response(send_raw(gateway.port, payload))
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["xff"], "198.51.100.7")

    def test_slow_header_deadline_returns_408(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                self.stub.port,
                overrides={"server": {"header_timeout": 0.2}},
            )
            with GatewayHarness(config) as gateway:
                sock = socket.create_connection(("127.0.0.1", gateway.port), timeout=1.0)
                try:
                    sock.sendall(b"GET /ok HTTP/1.1\r\nHost: test.local\r\n")
                    time.sleep(0.35)
                    sock.settimeout(2.0)
                    chunks: list[bytes] = []
                    while True:
                        try:
                            chunk = sock.recv(65536)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        chunks.append(chunk)
                    status, _, _ = parse_response(b"".join(chunks))
                finally:
                    sock.close()
            self.assertEqual(status, 408)


    def test_duplicate_upstream_content_length_returns_502(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(Path(directory), upstream.port)
                with GatewayHarness(config) as gateway:
                    status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 502)

    def test_upstream_content_length_and_transfer_encoding_returns_502(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(Path(directory), upstream.port)
                with GatewayHarness(config) as gateway:
                    status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 502)

    def test_upstream_invalid_content_length_returns_502(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello"
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(Path(directory), upstream.port)
                with GatewayHarness(config) as gateway:
                    status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 502)

    def test_upstream_content_length_mismatch_returns_502(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc"
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(Path(directory), upstream.port)
                with GatewayHarness(config) as gateway:
                    status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 502)

    def test_upstream_chunked_response_is_reencoded_with_length(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(Path(directory), upstream.port)
                with GatewayHarness(config) as gateway:
                    status, headers, body = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello")
        self.assertEqual(header_values(headers, "Content-Length"), ["5"])
        self.assertEqual(header_values(headers, "Transfer-Encoding"), [])

    def test_upstream_total_timeout_returns_504(self) -> None:
        response = [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 0.0),
            (b"a", 0.2),
            (b"b", 0.2),
            (b"c", 0.2),
            (b"d", 0.2),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with RawUpstream(response) as upstream:
                config = base_config(
                    Path(directory),
                    upstream.port,
                    overrides={"upstream": {"total_timeout": 0.5, "read_timeout": 10.0}},
                )
                with GatewayHarness(config) as gateway:
                    status, _, _ = parse_response(send_raw(gateway.port, build_request()))
        self.assertEqual(status, 504)


if __name__ == "__main__":
    unittest.main()
