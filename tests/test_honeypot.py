from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from highwall.config import ConfigError, HoneypotBackendConfig
from highwall.config_report import build_config_report
from highwall.errors import Forbidden
from highwall.protocol import RequestHead
from highwall.proxy import GatewayServer
from highwall.waf import validate_head
from tests.support import (
    GatewayHarness,
    StubUpstream,
    audit_text,
    base_config,
    build_request,
    free_port,
    header_values,
    parse_response,
    send_raw,
)


def decoy_routes() -> list[dict]:
    return [
        {
            "id": "env_probe",
            "path": "/.env",
            "status": 200,
            "content_type": "text/plain; charset=utf-8",
            "body": "APP_ENV=production\nDB_HOST=db.internal\nDB_PASSWORD=not-a-real-secret\n",
            "headers": {"X-Decoy": "environment"},
            "server_header": "nginx",
            "delay_ms": 0,
        },
        {
            "id": "login_probe",
            "path": "/decoy-login",
            "status": 200,
            "content_type": "text/html; charset=utf-8",
            "body": "<!doctype html><title>Sign in</title><form method=post></form>",
            "headers": {"X-Decoy": "login"},
            "server_header": "nginx",
            "delay_ms": 0,
        },
    ]


def honeypot_policy(*, enabled: bool = True, ban_seconds: float = 5.0) -> dict:
    return {
        "enabled": enabled,
        "ban_seconds": ban_seconds,
        "routes": decoy_routes(),
    }


class _CompromisedBackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        body = b"compromised backend"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "compromised-nginx")
        self.send_header("X-Powered-By", "php/8.2")
        self.send_header("Content-Security-Policy", "default-src *")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Clear-Site-Data", '"cookies", "storage"')
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Permissions-Policy", "camera=*")
        self.send_header("Refresh", "0; url=https://evil.example/")
        self.send_header("Set-Cookie", "ok=1; Path=/")
        self.send_header("Set-Cookie", "scoped=2; dOmAiN=test.local; Path=/; SameSite=Lax")
        self.send_header("Set-Cookie", "__Host-shadow=3; Path=/; Secure")
        self.send_header("Set-Cookie", "__Secure-shadow=4; Path=/; Secure")
        self.send_header("Set-Cookie", "bad name=5; Path=/")
        self.send_header("Set-Cookie", "=6; Path=/")
        self.send_header("Location", "https://evil.example/landing")
        self.send_header("Location", "/login")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class HoneypotConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def config(self, honeypot: dict) -> object:
        return base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"honeypot": honeypot}},
        )

    def test_honeypot_is_disabled_by_default(self) -> None:
        config = base_config(Path(self.temp.name), 18080)
        self.assertFalse(config.policy.honeypot.enabled)
        self.assertEqual(config.policy.honeypot.routes, ())

    def test_valid_honeypot_configuration(self) -> None:
        config = self.config(honeypot_policy())
        self.assertTrue(config.policy.honeypot.enabled)
        self.assertEqual(config.policy.honeypot.ban_seconds, 5.0)
        self.assertEqual([route.path for route in config.policy.honeypot.routes], ["/.env", "/decoy-login"])

    def test_enabled_honeypot_requires_routes(self) -> None:
        with self.assertRaisesRegex(ConfigError, "must not be empty"):
            self.config({"enabled": True, "routes": []})

    def test_additional_honeypot_listeners_are_parsed(self) -> None:
        config = self.config(
            {
                "enabled": True,
                "presets": ["common"],
                "listeners": [
                    {"name": "decoy-admin", "listen_port": 18092},
                    {"name": "decoy-api", "listen_host": "127.0.0.1", "listen_port": 18093},
                ],
            }
        )
        self.assertEqual(
            [(item.name, item.listen_host, item.listen_port) for item in config.policy.honeypot.listeners],
            [
                ("decoy-admin", "127.0.0.1", 18092),
                ("decoy-api", "127.0.0.1", 18093),
            ],
        )
        report = build_config_report(config)
        self.assertEqual(report["policy"]["honeypot"]["listeners"][0]["name"], "decoy-admin")

    def test_high_interaction_backend_is_parsed_and_reported(self) -> None:
        config = self.config(
            {
                "enabled": True,
                "presets": ["common"],
                "listeners": [
                    {
                        "name": "live-admin",
                        "listen_port": 18092,
                        "backend": {
                            "host": "10.20.30.40",
                            "port": 8080,
                            "host_header": "admin.internal",
                            "server_header": "Apache",
                            "connect_timeout": 1.5,
                            "read_timeout": 5,
                            "total_timeout": 12,
                            "max_response_bytes": 1048576,
                        },
                    }
                ],
            }
        )
        backend = config.policy.honeypot.listeners[0].backend
        assert backend is not None
        self.assertEqual(backend.scheme, "http")
        self.assertEqual((backend.host, backend.port), ("10.20.30.40", 8080))
        self.assertEqual(backend.host_header, "admin.internal")
        self.assertEqual(backend.server_header, "Apache")
        report = build_config_report(config)
        rendered = report["policy"]["honeypot"]["listeners"][0]["backend"]
        self.assertEqual(rendered["host"], "10.20.30.40")
        self.assertEqual(rendered["port"], 8080)

    def test_high_interaction_backend_requires_isolated_address(self) -> None:
        for host in ("8.8.8.8", "169.254.169.254", "0.0.0.0", "backend.internal"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(ConfigError, "IP literal"):
                    self.config(
                        {
                            "enabled": True,
                            "presets": ["common"],
                            "listeners": [
                                {
                                    "name": "live-admin",
                                    "listen_port": 18092,
                                    "backend": {"host": host, "port": 8080},
                                }
                            ],
                        }
                    )

        with self.assertRaisesRegex(ConfigError, "scheme must be http"):
            self.config(
                {
                    "enabled": True,
                    "presets": ["common"],
                    "listeners": [
                        {
                            "name": "live-admin",
                            "listen_port": 18092,
                            "backend": {"scheme": "https", "host": "10.0.0.5", "port": 443},
                        }
                    ],
                }
            )

    def test_high_interaction_backend_rejects_business_and_self_targets(self) -> None:
        with self.assertRaisesRegex(ConfigError, "business upstream"):
            self.config(
                {
                    "enabled": True,
                    "presets": ["common"],
                    "listeners": [
                        {
                            "name": "live-admin",
                            "listen_port": 18092,
                            "backend": {"host": "127.0.0.1", "port": 18080},
                        }
                    ],
                }
            )

        with self.assertRaisesRegex(ConfigError, "own listener"):
            self.config(
                {
                    "enabled": True,
                    "presets": ["common"],
                    "listeners": [
                        {
                            "name": "live-admin",
                            "listen_port": 18092,
                            "backend": {"host": "127.0.0.1", "port": 18092},
                        }
                    ],
                }
            )

    def test_high_interaction_backend_rejects_local_gateway_targets(self) -> None:
        cases = [
            (18090, "proxy listener"),
            (18091, "admin listener"),
            (18093, "another honeypot listener"),
        ]
        for port, message in cases:
            with self.subTest(port=port):
                with self.assertRaisesRegex(ConfigError, message):
                    self.config(
                        {
                            "enabled": True,
                            "presets": ["common"],
                            "listeners": [
                                {
                                    "name": "live-admin",
                                    "listen_port": 18092,
                                    "backend": {"host": "127.0.0.1", "port": port},
                                },
                                {
                                    "name": "static-admin",
                                    "listen_port": 18093,
                                },
                            ],
                        }
                    )

    def test_honeypot_listener_host_must_be_an_ip_literal(self) -> None:
        with self.assertRaisesRegex(ConfigError, "must be an IP address"):
            self.config(
                {
                    "enabled": True,
                    "presets": ["common"],
                    "listeners": [{"name": "hostname", "listen_host": "localhost", "listen_port": 18092}],
                }
            )

    def test_additional_honeypot_listeners_reject_conflicts(self) -> None:
        cases = [
            {"listeners": [{"name": "bad", "listen_port": 18090}]},
            {"listeners": [{"name": "bad", "listen_port": 18091}]},
            {
                "listeners": [
                    {"name": "one", "listen_port": 18092},
                    {"name": "two", "listen_port": 18092},
                ]
            },
            {
                "listeners": [
                    {"name": "same", "listen_port": 18092},
                    {"name": "same", "listen_port": 18093},
                ]
            },
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ConfigError):
                    self.config({"enabled": True, "presets": ["common"], **case})

        with self.assertRaisesRegex(ConfigError, "enabled"):
            self.config({"enabled": False, "listeners": [{"name": "decoy", "listen_port": 18092}]})

    def test_builtin_presets_expand_without_route_definitions(self) -> None:
        config = self.config({"enabled": True, "presets": ["common"]})
        paths = [route.path for route in config.policy.honeypot.routes]
        self.assertEqual(len(paths), 18)
        self.assertEqual(len(paths), len(set(paths)))
        for path in ("/.env", "/.git/HEAD", "/wp-login.php", "/actuator/env", "/server-status"):
            self.assertIn(path, paths)
        self.assertNotIn("/.aws/credentials", paths)

        all_templates = self.config({"enabled": True, "presets": ["common", "cloud"]})
        all_paths = [route.path for route in all_templates.policy.honeypot.routes]
        self.assertIn("/.aws/credentials", all_paths)
        self.assertIn("/.kube/config", all_paths)

    def test_individual_templates_and_groups_are_deduplicated(self) -> None:
        config = self.config({"enabled": True, "presets": ["env_probe", "secrets"]})
        paths = [route.path for route in config.policy.honeypot.routes]
        self.assertEqual(paths, ["/.env", "/.git/HEAD", "/.git/config", "/.svn/entries"])

    def test_expanded_template_preset_includes_build_and_infra_decoys(self) -> None:
        config = self.config({"enabled": True, "presets": ["all"]})
        paths = [route.path for route in config.policy.honeypot.routes]
        self.assertGreaterEqual(len(paths), 34)
        self.assertEqual(len(paths), len(set(paths)))
        for path in (
            "/package.json",
            "/docker-compose.yml",
            "/terraform.tfstate",
            "/actuator/health",
            "/metrics",
            "/.npmrc",
        ):
            self.assertIn(path, paths)

    def test_explicit_route_overrides_preset_path(self) -> None:
        custom = decoy_routes()[0]
        custom["body"] = "CUSTOM_DECOY=1\n"
        config = self.config({"enabled": True, "presets": ["secrets"], "routes": [custom]})
        route = next(route for route in config.policy.honeypot.routes if route.path == "/.env")
        self.assertEqual(route.body, b"CUSTOM_DECOY=1\n")

    def test_unknown_preset_and_cross_source_duplicate_id_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unknown preset or template"):
            self.config({"enabled": True, "presets": ["not_a_template"]})

        custom = decoy_routes()[0]
        custom["id"] = "env_probe"
        custom["path"] = "/custom-decoy"
        with self.assertRaisesRegex(ConfigError, "duplicate id across presets and routes"):
            self.config({"enabled": True, "presets": ["env_probe"], "routes": [custom]})

    def test_duplicate_paths_and_ids_are_rejected(self) -> None:
        routes = decoy_routes()
        routes[1]["path"] = routes[0]["path"]
        with self.assertRaisesRegex(ConfigError, "duplicate exact path"):
            self.config({"enabled": True, "routes": routes})

        routes = decoy_routes()
        routes[1]["id"] = routes[0]["id"]
        with self.assertRaisesRegex(ConfigError, "duplicate id"):
            self.config({"enabled": True, "routes": routes})

    def test_reserved_and_injected_headers_are_rejected(self) -> None:
        for name, value in (
            ("Set-Cookie", "a=b"),
            ("Content-Type", "text/plain"),
            ("Content-Security-Policy", "default-src *"),
            ("X-Test", "ok\r\nInjected: yes"),
        ):
            routes = decoy_routes()
            routes[0]["headers"] = {name: value}
            with self.subTest(name=name):
                with self.assertRaises(ConfigError):
                    self.config({"enabled": True, "routes": routes})

    def test_body_and_delay_limits_are_enforced(self) -> None:
        routes = decoy_routes()
        routes[0]["body"] = "x" * (64 * 1024 + 1)
        with self.assertRaisesRegex(ConfigError, "64 KiB"):
            self.config({"enabled": True, "routes": routes})

        routes = decoy_routes()
        routes[0]["delay_ms"] = 5001
        with self.assertRaises(ConfigError):
            self.config({"enabled": True, "routes": routes})

    def test_honeypot_overrides_denied_path_but_not_host_or_client_acl(self) -> None:
        config = self.config(honeypot_policy())
        head = RequestHead("GET", "/.env", "HTTP/1.1", (("Host", "test.local"),), 0, "127.0.0.1")
        inspection = validate_head(head, "127.0.0.1", config.policy)
        self.assertIsNotNone(inspection.honeypot)
        self.assertEqual(inspection.honeypot.id, "env_probe")

        bad_host = RequestHead("GET", "/.env", "HTTP/1.1", (("Host", "evil.local"),), 0, "127.0.0.1")
        with self.assertRaises(Forbidden):
            validate_head(bad_host, "127.0.0.1", config.policy)

        restricted = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "honeypot": honeypot_policy(),
                    "allowed_client_networks": ["10.0.0.0/8"],
                }
            },
        )
        with self.assertRaises(Forbidden):
            validate_head(head, "127.0.0.1", restricted.policy)


class HoneypotIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stub = StubUpstream()
        self.stub.__enter__()
        self.addCleanup(self.stub.__exit__, None, None, None)
        self.gateway: GatewayHarness | None = None

    def start(
        self,
        *,
        ban_seconds: float = 5.0,
        extra_policy: dict | None = None,
        honeypot: dict | None = None,
    ) -> GatewayHarness:
        policy: dict = {"honeypot": honeypot if honeypot is not None else honeypot_policy(ban_seconds=ban_seconds)}
        if extra_policy:
            policy.update(extra_policy)
        config = base_config(
            Path(self.temp.name),
            self.stub.port,
            overrides={"policy": policy},
        )
        gateway = GatewayHarness(config)
        gateway.__enter__()
        self.addCleanup(gateway.__exit__, None, None, None)
        self.gateway = gateway
        return gateway

    def request(self, payload: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        assert self.gateway is not None
        return parse_response(send_raw(self.gateway.port, payload))

    def start_honeypot_port(
        self,
        port: int = 0,
        backend: HoneypotBackendConfig | None = None,
    ) -> int:
        assert self.gateway is not None
        server = GatewayServer(
            ("127.0.0.1", port),
            self.gateway.runtime,
            honeypot_only=True,
            honeypot_backend=backend,
            owns_runtime=False,
        )
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()

        def cleanup() -> None:
            server.begin_drain()
            server.shutdown()
            server.server_close()
            server.wait_for_drain(1.0)
            thread.join(timeout=2.0)

        self.addCleanup(cleanup)
        return int(server.server_address[1])

    def backend_config(
        self,
        port: int,
        *,
        host_header: str | None = "admin.internal",
        max_response_bytes: int = 1048576,
    ) -> HoneypotBackendConfig:
        return HoneypotBackendConfig(
            scheme="http",
            host="127.0.0.1",
            port=port,
            host_header=host_header,
            server_header="nginx",
            connect_timeout=0.5,
            read_timeout=1.0,
            total_timeout=3.0,
            max_response_bytes=max_response_bytes,
        )

    def test_honeypot_only_port_serves_decoys_but_never_forwards(self) -> None:
        gateway = self.start(ban_seconds=0)
        port = self.start_honeypot_port()
        status, headers, body = parse_response(send_raw(port, build_request(path="/.env")))
        self.assertEqual(status, 200)
        self.assertIn(b"DB_HOST=db.internal", body)
        self.assertEqual(header_values(headers, "X-Decoy"), ["environment"])

        status, _, body = parse_response(send_raw(port, build_request(path="/ok")))
        self.assertEqual(status, 404)
        self.assertNotIn(b"hello from upstream", body)
        self.assertEqual(self.stub.state.snapshot(), [])
        text = audit_text(Path(self.temp.name))
        self.assertIn('"event":"honeypot_hit"', text)
        self.assertEqual(gateway.runtime.metrics.snapshot()["honeypot_hits_total"], 1)

    def test_multiple_honeypot_ports_share_honeypot_ban_state(self) -> None:
        gateway = self.start(ban_seconds=30)
        first = self.start_honeypot_port()
        second = self.start_honeypot_port()

        status, _, _ = parse_response(send_raw(first, build_request(path="/.env")))
        self.assertEqual(status, 200)
        status, _, body = parse_response(send_raw(second, build_request(path="/.env")))
        self.assertEqual(status, 429)
        self.assertNotIn(b"DB_HOST=db.internal", body)
        self.assertEqual(self.stub.state.snapshot(), [])
        metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(metrics["honeypot_bans_total"], 1)
        self.assertEqual(metrics["honeypot_ban_rejections_total"], 1)

    def test_high_interaction_listener_uses_only_its_isolated_backend(self) -> None:
        gateway = self.start(ban_seconds=0)
        backend_stub = StubUpstream()
        backend_stub.__enter__()
        self.addCleanup(backend_stub.__exit__, None, None, None)
        port = self.start_honeypot_port(
            backend=self.backend_config(backend_stub.port),
        )

        payload = build_request(
            method="POST",
            path="/admin/login?next=/dashboard",
            headers=[
                ("Content-Type", "text/plain"),
                ("Authorization", "Basic YWRtaW46YWRtaW4="),
                ("Cookie", "session=scanner"),
            ],
            body=b"username=admin&note=<script>alert(1)</script>",
        )
        status, headers, body = parse_response(send_raw(port, payload))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from upstream")
        self.assertEqual(header_values(headers, "Server"), ["upstream-secret"])
        self.assertEqual(header_values(headers, "X-Powered-By"), ["php/leaky"])
        self.assertEqual(header_values(headers, "X-Custom"), ["keep-me"])
        self.assertEqual(len(header_values(headers, "Set-Cookie")), 2)
        self.assertEqual(header_values(headers, "Content-Security-Policy"), [])
        self.assertEqual(self.stub.state.snapshot(), [])

        requests = backend_stub.state.snapshot()
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["path"], "/admin/login?next=/dashboard")
        self.assertEqual(request["body"], b"username=admin&note=<script>alert(1)</script>")
        forwarded = {name.lower(): value for name, value in request["headers"]}
        self.assertEqual(forwarded["host"], "admin.internal")
        self.assertEqual(forwarded["authorization"], "Basic YWRtaW46YWRtaW4=")
        self.assertEqual(forwarded["cookie"], "session=scanner")
        self.assertEqual(forwarded["x-forwarded-for"], "127.0.0.1")
        self.assertEqual(forwarded["accept-encoding"], "identity")

        metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(metrics["honeypot_hits_total"], 1)
        self.assertEqual(metrics["honeypot_backend_requests_total"], 1)
        event = json.loads(audit_text(Path(self.temp.name)).splitlines()[-1])
        self.assertEqual(event["event"], "honeypot_backend_forwarded")
        self.assertEqual(event["outcome"], "forwarded")

    def test_compromised_backend_cannot_set_cross_origin_state(self) -> None:
        self.start(ban_seconds=0)
        backend = ThreadingHTTPServer(("127.0.0.1", 0), _CompromisedBackendHandler)
        backend.daemon_threads = True
        thread = threading.Thread(target=backend.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()

        def cleanup() -> None:
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=2.0)

        self.addCleanup(cleanup)
        port = self.start_honeypot_port(backend=self.backend_config(int(backend.server_address[1])))

        status, headers, body = parse_response(send_raw(port, build_request(path="/dashboard")))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"compromised backend")
        self.assertEqual(header_values(headers, "Server"), ["compromised-nginx"])
        self.assertEqual(header_values(headers, "X-Powered-By"), ["php/8.2"])
        self.assertEqual(header_values(headers, "Location"), ["/login"])
        self.assertEqual(
            header_values(headers, "Set-Cookie"),
            ["ok=1; Path=/", "scoped=2; Path=/; SameSite=Lax"],
        )
        for name in (
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Access-Control-Allow-Origin",
            "Clear-Site-Data",
            "X-Frame-Options",
            "Permissions-Policy",
            "Refresh",
        ):
            with self.subTest(name=name):
                self.assertEqual(header_values(headers, name), [])

    def test_high_interaction_static_decoy_wins_without_touching_backend(self) -> None:
        self.start(ban_seconds=0)
        backend_stub = StubUpstream()
        backend_stub.__enter__()
        self.addCleanup(backend_stub.__exit__, None, None, None)
        port = self.start_honeypot_port(
            backend=self.backend_config(backend_stub.port),
        )

        status, headers, body = parse_response(send_raw(port, build_request(path="/.env")))
        self.assertEqual(status, 200)
        self.assertIn(b"DB_HOST=db.internal", body)
        self.assertEqual(header_values(headers, "X-Decoy"), ["environment"])
        self.assertEqual(backend_stub.state.snapshot(), [])
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_high_interaction_backend_failure_never_falls_back_to_business(self) -> None:
        gateway = self.start(ban_seconds=0)
        port = self.start_honeypot_port(backend=self.backend_config(free_port()))
        status, _, body = parse_response(send_raw(port, build_request(path="/dashboard")))
        self.assertIn(status, {502, 504})
        self.assertNotIn(b"hello from upstream", body)
        self.assertEqual(self.stub.state.snapshot(), [])
        metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(metrics["honeypot_backend_requests_total"], 1)
        self.assertEqual(metrics["honeypot_backend_errors_total"], 1)
        event = json.loads(audit_text(Path(self.temp.name)).splitlines()[-1])
        self.assertEqual(event["event"], "honeypot_backend_error")
        self.assertEqual(event["outcome"], "error")

    def test_exact_denied_path_serves_static_decoy_without_upstream(self) -> None:
        gateway = self.start()
        status, headers, body = self.request(build_request(path="/.env"))
        self.assertEqual(status, 200)
        self.assertIn(b"DB_HOST=db.internal", body)
        self.assertEqual(header_values(headers, "Server"), ["nginx"])
        self.assertEqual(header_values(headers, "X-Decoy"), ["environment"])
        self.assertTrue(header_values(headers, "X-Request-ID"))
        self.assertIn("default-src 'self'", header_values(headers, "Content-Security-Policy")[0])
        self.assertEqual(self.stub.state.snapshot(), [])

        event = json.loads(audit_text(Path(self.temp.name)).splitlines()[-1])
        self.assertEqual(event["event"], "honeypot_hit")
        self.assertEqual(event["outcome"], "decoy")
        self.assertEqual(event["rule_id"], "HW-HONEY-env_probe")
        metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(metrics["honeypot_hits_total"], 1)
        self.assertEqual(metrics["honeypot_bans_total"], 1)
        self.assertEqual(metrics["honeypot_ban_entries"], 1)

    def test_encoded_path_is_normalized_before_matching(self) -> None:
        self.start()
        status, _, body = self.request(build_request(path="/%2eenv?probe=1"))
        self.assertEqual(status, 200)
        self.assertIn(b"DB_HOST=db.internal", body)
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_builtin_preset_serves_decoy_without_upstream(self) -> None:
        self.start(honeypot={"enabled": True, "ban_seconds": 0, "presets": ["common"]})
        status, headers, body = self.request(build_request(path="/.git/HEAD"))
        self.assertEqual(status, 200)
        self.assertEqual(header_values(headers, "Server"), ["nginx"])
        self.assertIn(b"refs/heads/main", body)

        status, _, body = self.request(build_request(path="/wp-login.php"))
        self.assertEqual(status, 200)
        self.assertIn(b"WordPress Login", body)
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_matching_is_exact_not_prefix_based(self) -> None:
        self.start()
        status, _, body = self.request(build_request(path="/decoy-login/extra"))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from upstream")
        self.assertEqual(len(self.stub.state.snapshot()), 1)

    def test_first_hit_immediately_bans_subsequent_requests(self) -> None:
        gateway = self.start(ban_seconds=30)
        self.assertEqual(self.request(build_request(path="/.env"))[0], 200)

        status, headers, _ = self.request(build_request(path="/ok"))
        self.assertEqual(status, 429)
        self.assertTrue(header_values(headers, "Retry-After"))
        self.assertEqual(self.stub.state.snapshot(), [])
        metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(metrics["honeypot_ban_rejections_total"], 1)
        self.assertEqual(metrics["auto_ban_rejections_total"], 0)

    def test_zero_ban_seconds_keeps_endpoint_available(self) -> None:
        self.start(ban_seconds=0)
        self.assertEqual(self.request(build_request(path="/.env"))[0], 200)
        status, _, body = self.request(build_request(path="/ok"))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from upstream")

    def test_custom_security_headers_do_not_duplicate_gateway_headers(self) -> None:
        self.start(
            extra_policy={
                "security_headers": {
                    "Content-Type": "application/json",
                    "Cache-Control": "public, max-age=60",
                    "X-Robots-Tag": "noindex",
                }
            }
        )
        status, headers, _ = self.request(build_request(path="/.env"))
        self.assertEqual(status, 200)
        self.assertEqual(header_values(headers, "Content-Type"), ["text/plain; charset=utf-8"])
        self.assertEqual(header_values(headers, "Cache-Control"), ["no-store"])
        self.assertEqual(header_values(headers, "X-Robots-Tag"), ["noindex"])
        self.assertEqual(len(header_values(headers, "X-Request-ID")), 1)

    def test_honeypot_accepts_methods_and_payloads_outside_normal_policy(self) -> None:
        self.start(extra_policy={"allowed_methods": ["GET", "HEAD"]})
        payload = build_request(
            method="POST",
            path="/decoy-login",
            headers=[("Content-Type", "application/json")],
            body=b'{"username":"admin","password":"<script>alert(1)</script>"}',
        )
        status, _, body = self.request(payload)
        self.assertEqual(status, 200)
        self.assertIn(b"Sign in", body)
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_head_returns_decoy_headers_without_body(self) -> None:
        self.start()
        status, headers, body = self.request(build_request(method="HEAD", path="/.env"))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(
            header_values(headers, "Content-Length"),
            [str(len(decoy_routes()[0]["body"].encode("utf-8")))],
        )

    def test_audit_never_records_request_body_headers_or_query(self) -> None:
        self.start()
        payload = build_request(
            method="POST",
            path="/decoy-login?token=query-secret",
            headers=[
                ("Content-Type", "text/plain"),
                ("Authorization", "Bearer header-secret"),
            ],
            body=b"body-secret",
        )
        self.assertEqual(self.request(payload)[0], 200)
        logged = audit_text(Path(self.temp.name))
        self.assertNotIn("query-secret", logged)
        self.assertNotIn("header-secret", logged)
        self.assertNotIn("body-secret", logged)
        event = json.loads(logged.splitlines()[-1])
        self.assertEqual(event["path"], "/decoy-login")

    def test_incomplete_honeypot_body_is_rejected_without_ban(self) -> None:
        gateway = self.start(ban_seconds=30)
        payload = (
            b"POST /decoy-login HTTP/1.1\r\n"
            b"Host: test.local\r\n"
            b"Content-Length: 10\r\n\r\n"
            b"abc"
        )
        status, _, _ = self.request(payload)
        self.assertEqual(status, 400)
        self.assertEqual(self.stub.state.snapshot(), [])
        metrics = gateway.runtime.metrics.snapshot()
        self.assertEqual(metrics["honeypot_hits_total"], 0)
        self.assertEqual(metrics["honeypot_bans_total"], 0)
        self.assertEqual(self.request(build_request(path="/ok"))[0], 200)

    def test_disabled_honeypot_keeps_denied_path_blocked(self) -> None:
        config = base_config(Path(self.temp.name), self.stub.port)
        gateway = GatewayHarness(config)
        gateway.__enter__()
        self.addCleanup(gateway.__exit__, None, None, None)
        self.gateway = gateway
        status, _, _ = self.request(build_request(path="/.env"))
        self.assertEqual(status, 403)
        self.assertEqual(self.stub.state.snapshot(), [])


if __name__ == "__main__":
    unittest.main()
