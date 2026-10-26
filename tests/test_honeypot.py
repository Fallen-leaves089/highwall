from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from highwall.config import ConfigError
from highwall.errors import Forbidden
from highwall.protocol import RequestHead
from highwall.waf import validate_head
from tests.support import (
    GatewayHarness,
    StubUpstream,
    audit_text,
    base_config,
    build_request,
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
