from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from highwall.config import (
    ConfigError,
    canonicalize_host,
    canonicalize_origin,
    load_config,
    parse_config,
)
from highwall.runtime import load_admin_token
from tests.support import base_config


def minimal(port: int = 18080) -> dict:
    return {
        "version": 1,
        "upstream": {"scheme": "http", "host": "127.0.0.1", "port": port},
        "policy": {"allowed_hosts": ["example.test"], "allowed_methods": ["GET", "HEAD"]},
    }


class ConfigTests(unittest.TestCase):
    def test_minimal_defaults_fail_closed(self) -> None:
        config = parse_config(minimal())
        self.assertEqual(config.server.listen_host, "127.0.0.1")
        self.assertEqual(config.server.listen_port, 18090)
        self.assertEqual(config.server.max_connections_per_ip, 16)
        self.assertEqual(config.server.shutdown_timeout, 30.0)
        self.assertEqual(config.policy.allowed_hosts, ("example.test",))
        self.assertFalse(config.admin.enabled)
        self.assertTrue(config.policy.reject_encoded_separators)
        self.assertTrue(config.policy.waf_enabled)
        self.assertEqual(config.policy.waf_mode, "block")
        self.assertEqual(config.policy.response_scan_mode, "block")
        self.assertFalse(config.policy.allow_path_parameters)
        self.assertFalse(config.policy.allow_trailing_dot_or_space)
        self.assertTrue(config.policy.response_scan_headers)
        self.assertEqual(config.audit.path_mode, "redact")
        self.assertEqual(config.audit.on_write_failure, "fail_closed")
        self.assertEqual(config.threat_detection.agent_mode, "score")
        self.assertEqual(config.rate_limit.auto_ban_threshold, 20)

    def test_audit_and_agent_modes_are_validated(self) -> None:
        cases = (
            {"audit": {"on_write_failure": "sometimes"}},
            {"threat_detection": {"agent_mode": "ban"}},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                data = minimal()
                data.update(overrides)
                with self.assertRaises(ConfigError):
                    parse_config(data)

    def test_canonicalize_origin(self) -> None:
        self.assertEqual(canonicalize_origin("HTTPS://Example.TEST:443/"), "https://example.test")
        self.assertEqual(canonicalize_origin("http://[::1]:80"), "http://[::1]")
        self.assertEqual(canonicalize_origin("http://127.0.0.1:18090"), "http://127.0.0.1:18090")
        for value in (
            "example.test",
            "https://example.test/path",
            "https://user@example.test",
            "null",
            "https://example.test?x=1",
            "http://[::1",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    canonicalize_origin(value)

    def test_client_network_lists_are_validated(self) -> None:
        data = minimal()
        data["policy"]["allowed_client_networks"] = ["10.0.0.0/8", "2001:db8::/32"]
        data["policy"]["denied_client_networks"] = ["192.0.2.0/24"]
        config = parse_config(data)
        self.assertEqual(len(config.policy.allowed_client_networks), 2)
        self.assertEqual(len(config.policy.denied_client_networks), 1)
        for value in ("0.0.0.0/0", "::/0", "not-a-network"):
            broken = minimal()
            broken["policy"]["allowed_client_networks"] = [value]
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    parse_config(broken)

    def test_allowed_origins_are_canonical_and_unique(self) -> None:
        data = minimal()
        data["policy"]["allowed_origins"] = ["https://Example.TEST:443", "http://127.0.0.1:18090"]
        config = parse_config(data)
        self.assertEqual(config.policy.allowed_origins, ("https://example.test", "http://127.0.0.1:18090"))
        data["policy"]["allowed_origins"] = ["https://example.test", "HTTPS://EXAMPLE.TEST/"]
        with self.assertRaisesRegex(ConfigError, "duplicate"):
            parse_config(data)

    def test_per_ip_connection_limit_must_not_exceed_global(self) -> None:
        data = minimal()
        data["server"] = {"max_connections": 4, "max_connections_per_ip": 5}
        with self.assertRaisesRegex(ConfigError, "must not exceed"):
            parse_config(data)

    def test_per_ip_connection_limit_default_tracks_smaller_global_limit(self) -> None:
        data = minimal()
        data["server"] = {"max_connections": 8}
        config = parse_config(data)
        self.assertEqual(config.server.max_connections_per_ip, 8)

    def test_unknown_key_rejected(self) -> None:
        data = minimal()
        data["server"] = {"unexpected": True}
        with self.assertRaisesRegex(ConfigError, "unknown keys"):
            parse_config(data)

    def test_unsafe_method_rejected(self) -> None:
        data = minimal()
        data["policy"]["allowed_methods"] = ["TRACE"]
        with self.assertRaisesRegex(ConfigError, "unsafe or unsupported"):
            parse_config(data)

    def test_trust_all_proxies_rejected(self) -> None:
        data = minimal()
        data["policy"]["trusted_proxies"] = ["0.0.0.0/0"]
        with self.assertRaisesRegex(ConfigError, "entire internet"):
            parse_config(data)

    def test_non_loopback_admin_rejected(self) -> None:
        data = minimal()
        data["admin"] = {"enabled": True, "listen_host": "0.0.0.0"}
        with self.assertRaisesRegex(ConfigError, "loopback"):
            parse_config(data)

    def test_admin_and_proxy_port_collision_rejected(self) -> None:
        data = minimal()
        data["admin"] = {"enabled": True, "listen_host": "127.0.0.1", "listen_port": 18090}
        with self.assertRaisesRegex(ConfigError, "must not reuse"):
            parse_config(data)

    def test_admin_port_collision_with_wildcard_proxy_is_rejected(self) -> None:
        data = minimal()
        data["server"] = {"listen_host": "0.0.0.0", "listen_port": 18090}
        data["admin"] = {"enabled": True, "listen_host": "127.0.0.1", "listen_port": 18090}
        with self.assertRaisesRegex(ConfigError, "must not reuse"):
            parse_config(data)

    def test_custom_security_header_accepted(self) -> None:
        data = minimal()
        data["policy"]["security_headers"] = {"X-Robots-Tag": "noindex", "Content-Security-Policy": "default-src 'none'"}
        config = parse_config(data)
        self.assertIn(("X-Robots-Tag", "noindex"), config.policy.security_headers)
        self.assertIn("X-Content-Type-Options", dict(config.policy.security_headers))

    def test_forbidden_security_header_rejected(self) -> None:
        for name, value in (("Content-Length", "12"), ("X-Request-ID", "spoofed")):
            data = minimal()
            data["policy"]["security_headers"] = {name: value}
            with self.subTest(name=name):
                with self.assertRaisesRegex(ConfigError, "must not set"):
                    parse_config(data)

    def test_security_header_injection_rejected(self) -> None:
        data = minimal()
        data["policy"]["security_headers"] = {"X-Test": "ok\r\nInjected: yes"}
        with self.assertRaisesRegex(ConfigError, "control characters"):
            parse_config(data)

    def test_unknown_waf_rule_rejected(self) -> None:
        data = minimal()
        data["policy"]["waf_rules"] = ["sqli", "made-up"]
        with self.assertRaisesRegex(ConfigError, "unknown rules"):
            parse_config(data)

    def test_duplicate_json_keys_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                '{"version":1,"version":1,"upstream":{"host":"127.0.0.1"},'
                '"policy":{"allowed_hosts":["example.test"]}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigError, "duplicate JSON key"):
                load_config(path)

    def test_canonical_host(self) -> None:
        self.assertEqual(canonicalize_host("Example.TEST.:443"), "example.test:443")
        self.assertEqual(canonicalize_host("[::1]:18090"), "[::1]:18090")
        with self.assertRaises(ConfigError):
            canonicalize_host("user@example.test")
        with self.assertRaises(ConfigError):
            canonicalize_host("example.test:99999")

    def test_admin_token_loading(self) -> None:
        data = minimal()
        data["admin"] = {"enabled": True, "listen_host": "127.0.0.1", "listen_port": 18091}
        config = parse_config(data)
        with self.assertRaises(ConfigError):
            load_admin_token(config, {})
        self.assertIsNone(load_admin_token(parse_config(minimal()), {}))
        good = "A" * 32
        self.assertEqual(load_admin_token(config, {"HIGHWALL_ADMIN_TOKEN": good}), good)
        with self.assertRaises(ConfigError):
            load_admin_token(config, {"HIGHWALL_ADMIN_TOKEN": "too-short"})

    def test_relative_audit_path_is_config_relative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080)
            self.assertEqual(config.audit.path, Path(directory).resolve() / "audit.jsonl")

    def test_upstream_host_cannot_include_port(self) -> None:
        data = minimal()
        data["upstream"] = {"host": "127.0.0.1:8080"}
        with self.assertRaisesRegex(ConfigError, "must not include a port"):
            parse_config(data)

    def test_response_memory_budget_is_bounded(self) -> None:
        data = minimal()
        data["server"] = {"max_connections": 65}
        data["upstream"]["max_response_bytes"] = 8 * 1024 * 1024
        with self.assertRaisesRegex(ConfigError, "512 MiB"):
            parse_config(data)

    def test_routes_are_sorted_by_longest_prefix(self) -> None:
        data = minimal()
        data["policy"]["routes"] = [
            {"path_prefix": "/api"},
            {"path_prefix": "/api/admin"},
            {"path_prefix": "/ok"},
        ]
        config = parse_config(data)
        self.assertEqual(
            [route.path_prefix for route in config.policy.routes],
            ["/api/admin", "/api", "/ok"],
        )

    def test_duplicate_route_prefix_rejected(self) -> None:
        data = minimal()
        data["policy"]["routes"] = [
            {"path_prefix": "/api"},
            {"path_prefix": "/api"},
        ]
        with self.assertRaisesRegex(ConfigError, "duplicate path_prefix"):
            parse_config(data)

    def test_duplicate_route_prefix_is_case_insensitive(self) -> None:
        data = minimal()
        data["policy"]["routes"] = [
            {"path_prefix": "/api"},
            {"path_prefix": "/API"},
        ]
        with self.assertRaisesRegex(ConfigError, "duplicate path_prefix"):
            parse_config(data)

    def test_route_rate_defaults_and_validation(self) -> None:
        data = minimal()
        data["policy"]["routes"] = [{"path_prefix": "/api", "rate": 2.2}]
        config = parse_config(data)
        self.assertAlmostEqual(config.policy.routes[0].rate, 2.2)
        self.assertEqual(config.policy.routes[0].rate_burst, 3)

        data = minimal()
        data["policy"]["routes"] = [{"path_prefix": "/api", "rate_burst": 5}]
        with self.assertRaisesRegex(ConfigError, "rate_burst requires rate"):
            parse_config(data)

    def test_route_methods_must_be_global_subset(self) -> None:
        data = minimal()
        data["policy"]["routes"] = [{"path_prefix": "/api", "methods": ["GET", "POST"]}]
        with self.assertRaisesRegex(ConfigError, "subset"):
            parse_config(data)

    def test_route_methods_are_case_insensitive_and_unique(self) -> None:
        data = minimal()
        data["policy"]["routes"] = [{"path_prefix": "/api", "methods": ["GET", "get"]}]
        with self.assertRaisesRegex(ConfigError, "duplicate methods"):
            parse_config(data)

    def test_read_only_route_rejects_unsafe_methods(self) -> None:
        data = minimal()
        data["policy"]["allowed_methods"] = ["GET", "POST"]
        data["policy"]["routes"] = [
            {"path_prefix": "/admin", "methods": ["POST"], "read_only": True}
        ]
        with self.assertRaisesRegex(ConfigError, "unsafe methods"):
            parse_config(data)

    def test_read_only_route_without_method_subset_is_accepted(self) -> None:
        data = minimal()
        data["policy"]["allowed_methods"] = ["GET", "POST"]
        data["policy"]["routes"] = [{"path_prefix": "/admin", "read_only": True}]
        config = parse_config(data)
        self.assertTrue(config.policy.routes[0].read_only)
        self.assertIsNone(config.policy.routes[0].methods)

    def test_route_body_limit_must_not_exceed_global(self) -> None:
        data = minimal()
        data["policy"]["max_body_bytes"] = 1024
        data["policy"]["routes"] = [{"path_prefix": "/api", "max_body_bytes": 2048}]
        with self.assertRaisesRegex(ConfigError, "max_body_bytes"):
            parse_config(data)

    def test_route_concurrency_must_not_exceed_global_connections(self) -> None:
        data = minimal()
        data["server"] = {"max_connections": 4}
        data["policy"]["routes"] = [{"path_prefix": "/api", "max_concurrent": 5}]
        with self.assertRaisesRegex(ConfigError, "max_concurrent"):
            parse_config(data)

    def test_empty_route_client_network_list_is_rejected(self) -> None:
        data = minimal()
        data["policy"]["routes"] = [
            {"path_prefix": "/admin", "allowed_client_networks": []}
        ]
        with self.assertRaisesRegex(ConfigError, "must not be empty"):
            parse_config(data)

    def test_integrity_pin_validation(self) -> None:
        data = minimal()
        data["policy"]["response_integrity_mode"] = "bogus"
        with self.assertRaisesRegex(ConfigError, "off, detect, or block"):
            parse_config(data)

        data = minimal()
        data["policy"]["integrity_pins"] = [
            {"path": "/index.html", "status": 200, "sha256": "z" * 64}
        ]
        with self.assertRaisesRegex(ConfigError, "64 hexadecimal"):
            parse_config(data)

        data = minimal()
        data["policy"]["integrity_pins"] = [
            {"path": "/index.html", "status": 200, "sha256": "a" * 64},
            {"path": "/index.html", "status": 200, "sha256": "b" * 64},
        ]
        with self.assertRaisesRegex(ConfigError, "duplicate path"):
            parse_config(data)

        data = minimal()
        data["policy"]["integrity_pins"] = [
            {"path": "/index.html", "status": 200, "sha256": "a" * 64},
            {"path": "/INDEX.HTML", "status": 200, "sha256": "b" * 64},
        ]
        with self.assertRaisesRegex(ConfigError, "duplicate path"):
            parse_config(data)

    def test_duplicate_honeypot_path_is_case_insensitive(self) -> None:
        data = minimal()
        data["policy"]["honeypot"] = {
            "enabled": True,
            "routes": [
                {"id": "first", "path": "/decoy"},
                {"id": "second", "path": "/DECOY"},
            ],
        }
        with self.assertRaisesRegex(ConfigError, "duplicate exact path"):
            parse_config(data)

    def test_audit_path_mode_is_validated(self) -> None:
        for mode in ("exact", "redact", "hash"):
            data = minimal()
            data["audit"] = {"path_mode": mode}
            self.assertEqual(parse_config(data).audit.path_mode, mode)
        data = minimal()
        data["audit"] = {"path_mode": "plain"}
        with self.assertRaisesRegex(ConfigError, "path_mode"):
            parse_config(data)

    def test_inflight_request_limit_must_not_exceed_connections(self) -> None:
        data = minimal()
        data["server"] = {"max_connections": 4, "max_inflight_requests": 5}
        with self.assertRaisesRegex(ConfigError, "max_inflight_requests"):
            parse_config(data)

    def test_circuit_breaker_bounds_are_validated(self) -> None:
        for value, message in (
            ({"failure_threshold": 0}, "failure_threshold"),
            ({"window": 0.5}, "window"),
            ({"open_seconds": 0.5}, "open_seconds"),
            ({"half_open_max_requests": 65}, "half_open_max_requests"),
        ):
            data = minimal()
            data["upstream"]["circuit_breaker"] = value
            with self.subTest(value=value):
                with self.assertRaisesRegex(ConfigError, message):
                    parse_config(data)


    def test_load_config_accepts_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(minimal()), encoding="utf-8")
            config = load_config(path)
            self.assertEqual(config.source, path.resolve())
            self.assertEqual(config.upstream.total_timeout, 30.0)

    def test_load_config_rejects_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigError, "not a regular file"):
                load_config(Path(directory))

    def test_load_config_rejects_oversized_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_bytes(b"{" + b" " * (1024 * 1024))
            with self.assertRaisesRegex(ConfigError, "exceeds 1 MiB"):
                load_config(path)

    def test_load_config_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            target.write_text(json.dumps(minimal()), encoding="utf-8")
            link = Path(directory) / "config.json"
            try:
                os.symlink(target, link)
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {type(exc).__name__}")
            with self.assertRaisesRegex(ConfigError, "symbolic link"):
                load_config(link)

    def test_load_config_rejects_deep_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("[" * 1200 + "0" + "]" * 1200, encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "nesting is too deep"):
                load_config(path)

    def test_load_config_rejects_moderately_deep_json_on_all_parsers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("[" * 80 + "0" + "]" * 80, encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "nesting is too deep"):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
