from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from highwall.errors import BadRequest, Forbidden, MethodNotAllowed, PayloadTooLarge, UnsupportedMediaType
from highwall.protocol import RequestHead
from highwall.waf import inspect_body, inspect_texts, resolve_client_ip, validate_head
from tests.support import base_config


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = base_config(Path(self.temp.name), 18080)
        self.policy = self.config.policy

    def head(
        self,
        *,
        method: str = "GET",
        target: str = "/ok",
        headers: list[tuple[str, str]] | None = None,
        length: int = 0,
        client_ip: str = "127.0.0.1",
    ) -> RequestHead:
        values = [("Host", "test.local")] if headers is None else list(headers)
        return RequestHead(method, target, "HTTP/1.1", tuple(values), length, client_ip)

    def test_valid_request(self) -> None:
        result = validate_head(self.head(), "127.0.0.1", self.policy)
        self.assertEqual(result.host, "test.local")
        self.assertEqual(result.path, "/ok")
        self.assertIsNone(result.waf_hit)

    def test_client_network_acl(self) -> None:
        denied = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"denied_client_networks": ["127.0.0.1/32"]}},
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(self.head(), "127.0.0.1", denied.policy)
        self.assertEqual(caught.exception.rule_id, "HW-ACL-1002")

        allowed = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"allowed_client_networks": ["10.0.0.0/8"]}},
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(self.head(), "127.0.0.1", allowed.policy)
        self.assertEqual(caught.exception.rule_id, "HW-ACL-1001")

        loopback = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"allowed_client_networks": ["127.0.0.0/8"]}},
        )
        validate_head(self.head(), "127.0.0.1", loopback.policy)

    def test_origin_is_required_and_allowlisted_for_unsafe_methods(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"allowed_origins": ["https://test.local"]}},
        )
        good = self.head(
            method="POST",
            headers=[("Host", "test.local"), ("Origin", "https://TEST.local:443")],
        )
        validate_head(good, "127.0.0.1", config.policy)

        missing = self.head(method="POST")
        with self.assertRaises(Forbidden) as caught:
            validate_head(missing, "127.0.0.1", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-CSRF-1001")

        bad = self.head(
            method="POST",
            headers=[("Host", "test.local"), ("Origin", "https://evil.test")],
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(bad, "127.0.0.1", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-CSRF-1002")

    def test_cross_site_fetch_metadata_is_rejected(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"allowed_origins": ["https://test.local"]}},
        )
        head = self.head(
            method="POST",
            headers=[
                ("Host", "test.local"),
                ("Origin", "https://test.local"),
                ("Sec-Fetch-Site", "cross-site"),
            ],
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(head, "127.0.0.1", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-CSRF-1004")

    def test_host_is_case_insensitive_and_allowlisted(self) -> None:
        result = validate_head(self.head(headers=[("Host", "TEST.LOCAL.")]), "127.0.0.1", self.policy)
        self.assertEqual(result.host, "test.local")

    def test_host_mismatch_rejected(self) -> None:
        with self.assertRaises(Forbidden):
            validate_head(self.head(headers=[("Host", "evil.local")]), "127.0.0.1", self.policy)

    def test_duplicate_host_rejected(self) -> None:
        with self.assertRaises(BadRequest):
            validate_head(
                self.head(headers=[("Host", "test.local"), ("Host", "test.local")]),
                "127.0.0.1",
                self.policy,
            )

    def test_method_not_allowed(self) -> None:
        with self.assertRaises(MethodNotAllowed):
            validate_head(self.head(method="PUT"), "127.0.0.1", self.policy)

    def test_absolute_uri_rejected(self) -> None:
        with self.assertRaises(BadRequest):
            validate_head(self.head(target="http://evil.test/ok"), "127.0.0.1", self.policy)

    def test_network_path_rejected(self) -> None:
        with self.assertRaises(BadRequest):
            validate_head(self.head(target="//evil.test/ok"), "127.0.0.1", self.policy)

    def test_dot_segments_rejected(self) -> None:
        for target in ("/../etc/passwd", "/a/../b", "/%2e%2e/etc/passwd", "/a/%252e%252e%252fb"):
            with self.subTest(target=target):
                with self.assertRaises(BadRequest):
                    validate_head(self.head(target=target), "127.0.0.1", self.policy)

    def test_encoded_separator_rejected(self) -> None:
        with self.assertRaises(BadRequest):
            validate_head(self.head(target="/a%2fb"), "127.0.0.1", self.policy)
        permissive = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"reject_encoded_separators": False}},
        )
        with self.assertRaises(BadRequest):
            validate_head(self.head(target="/%2fevil"), "127.0.0.1", permissive.policy)

    def test_encoded_null_rejected(self) -> None:
        with self.assertRaises(BadRequest):
            validate_head(self.head(target="/a%00b"), "127.0.0.1", self.policy)

    def test_encoded_path_delimiters_rejected(self) -> None:
        for target in ("/allowed%3Fadmin", "/allowed%23admin", "/allowed%EF%BC%9Fadmin"):
            with self.subTest(target=target):
                with self.assertRaises(BadRequest):
                    validate_head(self.head(target=target), "127.0.0.1", self.policy)

    def test_denied_path_rejected(self) -> None:
        for target in ("/.git/config", "/.env.local", "/server-status", "/.GIT/config"):
            with self.subTest(target=target):
                with self.assertRaises(Forbidden):
                    validate_head(self.head(target=target), "127.0.0.1", self.policy)

    def test_dot_segment_with_path_parameters_rejected(self) -> None:
        targets = (
            "/allowed/..;/admin",
            "/allowed/..%20/admin",
            "/allowed/..;%20/admin",
            "/allowed/foo;../admin",
            "/allowed/%2e%2e;/admin",
        )
        for target in targets:
            with self.subTest(target=target):
                with self.assertRaises(BadRequest):
                    validate_head(self.head(target=target), "127.0.0.1", self.policy)

    def test_get_body_rejected(self) -> None:
        with self.assertRaises(BadRequest):
            validate_head(
                self.head(headers=[("Host", "test.local"), ("Content-Type", "text/plain")], length=1),
                "127.0.0.1",
                self.policy,
            )

    def test_missing_content_type_rejected(self) -> None:
        with self.assertRaises(UnsupportedMediaType):
            validate_head(self.head(method="POST", length=2), "127.0.0.1", self.policy)

    def test_unsupported_content_type_rejected(self) -> None:
        with self.assertRaises(UnsupportedMediaType):
            validate_head(
                self.head(
                    method="POST",
                    headers=[("Host", "test.local"), ("Content-Type", "application/octet-stream")],
                    length=2,
                ),
                "127.0.0.1",
                self.policy,
            )

    def test_sql_injection_in_query_blocked(self) -> None:
        with self.assertRaises(Forbidden) as caught:
            validate_head(self.head(target="/ok?q=%27%20OR%201%3D1"), "127.0.0.1", self.policy)
        self.assertEqual(caught.exception.rule_id, "HW-WAF-SQLI-1001")

    def test_waf_detect_mode_records_hit_without_blocking(self) -> None:
        config = base_config(Path(self.temp.name), 18080, overrides={"policy": {"waf_mode": "detect"}})
        result = validate_head(self.head(target="/ok?q=%27%20OR%201%3D1"), "127.0.0.1", config.policy)
        self.assertEqual(result.waf_hit, "HW-WAF-SQLI-1001")

    def test_json_unicode_escape_xss_blocked(self) -> None:
        body = b'{"comment":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}'
        with self.assertRaises(Forbidden) as caught:
            inspect_body(body, "application/json", self.policy)
        self.assertEqual(caught.exception.rule_id, "HW-WAF-XSS-1001")

    def test_double_encoded_xss_detected(self) -> None:
        hit = inspect_texts(["%253Cscript%253Ealert(1)%253C%252Fscript%253E"], ["xss"])
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule_id, "HW-WAF-XSS-1001")

    def test_untrusted_xff_is_ignored(self) -> None:
        head = self.head(headers=[("Host", "test.local"), ("X-Forwarded-For", "203.0.113.9")])
        self.assertEqual(resolve_client_ip(head, self.policy), "127.0.0.1")

    def test_trusted_xff_uses_rightmost_untrusted_client(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"trusted_proxies": ["127.0.0.1/32"]}},
        )
        head = self.head(
            headers=[("Host", "test.local"), ("X-Forwarded-For", "198.51.100.7, 127.0.0.1")],
            client_ip="127.0.0.1",
        )
        self.assertEqual(resolve_client_ip(head, config.policy), "198.51.100.7")

    def test_malformed_trusted_xff_rejected(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"trusted_proxies": ["127.0.0.1/32"]}},
        )
        head = self.head(headers=[("Host", "test.local"), ("X-Forwarded-For", "not-an-ip")])
        with self.assertRaises(BadRequest):
            resolve_client_ip(head, config.policy)

    def test_global_read_only_blocks_unsafe_methods(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"read_only": True}},
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(self.head(method="POST"), "127.0.0.1", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-MODE-1001")
        validate_head(self.head(method="GET"), "127.0.0.1", config.policy)

    def test_route_read_only_blocks_unsafe_methods_only_on_route(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "routes": [{"path_prefix": "/admin", "read_only": True}],
                }
            },
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(self.head(method="POST", target="/admin"), "127.0.0.1", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-MODE-1001")
        result = validate_head(self.head(method="POST", target="/api"), "127.0.0.1", config.policy)
        self.assertIsNone(result.route)

    def test_route_method_restriction_is_enforced(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "routes": [{"path_prefix": "/api", "methods": ["GET"]}],
                }
            },
        )
        with self.assertRaises(MethodNotAllowed) as caught:
            validate_head(self.head(method="POST", target="/api"), "127.0.0.1", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-METHOD-1102")

    def test_route_body_limit_is_enforced(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "routes": [{"path_prefix": "/api", "max_body_bytes": 4}],
                }
            },
        )
        head = self.head(
            method="POST",
            target="/api",
            headers=[("Host", "test.local"), ("Content-Type", "text/plain")],
            length=5,
        )
        with self.assertRaises(PayloadTooLarge) as caught:
            validate_head(head, "127.0.0.1", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-BODY-1105")

    def test_route_client_network_acl_is_enforced(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "routes": [
                        {
                            "path_prefix": "/admin",
                            "methods": ["GET"],
                            "allowed_client_networks": ["10.0.0.0/8"],
                        }
                    ],
                }
            },
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(self.head(method="POST", target="/admin"), "198.51.100.7", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-ACL-1101")

    def test_longest_route_prefix_wins(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "routes": [
                        {"path_prefix": "/api", "methods": ["GET"]},
                        {"path_prefix": "/api/admin", "methods": ["POST"]},
                    ],
                }
            },
        )
        result = validate_head(self.head(method="POST", target="/api/admin"), "127.0.0.1", config.policy)
        self.assertIsNotNone(result.route)
        assert result.route is not None
        self.assertEqual(result.route.path_prefix, "/api/admin")
        with self.assertRaises(MethodNotAllowed):
            validate_head(self.head(method="GET", target="/api/admin"), "127.0.0.1", config.policy)

    def test_route_prefix_respects_segment_boundary(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "routes": [{"path_prefix": "/api", "methods": ["GET"]}],
                }
            },
        )
        result = validate_head(self.head(target="/apix"), "127.0.0.1", config.policy)
        self.assertIsNone(result.route)

    def test_path_parameters_are_rejected_by_default(self) -> None:
        for target in ("/admin;foo", "/admin%3Bfoo", "/admin%3bfoo"):
            with self.subTest(target=target):
                with self.assertRaises(BadRequest) as caught:
                    validate_head(self.head(target=target), "127.0.0.1", self.policy)
                self.assertEqual(caught.exception.rule_id, "HW-PATH-1010")

    def test_trailing_dot_or_space_is_rejected_by_default(self) -> None:
        for target in ("/admin.", "/admin%20", "/admin%2e"):
            with self.subTest(target=target):
                with self.assertRaises(BadRequest) as caught:
                    validate_head(self.head(target=target), "127.0.0.1", self.policy)
                self.assertEqual(caught.exception.rule_id, "HW-PATH-1011")

    def test_compatibility_flags_only_change_routing_path(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "allow_path_parameters": True,
                    "allow_trailing_dot_or_space": True,
                    "routes": [{"path_prefix": "/admin", "methods": ["GET"]}],
                }
            },
        )
        result = validate_head(
            self.head(target="/ADMIN;jsessionid=abc."),
            "127.0.0.1",
            config.policy,
        )
        self.assertIsNotNone(result.route)
        self.assertEqual(result.route_path, "/ADMIN")
        self.assertEqual(result.upstream_target, "/ADMIN;jsessionid=abc.")

    def test_uppercase_path_cannot_bypass_route_acl(self) -> None:
        config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {
                    "routes": [
                        {
                            "path_prefix": "/admin",
                            "methods": ["GET"],
                            "allowed_client_networks": ["10.0.0.0/8"],
                        }
                    ],
                }
            },
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(self.head(target="/ADMIN"), "127.0.0.1", config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-ACL-1101")

    def test_uppercase_path_cannot_bypass_route_method_or_read_only(self) -> None:
        method_config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {"routes": [{"path_prefix": "/admin", "methods": ["GET"]}]},
            },
        )
        with self.assertRaises(MethodNotAllowed) as caught:
            validate_head(self.head(method="POST", target="/ADMIN"), "127.0.0.1", method_config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-METHOD-1102")

        read_only_config = base_config(
            Path(self.temp.name),
            18080,
            overrides={
                "policy": {"routes": [{"path_prefix": "/admin", "read_only": True}]},
            },
        )
        with self.assertRaises(Forbidden) as caught:
            validate_head(self.head(method="POST", target="/ADMIN"), "127.0.0.1", read_only_config.policy)
        self.assertEqual(caught.exception.rule_id, "HW-MODE-1001")

    def test_confirmed_waf_bypass_payloads_are_now_blocked(self) -> None:
        payloads = [
            ("sqli", "UNION/**/SELECT password FROM users"),
            ("cmdi", "; cat /etc/passwd"),
            ("xss", "onpointerover=alert(1)"),
            ("ssrf", "http://2130706433/"),
            ("ssrf", "http://0x7f000001/"),
            ("ssrf", "http://[::ffff:127.0.0.1]/"),
        ]
        for category, payload in payloads:
            with self.subTest(category=category, payload=payload):
                hit = inspect_texts([payload], [category])
                self.assertIsNotNone(hit)

    def test_utf16_and_nul_request_bodies_are_rejected(self) -> None:
        samples = [
            "{\"q\":\"UNION SELECT\"}".encode("utf-16-le"),
            b'{"q":"unix\x00value"}',
        ]
        for body in samples:
            with self.subTest(body=body[:8]):
                with self.assertRaises(UnsupportedMediaType) as caught:
                    inspect_body(body, "application/json", self.policy)
                self.assertEqual(caught.exception.rule_id, "HW-BODY-1007")

    def test_query_is_preserved_for_upstream_while_scanned_decoded(self) -> None:
        result = validate_head(
            self.head(target="/echo?a=%2526b&c=hello+world"),
            "127.0.0.1",
            self.policy,
        )
        self.assertEqual(result.upstream_target, "/echo?a=%2526b&c=hello+world")
        with self.assertRaises(Forbidden):
            validate_head(
                self.head(target="/echo?q=%2527%2520OR%25201%253D1"),
                "127.0.0.1",
                self.policy,
            )


if __name__ == "__main__":
    unittest.main()
