from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from highwall.config_diff import (
    EXIT_NO_CHANGES,
    EXIT_RELOADABLE,
    EXIT_RESTART_REQUIRED,
    EXIT_SECURITY_REGRESSION,
    build_config_diff,
)
from tests.support import base_config


class ConfigDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        (self.directory / "cert.pem").write_text("certificate placeholder", encoding="ascii")
        (self.directory / "key.pem").write_text("key placeholder", encoding="ascii")

    def config(self, **overrides: object):
        return base_config(self.directory, 8080, overrides=overrides)

    def test_equivalent_configuration_reports_no_change(self) -> None:
        current = self.config(
            policy={
                "allowed_hosts": ["a.local", "b.local"],
                "allowed_methods": ["GET", "HEAD", "POST"],
            }
        )
        candidate = self.config(
            policy={
                "allowed_hosts": ["b.local", "a.local"],
                "allowed_methods": ["POST", "GET", "HEAD"],
            }
        )

        report = build_config_diff(current, candidate)

        self.assertFalse(report["changed"])
        self.assertEqual(report["exit_code"], EXIT_NO_CHANGES)
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["security_regressions"], [])
        json.dumps(report)

    def test_reloadable_change_is_reported(self) -> None:
        current = self.config(policy={"allowed_hosts": ["a.local", "b.local"]})
        candidate = self.config(policy={"allowed_hosts": ["a.local"]})

        report = build_config_diff(current, candidate)

        self.assertTrue(report["changed"])
        self.assertEqual(report["exit_code"], EXIT_RELOADABLE)
        self.assertEqual(report["restart_required"], [])
        self.assertIn("policy.allowed_hosts", report["reloadable"])
        self.assertEqual(report["security_regressions"], [])

    def test_listener_change_requires_restart(self) -> None:
        current = self.config()
        candidate = self.config(server={"listen_port": 18091})

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_RESTART_REQUIRED)
        self.assertEqual(report["restart_required"], ["server.listen_port"])

    def test_waf_disable_is_a_security_regression(self) -> None:
        current = self.config()
        candidate = self.config(policy={"waf_enabled": False})

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_SECURITY_REGRESSION)
        self.assertEqual(report["security_regressions"][0]["path"], "policy.waf_enabled")

    def test_dlp_disable_is_a_security_regression(self) -> None:
        current = self.config()
        candidate = self.config(policy={"response_scan_mode": "off"})

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_SECURITY_REGRESSION)
        self.assertIn(
            "policy.response_scan_mode",
            [finding["path"] for finding in report["security_regressions"]],
        )

    def test_tls_disable_is_a_security_regression(self) -> None:
        current = self.config(server={"tls": {"enabled": True, "cert_file": "cert.pem", "key_file": "key.pem"}})
        candidate = self.config(server={"tls": {"enabled": False}})

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_SECURITY_REGRESSION)
        self.assertIn(
            "server.tls.enabled",
            [finding["path"] for finding in report["security_regressions"]],
        )
        self.assertIn("server.tls.enabled", [change["path"] for change in report["changes"]])
        self.assertNotIn("server.tls_enabled", [change["path"] for change in report["changes"]])
        self.assertNotIn(
            "server.tls.cert_file",
            [finding["path"] for finding in report["security_review"]],
        )

    def test_tls_min_version_downgrade_is_a_security_regression(self) -> None:
        current = self.config(
            server={"tls": {"enabled": True, "cert_file": "cert.pem", "key_file": "key.pem", "min_version": "TLSv1_3"}}
        )
        candidate = self.config(
            server={"tls": {"enabled": True, "cert_file": "cert.pem", "key_file": "key.pem", "min_version": "TLSv1_2"}}
        )

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_SECURITY_REGRESSION)
        self.assertIn(
            "server.tls.min_version",
            [finding["path"] for finding in report["security_regressions"]],
        )

    def test_tls_min_version_upgrade_is_not_a_regression(self) -> None:
        current = self.config(
            server={"tls": {"enabled": True, "cert_file": "cert.pem", "key_file": "key.pem", "min_version": "TLSv1_2"}}
        )
        candidate = self.config(
            server={"tls": {"enabled": True, "cert_file": "cert.pem", "key_file": "key.pem", "min_version": "TLSv1_3"}}
        )

        report = build_config_diff(current, candidate)

        self.assertEqual(report["security_regressions"], [])

    def test_multiple_global_controls_are_reported_together(self) -> None:
        current = self.config(
            rate_limit={"enabled": True},
            threat_detection={"enabled": True},
            ddos_detection={"enabled": True},
            alerting={"enabled": True},
            policy={"read_only": True},
        )
        candidate = self.config(
            rate_limit={"enabled": False},
            threat_detection={"enabled": False},
            ddos_detection={"enabled": False},
            alerting={"enabled": False},
            policy={"read_only": False},
        )

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_SECURITY_REGRESSION)
        paths = {finding["path"] for finding in report["security_regressions"]}
        self.assertTrue(
            {
                "rate_limit.enabled",
                "threat_detection.enabled",
                "ddos_detection.enabled",
                "alerting.enabled",
                "policy.read_only",
            }.issubset(paths)
        )

    def test_allowlist_and_limit_widening_is_reported(self) -> None:
        current = self.config(
            policy={
                "allowed_origins": ["https://app.example"],
                "allowed_client_networks": ["10.0.0.0/8"],
                "denied_client_networks": ["192.168.0.0/16"],
            }
        )
        candidate = self.config(
            policy={
                "allowed_origins": ["https://app.example", "https://evil.example"],
                "allowed_client_networks": [],
                "denied_client_networks": [],
                "trusted_proxies": ["172.16.0.0/12"],
                "deny_path_prefixes": ["/.git", "/.env"],
                "allowed_methods": ["GET", "HEAD", "POST", "PUT"],
                "allowed_body_content_types": [
                    "application/x-www-form-urlencoded",
                    "application/json",
                    "text/plain",
                    "text/html",
                ],
                "max_body_bytes": 8192,
                "max_header_count": 64,
                "reject_get_body": False,
                "allow_path_parameters": True,
            }
        )

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_SECURITY_REGRESSION)
        paths = {finding["path"] for finding in report["security_regressions"]}
        self.assertTrue(
            {
                "policy.allowed_origins",
                "policy.allowed_client_networks",
                "policy.denied_client_networks",
                "policy.trusted_proxies",
                "policy.deny_path_prefixes",
                "policy.allowed_methods",
                "policy.allowed_body_content_types",
                "policy.max_body_bytes",
                "policy.max_header_count",
                "policy.reject_get_body",
                "policy.allow_path_parameters",
            }.issubset(paths)
        )

    def test_route_limit_widening_is_reported(self) -> None:
        current = self.config(
            policy={
                "routes": [
                    {
                        "path_prefix": "/api",
                        "read_only": True,
                        "methods": ["GET"],
                        "max_body_bytes": 1024,
                        "max_concurrent": 2,
                        "rate": 1.0,
                        "allowed_client_networks": ["10.0.0.0/8"],
                    }
                ]
            }
        )
        candidate = self.config(
            policy={
                "routes": [
                    {
                        "path_prefix": "/api",
                        "read_only": False,
                        "methods": ["GET", "POST"],
                        "max_body_bytes": 2048,
                        "max_concurrent": 4,
                        "rate": 2.0,
                        "allowed_client_networks": ["10.0.0.0/8", "192.168.0.0/16"],
                    }
                ]
            }
        )

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_SECURITY_REGRESSION)
        messages = [finding["message"] for finding in report["security_regressions"]]
        self.assertIn("route read-only mode was disabled", messages)
        self.assertIn("route body-size limit was increased", messages)
        self.assertIn("route concurrency limit was increased", messages)
        self.assertIn("route rate limit was increased", messages)
        self.assertTrue(any(message.startswith("route methods were added") for message in messages))
        self.assertTrue(any(message.startswith("route client networks were added") for message in messages))

    def test_route_read_only_removal_is_a_security_regression(self) -> None:
        current = self.config(policy={"routes": [{"path_prefix": "/admin", "read_only": True}]})
        candidate = self.config(policy={"routes": [{"path_prefix": "/admin", "read_only": False}]})

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_SECURITY_REGRESSION)
        self.assertIn(
            "route read-only mode was disabled",
            [finding["message"] for finding in report["security_regressions"]],
        )

    def test_upstream_change_requires_review_but_is_not_a_regression(self) -> None:
        current = self.config()
        candidate = self.config(upstream={"port": 8081})

        report = build_config_diff(current, candidate)

        self.assertEqual(report["exit_code"], EXIT_RELOADABLE)
        self.assertEqual(report["security_regressions"], [])
        self.assertEqual(report["security_review"][0]["path"], "upstream")


if __name__ == "__main__":
    unittest.main()
