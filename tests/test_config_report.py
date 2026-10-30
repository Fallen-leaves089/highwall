from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from highwall.config_report import build_config_report
from tests.support import base_config


class ConfigReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_report_includes_new_effective_flags_and_route_limits(self) -> None:
        config = base_config(
            self.directory,
            18080,
            overrides={
                "policy": {
                    "allow_path_parameters": True,
                    "allow_trailing_dot_or_space": True,
                    "response_scan_headers": False,
                    "routes": [
                        {
                            "path_prefix": "/api",
                            "rate": 2.5,
                            "rate_burst": 4,
                        }
                    ],
                },
                "audit": {"path_mode": "hash"},
            },
        )
        report = build_config_report(config)
        self.assertTrue(report["policy"]["allow_path_parameters"])
        self.assertTrue(report["policy"]["allow_trailing_dot_or_space"])
        self.assertFalse(report["policy"]["response_scan_headers"])
        self.assertEqual(report["policy"]["routes"][0]["rate"], 2.5)
        self.assertEqual(report["policy"]["routes"][0]["rate_burst"], 4)
        self.assertEqual(report["audit"]["path_mode"], "hash")
        self.assertIsNone(report["policy"]["effective_hsts"])

    def test_report_shows_effective_hsts_for_tls(self) -> None:
        (self.directory / "cert.pem").write_text("certificate placeholder", encoding="ascii")
        (self.directory / "key.pem").write_text("key placeholder", encoding="ascii")
        config = base_config(
            self.directory,
            18080,
            overrides={
                "server": {
                    "tls": {
                        "enabled": True,
                        "cert_file": "cert.pem",
                        "key_file": "key.pem",
                    }
                }
            },
        )
        self.assertEqual(
            build_config_report(config)["policy"]["effective_hsts"],
            "max-age=31536000",
        )

        explicit = base_config(
            self.directory,
            18080,
            overrides={
                "server": {
                    "tls": {
                        "enabled": True,
                        "cert_file": "cert.pem",
                        "key_file": "key.pem",
                    }
                },
                "policy": {
                    "security_headers": {
                        "Strict-Transport-Security": "max-age=123",
                    }
                },
            },
        )
        self.assertEqual(
            build_config_report(explicit)["policy"]["effective_hsts"],
            "max-age=123",
        )

    def test_report_omits_secret_environment_references(self) -> None:
        config = base_config(
            self.directory,
            18080,
            overrides={
                "admin": {"token_env": "HIGHWALL_TEST_ADMIN_TOKEN"},
                "alerting": {
                    "webhook_url_env": "HIGHWALL_TEST_WEBHOOK",
                    "auth_token_env": "HIGHWALL_TEST_AUTH_TOKEN",
                },
            },
        )
        rendered = json.dumps(build_config_report(config))
        for value in ("HIGHWALL_TEST_ADMIN_TOKEN", "HIGHWALL_TEST_WEBHOOK", "HIGHWALL_TEST_AUTH_TOKEN"):
            self.assertNotIn(value, rendered)
        for key in ("token_env", "webhook_url_env", "auth_token_env"):
            self.assertNotIn(key, rendered)


if __name__ == "__main__":
    unittest.main()
