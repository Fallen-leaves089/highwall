from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from highwall.config_audit import audit_config
from tests.support import base_config


class ConfigAuditTests(unittest.TestCase):
    def test_risky_switches_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                9000,
                overrides={
                    "policy": {
                        "trusted_proxies": ["10.0.0.0/8"],
                        "allow_path_parameters": True,
                        "allow_trailing_dot_or_space": True,
                        "waf_enabled": False,
                    },
                    "rate_limit": {"enabled": False},
                    "audit": {"on_write_failure": "continue"},
                },
            )
            findings = {warning.path: warning for warning in audit_config(config)}

        self.assertEqual(findings["policy.trusted_proxies"].severity, "high")
        self.assertEqual(findings["policy.allow_path_parameters"].severity, "high")
        self.assertEqual(findings["policy.allow_trailing_dot_or_space"].severity, "high")
        self.assertEqual(findings["policy.waf_enabled"].severity, "high")
        self.assertEqual(findings["rate_limit.enabled"].severity, "medium")
        self.assertEqual(findings["audit.on_write_failure"].severity, "high")

    def test_origin_allowlist_without_options_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                9000,
                overrides={
                    "policy": {
                        "allowed_methods": ["GET", "HEAD", "POST"],
                        "allowed_origins": ["https://test.local"],
                    }
                },
            )
            findings = {warning.path: warning for warning in audit_config(config)}

        self.assertEqual(findings["policy.allowed_origins"].severity, "medium")

    def test_fail_closed_defaults_do_not_emit_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                9000,
                overrides={
                    "policy": {
                        "allowed_methods": ["GET", "HEAD", "POST", "OPTIONS"],
                        "allowed_origins": ["https://test.local"],
                        "allowed_client_networks": ["127.0.0.1/32"],
                        "allowed_path_prefixes": ["/api"],
                        "trusted_proxies": [],
                        "waf_enabled": True,
                        "waf_mode": "block",
                    },
                    "rate_limit": {"enabled": True},
                },
            )
            warnings = audit_config(config)

        self.assertEqual(warnings, ())


if __name__ == "__main__":
    unittest.main()
