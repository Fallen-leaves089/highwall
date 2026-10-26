from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from highwall.integrity import inspect_integrity
from tests.support import base_config


class IntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.body = b"stable response body"
        self.base_dir = Path(self.temp.name)

    def config(
        self,
        *,
        mode: str = "block",
        path: str = "/ok",
        status: int = 200,
        digest: str | None = None,
    ):
        pin = {
            "path": path,
            "status": status,
            "sha256": digest or hashlib.sha256(self.body).hexdigest(),
        }
        return base_config(
            self.base_dir,
            18080,
            overrides={
                "policy": {
                    "response_integrity_mode": mode,
                    "integrity_pins": [pin],
                }
            },
        )

    def test_matching_pin_passes(self) -> None:
        policy = self.config().policy
        self.assertIsNone(inspect_integrity("GET", "/ok", 200, self.body, policy))

    def test_body_mismatch_is_detected(self) -> None:
        policy = self.config().policy
        hit = inspect_integrity("GET", "/ok", 200, b"changed", policy)
        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertEqual(hit.rule_id, "HW-INTEGRITY-1001")
        self.assertEqual(hit.reason, "digest")

    def test_status_mismatch_is_detected(self) -> None:
        policy = self.config(status=201).policy
        hit = inspect_integrity("GET", "/ok", 200, self.body, policy)
        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertEqual(hit.reason, "status")

    def test_detect_mode_is_also_checked(self) -> None:
        policy = self.config(mode="detect").policy
        self.assertIsNotNone(inspect_integrity("GET", "/ok", 200, b"changed", policy))

    def test_off_mode_disables_pin_checks(self) -> None:
        policy = self.config(mode="off").policy
        self.assertIsNone(inspect_integrity("GET", "/ok", 200, b"changed", policy))

    def test_only_get_is_pinned(self) -> None:
        policy = self.config().policy
        self.assertIsNone(inspect_integrity("HEAD", "/ok", 200, b"changed", policy))
        self.assertIsNone(inspect_integrity("POST", "/ok", 200, b"changed", policy))

    def test_pin_match_is_exact_path(self) -> None:
        policy = self.config().policy
        self.assertIsNone(inspect_integrity("GET", "/ok/", 200, b"changed", policy))
        self.assertIsNone(inspect_integrity("GET", "/other", 200, b"changed", policy))

    def test_pin_match_is_case_insensitive(self) -> None:
        policy = self.config().policy
        hit = inspect_integrity("GET", "/OK", 200, b"changed", policy)
        self.assertIsNotNone(hit)


if __name__ == "__main__":
    unittest.main()
