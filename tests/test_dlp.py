from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from highwall.dlp import inspect_response
from tests.support import base_config


class ResponseDlpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.policy = base_config(Path(self.temp.name), 18080).policy

    def test_private_key_is_detected(self) -> None:
        hit = inspect_response(
            b"dump\n-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAK\n",
            "text/plain; charset=utf-8",
            self.policy,
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule_id, "HW-DLP-SECRET-1001")

    def test_cloud_tokens_are_detected(self) -> None:
        hit = inspect_response(
            b'{"key":"AKIAIOSFODNN7EXAMPLE"}',
            "application/json",
            self.policy,
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit.category, "aws-access-key")

    def test_debug_trace_is_detected(self) -> None:
        hit = inspect_response(
            b"Traceback (most recent call last):\n  File \"app.py\", line 1\n",
            "text/plain",
            self.policy,
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule_id, "HW-DLP-DEBUG-1002")

    def test_binary_responses_are_still_scanned(self) -> None:
        hit = inspect_response(
            b"\x00\x01-----BEGIN RSA PRIVATE KEY-----",
            "application/octet-stream",
            self.policy,
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit.category, "private-key")

    def test_utf16_response_is_detected_without_charset(self) -> None:
        body = "dump\n-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAK\n".encode("utf-16-le")
        hit = inspect_response(body, "application/octet-stream", self.policy)
        self.assertIsNotNone(hit)
        self.assertEqual(hit.category, "private-key")

    def test_response_header_secret_is_detected(self) -> None:
        hit = inspect_response(
            b"ok",
            "text/plain",
            self.policy,
            headers=[("X-Api-Key", "AKIAIOSFODNN7EXAMPLE")],
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit.category, "aws-access-key")

    def test_set_cookie_jwt_is_not_treated_as_dlp(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        hit = inspect_response(
            b"ok",
            "text/plain",
            self.policy,
            headers=[("Set-Cookie", f"session={jwt}; HttpOnly; Secure; Path=/")],
        )
        self.assertIsNone(hit)

    def test_header_scanning_can_be_disabled(self) -> None:
        policy = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"response_scan_headers": False}},
        ).policy
        hit = inspect_response(
            b"ok",
            "text/plain",
            policy,
            headers=[("X-Api-Key", "AKIAIOSFODNN7EXAMPLE")],
        )
        self.assertIsNone(hit)

    def test_additional_token_and_credential_patterns_are_detected(self) -> None:
        samples = {
            "openai-key": b"sk-proj-AbCdEfGhIjKlMnOpQrStUvWx",
            "gitlab-token": b"glpat-AbCdEfGhIjKlMnOpQrSt",
            "huggingface-token": b"hf_" + b"a" * 32,
            "azure-storage-key": b"AccountKey=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789==",
            "database-credential": b"postgresql://app:supersecret@db.internal:5432/app",
        }
        for category, sample in samples.items():
            with self.subTest(category=category):
                hit = inspect_response(sample, "text/plain", self.policy)
                self.assertIsNotNone(hit)
                assert hit is not None
                self.assertEqual(hit.category, category)

    def test_scan_limit_is_enforced(self) -> None:
        policy = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"response_scan_max_bytes": 1024}},
        ).policy
        body = b"x" * 1024 + b"-----BEGIN RSA PRIVATE KEY-----"
        hit = inspect_response(body, "text/plain", policy)
        self.assertIsNone(hit)

    def test_off_mode_disables_scanning(self) -> None:
        policy = base_config(
            Path(self.temp.name),
            18080,
            overrides={"policy": {"response_scan_mode": "off"}},
        ).policy
        hit = inspect_response(b"-----BEGIN RSA PRIVATE KEY-----", "text/plain", policy)
        self.assertIsNone(hit)


if __name__ == "__main__":
    unittest.main()
