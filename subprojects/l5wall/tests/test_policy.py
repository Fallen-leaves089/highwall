from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from l5wall.config import load_config
from l5wall.policy import ClientMetadata, L5Policy
from test_certificates import ensure_test_material

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def setUpModule() -> None:
    ensure_test_material(FIXTURES)


def metadata(**overrides: object) -> ClientMetadata:
    values: dict[str, object] = {
        "tls_version": "TLS1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "alpn": "http/1.1",
        "sni": "localhost",
        "peer_cert_sha256": "",
        "handshake_ms": 12,
    }
    values.update(overrides)
    return ClientMetadata(**values)  # type: ignore[arg-type]


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(ROOT / "config.example.json")
        self.policy = L5Policy(self.config)

    def test_allowed_session_passes(self) -> None:
        decision = self.policy.evaluate(metadata())

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reasons, ())
        self.assertEqual(decision.metadata.alpn, "http/1.1")

    def test_tls_below_minimum_is_rejected(self) -> None:
        decision = self.policy.evaluate(metadata(tls_version="TLS1.1"))

        self.assertFalse(decision.allowed)
        self.assertIn("below", " ".join(decision.reasons))

    def test_unknown_alpn_is_rejected(self) -> None:
        decision = self.policy.evaluate(metadata(alpn="h3"))

        self.assertFalse(decision.allowed)
        self.assertIn("ALPN", " ".join(decision.reasons))

    def test_missing_sni_is_rejected_by_default(self) -> None:
        decision = self.policy.evaluate(metadata(sni=""))

        self.assertFalse(decision.allowed)
        self.assertIn("SNI", " ".join(decision.reasons))

    def test_sni_mismatch_is_rejected(self) -> None:
        decision = self.policy.evaluate(metadata(sni="example.test"))

        self.assertFalse(decision.allowed)
        self.assertIn("SNI", " ".join(decision.reasons))

    def test_missing_sni_can_be_explicitly_allowed(self) -> None:
        policy = L5Policy(replace(self.config, allow_missing_sni=True))
        decision = policy.evaluate(metadata(sni=""))

        self.assertTrue(decision.allowed)

    def test_wildcard_sni_matches_one_or_more_labels(self) -> None:
        policy = L5Policy(replace(self.config, allowed_sni=("*.example.test",)))

        self.assertTrue(policy.evaluate(metadata(sni="api.example.test")).allowed)
        self.assertTrue(policy.evaluate(metadata(sni="a.b.example.test")).allowed)
        self.assertFalse(policy.evaluate(metadata(sni="example.test")).allowed)

    def test_mtls_required_rejects_missing_client_certificate(self) -> None:
        policy = L5Policy(replace(self.config, mtls_mode="required"))
        decision = policy.evaluate(metadata())

        self.assertFalse(decision.allowed)
        self.assertIn("mTLS", " ".join(decision.reasons))

    def test_malformed_certificate_fingerprint_is_rejected(self) -> None:
        decision = self.policy.evaluate(metadata(peer_cert_sha256="not-a-fingerprint"))

        self.assertFalse(decision.allowed)
        self.assertIn("fingerprint", " ".join(decision.reasons))
