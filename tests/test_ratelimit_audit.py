from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from highwall.audit import AuditLogger, AuditRecord
from highwall.config import ConfigError
from highwall.ratelimit import AdaptiveBanner, TokenBucketLimiter, retry_after_seconds
from tests.support import base_config


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RateLimitTests(unittest.TestCase):
    def test_token_bucket_limits_and_refills(self) -> None:
        clock = Clock()
        limiter = TokenBucketLimiter(2.0, 2, clock=clock)
        self.assertTrue(limiter.consume("a").allowed)
        self.assertTrue(limiter.consume("a").allowed)
        denied = limiter.consume("a")
        self.assertFalse(denied.allowed)
        self.assertAlmostEqual(denied.retry_after, 0.5, places=3)
        clock.advance(0.25)
        self.assertFalse(limiter.consume("a").allowed)
        clock.advance(0.25)
        self.assertTrue(limiter.consume("a").allowed)

    def test_client_map_is_bounded(self) -> None:
        clock = Clock()
        limiter = TokenBucketLimiter(1.0, 1, max_entries=2, idle_ttl=10.0, clock=clock)
        limiter.consume("one")
        limiter.consume("two")
        limiter.consume("three")
        self.assertLessEqual(limiter.size(), 2)
        self.assertEqual(limiter.evictions, 1)

    def test_retry_after_rounds_up(self) -> None:
        self.assertEqual(retry_after_seconds(0.1), 1)
        self.assertEqual(retry_after_seconds(1.01), 2)

    def test_adaptive_banner_bans_and_expires(self) -> None:
        clock = Clock()
        banner = AdaptiveBanner(2, 10.0, 30.0, clock=clock)
        self.assertTrue(banner.record_violation("203.0.113.9").allowed)
        self.assertTrue(banner.check("203.0.113.9").allowed)
        banned = banner.record_violation("203.0.113.9")
        self.assertFalse(banned.allowed)
        self.assertAlmostEqual(banned.retry_after, 30.0, places=3)
        self.assertFalse(banner.check("203.0.113.9").allowed)
        clock.advance(31.0)
        self.assertTrue(banner.check("203.0.113.9").allowed)
        self.assertTrue(banner.record_violation("203.0.113.9").allowed)

    def test_adaptive_banner_state_is_bounded(self) -> None:
        clock = Clock()
        banner = AdaptiveBanner(5, 10.0, 30.0, max_entries=2, clock=clock)
        banner.record_violation("one")
        banner.record_violation("two")
        banner.record_violation("three")
        self.assertEqual(banner.size(), 2)
        self.assertEqual(banner.evictions, 1)

    def test_active_bans_excludes_expired_entries(self) -> None:
        clock = Clock()
        banner = AdaptiveBanner(1, 10.0, 30.0, clock=clock)
        banner.force_ban("203.0.113.9")
        self.assertEqual(banner.active_bans(), 1)
        clock.advance(31.0)
        self.assertEqual(banner.active_bans(), 0)


class AuditTests(unittest.TestCase):
    def test_audit_write_failure_fails_closed_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080)
            logger = AuditLogger(config.audit)
            with mock.patch("os.write", side_effect=OSError("disk full")):
                self.assertFalse(logger.write(AuditRecord(event="request_allowed", status=200)))
            self.assertEqual(logger.writes_failed, 1)
            self.assertTrue(logger.unavailable)

    def test_audit_write_failure_can_continue_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                18080,
                overrides={"audit": {"on_write_failure": "continue"}},
            )
            logger = AuditLogger(config.audit)
            with mock.patch("os.write", side_effect=OSError("disk full")):
                self.assertFalse(logger.write(AuditRecord(event="request_allowed", status=200)))
            self.assertEqual(logger.writes_failed, 1)
            self.assertFalse(logger.unavailable)

    def test_query_secrets_are_not_logged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080)
            logger = AuditLogger(config.audit)
            logger.write(
                AuditRecord(
                    event="request_allowed",
                    request_id="a1b2c3d4",
                    client_ip="127.0.0.1",
                    method="GET",
                    path="/doc?token=topsecret",
                    status=200,
                    outcome="allowed",
                )
            )
            raw = (Path(directory) / "audit.jsonl").read_text("utf-8")
            self.assertNotIn("topsecret", raw)
            self.assertNotIn("Cookie", raw)
            self.assertNotIn("Authorization", raw)
            events = logger.tail(10)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["path"], "/doc")
            self.assertEqual(events[0]["client_ip"], "127.0.0.1")

    def test_client_ip_can_be_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080, overrides={"audit": {"include_client_ip": False}})
            logger = AuditLogger(config.audit)
            logger.write(AuditRecord(event="request_allowed", client_ip="127.0.0.1", status=200))
            events = logger.tail(1)
            self.assertEqual(events[0]["client_ip"], "")

    def test_sensitive_path_segments_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080)
            logger = AuditLogger(config.audit)
            logger.write(AuditRecord(event="request_allowed", path="/token/SUPERSECRET", status=200))
            events = logger.tail(1)
            self.assertEqual(events[0]["path"], "/token/<redacted>")
            self.assertNotIn("SUPERSECRET", (Path(directory) / "audit.jsonl").read_text("utf-8"))

    def test_percent_encoded_sensitive_path_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080)
            logger = AuditLogger(config.audit)
            logger.write(AuditRecord(event="request_blocked", path="/%74oken/SUPERSECRET", status=403))
            events = logger.tail(1)
            self.assertEqual(events[0]["path"], "/token/<redacted>")
            self.assertNotIn("SUPERSECRET", (Path(directory) / "audit.jsonl").read_text("utf-8"))

    def test_sensitive_path_parameter_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080)
            logger = AuditLogger(config.audit)
            logger.write(
                AuditRecord(
                    event="request_blocked",
                    path="/resource;token=SUPERSECRET",
                    status=400,
                )
            )
            self.assertEqual(logger.tail(1)[0]["path"], "/resource;token=<redacted>")
            self.assertNotIn("SUPERSECRET", (Path(directory) / "audit.jsonl").read_text("utf-8"))

    def test_audit_hash_mode_hides_and_correlates_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080, overrides={"audit": {"path_mode": "hash"}})
            logger = AuditLogger(config.audit)
            logger.write(AuditRecord(event="request_allowed", path="/token/SUPERSECRET?x=1", status=200))
            logger.write(AuditRecord(event="request_allowed", path="/token/SUPERSECRET", status=200))
            events = logger.tail(2)
            self.assertTrue(events[0]["path"].startswith("sha256:"))
            self.assertEqual(events[0]["path"], events[1]["path"])
            self.assertNotIn("SUPERSECRET", (Path(directory) / "audit.jsonl").read_text("utf-8"))

    def test_audit_exact_mode_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080, overrides={"audit": {"path_mode": "exact"}})
            logger = AuditLogger(config.audit)
            logger.write(AuditRecord(event="request_allowed", path="/token/SUPERSECRET?x=1", status=200))
            self.assertEqual(logger.tail(1)[0]["path"], "/token/SUPERSECRET")

    def test_audit_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(
                Path(directory),
                18080,
                overrides={"audit": {"max_bytes": 1024, "backup_count": 2}},
            )
            logger = AuditLogger(config.audit)
            for index in range(30):
                logger.write(
                    AuditRecord(
                        event="request_allowed",
                        request_id=f"{index:024x}",
                        client_ip="127.0.0.1",
                        method="GET",
                        path="/" + "a" * 200,
                        status=200,
                        outcome="allowed",
                    )
                )
            base = Path(directory) / "audit.jsonl"
            self.assertTrue(base.exists())
            self.assertTrue(base.with_name("audit.jsonl.1").exists())
            self.assertGreater(len(logger.tail(5)), 0)

    def test_audit_json_lines_parse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080)
            logger = AuditLogger(config.audit)
            logger.write(AuditRecord(event="startup"))
            logger.write(AuditRecord(event="shutdown"))
            lines = (Path(directory) / "audit.jsonl").read_text("utf-8").splitlines()
            self.assertEqual([json.loads(line)["event"] for line in lines], ["startup", "shutdown"])

    def test_audit_path_rejects_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "audit.jsonl").mkdir()
            config = base_config(Path(directory), 18080)
            with self.assertRaises(OSError):
                AuditLogger(config.audit)

    def test_audit_path_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.log"
            target.write_text("", encoding="utf-8")
            link = Path(directory) / "audit.jsonl"
            try:
                os.symlink(target, link)
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {type(exc).__name__}")
            with self.assertRaises(ConfigError):
                base_config(Path(directory), 18080)


if __name__ == "__main__":
    unittest.main()
