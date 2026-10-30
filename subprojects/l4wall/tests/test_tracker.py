from __future__ import annotations

import dataclasses
import ipaddress
import tempfile
import time
import unittest
from pathlib import Path

from l4wall.config import example_config, parse_config
from l4wall.tracker import BanStore, ConnectionRecord, ThreatTracker


class TrackerTests(unittest.TestCase):
    def _tracker(self, directory: str, **threat_updates: object) -> ThreatTracker:
        config = parse_config(example_config())
        threat = dataclasses.replace(
            config.threat,
            offender_path=str(Path(directory) / "offenders.json"),
            **threat_updates,
        )
        bans = BanStore(
            threat.offender_path,
            max_entries=threat.max_ban_entries,
            prefix_v4=threat.ban_prefix_v4,
            prefix_v6=threat.ban_prefix_v6,
        )
        return ThreatTracker(threat, bans)

    def test_fanout_short_zero_byte_and_rejection_confirms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tracker = self._tracker(
                directory,
                mode="block",
                window_seconds=60.0,
                min_connections=10,
                min_distinct_listeners=3,
                min_short_connections=8,
                min_zero_byte_connections=4,
                min_rejections=3,
                score_threshold=60,
                confirm_score=80,
                confirm_after_seconds=300.0,
                confirmed_containment_seconds=60.0,
                mark_ttl_seconds=60.0,
            )
            address = ipaddress.ip_address("203.0.113.9")
            listeners = ("web", "api", "admin")
            assessment = None
            for index in range(12):
                record = ConnectionRecord(
                    ts=1000.0 + index * 0.1,
                    listener=listeners[index % len(listeners)],
                    accepted=True,
                    reason="closed",
                    bytes_in=0,
                    bytes_out=0,
                    duration=0.1,
                )
                assessment = tracker.record(address, record, record.ts)
            for index in range(4):
                record = ConnectionRecord(
                    ts=1002.0 + index * 0.1,
                    listener="web",
                    accepted=False,
                    reason="connection_rate",
                )
                assessment = tracker.record(address, record, record.ts)
            self.assertIsNotNone(assessment)
            assert assessment is not None
            self.assertGreaterEqual(assessment.score, 80)
            self.assertTrue(assessment.confirmed)
            self.assertIsNotNone(tracker.bans.check(address))
            blocked = tracker.pre_connection(address, 1005.0)
            self.assertEqual(blocked.reason, "banned")
            self.assertEqual(blocked.action, "deny")

    def test_ban_persists_across_reload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "offenders.json"
            first = BanStore(path, max_entries=10, prefix_v4=32, prefix_v6=128)
            self.assertTrue(first.ban(ipaddress.ip_address("198.51.100.7"), "test", 60))
            second = BanStore(path, max_entries=10, prefix_v4=32, prefix_v6=128)
            self.assertIsNotNone(second.check(ipaddress.ip_address("198.51.100.7")))

    def test_prefix_ban_matches_neighbors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = BanStore(Path(directory) / "offenders.json", max_entries=10, prefix_v4=24, prefix_v6=128)
            store.ban(ipaddress.ip_address("203.0.113.9"), "scan", 60)
            self.assertIsNotNone(store.check(ipaddress.ip_address("203.0.113.200")))
            self.assertIsNone(store.check(ipaddress.ip_address("203.0.114.9")))

    def test_regular_timing_signal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tracker = self._tracker(
                directory,
                mode="score",
                window_seconds=60.0,
                min_connections=100,
                min_distinct_listeners=10,
                min_short_connections=100,
                min_zero_byte_connections=100,
                min_rejections=100,
                regular_timing_max_cv=0.01,
                agent_min_signals=1,
                agent_score=10,
                score_threshold=10,
                confirm_score=80,
            )
            address = ipaddress.ip_address("198.51.100.20")
            assessment = None
            for index in range(6):
                record = ConnectionRecord(
                    ts=100.0 + index,
                    listener="web",
                    accepted=True,
                    reason="closed",
                    bytes_in=100,
                    bytes_out=100,
                    duration=2.0,
                )
                assessment = tracker.record(address, record, record.ts)
            self.assertIsNotNone(assessment)
            assert assessment is not None
            self.assertIn("regular_timing", assessment.signals)
            self.assertTrue(assessment.suspected)

    def test_score_mode_never_bans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tracker = self._tracker(
                directory,
                mode="score",
                window_seconds=60.0,
                min_connections=1,
                min_distinct_listeners=1,
                min_short_connections=1,
                min_zero_byte_connections=1,
                min_rejections=1,
                agent_min_signals=1,
                agent_score=10,
                score_threshold=10,
                confirm_score=20,
            )
            address = ipaddress.ip_address("192.0.2.44")
            for index in range(10):
                record = ConnectionRecord(
                    ts=200.0 + index,
                    listener="web",
                    accepted=False,
                    reason="rate",
                )
                assessment = tracker.record(address, record, record.ts)
            self.assertTrue(assessment.confirmed)
            self.assertIsNone(tracker.bans.check(address))

    def test_existing_ban_is_enforced_when_scoring_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tracker = self._tracker(directory, enabled=False, mode="block")
            address = ipaddress.ip_address("192.0.2.46")
            tracker.bans.ban(address, "manual", 60.0)
            assessment = tracker.pre_connection(address, time.time())
            self.assertEqual(assessment.action, "deny")
            self.assertEqual(assessment.reason, "banned")

    def test_disabled_tracker_never_bans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tracker = self._tracker(
                directory,
                enabled=False,
                mode="block",
                min_connections=1,
                min_distinct_listeners=1,
                min_short_connections=1,
                min_zero_byte_connections=1,
                min_rejections=1,
                agent_min_signals=1,
                agent_score=10,
                score_threshold=10,
                confirm_score=20,
            )
            address = ipaddress.ip_address("192.0.2.45")
            for index in range(10):
                record = ConnectionRecord(
                    ts=300.0 + index,
                    listener="web",
                    accepted=False,
                    reason="rate",
                )
                assessment = tracker.record(address, record, record.ts)
            self.assertFalse(assessment.confirmed)
            self.assertEqual(assessment.action, "allow")
            self.assertIsNone(tracker.bans.check(address))


if __name__ == "__main__":
    unittest.main()

