from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from highwall.alerting import AlertDispatcher
from highwall.config import ConfigError, parse_config
from highwall.fingerprint import request_fingerprint, shape_fingerprint
from highwall.metrics import Metrics
from highwall.offenders import OffenderRegistry
from highwall.protocol import RequestHead
from highwall.threat import DdosDetector, ThreatDetector
from highwall.tlsfingerprint import TLSProfile, parse_client_hello
from tests.support import base_config


def _head(target: str = "/ok", *, ua: str = "agent/1", cookie: str = "session=one") -> RequestHead:
    return RequestHead(
        method="GET",
        target=target,
        version="HTTP/1.1",
        headers=(
            ("Host", "test.local"),
            ("User-Agent", ua),
            ("Cookie", cookie),
            ("Accept", "text/html"),
        ),
        content_length=0,
        client_ip="127.0.0.1",
    )


def _extension(kind: int, value: bytes) -> bytes:
    return kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _client_hello(*, ua: bytes = b"h2", sni: bool = True) -> bytes:
    ciphers = b"\x13\x01\x13\x02\xc0\x2f"
    extensions = b""
    extensions += _extension(43, b"\x02\x03\x04")
    extensions += _extension(10, b"\x00\x04\x00\x1d\x00\x17")
    extensions += _extension(13, b"\x00\x04\x04\x03\x08\x04")
    extensions += _extension(16, b"\x00" + bytes([len(ua) + 1, len(ua)]) + ua)
    if sni:
        name = b"example.test"
        server_name = b"\x00" + len(name).to_bytes(2, "big") + name
        extensions += _extension(0, len(server_name).to_bytes(2, "big") + server_name)
    body = (
        b"\x03\x03"
        + b"x" * 32
        + b"\x00"
        + len(ciphers).to_bytes(2, "big")
        + ciphers
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class FingerprintTests(unittest.TestCase):
    def test_secrets_do_not_change_shape(self) -> None:
        first = _head(cookie="session=one")
        second = _head(cookie="session=two")
        self.assertEqual(shape_fingerprint(first), shape_fingerprint(second))
        self.assertEqual(request_fingerprint(first, "203.0.113.8")[0], request_fingerprint(second, "203.0.113.9")[0])

    def test_user_agent_and_tls_change_fingerprint(self) -> None:
        first = _head(ua="agent/1")
        second = _head(ua="agent/2")
        self.assertNotEqual(shape_fingerprint(first), shape_fingerprint(second))
        profile = parse_client_hello(_client_hello())
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertNotEqual(shape_fingerprint(first), shape_fingerprint(first, profile))

    def test_source_prefix_clusters_same_slash_24(self) -> None:
        first = request_fingerprint(_head(), "203.0.113.8")[0]
        second = request_fingerprint(_head(), "203.0.113.200")[0]
        third = request_fingerprint(_head(), "203.0.114.8")[0]
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)


class TLSFingerprintTests(unittest.TestCase):
    def test_parses_client_hello(self) -> None:
        profile = parse_client_hello(_client_hello())
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile.version, "TLS1.3")
        self.assertEqual(profile.alpn, "h2")
        self.assertTrue(profile.sni_present)
        self.assertEqual(len(profile.digest), 64)
        self.assertIn(43, profile.extensions)

    def test_rejects_incomplete_or_non_client_hello(self) -> None:
        data = _client_hello()
        self.assertIsNone(parse_client_hello(data[:10]))
        self.assertIsNone(parse_client_hello(b"\x17" + data[1:]))
        self.assertIsNone(parse_client_hello(b""))


def _threat_config(directory: Path, *, mode: str = "tarpit", **overrides):
    values = {
        "enabled": True,
        "mode": mode,
        "window_seconds": 10.0,
        "min_requests": 4,
        "min_distinct_paths": 3,
        "min_violations": 2,
        "score_threshold": 70,
        "confirm_score": 85,
        "confirm_after_seconds": 9999,
        "containment_seconds": 300,
        "confirmed_containment_seconds": 900,
        "throttle_ms": 100,
        "max_throttle_ms": 200,
        "tarpit_hold_seconds": 1,
        "max_tarpit_hold_seconds": 2,
        "per_actor_tarpit_slots": 2,
        "global_tarpit_slots": 3,
        "max_tracked_actors": 32,
        "max_paths_per_actor": 16,
        "alert_cooldown_seconds": 1,
        "mark_ttl_seconds": 3600,
        "offender_path": "offenders.json",
    }
    values.update(overrides)
    config = base_config(directory, 18080, overrides={"threat_detection": values})
    return config.threat_detection


class ThreatDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.clock_value = [100.0]
        self.registry = OffenderRegistry(
            self.directory / "offenders.json",
            max_entries=32,
            ttl_seconds=3600,
            clock=lambda: 1_700_000_000 + self.clock_value[0],
        )
        self.detector = ThreatDetector(
            _threat_config(self.directory),
            Metrics(),
            self.registry,
            include_client_ip=False,
            clock=lambda: self.clock_value[0],
            wall_clock=lambda: 1_700_000_000 + self.clock_value[0],
        )

    def test_rate_and_path_breadth_produce_suspected_throttle(self) -> None:
        assessment = None
        for index in range(4):
            assessment = self.detector.assess(_head(f"/scan/{index}"), "203.0.113.8")
        assert assessment is not None
        self.assertEqual(assessment.confidence, "suspected")
        self.assertEqual(assessment.action, "throttle")
        self.assertGreater(assessment.delay_ms, 0)
        self.assertIsNotNone(assessment.alert)
        self.assertEqual(assessment.alert["event"], "threat_suspected")

    def test_violations_confirm_and_persist_mark(self) -> None:
        for index in range(4):
            self.detector.assess(_head(f"/scan/{index}"), "203.0.113.8")
        fingerprint = self.detector.assess(_head("/scan/new"), "203.0.113.8").fingerprint
        shape = self.detector.assess(_head("/scan/newer"), "203.0.113.8").shape_fingerprint
        assessment = self.detector.record_violation(
            fingerprint,
            shape,
            "HW-WAF-1001",
            403,
            client_ip="203.0.113.8",
        )
        assert assessment is not None
        self.assertEqual(assessment.confidence, "confirmed")
        self.assertEqual(assessment.action, "tarpit")
        marks = self.registry.active()
        self.assertEqual(len(marks), 1)
        self.assertEqual(marks[0].tag, "confirmed_fast_attack")

    def test_tarpit_slots_are_bounded(self) -> None:
        self.assertTrue(self.detector.acquire_tarpit("one"))
        self.assertTrue(self.detector.acquire_tarpit("one"))
        self.assertFalse(self.detector.acquire_tarpit("one"))
        self.assertTrue(self.detector.acquire_tarpit("two"))
        self.assertFalse(self.detector.acquire_tarpit("three"))
        self.detector.release_tarpit("one")
        self.assertTrue(self.detector.acquire_tarpit("three"))

    def test_mark_survives_registry_reload(self) -> None:
        self.registry.mark(
            fingerprint="a" * 32,
            shape_fingerprint_value="b" * 32,
            tag="confirmed_fast_attack",
            confidence="confirmed",
            score=95,
            signals=("request_rate",),
            action="tarpit",
            source_prefix_value="203.0.113.0/24",
        )
        reloaded = OffenderRegistry(
            self.directory / "offenders.json",
            max_entries=32,
            ttl_seconds=3600,
            clock=lambda: 1_700_000_000 + self.clock_value[0],
        )
        self.assertEqual(len(reloaded.active()), 1)
        self.assertEqual(reloaded.active()[0].score, 95)

    def test_shape_only_mark_is_a_signal_not_auto_confirmation(self) -> None:
        head = _head()
        self.registry.mark(
            fingerprint="a" * 32,
            shape_fingerprint_value=shape_fingerprint(head),
            tag="confirmed_fast_attack",
            confidence="confirmed",
            score=95,
            signals=("request_rate",),
            action="tarpit",
            source_prefix_value="203.0.113.0/24",
        )
        assessment = self.detector.assess(head, "198.51.100.8")
        self.assertNotEqual(assessment.confidence, "confirmed")
        self.assertNotEqual(assessment.action, "tarpit")
        self.assertIn("shape_match", assessment.signals)
        self.assertIsNone(assessment.offender)

    def test_exact_confirmed_mark_is_contained_immediately(self) -> None:
        head = _head()
        fingerprint, shape = request_fingerprint(head, "203.0.113.8")
        self.registry.mark(
            fingerprint=fingerprint,
            shape_fingerprint_value=shape,
            tag="confirmed_fast_attack",
            confidence="confirmed",
            score=95,
            signals=("request_rate",),
            action="tarpit",
            source_prefix_value="203.0.113.0/24",
        )
        assessment = self.detector.assess(head, "203.0.113.8")
        self.assertEqual(assessment.confidence, "confirmed")
        self.assertEqual(assessment.action, "tarpit")
        self.assertIsNotNone(assessment.offender)

    def test_expired_containment_resets_confirmation_timer(self) -> None:
        detector = ThreatDetector(
            _threat_config(
                self.directory,
                confirm_after_seconds=50,
                containment_seconds=20,
                confirmed_containment_seconds=900,
            ),
            Metrics(),
            self.registry,
            clock=lambda: self.clock_value[0],
            wall_clock=lambda: 1_700_000_000 + self.clock_value[0],
        )
        for index in range(4):
            detector.assess(_head(f"/first/{index}"), "203.0.113.8")
        self.clock_value[0] += 51
        assessment = None
        for index in range(4):
            assessment = detector.assess(_head(f"/second/{index}"), "203.0.113.8")
        assert assessment is not None
        self.assertEqual(assessment.confidence, "suspected")
        self.assertNotEqual(assessment.action, "tarpit")

    def test_alert_payload_omits_paths_and_secrets(self) -> None:
        assessment = None
        for index in range(4):
            assessment = self.detector.assess(
                _head(f"/private/scan/{index}?token=supersecret", cookie="session=topsecret"),
                "203.0.113.8",
            )
        assert assessment is not None and assessment.alert is not None
        serialized = json.dumps(assessment.alert, sort_keys=True)
        for secret in ("supersecret", "topsecret", "/private", "token=", "session="):
            self.assertNotIn(secret, serialized)


class DdosDetectorTests(unittest.TestCase):
    def test_escalates_and_recovers(self) -> None:
        clock = [10.0]
        config = base_config(
            Path(tempfile.mkdtemp()),
            18080,
            overrides={
                "ddos_detection": {
                    "enabled": True,
                    "window_seconds": 1,
                    "request_rate_threshold": 2,
                    "global_rejection_ratio": 0.2,
                    "connection_saturation": 0.8,
                    "tls_failure_threshold": 2,
                    "upstream_error_ratio": 0.1,
                    "min_signals": 2,
                    "cooldown_seconds": 60,
                    "escalation_seconds": 5,
                    "recovery_seconds": 2,
                }
            },
        ).ddos_detection
        detector = DdosDetector(config, Metrics(), clock=lambda: clock[0], wall_clock=lambda: 1_700_000_000 + clock[0])
        for _ in range(3):
            detector.record_request(connection_load=0.9)
        first = detector.evaluate()
        self.assertTrue(first.triggered)
        self.assertEqual(first.alerts[0]["event"], "ddos_suspected")
        clock[0] = 16.0
        for _ in range(3):
            detector.record_request(connection_load=0.9)
        escalated = detector.evaluate()
        self.assertEqual(escalated.alerts[0]["event"], "ddos_escalated")
        self.assertEqual(first.alerts[0]["containment_window_seconds"], 300)
        self.assertEqual(first.alerts[0]["action"], "alert_and_check_l7_capacity")
        self.assertEqual(escalated.alerts[0]["severity"], "critical")
        self.assertEqual(escalated.alerts[0]["action"], "escalate_to_noc_and_check_edge_scrubbing")
        clock[0] = 19.0
        recovered = detector.evaluate()
        self.assertEqual(recovered.alerts[0]["event"], "ddos_recovered")
        self.assertEqual(recovered.alerts[0]["action"], "monitor_and_preserve_evidence")


class AlertingTests(unittest.TestCase):
    def test_dispatch_deduplicates_and_flushes(self) -> None:
        metrics = Metrics()
        sent: list[dict] = []

        def sender(url: str, token: str | None, payload: dict, timeout: float) -> int:
            sent.append(payload)
            return 204

        dispatcher = AlertDispatcher(
            url="https://alerts.example.test/hook",
            token="a" * 32,
            timeout=1.0,
            max_queue=8,
            cooldown_seconds=60,
            metrics=metrics,
            sender=sender,
        )
        self.addCleanup(dispatcher.close)
        self.assertTrue(dispatcher.emit({"event": "one"}, "same"))
        self.assertFalse(dispatcher.emit({"event": "two"}, "same"))
        self.assertTrue(dispatcher.flush(2.0))
        self.assertEqual(len(sent), 1)
        self.assertEqual(metrics.snapshot()["alert_sent_total"], 1)

    def test_queue_full_does_not_start_cooldown(self) -> None:
        metrics = Metrics()
        started = threading.Event()
        release = threading.Event()
        clock = [0.0]

        def sender(url: str, token: str | None, payload: dict, timeout: float) -> int:
            started.set()
            release.wait(2.0)
            return 204

        dispatcher = AlertDispatcher(
            url="https://alerts.example.test/hook",
            token=None,
            timeout=1.0,
            max_queue=1,
            cooldown_seconds=1,
            metrics=metrics,
            sender=sender,
            clock=lambda: clock[0],
        )
        self.addCleanup(dispatcher.close)
        self.addCleanup(release.set)
        self.assertTrue(dispatcher.emit({"event": "first"}, "same"))
        self.assertTrue(started.wait(1.0))
        self.assertTrue(dispatcher.emit({"event": "fill"}, "fill"))
        clock[0] = 2.0
        self.assertFalse(dispatcher.emit({"event": "dropped"}, "same"))
        release.set()
        self.assertTrue(dispatcher.flush(2.0))
        self.assertTrue(dispatcher.emit({"event": "after"}, "same"))
        self.assertTrue(dispatcher.flush(2.0))
        self.assertEqual(metrics.snapshot()["alert_dropped_total"], 1)


class ThreatConfigTests(unittest.TestCase):
    def test_default_windows_are_five_and_fifteen_minutes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(Path(directory), 18080)
            self.assertEqual(config.threat_detection.containment_seconds, 300.0)
            self.assertEqual(config.threat_detection.confirmed_containment_seconds, 900.0)
            self.assertEqual(config.ddos_detection.escalation_seconds, 300.0)

    def test_new_sections_are_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data = {
                "version": 1,
                "upstream": {"scheme": "http", "host": "127.0.0.1", "port": 18080},
                "policy": {"allowed_hosts": ["example.test"], "allowed_methods": ["GET"]},
                "threat_detection": {"enabled": True, "mode": "nonsense"},
            }
            with self.assertRaises(ConfigError):
                parse_config(data, directory)
            data["threat_detection"]["mode"] = "tarpit"
            data["threat_detection"]["confirm_score"] = 10
            with self.assertRaises(ConfigError):
                parse_config(data, directory)

    def test_alerting_env_names_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data = {
                "version": 1,
                "upstream": {"scheme": "http", "host": "127.0.0.1", "port": 18080},
                "policy": {"allowed_hosts": ["example.test"], "allowed_methods": ["GET"]},
                "alerting": {"enabled": True, "webhook_url_env": "not a name"},
            }
            with self.assertRaises(ConfigError):
                parse_config(data, directory)


if __name__ == "__main__":
    unittest.main()
