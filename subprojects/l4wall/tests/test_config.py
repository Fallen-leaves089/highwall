from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from l4wall.config import config_to_dict, example_config, parse_config, resolve_runtime_paths
from l4wall.errors import ConfigError


class ConfigTests(unittest.TestCase):
    def test_example_is_valid(self) -> None:
        config = parse_config(example_config())
        self.assertEqual(config.version, 1)
        self.assertEqual(len(config.listeners), 2)
        self.assertEqual(config.listeners[0].name, "web")

    def test_unknown_key_is_rejected(self) -> None:
        raw = example_config()
        raw["listeners"][0]["allow_all"] = True
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_admin_must_be_loopback(self) -> None:
        raw = example_config()
        raw["admin"]["enabled"] = True
        raw["admin"]["listen_host"] = "0.0.0.0"
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_duplicate_listen_port_is_rejected(self) -> None:
        raw = example_config()
        raw["listeners"][1]["listen_port"] = raw["listeners"][0]["listen_port"]
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_allowlist_can_be_required(self) -> None:
        raw = example_config()
        raw["server"]["require_client_allowlist"] = True
        raw["listeners"][0]["allowed_client_networks"] = []
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_invalid_cidr_is_rejected(self) -> None:
        raw = example_config()
        raw["listeners"][0]["allowed_client_networks"] = ["not-a-network"]
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_self_forward_is_rejected(self) -> None:
        raw = example_config()
        raw["listeners"][0]["upstream_host"] = "127.0.0.1"
        raw["listeners"][0]["upstream_port"] = raw["listeners"][0]["listen_port"]
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_confirm_score_must_not_be_below_threshold(self) -> None:
        raw = example_config()
        raw["threat_detection"]["confirm_score"] = 10
        raw["threat_detection"]["score_threshold"] = 70
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_shared_bans_rejects_unknown_key(self) -> None:
        raw = example_config()
        raw["threat_detection"]["shared_bans"]["unknown"] = True
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_shared_bans_only_supports_redis(self) -> None:
        raw = example_config()
        raw["threat_detection"]["shared_bans"]["backend"] = "sqlite"
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_shared_bans_rejects_public_literal_address(self) -> None:
        raw = example_config()
        raw["threat_detection"]["shared_bans"]["host"] = "8.8.8.8"
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_shared_bans_rejects_invalid_timeout_and_key(self) -> None:
        for field, value in (("connect_timeout", 0.0), ("read_timeout", float("nan")), ("key", "bad key")):
            with self.subTest(field=field):
                raw = example_config()
                raw["threat_detection"]["shared_bans"][field] = value
                with self.assertRaises(ConfigError):
                    parse_config(raw)

    def test_shared_bans_is_disabled_by_default_and_serialized(self) -> None:
        raw = example_config()
        config = parse_config(raw)
        self.assertFalse(config.threat.shared_bans.enabled)
        self.assertEqual(config.threat.shared_bans.backend, "redis")
        self.assertEqual(raw["threat_detection"]["shared_bans"]["key"], "l4wall:bans:v1")

    def test_config_is_not_mutated_by_parse(self) -> None:
        raw = example_config()
        before = copy.deepcopy(raw)
        parse_config(raw)
        self.assertEqual(raw, before)

    def test_effective_config_omits_secret_environment_names(self) -> None:
        raw = example_config()
        raw["threat_detection"]["shared_bans"]["password_env"] = "L4WALL_TEST_REDIS_PASSWORD"
        raw["admin"]["enabled"] = True
        raw["admin"]["token_env"] = "L4WALL_TEST_ADMIN_TOKEN"
        rendered = json.dumps(config_to_dict(parse_config(raw)))
        self.assertNotIn("L4WALL_TEST_REDIS_PASSWORD", rendered)
        self.assertNotIn("L4WALL_TEST_ADMIN_TOKEN", rendered)
        self.assertNotIn("password_env", rendered)
        self.assertNotIn("token_env", rendered)

    def test_relative_runtime_paths_resolve_against_config_directory(self) -> None:
        config = parse_config(example_config())
        base = Path(tempfile.gettempdir())
        resolved = resolve_runtime_paths(config, base)
        self.assertEqual(Path(resolved.audit.path), base / "audit.jsonl")
        self.assertEqual(Path(resolved.threat.offender_path), base / "offenders.json")


if __name__ == "__main__":
    unittest.main()

