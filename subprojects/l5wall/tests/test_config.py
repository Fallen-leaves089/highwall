from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from l5wall.config import ConfigError, load_config, parse_config
from test_certificates import ensure_test_material

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def setUpModule() -> None:
    ensure_test_material(FIXTURES)


class ConfigTests(unittest.TestCase):
    def test_example_config_is_valid(self) -> None:
        config = load_config(ROOT / "config.example.json")

        self.assertEqual(config.min_version, "TLSv1_2")
        self.assertEqual(config.allowed_alpn, ("http/1.1",))
        self.assertEqual(config.allowed_sni, ("localhost",))
        self.assertEqual(config.mtls_mode, "off")
        self.assertEqual(config.listen_host, "127.0.0.1")
        self.assertTrue(config.require_sni_host_match)

    def test_unknown_field_is_rejected(self) -> None:
        value = self.example()
        value["shell"] = "id"

        with self.assertRaisesRegex(ConfigError, "unknown field"):
            parse_config(value, ROOT)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"cert_file":"a","cert_file":"b"}', encoding="utf-8")

            with self.assertRaisesRegex(ConfigError, "duplicate"):
                load_config(path)

    def test_mtls_requires_a_client_ca(self) -> None:
        value = self.example()
        value["mtls_mode"] = "required"

        with self.assertRaisesRegex(ConfigError, "client_ca_file"):
            parse_config(value, ROOT)

    def test_tls10_is_rejected(self) -> None:
        value = self.example()
        value["min_version"] = "TLSv1_0"

        with self.assertRaisesRegex(ConfigError, "min_version"):
            parse_config(value, ROOT)

    def test_wildcard_sni_must_be_a_single_leading_label(self) -> None:
        value = self.example()
        value["allowed_sni"] = ["api.*.example.test"]

        with self.assertRaisesRegex(ConfigError, "invalid DNS"):
            parse_config(value, ROOT)

    def test_missing_certificate_is_rejected(self) -> None:
        value = self.example()
        value["cert_file"] = "tests/fixtures/missing.pem"

        with self.assertRaisesRegex(ConfigError, "cert_file"):
            parse_config(value, ROOT)

    def test_non_loopback_listener_is_rejected(self) -> None:
        value = self.example()
        value["listen_host"] = "0.0.0.0"

        with self.assertRaisesRegex(ConfigError, "loopback"):
            parse_config(value, ROOT)

    def test_non_loopback_upstream_is_rejected(self) -> None:
        value = self.example()
        value["upstream_host"] = "192.0.2.10"

        with self.assertRaisesRegex(ConfigError, "loopback"):
            parse_config(value, ROOT)

    def test_boolean_port_is_rejected(self) -> None:
        value = self.example()
        value["listen_port"] = True

        with self.assertRaisesRegex(ConfigError, "integer"):
            parse_config(value, ROOT)

    def example(self) -> dict[str, object]:
        return json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
