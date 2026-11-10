from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative_path: str) -> ModuleType:
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


relay = _load("honeypot_relay", "deploy/honeypot/relay/relay.py")
decoy = _load("honeypot_decoy", "deploy/honeypot/web/decoy.py")


class ListenHostTests(unittest.TestCase):
    def test_relay_defaults_to_loopback(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(relay._listen_host(), "127.0.0.1")

    def test_decoy_defaults_to_loopback(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(decoy._listen_host(), "127.0.0.1")

    def test_explicit_container_address_is_accepted(self) -> None:
        with mock.patch.dict(os.environ, {"LISTEN_HOST": "0.0.0.0"}, clear=True):
            self.assertEqual(relay._listen_host(), "0.0.0.0")
            self.assertEqual(decoy._listen_host(), "0.0.0.0")

    def test_hostname_is_rejected(self) -> None:
        with mock.patch.dict(os.environ, {"LISTEN_HOST": "localhost"}, clear=True):
            with self.assertRaises(SystemExit):
                relay._listen_host()
            with self.assertRaises(SystemExit):
                decoy._listen_host()

    def test_ipv6_is_rejected_by_ipv4_socket_path(self) -> None:
        with mock.patch.dict(os.environ, {"LISTEN_HOST": "::1"}, clear=True):
            with self.assertRaises(SystemExit):
                relay._listen_host()
            with self.assertRaises(SystemExit):
                decoy._listen_host()


if __name__ == "__main__":
    unittest.main()
