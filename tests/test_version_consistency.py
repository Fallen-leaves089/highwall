"""Version consistency checks for source, native, and container defaults."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from highwall import __version__

ROOT = Path(__file__).resolve().parents[1]


def _match(path: Path, pattern: str) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise AssertionError(f"pattern not found in {path}: {pattern}")
    return match.group(1)


class VersionConsistencyTests(unittest.TestCase):
    def test_python_metadata_matches_package(self) -> None:
        expected = _match(ROOT / "pyproject.toml", r'^version = "([^"]+)"$')
        self.assertEqual(expected, __version__)

    def test_container_defaults_match_source_version(self) -> None:
        for name in ("Dockerfile", "Dockerfile.native"):
            values = re.findall(
                r"^ARG HIGHWALL_VERSION=(\S+)$",
                (ROOT / name).read_text(encoding="utf-8"),
                re.MULTILINE,
            )
            self.assertTrue(values, name)
            for value in values:
                self.assertEqual(value, __version__, name)

    def test_native_core_version_tracks_python_version(self) -> None:
        cargo_version = _match(
            ROOT / "subprojects/native-core/Cargo.toml",
            r'^version = "([^"]+)"$',
        )
        expected = __version__.replace(".dev", "-dev", 1)
        self.assertEqual(cargo_version, expected)
        lock = (ROOT / "subprojects/native-core/Cargo.lock").read_text(encoding="utf-8")
        lock_match = re.search(
            r'name = "highwall-native-core"\s+version = "([^"]+)"',
            lock,
        )
        self.assertIsNotNone(lock_match)
        self.assertEqual(lock_match.group(1), cargo_version)
