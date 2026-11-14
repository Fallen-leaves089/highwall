from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.set_release_version import set_cargo_version, set_python_version


class SetReleaseVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8", newline="")
        return path

    def test_sets_python_versions_and_preserves_crlf(self) -> None:
        pyproject = self.write("pyproject.toml", '[project]\r\nversion = "0.13.0.dev0"\r\n')
        module = self.write("__init__.py", '__version__ = "0.13.0.dev0"\r\n')

        set_python_version("0.13.0rc1", pyproject, module)

        self.assertEqual(pyproject.read_bytes(), b'[project]\r\nversion = "0.13.0rc1"\r\n')
        self.assertEqual(module.read_bytes(), b'__version__ = "0.13.0rc1"\r\n')

    def test_sets_cargo_manifest_and_root_lock_entry_only(self) -> None:
        manifest = self.write("Cargo.toml", '[package]\nname = "highwall-native-core"\nversion = "0.13.0-dev0"\n')
        lockfile = self.write(
            "Cargo.lock",
            'version = 4\n\n[[package]]\nname = "anyhow"\nversion = "1.0.104"\n\n'
            '[[package]]\nname = "highwall-native-core"\nversion = "0.13.0-dev0"\n',
        )

        set_cargo_version("0.13.0-rc.1", manifest, lockfile, "highwall-native-core")

        self.assertIn('version = "0.13.0-rc.1"', manifest.read_text(encoding="utf-8"))
        lock_text = lockfile.read_text(encoding="utf-8")
        self.assertIn('name = "anyhow"\nversion = "1.0.104"', lock_text)
        self.assertIn('name = "highwall-native-core"\nversion = "0.13.0-rc.1"', lock_text)

    def test_rejects_invalid_versions_and_ambiguous_replacements(self) -> None:
        pyproject = self.write("pyproject.toml", 'version = "1.0.0"\nversion = "1.0.0"\n')
        module = self.write("__init__.py", '__version__ = "1.0.0"\n')
        with self.assertRaisesRegex(ValueError, "PEP 440"):
            set_python_version("1.0.0-alpha.1", pyproject, module)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            set_python_version("1.0.0", pyproject, module)


if __name__ == "__main__":
    unittest.main()
