from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from highwall import __version__

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "highwall", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def test_version(self) -> None:
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"highwall {__version__}", result.stdout)

    def test_example_config_checks(self) -> None:
        result = self.run_cli("check", "-c", str(ROOT / "config.example.json"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("configuration OK", result.stdout)

    def test_invalid_config_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"version":1,"upstream":{"host":"127.0.0.1"},"policy":{}}', encoding="utf-8")
            result = self.run_cli("check", "-c", str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("configuration error", result.stderr)


if __name__ == "__main__":
    unittest.main()
