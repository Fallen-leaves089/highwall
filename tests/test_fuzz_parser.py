from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ParserFuzzTests(unittest.TestCase):
    def test_bounded_fuzz_run_has_no_unexpected_exceptions(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.fuzz_parser",
                "--iterations",
                "250",
                "--seed",
                "1",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unexpected=0", result.stdout)


if __name__ == "__main__":
    unittest.main()
