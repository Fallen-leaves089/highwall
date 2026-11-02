"""Release consistency checks for the standalone L5Wall package."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from l5wall import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PROJECT_ROOT.parents[1]


class VersionTests(unittest.TestCase):
    def test_pyproject_version_matches_package(self) -> None:
        text = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), __version__)

    def test_license_files_match_repository_root(self) -> None:
        for name in ("LICENSE", "NOTICE"):
            with self.subTest(name=name):
                self.assertEqual(
                    (PROJECT_ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n"),
                    (REPOSITORY_ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n"),
                )


if __name__ == "__main__":
    unittest.main()
