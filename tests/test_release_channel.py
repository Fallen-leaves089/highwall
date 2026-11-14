from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.release_channel import classify_release, package_version, write_github_output


class ReleaseChannelTests(unittest.TestCase):
    def test_classifies_each_channel(self) -> None:
        cases = {
            "v0.13.0-alpha.1": ("0.13.0-alpha.1", "0.13.0a1", "alpha", True, "Alpha"),
            "v0.13.0-beta.2": ("0.13.0-beta.2", "0.13.0b2", "beta", True, "Beta"),
            "v0.13.0-rc.1": ("0.13.0-rc.1", "0.13.0rc1", "rc", True, "Release Candidate"),
            "v0.13.0": ("0.13.0", "0.13.0", "stable", False, "Stable"),
        }
        for tag, expected in cases.items():
            with self.subTest(tag=tag):
                release = classify_release(tag, "v")
                self.assertEqual(
                    (
                        release.version,
                        release.package_version,
                        release.channel,
                        release.prerelease,
                        release.label,
                    ),
                    expected,
                )

    def test_supports_all_release_prefixes(self) -> None:
        self.assertEqual(classify_release("v1.2.3", "v").version, "1.2.3")
        self.assertEqual(classify_release("l4wall-v0.1.0", "l4wall-v").version, "0.1.0")
        self.assertEqual(classify_release("l5wall-v0.2.1", "l5wall-v").version, "0.2.1")

    def test_rejects_ambiguous_or_invalid_tags(self) -> None:
        invalid = (
            ("v0.13.0-alpha", "v"),
            ("v0.13.0-alpha.0", "v"),
            ("v01.2.3", "v"),
            ("v1.2", "v"),
            ("v1.2.3+build.1", "v"),
            ("l5wall-v0.2.1", "v"),
        )
        for tag, prefix in invalid:
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    classify_release(tag, prefix)

    def test_writes_github_outputs(self) -> None:
        release = classify_release("l5wall-v0.3.0-rc.2", "l5wall-v")
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "output"
            write_github_output(output, release)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "tag=l5wall-v0.3.0-rc.2\n"
                "version=0.3.0-rc.2\n"
                "package_version=0.3.0rc2\n"
                "channel=rc\n"
                "prerelease=true\n"
                "label=Release Candidate\n",
            )

    def test_rejects_non_release_versions_as_package_versions(self) -> None:
        for version in ("0.13.0-dev0", "0.13.0-alpha", "0.13.0-alpha.01"):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    package_version(version)


if __name__ == "__main__":
    unittest.main()
