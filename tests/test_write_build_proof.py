from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.write_build_proof import write_proof


class WriteBuildProofTests(unittest.TestCase):
    def test_writes_deterministic_proof_for_identical_builds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first.bin"
            second = root / "highwall-native-core-0.13.0-linux-x86_64"
            output = root / "proof.json"
            first.write_bytes(b"reproducible")
            second.write_bytes(b"reproducible")

            proof = write_proof(
                first,
                second,
                output,
                version="0.13.0",
                target="linux-x86_64",
                rustc_version="rustc 1.97.1",
            )

            self.assertEqual(proof["asset"], second.name)
            self.assertEqual(proof["sha256"], "09d00b20d8e222f36096ed5c6b6e6f7f216b96d839ca0fe9c87f01337827a787")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), proof)
            self.assertTrue(output.read_text(encoding="utf-8").endswith("\n"))

    def test_rejects_mismatched_builds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first.bin"
            second = root / "second.bin"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            with self.assertRaisesRegex(ValueError, "not reproducible"):
                write_proof(
                    first,
                    second,
                    root / "proof.json",
                    version="0.13.0",
                    target="linux-x86_64",
                    rustc_version="rustc 1.97.1",
                )


if __name__ == "__main__":
    unittest.main()
