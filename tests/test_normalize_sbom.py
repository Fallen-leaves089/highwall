from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_sbom import normalize_document, normalize_sbom


def sample_document() -> dict[str, object]:
    root_ref = "path+file:///home/runner/work/repo/repo/subprojects/native-core#highwall-native-core@0.13.0"
    h2_ref = "path+file:///home/runner/work/repo/repo/vendor/h2#0.4.20"
    h3_ref = "path+file:///home/runner/work/repo/repo/vendor/h3#0.0.8"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "highwall-native-core",
                "version": "0.13.0",
                "purl": "pkg:cargo/highwall-native-core@0.13.0?download_url=file://.",
                "components": [
                    {
                        "type": "library",
                        "bom-ref": root_ref + " bin-target-0",
                        "name": "highwall_native_core",
                        "version": "0.13.0",
                        "purl": "pkg:cargo/highwall-native-core@0.13.0?download_url=file://.#src/lib.rs",
                    }
                ],
            }
        },
        "components": [
            {
                "type": "library",
                "bom-ref": h2_ref,
                "name": "h2",
                "version": "0.4.20",
                "purl": "pkg:cargo/h2@0.4.20?download_url=file:///home/runner/work/repo/repo/vendor/h2",
                "externalReferences": [
                    {"type": "vcs", "url": "https://github.com/hyperium/h2"},
                    {"type": "distribution", "url": "file:///home/runner/work/repo/repo/vendor/h2"},
                ],
            },
            {
                "type": "library",
                "bom-ref": h3_ref,
                "name": "h3",
                "version": "0.0.8",
                "purl": "pkg:cargo/h3@0.0.8?download_url=file:///home/runner/work/repo/repo/vendor/h3",
            },
        ],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [h2_ref, h3_ref, "registry+https://index.crates.io/#bytes@1.12.1"]},
            {"ref": h2_ref, "dependsOn": ["registry+https://index.crates.io/#bytes@1.12.1"]},
            {"ref": h3_ref},
        ],
    }


class NormalizeSbomTests(unittest.TestCase):
    def test_replaces_local_refs_and_download_urls(self) -> None:
        document = normalize_document(sample_document())
        metadata = document["metadata"]
        assert isinstance(metadata, dict)
        root = metadata["component"]
        assert isinstance(root, dict)

        self.assertEqual(root["bom-ref"], "pkg:cargo/highwall-native-core@0.13.0")
        self.assertEqual(root["purl"], "pkg:cargo/highwall-native-core@0.13.0")
        nested = root["components"][0]
        self.assertEqual(nested["bom-ref"], "pkg:cargo/highwall-native-core@0.13.0#src/lib.rs")
        self.assertEqual(nested["purl"], "pkg:cargo/highwall-native-core@0.13.0#src/lib.rs")

        h2, h3 = document["components"]
        self.assertEqual(h2["bom-ref"], "pkg:cargo/h2@0.4.20")
        self.assertEqual(h2["purl"], "pkg:cargo/h2@0.4.20")
        self.assertEqual(h3["bom-ref"], "pkg:cargo/h3@0.0.8")
        self.assertEqual(h2["externalReferences"], [{"type": "vcs", "url": "https://github.com/hyperium/h2"}])

        root_dependency = document["dependencies"][0]
        self.assertEqual(root_dependency["ref"], "pkg:cargo/highwall-native-core@0.13.0")
        self.assertEqual(root_dependency["dependsOn"][:2], ["pkg:cargo/h2@0.4.20", "pkg:cargo/h3@0.0.8"])
        self.assertNotIn("/home/runner/", json.dumps(document))

    def test_is_idempotent(self) -> None:
        once = normalize_document(sample_document())
        twice = normalize_document(json.loads(json.dumps(once)))
        self.assertEqual(once, twice)

    def test_preserves_nonlocal_download_url(self) -> None:
        document = {
            "components": [
                {
                    "bom-ref": "pkg:cargo/example@1.2.3",
                    "purl": "pkg:cargo/example@1.2.3?download_url=https://example.invalid/example.crate",
                }
            ]
        }
        normalized = normalize_document(document)
        self.assertEqual(
            normalized["components"][0]["purl"],
            "pkg:cargo/example@1.2.3?download_url=https://example.invalid/example.crate",
        )

    def test_rejects_unknown_local_dependency(self) -> None:
        document = {
            "dependencies": [
                {
                    "ref": "path+file:///home/runner/work/repo/repo/vendor/missing#1.0.0",
                    "dependsOn": [],
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "unknown local component"):
            normalize_document(document)

    def test_writes_utf8_with_lf_line_endings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sbom.cdx.json"
            path.write_text(json.dumps(sample_document()), encoding="utf-8")
            normalize_sbom(path)
            content = path.read_text(encoding="utf-8")
            self.assertTrue(content.endswith("\n"))
            self.assertNotIn("\r\n", content)
            self.assertNotIn("/home/runner/", content)


if __name__ == "__main__":
    unittest.main()
