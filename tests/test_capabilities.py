from __future__ import annotations

import contextlib
import io
import json
import unittest

from highwall.capabilities import CAPABILITY_LEVELS, capability_manifest
from highwall.cli import main


class CapabilityManifestTests(unittest.TestCase):
    def test_manifest_has_a_stable_schema_and_valid_levels(self) -> None:
        manifest = capability_manifest()

        self.assertEqual(manifest["schema"], "highwall.capabilities.v1")
        self.assertEqual(set(CAPABILITY_LEVELS), {"C0", "C1", "C2", "C3", "C4"})
        for surface in manifest["surfaces"]:
            with self.subTest(surface=surface["name"]):
                self.assertIn(surface["level"], CAPABILITY_LEVELS)
                self.assertIn("complete", surface)
                self.assertIn("limitations", surface)

    def test_http1_is_declared_complete_but_h2_h3_websocket_and_grpc_are_not(self) -> None:
        surfaces = {surface["name"]: surface for surface in capability_manifest()["surfaces"]}

        self.assertEqual(surfaces["http1"]["level"], "C3")
        self.assertTrue(surfaces["http1"]["complete"])
        for name in ("http2", "http3", "websocket", "grpc"):
            with self.subTest(surface=name):
                self.assertEqual(surfaces[name]["level"], "C0")
                self.assertFalse(surfaces[name]["complete"])

    def test_l5_is_not_overclaimed_before_l5wall_integration(self) -> None:
        surfaces = {surface["name"]: surface for surface in capability_manifest()["surfaces"]}

        self.assertEqual(surfaces["tls"]["level"], "C1")
        self.assertFalse(surfaces["tls"]["complete"])
        self.assertIn("SNI", surfaces["tls"]["limitations"])


class CapabilityCliTests(unittest.TestCase):
    def test_capabilities_json_is_machine_readable(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["capabilities", "--json"])

        self.assertEqual(code, 0, stderr.getvalue())
        manifest = json.loads(stdout.getvalue())
        self.assertEqual(manifest["schema"], "highwall.capabilities.v1")
        self.assertTrue(manifest["not_a_certification"])


if __name__ == "__main__":
    unittest.main()
