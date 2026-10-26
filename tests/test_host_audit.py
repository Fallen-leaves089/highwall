from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "host-audit.ps1"
POWERSHELL = shutil.which("powershell.exe")


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "Windows PowerShell is required")
class HostAuditScriptTests(unittest.TestCase):
    def test_script_source_is_read_only(self) -> None:
        source = SCRIPT.read_text("utf-8")
        destructive = (
            "New-NetFirewallRule",
            "Set-NetFirewallRule",
            "Remove-NetFirewallRule",
            "New-NetIPAddress",
            "Remove-NetIPAddress",
            "Start-Service",
            "Stop-Service",
            "Remove-Item",
            "Set-ItemProperty",
            "icacls",
            "portproxy add",
            "portproxy delete",
        )
        for token in destructive:
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_json_report_is_parseable_and_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    POWERSHELL,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(SCRIPT),
                    "-Json",
                    "-HighWallRoot",
                    directory,
                ],
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=60,
            )
        self.assertIn(result.returncode, {0, 1}, result.stderr)
        report = json.loads(result.stdout.lstrip("\ufeff"))
        self.assertEqual(report["schemaVersion"], 1)
        self.assertIsInstance(report["elevated"], bool)
        self.assertIn(report["exitCode"], {0, 1})
        checks = report["checks"]
        self.assertGreater(len(checks), 5)
        self.assertEqual(sum(report["summary"].values()), len(checks))
        for check in checks:
            self.assertIn(check["status"], {"PASS", "WARN", "FAIL", "INFO"})
            self.assertIn(check["severity"], {"Info", "Low", "Medium", "High"})
            self.assertTrue(check["name"])
            self.assertTrue(check["detail"])
        self.assertIn("WSL", " ".join(report["limitations"]))
        self.assertNotIn("Authorization: Bearer", result.stdout)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", result.stdout)


if __name__ == "__main__":
    unittest.main()
