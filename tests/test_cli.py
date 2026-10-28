from __future__ import annotations

import contextlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from highwall import __version__
from highwall.cli import main

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_module_entrypoint_reports_version(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "highwall", "--version"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"highwall {__version__}", result.stdout)

    def test_example_config_checks(self) -> None:
        code, stdout, stderr = self.run_cli("check", "-c", str(ROOT / "config.example.json"))

        self.assertEqual(code, 0, stderr)
        self.assertIn("configuration OK", stdout)

    def test_invalid_config_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"version":1,"upstream":{"host":"127.0.0.1"},"policy":{}}', encoding="utf-8")
            code, _, stderr = self.run_cli("check", "-c", str(path))

        self.assertEqual(code, 2)
        self.assertIn("configuration error", stderr)

    def test_check_strict_rejects_high_risk_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_config(directory, "config.json", waf_enabled=False)
            code, stdout, stderr = self.run_cli("check", "-c", str(path))
            strict_code, _, strict_stderr = self.run_cli("check", "-c", str(path), "--strict")

        self.assertEqual(code, 0, stderr)
        self.assertIn("configuration OK", stdout)
        self.assertIn("warning [high] policy.waf_enabled", stderr)
        self.assertEqual(strict_code, 4)
        self.assertIn("strict configuration check failed", strict_stderr)

    def test_check_strict_accepts_medium_only_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_config(directory, "config.json")
            code, _, stderr = self.run_cli("check", "-c", str(path), "--strict")

        self.assertEqual(code, 0, stderr)
        self.assertIn("warning [medium]", stderr)
        self.assertNotIn("warning [high]", stderr)

    def write_config(self, directory: str, name: str, *, waf_enabled: bool = True, listen_port: int = 18090) -> Path:
        path = Path(directory) / name
        data = {
            "version": 1,
            "server": {"listen_port": listen_port},
            "upstream": {"host": "127.0.0.1"},
            "policy": {
                "allowed_hosts": ["test.local"],
                "waf_enabled": waf_enabled,
            },
        }
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_diff_reports_restart_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            current = self.write_config(directory, "current.json")
            candidate = self.write_config(directory, "candidate.json", listen_port=18091)
            code, stdout, stderr = self.run_cli("diff", "-c", str(current), "--candidate", str(candidate))

        self.assertEqual(code, 3, stderr)
        self.assertIn("restart required", stdout)
        self.assertIn("server.listen_port", stdout)

    def test_diff_blocks_security_regression_and_emits_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            current = self.write_config(directory, "current.json")
            candidate = self.write_config(directory, "candidate.json", waf_enabled=False)
            code, stdout, stderr = self.run_cli(
                "diff",
                "-c",
                str(current),
                "--candidate",
                str(candidate),
                "--json",
            )

        self.assertEqual(code, 4, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["exit_code"], 4)
        self.assertEqual(report["security_regressions"][0]["path"], "policy.waf_enabled")

    def test_diff_reports_no_effective_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            current = self.write_config(directory, "current.json")
            code, stdout, stderr = self.run_cli("diff", "-c", str(current), "--candidate", str(current))

        self.assertEqual(code, 0, stderr)
        self.assertIn("no effective configuration changes", stdout)

    def test_diff_rejects_invalid_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            current = self.write_config(directory, "current.json")
            candidate = Path(directory) / "broken.json"
            candidate.write_text("{", encoding="utf-8")
            code, _, stderr = self.run_cli("diff", "-c", str(current), "--candidate", str(candidate))

        self.assertEqual(code, 2)
        self.assertIn("configuration error", stderr)

    def test_inspect_prints_effective_configuration(self) -> None:
        code, stdout, stderr = self.run_cli("inspect", "-c", str(ROOT / "config.example.json"))

        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertIn("server", report)

    def test_init_writes_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "config.json"
            code, stdout, stderr = self.run_cli(
                "init",
                "-o",
                str(output),
                "--upstream",
                "http://127.0.0.1:9000",
                "--listen-port",
                "18092",
                "--allowed-host",
                "test.local",
                "--no-honeypot",
                "--print-config",
            )

            self.assertEqual(code, 0, stderr)
            self.assertIn("configuration written", stdout)
            self.assertIn("honeypot: disabled", stdout)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["server"]["listen_port"], 18092)

    def test_init_merges_base_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base.json"
            merged = Path(directory) / "merged.json"
            first, _, first_stderr = self.run_cli("init", "-o", str(base), "--allowed-host", "test.local")
            self.assertEqual(first, 0, first_stderr)
            second, stdout, second_stderr = self.run_cli(
                "init",
                "--base",
                str(base),
                "-o",
                str(merged),
                "--listen-port",
                "18093",
            )

            self.assertEqual(second, 0, second_stderr)
            self.assertIn("configuration written", stdout)
            data = json.loads(merged.read_text(encoding="utf-8"))
            self.assertEqual(data["server"]["listen_port"], 18093)

    def test_init_rejects_conflicting_honeypot_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "config.json"
            code, _, stderr = self.run_cli(
                "init",
                "-o",
                str(output),
                "--no-honeypot",
                "--honeypot-preset",
                "common",
            )

        self.assertEqual(code, 2)
        self.assertIn("mutually exclusive", stderr)

    def test_unknown_command_exits_with_usage_error(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                main(["bogus"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("invalid choice", stderr.getvalue())

    def test_serve_reports_listener_bind_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
                holder.bind(("127.0.0.1", 0))
                holder.listen(1)
                port = int(holder.getsockname()[1])
                path = self.write_config(directory, "config.json", listen_port=port)
                code, _, _ = self.run_cli("serve", "-c", str(path))

        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
