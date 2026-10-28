from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from highwall.config import ConfigError, load_config
from highwall.init_config import build_initial_config, parse_upstream_url, write_initial_config

ROOT = Path(__file__).resolve().parents[1]


class InitConfigTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "highwall", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=15,
        )

    def build(self, directory: Path, **overrides: object) -> dict:
        values = {
            "upstream_scheme": "http",
            "upstream_host": "127.0.0.1",
            "upstream_port": 8080,
            "listen_host": "127.0.0.1",
            "listen_port": 18090,
            "allowed_hosts": ("example.test",),
            "allowed_methods": ("GET", "HEAD"),
            "honeypot_presets": ("secrets",),
            "audit_path": "audit.jsonl",
            "base_dir": directory,
        }
        values.update(overrides)
        return build_initial_config(**values)

    def test_upstream_url_parsing(self) -> None:
        self.assertEqual(
            parse_upstream_url("http://127.0.0.1:8080"),
            ("http", "127.0.0.1", 8080),
        )
        self.assertEqual(
            parse_upstream_url("https://Example.TEST"),
            ("https", "example.test", 443),
        )
        for value in (
            "ftp://example.test",
            "http://example.test/path",
            "http://user:pass@example.test",
            "http://example.test/?query=1",
            "http://example.test:bad",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    parse_upstream_url(value)

    def test_generated_config_is_valid_and_has_secure_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = write_initial_config(base / "config.json", self.build(base))
            config = load_config(path)

        self.assertEqual(config.server.listen_port, 18090)
        self.assertEqual(config.server.max_inflight_requests, 32)
        self.assertEqual(config.server.shutdown_timeout, 30.0)
        self.assertTrue(config.upstream.circuit_breaker.enabled)
        self.assertEqual(config.upstream.port, 8080)
        self.assertEqual(config.policy.allowed_hosts, ("example.test",))
        self.assertEqual(config.policy.allowed_methods, ("GET", "HEAD"))
        self.assertIn("ssrf", config.policy.waf_rules)
        self.assertTrue(config.policy.honeypot.enabled)
        self.assertEqual(
            [route.path for route in config.policy.honeypot.routes],
            ["/.env", "/.git/HEAD", "/.git/config", "/.svn/entries"],
        )

    def test_write_does_not_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / "config.json"
            write_initial_config(path, self.build(base, listen_port=18090))
            original = path.read_bytes()
            with self.assertRaisesRegex(ConfigError, "already exists"):
                write_initial_config(path, self.build(base, listen_port=18091))
            self.assertEqual(path.read_bytes(), original)

            write_initial_config(path, self.build(base, listen_port=18091), force=True)
            config = load_config(path)
            self.assertEqual(config.server.listen_port, 18091)

    def test_write_rejects_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = base / "config.json"
            try:
                os.symlink(target, link)
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {type(exc).__name__}")
            with self.assertRaisesRegex(ConfigError, "symbolic link or reparse point"):
                write_initial_config(link, self.build(base), force=True)

    def test_init_cli_refuses_overwrite_and_inspect_expands_presets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            first = self.run_cli(
                "init",
                "--output",
                str(path),
                "--upstream",
                "http://127.0.0.1:9090",
                "--listen-port",
                "19090",
                "--allowed-host",
                "example.test",
                "--method",
                "GET",
                "--method",
                "HEAD",
                "--honeypot-preset",
                "secrets",
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            original = path.read_bytes()

            second = self.run_cli("init", "--output", str(path), "--listen-port", "19091")
            self.assertEqual(second.returncode, 2)
            self.assertIn("already exists", second.stderr)
            self.assertEqual(path.read_bytes(), original)

            inspected = self.run_cli("inspect", "-c", str(path))
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            report = json.loads(inspected.stdout)
            self.assertEqual(report["server"]["listen_port"], 19090)
            self.assertEqual(report["upstream"]["port"], 9090)
            self.assertEqual(report["policy"]["allowed_hosts"], ["example.test"])
            self.assertEqual(report["policy"]["allowed_methods"], ["GET", "HEAD"])
            self.assertEqual(
                [route["path"] for route in report["policy"]["honeypot"]["routes"]],
                ["/.env", "/.git/HEAD", "/.git/config", "/.svn/entries"],
            )

    def test_init_cli_can_disable_honeypot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            result = self.run_cli("init", "--output", str(path), "--no-honeypot")
            self.assertEqual(result.returncode, 0, result.stderr)
            config = load_config(path)
            self.assertFalse(config.policy.honeypot.enabled)
            self.assertEqual(config.policy.honeypot.routes, ())

    def test_init_base_merges_explicit_fields_and_preserves_custom_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = write_initial_config(base / "config.json", self.build(base))
            data = json.loads(path.read_text("utf-8"))
            data["upstream"]["connect_timeout"] = 4.5
            data["policy"]["routes"] = [
                {
                    "path_prefix": "/api/private",
                    "methods": ["GET"],
                    "read_only": True,
                }
            ]
            data["policy"]["response_scan_mode"] = "detect"
            data["policy"]["security_headers"] = {"X-Audit-Marker": "keep-me"}
            data["rate_limit"] = {
                "enabled": True,
                "per_ip_rate": 7.5,
                "per_ip_burst": 9,
                "global_rate": 111.0,
                "global_burst": 222,
                "max_tracked_clients": 333,
                "client_idle_ttl": 44.0,
                "auto_ban_threshold": 5,
                "auto_ban_window": 6.0,
                "auto_ban_seconds": 7.0,
                "max_ban_entries": 16,
            }
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

            merged = self.run_cli(
                "init",
                "--base",
                str(path),
                "--force",
                "--listen-port",
                "19123",
            )
            self.assertEqual(merged.returncode, 0, merged.stderr)
            config = load_config(path)

        self.assertEqual(config.server.listen_port, 19123)
        self.assertEqual(config.upstream.port, 8080)
        self.assertEqual(config.upstream.connect_timeout, 4.5)
        self.assertEqual(config.policy.allowed_hosts, ("example.test",))
        self.assertEqual(config.policy.response_scan_mode, "detect")
        self.assertEqual(len(config.policy.routes), 1)
        self.assertEqual(config.policy.routes[0].path_prefix, "/api/private")
        self.assertTrue(config.policy.routes[0].read_only)
        self.assertEqual(dict(config.policy.security_headers)["X-Audit-Marker"], "keep-me")
        self.assertEqual(config.rate_limit.per_ip_rate, 7.5)
        self.assertEqual(config.rate_limit.max_ban_entries, 16)

    def test_init_base_failure_leaves_original_file_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = write_initial_config(base / "config.json", self.build(base))
            original = path.read_bytes()
            result = self.run_cli(
                "init",
                "--base",
                str(path),
                "--force",
                "--listen-port",
                "0",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("server.listen_port", result.stderr)
            self.assertEqual(path.read_bytes(), original)

    def test_init_base_rejects_move_with_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "source"
            target_dir = root / "target"
            source_dir.mkdir()
            target_dir.mkdir()
            source = write_initial_config(source_dir / "config.json", self.build(source_dir))
            target = target_dir / "config.json"

            result = self.run_cli(
                "init",
                "--base",
                str(source),
                "--output",
                str(target),
                "--force",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("relative paths", result.stderr)
            self.assertIn("audit.path", result.stderr)
            self.assertFalse(target.exists())

            allowed_target = target_dir / "allowed.json"
            allowed = self.run_cli(
                "init",
                "--base",
                str(source),
                "--output",
                str(allowed_target),
                "--audit-path",
                str(target_dir / "audit.jsonl"),
                "--force",
            )
            self.assertEqual(allowed.returncode, 0, allowed.stderr)
            self.assertEqual(
                load_config(allowed_target).audit.path,
                (target_dir / "audit.jsonl").resolve(),
            )

    def test_inspect_reports_effective_limits_headers_and_circuit_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = write_initial_config(base / "config.json", self.build(base))
            result = self.run_cli("inspect", "-c", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)

        self.assertIn("header_timeout", report["server"])
        self.assertIn("min_version", report["server"]["tls"])
        self.assertIn("cert_file", report["server"]["tls"])
        self.assertIn("key_file", report["server"]["tls"])
        self.assertIn("connect_timeout", report["upstream"])
        self.assertTrue(report["upstream"]["circuit_breaker"]["enabled"])
        self.assertIn("sqli", report["policy"]["waf_rules"])
        self.assertIn("Content-Security-Policy", report["policy"]["security_headers"])
        self.assertGreater(report["policy"]["max_request_line"], 0)
        self.assertGreater(report["policy"]["response_scan_max_bytes"], 0)
        self.assertIn("global_rate", report["rate_limit"])
        self.assertIn("max_ban_entries", report["rate_limit"])
        self.assertIn("include_client_ip", report["audit"])
        self.assertIn("audit_tail_max_lines", report["admin"])
        for route in report["policy"]["honeypot"]["routes"]:
            self.assertNotIn("body", route)


if __name__ == "__main__":
    unittest.main()
