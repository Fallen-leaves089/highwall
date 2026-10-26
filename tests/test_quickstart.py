from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from highwall.config import load_config
from tests.support import free_port

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "quickstart.ps1"
POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell")


def _free_distinct_ports(count: int) -> list[int]:
    ports: list[int] = []
    while len(ports) < count:
        candidate = free_port()
        if candidate not in ports:
            ports.append(candidate)
    return ports


def _http_status(port: int, host_header: str, path: str = "/") -> int:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        connection.sendall(request)
        chunks: list[bytes] = []
        while sum(len(chunk) for chunk in chunks) < 4096:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
    response = b"".join(chunks)
    parts = response.split(b" ", 2)
    if len(parts) < 2:
        raise AssertionError(f"incomplete response: {response!r}")
    return int(parts[1])


@unittest.skipUnless(
    os.name == "nt" and POWERSHELL is not None and SCRIPT.exists(),
    "Windows PowerShell quickstart integration test",
)
class QuickstartIntegrationTests(unittest.TestCase):
    def run_script(
        self,
        runtime: Path,
        *args: str,
        timeout: int = 45,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            str(POWERSHELL),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            "-RuntimeDir",
            str(runtime),
        ]
        command.extend(args)
        return subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
        )

    def test_start_drift_reconfigure_and_stop(self) -> None:
        listen_port, upstream_port, new_listen_port, new_upstream_port = _free_distinct_ports(4)
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime with spaces"
            config_path = runtime / "config.json"
            try:
                started = self.run_script(
                    runtime,
                    "-ListenPort",
                    str(listen_port),
                    "-UpstreamUrl",
                    f"http://127.0.0.1:{upstream_port}",
                    "-AllowedHost",
                    "smoke.test",
                    "-WithDemoUpstream",
                )
                self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
                self.assertIn("HighWall ready.", started.stdout)

                config = load_config(config_path)
                self.assertEqual(config.server.listen_port, listen_port)
                self.assertEqual(config.upstream.port, upstream_port)
                self.assertEqual(config.server.max_inflight_requests, 32)
                self.assertTrue(config.upstream.circuit_breaker.enabled)
                self.assertEqual(len(config.policy.honeypot.routes), 18)

                self.assertEqual(_http_status(listen_port, "not-allowed.invalid"), 403)
                self.assertEqual(_http_status(listen_port, "smoke.test"), 200)
                self.assertEqual(_http_status(listen_port, "smoke.test", "/.env"), 200)
                audit = (runtime / "audit.jsonl").read_text("utf-8")
                self.assertIn('"event":"request_blocked"', audit)
                self.assertIn('"event":"honeypot_hit"', audit)

                status = self.run_script(runtime, "-Status", timeout=15)
                self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
                self.assertIn("HighWall status: running", status.stdout)
                self.assertIn("configuration changed since start: False", status.stdout)

                original = config_path.read_bytes()
                drift = self.run_script(
                    runtime,
                    "-ListenPort",
                    str(new_listen_port),
                    timeout=15,
                )
                self.assertEqual(drift.returncode, 2, drift.stdout + drift.stderr)
                self.assertIn("does not match effective port", drift.stdout)
                self.assertEqual(config_path.read_bytes(), original)

                running_reconfigure = self.run_script(
                    runtime,
                    "-Reconfigure",
                    "-ListenPort",
                    str(new_listen_port),
                    timeout=15,
                )
                self.assertEqual(
                    running_reconfigure.returncode,
                    2,
                    running_reconfigure.stdout + running_reconfigure.stderr,
                )
                self.assertIn("stop it before using -Reconfigure", running_reconfigure.stdout)
                self.assertEqual(config_path.read_bytes(), original)

                stopped = self.run_script(runtime, "-Stop", timeout=20)
                self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
                self.assertIn("Stopped HighWall.", stopped.stdout)
                stopped_status = self.run_script(runtime, "-Status", timeout=15)
                self.assertEqual(stopped_status.returncode, 1)

                custom = json.loads(config_path.read_text("utf-8"))
                custom["upstream"]["connect_timeout"] = 4.5
                custom["policy"]["routes"] = [
                    {
                        "path_prefix": "/api/private",
                        "methods": ["GET"],
                        "read_only": True,
                    }
                ]
                custom["policy"]["response_scan_mode"] = "detect"
                custom["policy"]["security_headers"] = {"X-Audit-Marker": "preserve-me"}
                custom["rate_limit"] = {"per_ip_rate": 7.5}
                config_path.write_text(json.dumps(custom, indent=2) + "\n", encoding="utf-8")
                custom_bytes = config_path.read_bytes()

                reconfigured = self.run_script(
                    runtime,
                    "-Reconfigure",
                    "-ListenPort",
                    str(new_listen_port),
                    "-UpstreamUrl",
                    f"http://127.0.0.1:{new_upstream_port}",
                    "-AllowedHost",
                    "new.smoke.test",
                    "-HoneypotPresets",
                    "secrets",
                    "-WithDemoUpstream",
                )
                self.assertEqual(
                    reconfigured.returncode,
                    0,
                    reconfigured.stdout + reconfigured.stderr,
                )
                self.assertIn("Existing configuration backed up", reconfigured.stdout)
                backups = list(runtime.glob("config.json.bak.*"))
                self.assertEqual(len(backups), 1)
                self.assertEqual(
                    hashlib.sha256(backups[0].read_bytes()).hexdigest(),
                    hashlib.sha256(custom_bytes).hexdigest(),
                )
                new_config = load_config(config_path)
                self.assertEqual(new_config.server.listen_port, new_listen_port)
                self.assertEqual(new_config.upstream.port, new_upstream_port)
                self.assertEqual(new_config.upstream.connect_timeout, 4.5)
                self.assertEqual(new_config.policy.allowed_hosts, ("new.smoke.test",))
                self.assertEqual(new_config.policy.response_scan_mode, "detect")
                self.assertEqual(len(new_config.policy.routes), 1)
                self.assertEqual(new_config.policy.routes[0].path_prefix, "/api/private")
                self.assertEqual(
                    dict(new_config.policy.security_headers)["X-Audit-Marker"],
                    "preserve-me",
                )
                self.assertEqual(new_config.rate_limit.per_ip_rate, 7.5)
                self.assertEqual(
                    [route.path for route in new_config.policy.honeypot.routes],
                    ["/.env", "/.git/HEAD", "/.git/config", "/.svn/entries"],
                )
                self.assertEqual(_http_status(new_listen_port, "new.smoke.test"), 200)
            finally:
                self.run_script(runtime, "-Stop", timeout=20)

    def test_status_detects_configuration_changed_after_start(self) -> None:
        listen_port, upstream_port = _free_distinct_ports(2)
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime with spaces"
            config_path = runtime / "config.json"
            try:
                started = self.run_script(
                    runtime,
                    "-ListenPort",
                    str(listen_port),
                    "-UpstreamUrl",
                    f"http://127.0.0.1:{upstream_port}",
                    "-AllowedHost",
                    "changed.test",
                    "-WithDemoUpstream",
                )
                self.assertEqual(started.returncode, 0, started.stdout + started.stderr)

                data = json.loads(config_path.read_text("utf-8"))
                data["policy"]["response_scan_mode"] = "detect"
                config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

                status = self.run_script(runtime, "-Status", timeout=15)
                output = status.stdout + status.stderr
                self.assertEqual(status.returncode, 1, output)
                self.assertIn("configuration changed since start: True", output)
                self.assertIn("has not reloaded", output)

                reused = self.run_script(runtime, timeout=15)
                output = reused.stdout + reused.stderr
                self.assertEqual(reused.returncode, 2, output)
                self.assertIn("configuration changed after HighWall started", output)
            finally:
                self.run_script(runtime, "-Stop", timeout=20)

    def test_unreachable_upstream_is_not_reported_ready(self) -> None:
        listen_port, upstream_port = _free_distinct_ports(2)
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime with spaces"
            try:
                result = self.run_script(
                    runtime,
                    "-ListenPort",
                    str(listen_port),
                    "-UpstreamUrl",
                    f"http://127.0.0.1:{upstream_port}",
                    "-AllowedHost",
                    "dead-upstream.test",
                )
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 2, output)
                self.assertIn("Upstream connection check failed", output)
                self.assertNotIn("HighWall ready.", output)
            finally:
                self.run_script(runtime, "-Stop", timeout=20)

    def test_reconfigure_preserves_omitted_deployment_fields(self) -> None:
        listen_port, upstream_port, new_listen_port = _free_distinct_ports(3)
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime with spaces"
            config_path = runtime / "config.json"
            try:
                started = self.run_script(
                    runtime,
                    "-ListenPort",
                    str(listen_port),
                    "-UpstreamUrl",
                    f"http://127.0.0.1:{upstream_port}",
                    "-AllowedHost",
                    "preserve.test",
                    "-HoneypotPresets",
                    "secrets",
                    "-WithDemoUpstream",
                )
                self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
                stopped = self.run_script(runtime, "-Stop", timeout=20)
                self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)

                reconfigured = self.run_script(
                    runtime,
                    "-Reconfigure",
                    "-ListenPort",
                    str(new_listen_port),
                    "-WithDemoUpstream",
                )
                output = reconfigured.stdout + reconfigured.stderr
                self.assertEqual(reconfigured.returncode, 0, output)
                self.assertIn("unspecified settings preserved", output)

                config = load_config(config_path)
                self.assertEqual(config.server.listen_port, new_listen_port)
                self.assertEqual(config.upstream.port, upstream_port)
                self.assertEqual(config.policy.allowed_hosts, ("preserve.test",))
                self.assertEqual(
                    [route.path for route in config.policy.honeypot.routes],
                    ["/.env", "/.git/HEAD", "/.git/config", "/.svn/entries"],
                )
                self.assertEqual(_http_status(new_listen_port, "preserve.test"), 200)
            finally:
                self.run_script(runtime, "-Stop", timeout=20)


if __name__ == "__main__":
    unittest.main()
