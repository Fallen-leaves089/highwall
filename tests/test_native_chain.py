from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE_DIR = ROOT / "subprojects" / "native-core"
L4WALL_DIR = ROOT / "subprojects" / "l4wall"
CHAIN_RUN_ENV = "HIGHWALL_RUN_NATIVE_CHAIN"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, process: subprocess.Popen[bytes], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate(timeout=1)
            raise AssertionError(f"process exited before listening on {port}: {stderr.decode(errors='replace')}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"process did not listen on {port}")


def wait_for_text(path: Path, needle: str, timeout: float = 3.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        if needle in text:
            return text
        time.sleep(0.02)
    raise AssertionError(f"file {path} never contained {needle!r}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def native_binary() -> Path | None:
    configured = os.environ.get("HIGHWALL_NATIVE_CORE_BIN")
    if configured:
        path = Path(configured).resolve()
        if not path.is_file():
            raise AssertionError(f"HIGHWALL_NATIVE_CORE_BIN does not exist: {path}")
        return path
    if os.environ.get(CHAIN_RUN_ENV) != "1":
        return None
    if shutil.which("cargo") is None:
        return None
    subprocess.run(
        ["cargo", "build", "--quiet", "--bin", "highwall-native-core"],
        cwd=NATIVE_DIR,
        check=True,
        timeout=300,
    )
    suffix = ".exe" if os.name == "nt" else ""
    return NATIVE_DIR / "target" / "debug" / f"highwall-native-core{suffix}"


class ChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        binary = native_binary()
        if binary is None:
            raise unittest.SkipTest(
                f"set {CHAIN_RUN_ENV}=1 or HIGHWALL_NATIVE_CORE_BIN to run the native chain test"
            )
        cls.binary = binary

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.processes: list[subprocess.Popen[bytes]] = []
        self.upstream_records: list[dict[str, str]] = []
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.upstream.daemon_threads = True
        self.upstream_thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.upstream_thread.start()

    def tearDown(self) -> None:
        for process in reversed(self.processes):
            stop_process(process)
        self.upstream.shutdown()
        self.upstream.server_close()
        self.upstream_thread.join(timeout=3)
        self.temp.cleanup()

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        records = self.upstream_records

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                records.append({name.lower(): value for name, value in self.headers.items()})
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *args: object) -> None:
                return

        return Handler

    def test_l4wall_proxy_v2_reaches_native_core_and_direct_bypass_fails(self) -> None:
        native_port = free_port()
        l4wall_port = free_port()
        native_audit = self.directory / "native-audit.jsonl"
        l4wall_audit = self.directory / "l4wall-audit.jsonl"

        native_config = json.loads((NATIVE_DIR / "config.example.json").read_text(encoding="utf-8"))
        native_config["listen"]["port"] = native_port
        native_config["listen"]["proxy_protocol"] = {
            "mode": "required",
            "trusted_proxy_networks": ["127.0.0.1/32"],
            "header_timeout_ms": 1000,
        }
        native_config["upstream"]["port"] = int(self.upstream.server_address[1])
        native_config["upstream"]["set_forwarded_for"] = True
        native_config["audit"]["path"] = str(native_audit)
        native_config["agent"]["enabled"] = False
        native_config["bans"]["enabled"] = False
        native_config_path = self.directory / "native.json"
        native_config_path.write_text(json.dumps(native_config), encoding="utf-8")

        l4wall_config = json.loads((L4WALL_DIR / "config.example.json").read_text(encoding="utf-8"))
        listener = l4wall_config["listeners"][0]
        listener.update(
            {
                "listen_port": l4wall_port,
                "upstream_host": "127.0.0.1",
                "upstream_port": native_port,
                "allowed_client_networks": ["127.0.0.0/8"],
                "denied_client_networks": [],
                "send_proxy_v2": True,
            }
        )
        l4wall_config["listeners"] = [listener]
        l4wall_config["threat_detection"]["enabled"] = False
        l4wall_config["audit"]["path"] = str(l4wall_audit)
        l4wall_config["metrics"]["enabled"] = False
        l4wall_config["admin"]["enabled"] = False
        l4wall_config_path = self.directory / "l4wall.json"
        l4wall_config_path.write_text(json.dumps(l4wall_config), encoding="utf-8")

        native = subprocess.Popen(
            [str(self.binary), "--config", str(native_config_path)],
            cwd=NATIVE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.processes.append(native)
        wait_for_port(native_port, native)

        l4wall = subprocess.Popen(
            [sys.executable, "-m", "l4wall", "run", "--config", str(l4wall_config_path)],
            cwd=L4WALL_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.processes.append(l4wall)
        wait_for_port(l4wall_port, l4wall)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.bind(("127.0.0.2", 0))
            client.settimeout(5)
            client.connect(("127.0.0.1", l4wall_port))
            client.sendall(b"GET /chain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            response = bytearray()
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)

        self.assertIn(b"200 OK", response)
        self.assertTrue(response.endswith(b"ok"))
        self.assertEqual(len(self.upstream_records), 1)
        self.assertEqual(self.upstream_records[0].get("x-forwarded-for"), "127.0.0.2")
        wait_for_text(native_audit, '"peer":"127.0.0.2:')
        wait_for_text(l4wall_audit, '"event":"connection_allowed"')

        with socket.create_connection(("127.0.0.1", native_port), timeout=3) as bypass:
            bypass.sendall(b"GET /bypass HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            bypass.settimeout(2)
            try:
                bypass_response = bypass.recv(4096)
            except (ConnectionResetError, socket.timeout):
                bypass_response = b""
        self.assertNotIn(b"200 OK", bypass_response)
        wait_for_text(native_audit, "HW-NATIVE-PROXY-001")
        self.assertEqual(len(self.upstream_records), 1)


if __name__ == "__main__":
    unittest.main()
