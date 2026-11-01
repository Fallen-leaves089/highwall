from __future__ import annotations

import contextlib
import io
import json
import socket
import ssl
import threading
import unittest
from pathlib import Path

from l5wall.cli import main
from l5wall.config import load_config
from l5wall.gateway import L5Wall, build_tls_context
from test_certificates import ensure_test_material

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def setUpModule() -> None:
    ensure_test_material(FIXTURES)


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(ROOT / "config.example.json")

    def test_tls_context_uses_configured_minimum_and_alpn(self) -> None:
        context = build_tls_context(self.config)

        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.options & ssl.OP_NO_COMPRESSION)

    def test_tls_handshake_returns_policy_decision_and_echoes(self) -> None:
        wall = L5Wall(self.config)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = int(listener.getsockname()[1])
        result: dict[str, object] = {}

        def serve() -> None:
            try:
                raw, _ = listener.accept()
                connection = wall.wrap(raw)
                result["decision"] = connection.decision.as_public()
                payload = connection.socket.recv(4)
                connection.socket.sendall(b"pong" if payload == b"ping" else b"bad")
                connection.close()
            except BaseException as exc:  # pragma: no cover - reported by assertion below
                result["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        client_context.set_alpn_protocols(["http/1.1"])
        raw = socket.create_connection(("127.0.0.1", port), timeout=2.0)
        with client_context.wrap_socket(raw, server_hostname="localhost") as client:
            self.assertEqual(client.selected_alpn_protocol(), "http/1.1")
            client.sendall(b"ping")
            self.assertEqual(client.recv(4), b"pong")
        thread.join(timeout=2.0)

        self.assertNotIn("error", result, result.get("error"))
        decision = result["decision"]
        assert isinstance(decision, dict)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["metadata"]["sni"], "localhost")

    def test_cli_check_and_inspect_never_emit_private_key_material(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["check", "-c", str(ROOT / "config.example.json")])
        self.assertEqual(code, 0, stderr.getvalue())
        self.assertIn("L5Wall configuration OK", stdout.getvalue())

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["inspect", "-c", str(ROOT / "config.example.json")])
        self.assertEqual(code, 0, stderr.getvalue())
        report = json.loads(stdout.getvalue())
        rendered = json.dumps(report)
        self.assertNotIn("BEGIN PRIVATE KEY", rendered)
        self.assertEqual(report["coverage"]["level"], "C1")
