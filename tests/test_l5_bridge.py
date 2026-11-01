"""Loopback acceptance for the B+D-1 TLS-to-HighWall bridge."""

from __future__ import annotations

import socket
import ssl
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
L5_ROOT = ROOT / "subprojects" / "l5wall"
for _path in (L5_ROOT,):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from l5wall.config import load_config  # noqa: E402
from l5wall.proxy import L5ProxyServer  # noqa: E402
from test_certificates import ensure_test_material  # noqa: E402

from tests.support import GatewayHarness, StubUpstream, base_config, parse_response  # noqa: E402


class L5BridgeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        ensure_test_material(L5_ROOT / "tests" / "fixtures")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stub = StubUpstream()
        self.stub.__enter__()
        self.addCleanup(self.stub.__exit__, None, None, None)
        config = base_config(
            Path(self.temp.name),
            self.stub.port,
            overrides={"policy": {"allowed_hosts": ["localhost"]}},
        )
        self.gateway = GatewayHarness(config)
        self.gateway.__enter__()
        self.addCleanup(self.gateway.__exit__, None, None, None)
        l5_config = load_config(L5_ROOT / "config.example.json")
        self.l5 = L5ProxyServer(
            replace(
                l5_config,
                listen_port=0,
                upstream_port=self.gateway.port,
                connect_timeout=1.0,
                idle_timeout=3.0,
                handshake_timeout=2.0,
            )
        )
        self.l5.bind()
        self.l5_thread = threading.Thread(target=self.l5.serve_forever, daemon=True)
        self.l5_thread.start()
        self.addCleanup(self._stop_l5)

    def _stop_l5(self) -> None:
        self.l5.stop()
        self.l5_thread.join(timeout=3.0)

    def test_allowed_h1_request_crosses_tls_bridge_and_reaches_highwall(self) -> None:
        response = self._request(b"GET /ok HTTP/1.1\r\nHost: localhost\r\n\r\n")

        status, _headers, body = parse_response(response)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from upstream")
        self.assertEqual(len(self.stub.state.snapshot()), 1)

    def test_sni_host_mismatch_never_reaches_highwall_or_upstream(self) -> None:
        response = self._request(b"GET /ok HTTP/1.1\r\nHost: wrong.test\r\n\r\n", allow_error=True)

        self.assertFalse(response.startswith(b"HTTP/1.1"))
        self.assertEqual(self.stub.state.snapshot(), [])

    def test_unknown_alpn_never_reaches_highwall_or_upstream(self) -> None:
        response = self._request(
            b"GET /ok HTTP/1.1\r\nHost: localhost\r\n\r\n",
            alpn=["h2"],
            allow_error=True,
        )

        self.assertFalse(response.startswith(b"HTTP/1.1"))
        self.assertEqual(self.stub.state.snapshot(), [])

    def _request(
        self,
        payload: bytes,
        *,
        alpn: list[str] | None = None,
        allow_error: bool = False,
    ) -> bytes:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(alpn or ["http/1.1"])
        try:
            raw = socket.create_connection(("127.0.0.1", self.l5.address[1]), timeout=3.0)
            with context.wrap_socket(raw, server_hostname="localhost") as client:
                client.settimeout(3.0)
                client.sendall(payload)
                chunks = bytearray()
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    chunks.extend(chunk)
                return bytes(chunks)
        except (ssl.SSLError, OSError):
            if allow_error:
                return b""
            raise


if __name__ == "__main__":
    unittest.main()
