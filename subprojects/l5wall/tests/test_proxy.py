from __future__ import annotations

import socket
import ssl
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from l5wall.config import load_config
from l5wall.proxy import L5ProxyError, L5ProxyServer, _relay, _validate_request_head
from test_certificates import ensure_test_material

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def setUpModule() -> None:
    ensure_test_material(FIXTURES)


class _Upstream:
    def __init__(
        self, response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    ) -> None:
        self.response = response
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = int(self.listener.getsockname()[1])
        self.accepted = 0
        self.received: list[bytes] = []
        self._stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self._stopped.set()
        self.listener.close()
        self.thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            try:
                connection.settimeout(2.0)
                data = bytearray()
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                self.received.append(bytes(data))
                connection.sendall(self.response)
            except OSError:
                pass
            finally:
                connection.close()


class ProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(ROOT / "config.example.json")

    def test_valid_http1_request_reaches_upstream_and_returns_response(self) -> None:
        upstream = _Upstream()
        upstream.start()
        server, thread = self._start_server(upstream.port)
        try:
            response = self._request(
                server.address[1],
                b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
        finally:
            server.stop()
            thread.join(timeout=3.0)
            upstream.close()

        self.assertIn(b"200 OK", response)
        self.assertEqual(upstream.accepted, 1)
        self.assertEqual(upstream.received[0], b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

    def test_sni_host_mismatch_is_rejected_before_upstream(self) -> None:
        upstream = _Upstream()
        upstream.start()
        server, thread = self._start_server(upstream.port)
        try:
            self._request_expect_closed(
                server.address[1],
                b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n",
            )
            time.sleep(0.1)
        finally:
            server.stop()
            thread.join(timeout=3.0)
            upstream.close()

        self.assertEqual(upstream.accepted, 0)

    def test_missing_host_is_rejected_before_upstream(self) -> None:
        upstream = _Upstream()
        upstream.start()
        server, thread = self._start_server(upstream.port)
        try:
            self._request_expect_closed(server.address[1], b"GET / HTTP/1.1\r\n\r\n")
            time.sleep(0.1)
        finally:
            server.stop()
            thread.join(timeout=3.0)
            upstream.close()

        self.assertEqual(upstream.accepted, 0)

    def test_ambiguous_framing_is_rejected_before_upstream(self) -> None:
        upstream = _Upstream()
        upstream.start()
        server, thread = self._start_server(upstream.port)
        try:
            self._request_expect_closed(
                server.address[1],
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\nx",
            )
            time.sleep(0.1)
        finally:
            server.stop()
            thread.join(timeout=3.0)
            upstream.close()

        self.assertEqual(upstream.accepted, 0)

    def test_oversized_request_head_is_rejected_before_upstream(self) -> None:
        upstream = _Upstream()
        upstream.start()
        server, thread = self._start_server(upstream.port, max_request_head_bytes=1024)
        try:
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Long: " + b"a" * 2048 + b"\r\n\r\n"
            self._request_expect_closed(server.address[1], request)
            time.sleep(0.1)
        finally:
            server.stop()
            thread.join(timeout=3.0)
            upstream.close()

        self.assertEqual(upstream.accepted, 0)

    def test_unknown_alpn_is_rejected_by_policy(self) -> None:
        upstream = _Upstream()
        upstream.start()
        server, thread = self._start_server(upstream.port)
        try:
            response = self._request(
                server.address[1],
                b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                alpn=["h2"],
                allow_error=True,
            )
            time.sleep(0.1)
        finally:
            server.stop()
            thread.join(timeout=3.0)
            upstream.close()

        self.assertFalse(response.startswith(b"HTTP/1.1"))
        self.assertEqual(upstream.accepted, 0)

    def test_h2_preface_is_rejected_as_http1(self) -> None:
        with self.assertRaisesRegex(L5ProxyError, "only HTTP/1"):
            _validate_request_head(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "localhost")

    def test_duplicate_host_and_control_characters_are_rejected(self) -> None:
        with self.assertRaisesRegex(L5ProxyError, "exactly one Host"):
            _validate_request_head(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\n\r\n",
                "localhost",
            )
        with self.assertRaisesRegex(L5ProxyError, "header value"):
            _validate_request_head(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: a\x01b\r\n\r\n",
                "localhost",
            )

    def test_invalid_host_authority_is_rejected(self) -> None:
        with self.assertRaisesRegex(L5ProxyError, "Host"):
            _validate_request_head(
                b"GET / HTTP/1.1\r\nHost: localhost;evil\r\n\r\n",
                "localhost",
            )

    def test_host_with_matching_port_is_accepted(self) -> None:
        _validate_request_head(
            b"GET / HTTP/1.1\r\nHost: localhost:443\r\n\r\n",
            "localhost",
        )

    def test_relay_byte_limit_is_enforced(self) -> None:
        left, right = socket.socketpair()
        try:
            left.sendall(b"x" * 2048)
            with self.assertRaisesRegex(L5ProxyError, "byte limit"):
                _relay(right, left, 1.0, 1024)
        finally:
            left.close()
            right.close()

    def test_serve_mode_rejects_non_h1_alpn(self) -> None:
        with self.assertRaisesRegex(ValueError, "http/1.1"):
            L5ProxyServer(replace(self.config, allowed_alpn=("h2",)))

    def _start_server(
        self,
        upstream_port: int,
        **overrides: object,
    ) -> tuple[L5ProxyServer, threading.Thread]:
        config = replace(
            self.config,
            listen_port=0,
            upstream_port=upstream_port,
            connect_timeout=1.0,
            idle_timeout=2.0,
            handshake_timeout=2.0,
            **overrides,
        )
        server = L5ProxyServer(config)
        server.bind()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def _request(
        self,
        port: int,
        request: bytes,
        *,
        alpn: list[str] | None = None,
        allow_error: bool = False,
    ) -> bytes:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(alpn or ["http/1.1"])
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=3.0)
            with context.wrap_socket(raw, server_hostname="localhost") as client:
                client.settimeout(3.0)
                client.sendall(request)
                chunks = bytearray()
                while True:
                    try:
                        chunk = client.recv(4096)
                    except (ssl.SSLError, OSError):
                        if allow_error:
                            break
                        raise
                    if not chunk:
                        break
                    chunks.extend(chunk)
                return bytes(chunks)
        except (ssl.SSLError, OSError):
            if allow_error:
                return b""
            raise

    def _request_expect_closed(self, port: int, request: bytes) -> None:
        response = self._request(port, request, allow_error=True)
        self.assertFalse(response.startswith(b"HTTP/1.1"))


if __name__ == "__main__":
    unittest.main()
