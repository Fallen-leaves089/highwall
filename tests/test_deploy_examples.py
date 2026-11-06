from __future__ import annotations

import ipaddress
import unittest
from pathlib import Path

from highwall.config import load_config

ROOT = Path(__file__).resolve().parents[1]


class StandardDeploymentConfigTests(unittest.TestCase):
    def test_standard_highwall_config_is_valid_and_scoped(self) -> None:
        config = load_config(ROOT / "deploy/standard/highwall/config.json")
        self.assertEqual(config.server.listen_host, "0.0.0.0")
        self.assertEqual(config.server.listen_port, 18090)
        self.assertEqual(config.upstream.host, "172.31.0.30")
        self.assertEqual(config.upstream.port, 18080)
        self.assertEqual(config.policy.allowed_hosts, ("app.internal",))
        self.assertEqual(
            config.policy.proxy_networks,
            (ipaddress.ip_network("172.30.0.10/32"),),
        )
        self.assertEqual(config.policy.max_xff_hops, 2)

    def test_haproxy_sanitizes_forwarded_headers(self) -> None:
        text = (ROOT / "deploy/standard/haproxy/haproxy.cfg").read_text(encoding="utf-8")
        self.assertIn("http-request del-header X-Forwarded-For", text)
        self.assertIn("http-request del-header Forwarded", text)
        self.assertIn("http-request set-header X-Forwarded-For %[src]", text)


class HoneypotDeploymentExampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose_text = (ROOT / "deploy/honeypot/docker-compose.yml").read_text(encoding="utf-8")

    def test_compose_declares_two_internal_networks(self) -> None:
        self.assertEqual(self.compose_text.count("internal: true"), 2)
        self.assertIn("name: highwall-honeypot-ssh", self.compose_text)
        self.assertIn("name: highwall-honeypot-web", self.compose_text)
        self.assertIn("subnet: 172.30.0.0/24", self.compose_text)
        self.assertIn("subnet: 172.31.0.0/24", self.compose_text)

    def test_published_ports_are_loopback_only(self) -> None:
        self.assertIn('- "127.0.0.1:${HONEYPOT_SSH_PORT:-12222}:2222"', self.compose_text)
        self.assertIn('- "127.0.0.1:${HONEYPOT_WEB_PORT:-18080}:8080"', self.compose_text)
        self.assertNotIn('- "0.0.0.0:', self.compose_text)

    def test_services_drop_privileges_and_have_no_host_control(self) -> None:
        self.assertEqual(self.compose_text.count("read_only: true"), 2)
        self.assertEqual(self.compose_text.count("init: true"), 2)
        self.assertEqual(self.compose_text.count("cap_drop:\n      - ALL"), 2)
        self.assertNotIn("privileged: true", self.compose_text)
        self.assertNotIn("network_mode: host", self.compose_text)
        self.assertNotIn("pid: host", self.compose_text)
        self.assertNotIn("docker.sock", self.compose_text)
        self.assertNotIn("\n    volumes:", self.compose_text)

    def test_secret_file_and_verification_helpers_are_documented(self) -> None:
        self.assertTrue((ROOT / "deploy/honeypot/verify.py").is_file())
        self.assertTrue((ROOT / "deploy/honeypot/README.md").is_file())
        self.assertTrue((ROOT / "deploy/honeypot/.env.example").is_file())
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/deploy/honeypot/.env", gitignore)


if __name__ == "__main__":
    unittest.main()
