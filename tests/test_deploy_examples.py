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


if __name__ == "__main__":
    unittest.main()
