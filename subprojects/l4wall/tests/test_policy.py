from __future__ import annotations

import ipaddress
import unittest

from l4wall.policy import SourcePolicy, normalize_ip


class PolicyTests(unittest.TestCase):
    def test_ipv4_mapped_address_is_unmapped(self) -> None:
        self.assertEqual(normalize_ip("::ffff:127.0.0.1"), ipaddress.ip_address("127.0.0.1"))

    def test_empty_allow_list_allows_unless_denied(self) -> None:
        policy = SourcePolicy((), (ipaddress.ip_network("10.0.0.0/8"),))
        self.assertEqual(policy.evaluate(ipaddress.ip_address("192.0.2.1")), (True, "allowed"))
        self.assertEqual(policy.evaluate(ipaddress.ip_address("10.1.2.3")), (False, "source_denied"))

    def test_explicit_allow_list_is_default_deny(self) -> None:
        policy = SourcePolicy((ipaddress.ip_network("192.0.2.0/24"),), ())
        self.assertEqual(policy.evaluate(ipaddress.ip_address("192.0.2.9")), (True, "allowed"))
        self.assertEqual(policy.evaluate(ipaddress.ip_address("198.51.100.9")), (False, "source_not_allowed"))

    def test_deny_wins_over_allow(self) -> None:
        policy = SourcePolicy(
            (ipaddress.ip_network("192.0.2.0/24"),),
            (ipaddress.ip_network("192.0.2.128/25"),),
        )
        self.assertEqual(policy.evaluate(ipaddress.ip_address("192.0.2.200")), (False, "source_denied"))


if __name__ == "__main__":
    unittest.main()

