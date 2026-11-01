from __future__ import annotations

import ipaddress
import struct
import unittest

from l4wall.proxy_protocol import SIGNATURE, encode_proxy_v2


class ProxyProtocolTests(unittest.TestCase):
    def test_ipv4_header_contains_source_and_destination(self) -> None:
        header = encode_proxy_v2(
            "203.0.113.7",
            51_234,
            ("127.0.0.1", 18443),
        )
        self.assertEqual(header[:12], SIGNATURE)
        self.assertEqual(header[12:14], bytes((0x21, 0x11)))
        self.assertEqual(struct.unpack("!H", header[14:16])[0], 12)
        self.assertEqual(header[16:20], ipaddress.ip_address("203.0.113.7").packed)
        self.assertEqual(header[20:24], ipaddress.ip_address("127.0.0.1").packed)
        self.assertEqual(struct.unpack("!HH", header[24:28]), (51_234, 18443))

    def test_ipv6_header_is_family_correct(self) -> None:
        header = encode_proxy_v2("2001:db8::7", 443)
        self.assertEqual(header[12:14], bytes((0x21, 0x21)))
        self.assertEqual(struct.unpack("!H", header[14:16])[0], 36)
        self.assertEqual(header[16:32], ipaddress.ip_address("2001:db8::7").packed)
        self.assertEqual(header[32:48], ipaddress.ip_address("::").packed)
        self.assertEqual(struct.unpack("!HH", header[48:52]), (443, 0))

    def test_destination_family_mismatch_uses_unspecified_address(self) -> None:
        header = encode_proxy_v2("203.0.113.7", 1234, ("2001:db8::1", 443))
        self.assertEqual(header[20:24], b"\x00\x00\x00\x00")
        self.assertEqual(struct.unpack("!HH", header[24:28]), (1234, 0))

    def test_invalid_source_and_port_are_rejected(self) -> None:
        for source, port in (
            ("0.0.0.0", 1234),
            ("::", 1234),
            ("203.0.113.7", 0),
            ("203.0.113.7", 65536),
            ("not-an-address", 1234),
        ):
            with self.subTest(source=source, port=port):
                with self.assertRaises(ValueError):
                    encode_proxy_v2(source, port)


if __name__ == "__main__":
    unittest.main()
