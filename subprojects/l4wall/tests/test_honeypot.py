from __future__ import annotations

import asyncio
import copy
import dataclasses
import ipaddress
import json
import socket
import tempfile
import unittest
from pathlib import Path

from l4wall.audit import AuditWriter
from l4wall.config import config_to_dict, example_config, parse_config
from l4wall.errors import ConfigError
from l4wall.gateway import Gateway
from l4wall.honeypot_templates import HONEYPOT_TEMPLATES
from l4wall.metrics import Metrics
from l4wall.tracker import BanStore, ThreatTracker


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class HoneypotConfigTests(unittest.TestCase):
    def test_example_contains_valid_honeypots(self) -> None:
        config = parse_config(example_config())
        self.assertEqual([item.name for item in config.honeypots], ["ssh-decoy", "custom-decoy"])
        self.assertEqual(config.honeypots[0].template, "ssh")
        self.assertEqual(config.honeypots[1].template, "custom")
        self.assertEqual(config.honeypots[1].banner, b"220 decoy SMTP ready\r\n")

    def test_template_catalog_is_large_and_unique(self) -> None:
        self.assertGreaterEqual(len(HONEYPOT_TEMPLATES), 28)
        for name in ("ssh", "redis", "mysql", "mqtt", "http", "rdp", "stomp"):
            self.assertIn(name, HONEYPOT_TEMPLATES)

    def test_custom_hex_rule_and_template_override(self) -> None:
        raw = example_config()
        raw["honeypots"] = [
            {
                "name": "custom-hex",
                "listen_port": 18100,
                "template": "redis",
                "banner_hex": "2b52454144590d0a",
                "rules": [
                    {"expect_hex": "50494e47", "reply_hex": "2b504f4e470d0a"},
                ],
                "default_reply_text": "-ERR denied\r\n",
            }
        ]
        config = parse_config(raw)
        honeypot = config.honeypots[0]
        self.assertEqual(honeypot.banner, b"+READY\r\n")
        self.assertEqual(honeypot.rules[0].expect, b"PING")
        self.assertEqual(honeypot.rules[0].reply, b"+PONG\r\n")

    def test_honeypot_port_must_not_conflict_with_listener_or_admin(self) -> None:
        for port in (18080, 18091):
            with self.subTest(port=port):
                raw = example_config()
                raw["honeypots"][0]["listen_port"] = port
                with self.assertRaises(ConfigError):
                    parse_config(raw)

    def test_honeypot_name_and_port_must_be_unique(self) -> None:
        raw = example_config()
        raw["honeypots"][1]["name"] = raw["honeypots"][0]["name"]
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_unknown_template_and_ambiguous_bytes_are_rejected(self) -> None:
        raw = example_config()
        raw["honeypots"][0]["template"] = "not-real"
        with self.assertRaises(ConfigError):
            parse_config(raw)

        raw = example_config()
        raw["honeypots"][1]["banner_hex"] = "00"
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_custom_honeypot_requires_dialogue_content(self) -> None:
        raw = example_config()
        raw["honeypots"] = [{"name": "empty", "listen_port": 18100, "template": "custom"}]
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_high_interaction_backend_is_parsed_without_static_payload(self) -> None:
        raw = example_config()
        raw["honeypots"] = [
            {
                "name": "ssh-live",
                "listen_port": 18100,
                "template": "custom",
                "backend_host": "127.0.0.1",
                "backend_port": 2222,
                "backend_connect_timeout": 1.25,
            }
        ]
        config = parse_config(raw)
        honeypot = config.honeypots[0]
        self.assertEqual(honeypot.backend_host, "127.0.0.1")
        self.assertEqual(honeypot.backend_port, 2222)
        self.assertEqual(honeypot.backend_connect_timeout, 1.25)
        self.assertEqual(honeypot.banner, b"")
        rendered = config_to_dict(config)["honeypots"][0]
        self.assertEqual(rendered["mode"], "backend")
        self.assertEqual(rendered["backend_port"], 2222)

    def test_high_interaction_backend_requires_isolated_address(self) -> None:
        for host in ("8.8.8.8", "169.254.169.254", "0.0.0.0", "ssh.internal"):
            with self.subTest(host=host):
                raw = example_config()
                raw["honeypots"] = [
                    {
                        "name": "ssh-live",
                        "listen_port": 18100,
                        "template": "custom",
                        "backend_host": host,
                        "backend_port": 2222,
                    }
                ]
                with self.assertRaisesRegex(ConfigError, "IP literal"):
                    parse_config(raw)

    def test_high_interaction_backend_rejects_partial_self_and_business_targets(self) -> None:
        raw = example_config()
        raw["honeypots"] = [
            {
                "name": "ssh-live",
                "listen_port": 18100,
                "template": "custom",
                "backend_host": "127.0.0.1",
            }
        ]
        with self.assertRaisesRegex(ConfigError, "set together"):
            parse_config(raw)

        raw = example_config()
        raw["honeypots"] = [
            {
                "name": "ssh-live",
                "listen_port": 18100,
                "template": "custom",
                "backend_host": "127.0.0.1",
                "backend_port": 18100,
            }
        ]
        with self.assertRaisesRegex(ConfigError, "own listener"):
            parse_config(raw)

        raw = example_config()
        business = raw["listeners"][0]
        raw["honeypots"] = [
            {
                "name": "ssh-live",
                "listen_port": 18100,
                "template": "custom",
                "backend_host": business["upstream_host"],
                "backend_port": business["upstream_port"],
            }
        ]
        if business["upstream_host"].startswith("127."):
            with self.assertRaisesRegex(ConfigError, "business upstream"):
                parse_config(raw)

    def test_high_interaction_backend_rejects_local_gateway_targets(self) -> None:
        cases = [
            (18080, "business listener"),
            (18091, "admin listener"),
            (18092, "another honeypot listener"),
        ]
        for port, message in cases:
            with self.subTest(port=port):
                raw = example_config()
                raw["honeypots"].append(
                    {
                        "name": "ssh-live",
                        "listen_port": 18100,
                        "template": "custom",
                        "backend_host": "127.0.0.1",
                        "backend_port": port,
                    }
                )
                with self.assertRaisesRegex(ConfigError, message):
                    parse_config(raw)

    def test_effective_config_does_not_render_payloads(self) -> None:
        raw = example_config()
        raw["honeypots"] = [
            {
                "name": "private-banner",
                "listen_port": 18100,
                "template": "custom",
                "banner_text": "sensitive-banner\r\n",
            }
        ]
        rendered = json.dumps(config_to_dict(parse_config(raw)))
        self.assertNotIn("sensitive-banner", rendered)
        self.assertIn('"banner_bytes": 18', rendered)

    def test_parse_does_not_mutate_input(self) -> None:
        raw = example_config()
        before = copy.deepcopy(raw)
        parse_config(raw)
        self.assertEqual(raw, before)


class HoneypotGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name)
        self.gateway: Gateway | None = None

    async def asyncTearDown(self) -> None:
        if self.gateway is not None:
            await self.gateway.stop()
        self._temp.cleanup()

    async def _start_gateway(
        self,
        *,
        ban_seconds: float = 0,
        backend_host: str | None = None,
        backend_port: int | None = None,
    ) -> tuple[Gateway, AuditWriter, bytes]:
        config = parse_config(example_config())
        listener_port = free_port()
        honeypot_port = free_port()
        while honeypot_port == listener_port:
            honeypot_port = free_port()
        listener = dataclasses.replace(
            config.listeners[0],
            listen_port=listener_port,
            upstream_host="127.0.0.1",
            upstream_port=free_port(),
            allowed_client_networks=(ipaddress.ip_network("127.0.0.1/32"),),
            denied_client_networks=(),
            first_byte_timeout=0.5,
            idle_timeout=0.5,
            max_connection_seconds=2.0,
        )
        honeypot = dataclasses.replace(
            config.honeypots[1],
            listen_port=honeypot_port,
            backend_host=backend_host,
            backend_port=backend_port,
            backend_connect_timeout=0.5,
            allowed_client_networks=(ipaddress.ip_network("127.0.0.1/32"),),
            denied_client_networks=(),
            first_byte_timeout=1.0,
            idle_timeout=1.0,
            max_connection_seconds=2.0,
            ban_seconds=ban_seconds,
        )
        server = dataclasses.replace(
            config.server,
            max_connections=8,
            max_connections_per_ip=4,
            max_honeypot_connections=4,
            shutdown_timeout=1.0,
        )
        threat = dataclasses.replace(
            config.threat,
            offender_path=str(self.directory / "offenders.json"),
            ban_prefix_v4=32,
            ban_prefix_v6=128,
        )
        config = dataclasses.replace(
            config,
            server=server,
            listeners=(listener,),
            honeypots=(honeypot,),
            threat=threat,
        )
        audit = AuditWriter(self.directory / "audit.jsonl")
        bans = BanStore(
            threat.offender_path,
            max_entries=threat.max_ban_entries,
            prefix_v4=threat.ban_prefix_v4,
            prefix_v6=threat.ban_prefix_v6,
        )
        tracker = ThreatTracker(threat, bans)
        gateway = Gateway(config, audit=audit, metrics=Metrics(True), tracker=tracker)
        await gateway.start()
        self.gateway = gateway
        return gateway, audit, honeypot.banner

    async def _wait_for_audit(self, audit: AuditWriter, *needles: str) -> str:
        deadline = asyncio.get_running_loop().time() + 2.0
        while True:
            text = audit.path.read_text(encoding="utf-8") if audit.path.exists() else ""
            if all(needle in text for needle in needles):
                return text
            if asyncio.get_running_loop().time() >= deadline:
                self.fail(f"audit did not contain {needles!r}: {text}")
            await asyncio.sleep(0.02)

    async def test_custom_honeypot_dialogue_is_audited_without_upstream(self) -> None:
        gateway, audit, banner = await self._start_gateway()
        port = gateway.honeypot_ports["custom-decoy"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(banner)), 2.0), banner)
        writer.write(b"HELO scanner\r\n")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2.0), b"250 decoy.internal.invalid\r\n")
        writer.close()
        await writer.wait_closed()

        text = await self._wait_for_audit(audit, '"event":"honeypot_hit"', '"event":"honeypot_closed"')
        self.assertIn('"reason":"honeypot_reply"', text)
        self.assertIn('"listener":"custom-decoy"', text)
        snapshot = gateway.metrics.snapshot()
        self.assertEqual(snapshot["l4wall_honeypot_hits_total"], 1)
        self.assertGreater(snapshot["l4wall_honeypot_bytes_in_total"], 0)
        self.assertGreater(snapshot["l4wall_honeypot_bytes_out_total"], 0)

    async def test_honeypot_hit_can_ban_source_for_all_gateway_ports(self) -> None:
        gateway, audit, banner = await self._start_gateway(ban_seconds=60)
        port = gateway.honeypot_ports["custom-decoy"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(banner)), 2.0), banner)
        writer.close()
        await writer.wait_closed()
        await self._wait_for_audit(audit, '"event":"source_banned"')

        second_reader, second_writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await asyncio.wait_for(second_reader.read(), 2.0), b"")
        second_writer.close()
        await second_writer.wait_closed()
        await self._wait_for_audit(audit, '"event":"honeypot_denied"', '"reason":"banned"')

    async def test_stop_closes_honeypot_listener(self) -> None:
        gateway, _, _ = await self._start_gateway()
        port = gateway.honeypot_ports["custom-decoy"]
        await gateway.stop()
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", port)

    async def test_high_interaction_backend_relays_both_directions(self) -> None:
        async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                writer.write(b"live:" + data)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        backend = await asyncio.start_server(echo, "127.0.0.1", 0)
        async def close_backend() -> None:
            backend.close()
            await backend.wait_closed()

        self.addAsyncCleanup(close_backend)
        backend_port = int(backend.sockets[0].getsockname()[1])
        gateway, audit, _ = await self._start_gateway(
            backend_host="127.0.0.1",
            backend_port=backend_port,
        )
        port = gateway.honeypot_ports["custom-decoy"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"hello scanner\r\n")
        await writer.drain()
        self.assertEqual(
            await asyncio.wait_for(reader.read(), 2.0),
            b"live:hello scanner\r\n",
        )
        writer.close()
        await writer.wait_closed()

        text = await self._wait_for_audit(
            audit,
            '"event":"honeypot_backend_connected"',
            '"event":"honeypot_backend_closed"',
            '"event":"honeypot_closed"',
        )
        self.assertIn('"mode":"backend"', text)
        self.assertNotIn("220 decoy SMTP ready", text)
        snapshot = gateway.metrics.snapshot()
        self.assertEqual(snapshot["l4wall_honeypot_backend_connections_total"], 1)
        self.assertGreater(snapshot["l4wall_honeypot_bytes_in_total"], 0)
        self.assertGreater(snapshot["l4wall_honeypot_bytes_out_total"], 0)

    async def test_high_interaction_backend_failure_is_audited_and_closed(self) -> None:
        gateway, audit, _ = await self._start_gateway(
            backend_host="127.0.0.1",
            backend_port=free_port(),
        )
        port = gateway.honeypot_ports["custom-decoy"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await asyncio.wait_for(reader.read(), 2.0), b"")
        writer.close()
        await writer.wait_closed()

        text = await self._wait_for_audit(
            audit,
            '"event":"honeypot_backend_error"',
            '"event":"honeypot_closed"',
        )
        self.assertIn('"reason":"backend_', text)
        self.assertEqual(
            gateway.metrics.snapshot()["l4wall_honeypot_backend_errors_total"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
