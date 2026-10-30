from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from l4wall.audit import AuditWriter


class AuditTests(unittest.TestCase):
    def test_write_and_tail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            writer = AuditWriter(path, include_client_ip=True)
            self.assertTrue(writer.write("connection_allowed", client_ip="127.0.0.1", listener="web"))
            writer.close()
            lines = writer.tail(10)
            self.assertEqual(len(lines), 1)
            event = json.loads(lines[0])
            self.assertEqual(event["event"], "connection_allowed")
            self.assertEqual(event["client_ip"], "127.0.0.1")

    def test_client_ip_can_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            writer = AuditWriter(path, include_client_ip=False)
            writer.write("connection_allowed", client_ip="127.0.0.1")
            writer.close()
            event = json.loads(writer.tail(1)[0])
            self.assertNotIn("client_ip", event)

    def test_rotation_keeps_backups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            writer = AuditWriter(path, max_bytes=120, backup_count=2)
            for index in range(20):
                writer.write("event", index=index, padding="x" * 40)
            writer.close()
            self.assertTrue(path.exists())
            self.assertTrue(path.with_name("audit.jsonl.1").exists())

    def test_fail_closed_when_path_is_a_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = AuditWriter(directory, on_write_failure="fail_closed")
            self.assertFalse(writer.healthy)
            self.assertFalse(writer.write("event"))


if __name__ == "__main__":
    unittest.main()

