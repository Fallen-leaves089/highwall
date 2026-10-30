"""Bounded JSONL audit log with rotation and fail-closed error signaling."""

from __future__ import annotations

import json
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class AuditWriter:
    def __init__(
        self,
        path: str | Path,
        *,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
        on_write_failure: str = "fail_closed",
        include_client_ip: bool = True,
    ) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.on_write_failure = on_write_failure
        self.include_client_ip = include_client_ip
        self.healthy = True
        self.error_count = 0
        self._file: Any = None
        self._size = 0
        self._open()

    @property
    def fail_closed(self) -> bool:
        return self.on_write_failure == "fail_closed"

    def _open(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = self.path.open("a", encoding="utf-8", newline="\n")
            self._size = self.path.stat().st_size
        except (OSError, ValueError):
            self._file = None
            self._size = 0
            self._fail()

    def _fail(self) -> None:
        self.error_count += 1
        if self.fail_closed:
            self.healthy = False

    def _rotate(self) -> bool:
        if self._file is None:
            return False
        try:
            self._file.close()
            self._file = None
            oldest = self.path.with_name(f"{self.path.name}.{self.backup_count}")
            if oldest.exists():
                oldest.unlink()
            for index in range(self.backup_count - 1, 0, -1):
                source = self.path.with_name(f"{self.path.name}.{index}")
                target = self.path.with_name(f"{self.path.name}.{index + 1}")
                if source.exists():
                    os.replace(source, target)
            if self.path.exists():
                os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
            self._file = self.path.open("a", encoding="utf-8", newline="\n")
            self._size = 0
            return True
        except OSError:
            self._fail()
            self._open()
            return False

    def write(self, event: str, **fields: Any) -> bool:
        payload: dict[str, Any] = {"ts": utc_now_iso(), "event": event}
        if not self.include_client_ip:
            fields.pop("client_ip", None)
        payload.update(fields)
        try:
            line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
        except (TypeError, ValueError):
            self._fail()
            return False
        encoded = len(line.encode("utf-8"))
        if self._file is None:
            self._open()
        if self._file is None:
            return False
        try:
            if self._size + encoded > self.max_bytes and self._size > 0:
                if not self._rotate():
                    return False
            self._file.write(line)
            self._file.flush()
            self._size += encoded
            return True
        except OSError:
            self._fail()
            return False

    def tail(self, lines: int) -> list[str]:
        if lines < 1:
            return []
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as handle:
                return list(deque((line.rstrip("\n") for line in handle), maxlen=lines))
        except OSError:
            return []

    def close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            finally:
                self._file = None

