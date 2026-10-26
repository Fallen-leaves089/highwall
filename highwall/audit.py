"""Bounded JSONL audit logging with fixed fields and no request secrets."""

from __future__ import annotations

import ipaddress
import hashlib
import json
import logging
import os
import re
import stat
import threading
import unicodedata
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AuditConfig

_LOG = logging.getLogger(__name__)
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{0,64}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{0,64}$")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_SENSITIVE_PATH_KEYS = {
    "access_token",
    "apikey",
    "api-key",
    "api_key",
    "auth",
    "authorization",
    "code",
    "credential",
    "invite",
    "key",
    "oauth",
    "password",
    "passwd",
    "private_key",
    "refresh_token",
    "reset",
    "secret",
    "session",
    "sig",
    "signature",
    "token",
}
_HIGH_ENTROPY_SEGMENT_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._~-]{20,}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_label(value: str) -> str:
    return value if _SAFE_TOKEN_RE.fullmatch(value) else "-"


def _redact_path(path: str) -> str:
    segments = path.split("/")
    previous_sensitive = False
    for index, segment in enumerate(segments):
        if not segment:
            continue
        if previous_sensitive:
            segments[index] = "<redacted>"
            previous_sensitive = False
            continue

        parts = segment.split(";")
        for part_index, part in enumerate(parts):
            lowered = part.casefold()
            key, separator, _ = lowered.partition("=")
            if separator and key in _SENSITIVE_PATH_KEYS:
                parts[part_index] = f"{part.split('=', 1)[0]}=<redacted>"
            elif _HIGH_ENTROPY_SEGMENT_RE.fullmatch(part):
                parts[part_index] = "<redacted>"
        segments[index] = ";".join(parts)
        previous_sensitive = any(part.casefold() in _SENSITIVE_PATH_KEYS for part in segment.split(";"))
    return "/".join(segments)


def _decode_path_for_redaction(path: str) -> str:
    current = path
    for _ in range(4):
        decoded = urllib.parse.unquote(current, encoding="utf-8", errors="replace")
        if decoded == current:
            break
        current = decoded
    current = unicodedata.normalize("NFKC", current)
    return "".join(ch if 0x20 <= ord(ch) <= 0x7E else "?" for ch in current)


def _safe_path(value: str, mode: str = "redact") -> str:
    path = value.split("?", 1)[0]
    cleaned = "".join(ch if 0x20 <= ord(ch) <= 0x7E else "?" for ch in path)
    if mode == "hash":
        return "sha256:" + hashlib.sha256(cleaned.encode("utf-8", errors="replace")).hexdigest()
    if mode == "redact":
        cleaned = _redact_path(_decode_path_for_redaction(cleaned))
    return cleaned[:1024]


def _safe_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


@dataclass(frozen=True)
class AuditRecord:
    event: str
    request_id: str = ""
    client_ip: str = ""
    method: str = ""
    path: str = ""
    status: int = 0
    outcome: str = ""
    rule_id: str = ""
    duration_ms: int = 0
    request_bytes: int = 0
    response_bytes: int = 0
    detail: str = ""
    timestamp: str = field(default_factory=_utc_now)

    def as_log_dict(self, include_client_ip: bool = True, path_mode: str = "redact") -> dict[str, Any]:
        data = asdict(self)
        data["event"] = _safe_label(self.event)
        data["outcome"] = _safe_label(self.outcome)
        data["rule_id"] = _safe_label(self.rule_id)
        data["request_id"] = self.request_id if _HEX_RE.fullmatch(self.request_id) else "-"
        data["method"] = self.method if re.fullmatch(r"[A-Z]{1,16}", self.method) else "-"
        data["path"] = _safe_path(self.path, path_mode)
        data["client_ip"] = _safe_ip(self.client_ip) if include_client_ip else ""
        data["detail"] = "".join(ch if 0x20 <= ord(ch) <= 0x7E else "?" for ch in self.detail)[:256]
        data["status"] = int(self.status) if 0 <= int(self.status) <= 599 else 0
        data["duration_ms"] = max(0, min(int(self.duration_ms), 86_400_000))
        data["request_bytes"] = max(0, min(int(self.request_bytes), 2**31 - 1))
        data["response_bytes"] = max(0, min(int(self.response_bytes), 2**31 - 1))
        return data


class AuditLogger:
    """Thread-safe, size-bounded JSONL writer."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self.path: Path = config.path
        self._lock = threading.Lock()
        self.writes_failed = 0
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._check_regular_path()
        self._ensure_file()

    def _check_regular_path(self) -> None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise OSError(f"audit path cannot be inspected: {self.path}") from exc
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(f"audit path must not be a symbolic link: {self.path}")
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"audit path is not a regular file: {self.path}")

    def _open_flags(self) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return flags

    def _ensure_file(self) -> None:
        self._check_regular_path()
        descriptor = os.open(self.path, self._open_flags(), 0o600)
        os.close(descriptor)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _rotate(self) -> None:
        if self.config.backup_count == 0:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self._ensure_file()
            return
        for index in range(self.config.backup_count - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            target = self.path.with_name(f"{self.path.name}.{index + 1}")
            if source.exists():
                try:
                    target.unlink()
                except FileNotFoundError:
                    pass
                os.replace(source, target)
        oldest = self.path.with_name(f"{self.path.name}.1")
        try:
            oldest.unlink()
        except FileNotFoundError:
            pass
        os.replace(self.path, oldest)
        self._ensure_file()

    def write(self, record: AuditRecord) -> bool:
        line = json.dumps(
            record.as_log_dict(self.config.include_client_ip, self.config.path_mode),
            ensure_ascii=True,
            separators=(",", ":"),
        ) + "\n"
        payload = line.encode("utf-8")
        with self._lock:
            try:
                self._check_regular_path()
                try:
                    current_size = self.path.stat().st_size
                except FileNotFoundError:
                    self._ensure_file()
                    current_size = 0
                if current_size > 0 and current_size + len(payload) > self.config.max_bytes:
                    self._rotate()
                descriptor = os.open(self.path, self._open_flags(), 0o600)
                try:
                    os.write(descriptor, payload)
                finally:
                    os.close(descriptor)
                return True
            except OSError as exc:
                self.writes_failed += 1
                _LOG.error("audit write failed (%s)", type(exc).__name__)
                return False

    def tail(self, limit: int) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        max_tail_bytes = min(max(self.config.max_bytes, 1024), 4 * 1024 * 1024)
        try:
            self._check_regular_path()
            with self.path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                start = max(0, size - max_tail_bytes)
                handle.seek(start)
                raw = handle.read(max_tail_bytes)
        except OSError as exc:
            _LOG.error("audit tail failed (%s)", type(exc).__name__)
            return []
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if start > 0 and lines:
            lines = lines[1:]
        result: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                result.append(item)
        return result
