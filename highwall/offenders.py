"""Bounded, persistent attacker marks for HighWall.

Only derived fingerprints, counters, signal names and coarse source prefixes are
stored.  Raw request paths, bodies, cookies and authorization values never enter
this file.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .config import ConfigError

_LOG = logging.getLogger(__name__)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_MAX_STATE_BYTES = 8 * 1024 * 1024
_STATE_VERSION = 1
_TAGS = {"suspected_fast_attack", "confirmed_fast_attack"}


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class OffenderRecord:
    fingerprint: str
    shape_fingerprint: str
    tag: str
    confidence: str
    score: int
    signals: tuple[str, ...]
    first_seen: float
    last_seen: float
    expires_at: float
    hits: int
    action: str
    source_prefix: str = ""
    client_ip: str = ""

    def as_public(self, *, include_client_ip: bool = False) -> dict[str, Any]:
        data = asdict(self)
        data["signals"] = list(self.signals)
        data["first_seen"] = _iso(self.first_seen)
        data["last_seen"] = _iso(self.last_seen)
        data["expires_at"] = _iso(self.expires_at)
        if not include_client_ip:
            data.pop("client_ip", None)
        return data


@dataclass(frozen=True)
class OffenderMatch:
    record: OffenderRecord
    exact: bool


def _parse_record(value: Any) -> OffenderRecord:
    if not isinstance(value, dict):
        raise ConfigError("offender state contains a non-object record")
    allowed = {
        "fingerprint",
        "shape_fingerprint",
        "tag",
        "confidence",
        "score",
        "signals",
        "first_seen",
        "last_seen",
        "expires_at",
        "hits",
        "action",
        "source_prefix",
        "client_ip",
    }
    if set(value) - allowed:
        raise ConfigError("offender state contains unknown fields")
    try:
        fingerprint = str(value["fingerprint"])
        shape = str(value["shape_fingerprint"])
        tag = str(value["tag"])
        confidence = str(value["confidence"])
        signals = tuple(str(item) for item in value.get("signals", []))
        first_seen = float(value["first_seen"])
        last_seen = float(value["last_seen"])
        expires_at = float(value["expires_at"])
        hits = int(value["hits"])
        action = str(value["action"])
        source_prefix = str(value.get("source_prefix", ""))
        client_ip = str(value.get("client_ip", ""))
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError("offender state contains an invalid record") from exc
    if len(fingerprint) != 32 or any(ch not in "0123456789abcdef" for ch in fingerprint):
        raise ConfigError("offender state contains an invalid fingerprint")
    if len(shape) != 32 or any(ch not in "0123456789abcdef" for ch in shape):
        raise ConfigError("offender state contains an invalid shape fingerprint")
    if tag not in _TAGS:
        raise ConfigError("offender state contains an unknown tag")
    if confidence not in {"suspected", "confirmed"}:
        raise ConfigError("offender state contains an invalid confidence")
    if not 0 <= hits <= 2**31 - 1 or not 0 <= int(value["score"]) <= 100:
        raise ConfigError("offender state contains an out-of-range counter")
    if action not in {"monitor", "throttle", "tarpit", "block"}:
        raise ConfigError("offender state contains an invalid action")
    return OffenderRecord(
        fingerprint=fingerprint,
        shape_fingerprint=shape,
        tag=tag,
        confidence=confidence,
        score=int(value["score"]),
        signals=signals[:32],
        first_seen=first_seen,
        last_seen=last_seen,
        expires_at=expires_at,
        hits=hits,
        action=action,
        source_prefix=source_prefix[:64],
        client_ip=client_ip[:64],
    )


class OffenderRegistry:
    """Thread-safe, capacity-bounded and TTL-bounded attacker mark store."""

    def __init__(
        self,
        path: Path,
        *,
        max_entries: int,
        ttl_seconds: float,
        include_client_ip: bool = False,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.path = path
        self.max_entries = int(max_entries)
        self.ttl_seconds = float(ttl_seconds)
        self.include_client_ip = bool(include_client_ip)
        self._clock = clock
        self._lock = threading.Lock()
        self._records: dict[str, OffenderRecord] = {}
        self._load()

    def _check_path(self) -> None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ConfigError("offender state path cannot be inspected") from exc
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise ConfigError("offender state path must not be a symbolic link or reparse point")
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("offender state path is not a regular file")
        if info.st_size > _MAX_STATE_BYTES:
            raise ConfigError("offender state file is too large")

    def _load(self) -> None:
        self._check_path()
        if not self.path.exists():
            return
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise ConfigError("offender state cannot be read") from exc
        if len(raw) > _MAX_STATE_BYTES:
            raise ConfigError("offender state file is too large")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigError("offender state is not valid JSON") from exc
        if not isinstance(data, dict) or data.get("version") != _STATE_VERSION:
            raise ConfigError("offender state version is unsupported")
        items = data.get("offenders")
        if not isinstance(items, list):
            raise ConfigError("offender state is missing offenders")
        now = self._clock()
        loaded: dict[str, OffenderRecord] = {}
        for item in items[: self.max_entries]:
            record = _parse_record(item)
            if record.expires_at <= now:
                continue
            loaded[record.fingerprint] = record
        self._records = loaded

    def _save(self) -> None:
        payload = json.dumps(
            {
                "version": _STATE_VERSION,
                "offenders": [asdict(record) for record in self._records.values()],
            },
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        parent = self.path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".highwall-offenders-",
                dir=str(parent),
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o600)
                os.replace(temporary, self.path)
            except OSError:
                try:
                    temporary.unlink()
                except OSError:
                    pass
                raise
        except OSError as exc:
            _LOG.warning("offender state save failed (%s)", type(exc).__name__)
            return

    def _prune(self, now: float) -> None:
        expired = [key for key, record in self._records.items() if record.expires_at <= now]
        for key in expired:
            self._records.pop(key, None)
        while len(self._records) > self.max_entries:
            oldest = min(self._records.values(), key=lambda record: record.last_seen)
            self._records.pop(oldest.fingerprint, None)

    def get(self, fingerprint: str, shape_fingerprint_value: str) -> OffenderMatch | None:
        now = self._clock()
        with self._lock:
            self._prune(now)
            record = self._records.get(fingerprint)
            if record is not None and record.expires_at > now:
                return OffenderMatch(record=record, exact=True)
            for candidate in self._records.values():
                if candidate.shape_fingerprint == shape_fingerprint_value and candidate.expires_at > now:
                    return OffenderMatch(record=candidate, exact=False)
            return None

    def mark(
        self,
        *,
        fingerprint: str,
        shape_fingerprint_value: str,
        tag: str,
        confidence: str,
        score: int,
        signals: tuple[str, ...],
        action: str,
        source_prefix_value: str = "",
        client_ip: str = "",
    ) -> OffenderRecord:
        if tag not in _TAGS or confidence not in {"suspected", "confirmed"}:
            raise ValueError("invalid offender tag or confidence")
        now = self._clock()
        with self._lock:
            existing = self._records.get(fingerprint)
            first_seen = now if existing is None else existing.first_seen
            hits = 1 if existing is None else min(existing.hits + 1, 2**31 - 1)
            if existing is not None and existing.tag == "confirmed_fast_attack":
                tag = "confirmed_fast_attack"
                confidence = "confirmed"
            record = OffenderRecord(
                fingerprint=fingerprint,
                shape_fingerprint=shape_fingerprint_value,
                tag=tag,
                confidence=confidence,
                score=max(0, min(100, int(score))),
                signals=tuple(signals)[:32],
                first_seen=first_seen,
                last_seen=now,
                expires_at=max(now + self.ttl_seconds, existing.expires_at if existing else 0.0),
                hits=hits,
                action=action,
                source_prefix=source_prefix_value[:64],
                client_ip=client_ip[:64] if self.include_client_ip else "",
            )
            self._records[fingerprint] = record
            self._prune(now)
            self._save()
            return record

    def active(self) -> list[OffenderRecord]:
        with self._lock:
            self._prune(self._clock())
            return list(self._records.values())

    def size(self) -> int:
        with self._lock:
            self._prune(self._clock())
            return len(self._records)
