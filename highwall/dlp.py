"""Response-side detection for obvious secret and debug-data disclosure."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .config import PolicyConfig


@dataclass(frozen=True)
class DlpHit:
    rule_id: str
    category: str


_SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.I)),
    ("putty-key", re.compile(r"PuTTY-User-Key-File-\d+", re.I)),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-secret", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("azure-storage-key", re.compile(r"\bAccountKey=[A-Za-z0-9+/=]{20,}", re.I)),
    (
        "database-credential",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:[^/\s@]+@", re.I),
    ),
]

_DEBUG_PATTERNS = [
    ("python-traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("java-stack", re.compile(r"\bat [\w.$]+\([\w$]+\.java:\d+\)")),
    ("dotnet-exception", re.compile(r"\bSystem\.[A-Za-z0-9_.]+Exception\b")),
    ("sql-error", re.compile(r"\b(?:SQLSTATE\[[A-Z0-9]{5}\]|ORA-\d{5}|mysql_fetch_(?:array|assoc)|Microsoft OLE DB Provider)\b", re.I)),
    ("php-error", re.compile(r"\bPHP (?:Warning|Fatal error|Parse error):", re.I)),
]

_HEADER_SCAN_EXCLUSIONS = {"set-cookie"}


def _media_type(value: str | None) -> str:
    if not value:
        return ""
    return value.split(";", 1)[0].strip().lower()


def _charset(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(";")[1:]:
        key, separator, raw_value = part.partition("=")
        if not separator or key.strip().lower() != "charset":
            continue
        charset = raw_value.strip().strip('"').lower()
        return charset or None
    return None


def _decoded_texts(sample: bytes, content_type: str | None) -> list[str]:
    codecs_to_try: list[str] = []
    declared = _charset(content_type)
    if declared:
        aliases = {
            "utf8": "utf-8",
            "utf-16le": "utf-16-le",
            "utf-16be": "utf-16-be",
            "latin-1": "latin-1",
            "latin1": "latin-1",
            "iso-8859-1": "latin-1",
            "windows-1252": "cp1252",
        }
        normalized = aliases.get(declared, declared)
        if normalized in {
            "utf-8",
            "utf-16",
            "utf-16-le",
            "utf-16-be",
            "latin-1",
            "cp1252",
        }:
            codecs_to_try.append(normalized)
    codecs_to_try.extend(["utf-8", "latin-1", "utf-16-le", "utf-16-be"])
    texts: list[str] = []
    seen: set[str] = set()
    for codec in codecs_to_try:
        if codec in seen:
            continue
        seen.add(codec)
        try:
            text = sample.decode(codec, errors="ignore")
        except (LookupError, UnicodeError):
            continue
        if text and text not in texts:
            texts.append(text)
    return texts


def inspect_response(
    body: bytes,
    content_type: str | None,
    policy: PolicyConfig,
    headers: Iterable[tuple[str, str]] | None = None,
) -> DlpHit | None:
    if policy.response_scan_mode == "off":
        return None
    sample = body[: policy.response_scan_max_bytes]
    texts = _decoded_texts(sample, content_type) if sample else []
    if headers is not None and policy.response_scan_headers:
        texts.extend(
            f"{name}: {value}"
            for name, value in headers
            if name.casefold() not in _HEADER_SCAN_EXCLUSIONS
        )
    if not texts:
        return None
    for category, patterns in (("secret", _SECRET_PATTERNS), ("debug", _DEBUG_PATTERNS)):
        for name, pattern in patterns:
            for text in texts:
                if pattern.search(text):
                    rule_id = "HW-DLP-SECRET-1001" if category == "secret" else "HW-DLP-DEBUG-1002"
                    return DlpHit(rule_id=rule_id, category=name)
    return None
