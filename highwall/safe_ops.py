"""Read-only Safe Ops planning and deny-by-default policy.

This module deliberately has no execution primitive.  It evaluates typed plans,
normalizes their targets and explains why an operation is allowed or denied.
Destructive operations stay disabled until an independent executor, verified
approval channel and rollback verification exist.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

MAX_PLAN_BYTES = 64 * 1024
POLICY_VERSION = "2026-11-01"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ENVIRONMENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ENV_REFERENCE_RE = re.compile(r"(?:\$[A-Za-z_{(]|%[A-Za-z_][A-Za-z0-9_]*%)")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_WILDCARD_CHARS = frozenset("*?[]")

_RISK_BY_ACTION = {
    "read_status": "R0",
    "read_config_summary": "R0",
    "read_logs": "R0",
    "generate_config_draft": "R1",
    "dry_run_config": "R1",
    "export_report": "R1",
    "replace_config": "R2",
    "restart_service": "R2",
    "rotate_certificate": "R2",
    "cleanup_cache": "R2",
    "delete_data": "R3",
    "format_disk": "R3",
    "clear_backups": "R3",
    "modify_firewall": "R3",
    "delete_certificate": "R3",
    "alter_acl": "R3",
    "clear_logs": "R3",
    "run_shell": "R3",
}

_PATH_ACTIONS = {
    "read_config_summary",
    "read_logs",
    "generate_config_draft",
    "dry_run_config",
    "export_report",
    "replace_config",
    "rotate_certificate",
    "cleanup_cache",
    "delete_data",
    "clear_backups",
    "delete_certificate",
    "alter_acl",
    "clear_logs",
}

_TARGET_REQUIRED = _PATH_ACTIONS | {
    "restart_service",
    "format_disk",
    "modify_firewall",
    "run_shell",
}


class SafeOpsError(ValueError):
    """A safe, actionable Safe Ops input error."""


@dataclass(frozen=True)
class OpsRequest:
    action: str
    targets: tuple[str, ...] = ()
    environment: str = "production"
    dry_run: bool = False
    requested_by: str = "agent"
    approval_reference: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OpsRequest":
        if not isinstance(value, dict):
            raise SafeOpsError("plan must be a JSON object")
        allowed = {
            "action",
            "targets",
            "environment",
            "dry_run",
            "requested_by",
            "approval_reference",
        }
        unknown = set(value) - allowed
        if unknown:
            raise SafeOpsError("plan contains an unknown field")

        action_value = value.get("action")
        if not isinstance(action_value, str):
            raise SafeOpsError("action must be a string")
        action = action_value.strip().lower()
        if not _ACTION_RE.fullmatch(action):
            raise SafeOpsError("action must be a lowercase operation identifier")

        targets_value = value.get("targets", [])
        if not isinstance(targets_value, list):
            raise SafeOpsError("targets must be an array")
        if len(targets_value) > 32:
            raise SafeOpsError("targets must not contain more than 32 entries")
        targets: list[str] = []
        for target in targets_value:
            if not isinstance(target, str) or not target or len(target) > 1024:
                raise SafeOpsError("each target must be a non-empty string up to 1024 characters")
            targets.append(target)

        environment_value = value.get("environment", "production")
        if not isinstance(environment_value, str):
            raise SafeOpsError("environment must be a string")
        environment = environment_value.strip().lower()
        if not _ENVIRONMENT_RE.fullmatch(environment):
            raise SafeOpsError("environment must be a lowercase identifier")

        dry_run = value.get("dry_run", False)
        if not isinstance(dry_run, bool):
            raise SafeOpsError("dry_run must be a boolean")

        requested_by_value = value.get("requested_by", "agent")
        if not isinstance(requested_by_value, str) or len(requested_by_value) > 128:
            raise SafeOpsError("requested_by must be a string up to 128 characters")
        requested_by = requested_by_value.strip()
        if _contains_control(requested_by):
            raise SafeOpsError("requested_by contains unsupported control characters")

        approval_value = value.get("approval_reference", "")
        if not isinstance(approval_value, str) or len(approval_value) > 256:
            raise SafeOpsError("approval_reference must be a string up to 256 characters")
        approval_reference = approval_value.strip()
        if _contains_control(approval_reference):
            raise SafeOpsError("approval_reference contains unsupported control characters")

        return cls(
            action=action,
            targets=tuple(targets),
            environment=environment,
            dry_run=dry_run,
            requested_by=requested_by,
            approval_reference=approval_reference,
        )


@dataclass(frozen=True)
class OpsDecision:
    allowed: bool
    action: str
    risk: str
    reasons: tuple[str, ...]
    requires_approval: tuple[str, ...]
    normalized_targets: tuple[str, ...]
    environment: str
    dry_run: bool
    plan_sha256: str
    policy_version: str = POLICY_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "highwall.safe-ops.decision.v1",
            "allowed": self.allowed,
            "action": self.action,
            "risk": self.risk,
            "reasons": list(self.reasons),
            "requires_approval": list(self.requires_approval),
            "normalized_targets": list(self.normalized_targets),
            "environment": self.environment,
            "dry_run": self.dry_run,
            "plan_sha256": self.plan_sha256,
            "policy_version": self.policy_version,
        }


class SafeOpsPolicy:
    """Deny-by-default policy for typed operations; never executes a plan."""

    def __init__(self, allowed_roots: tuple[str | Path, ...] = ()) -> None:
        roots: list[Path] = []
        for value in allowed_roots:
            root = Path(value).expanduser()
            if not root.is_absolute():
                raise ValueError("allowed roots must be absolute paths")
            try:
                resolved = root.resolve(strict=True)
            except OSError as exc:
                raise ValueError("allowed root must exist and be readable") from exc
            if not resolved.is_dir():
                raise ValueError("allowed root must be a directory")
            roots.append(resolved)
        self.allowed_roots = tuple(roots)

    def evaluate(self, request: OpsRequest) -> OpsDecision:
        risk = _RISK_BY_ACTION.get(request.action, "unknown")
        reasons: list[str] = []
        required: list[str] = []
        normalized: list[str] = []
        allowed = False

        if risk == "unknown":
            reasons.append("unknown action is denied")
        elif request.action == "run_shell":
            reasons.append("raw shell operations are never accepted")
            required.extend(("typed action", "offline break-glass", "dual approval"))
        elif request.action in _TARGET_REQUIRED and not request.targets:
            reasons.append("operation requires at least one explicit target")

        if request.action in _PATH_ACTIONS:
            for target in request.targets:
                normalized_target, target_error = self._normalize_target(target)
                if target_error:
                    reasons.append(target_error)
                else:
                    normalized.append(normalized_target)
        else:
            normalized.extend(request.targets)

        if risk == "R0":
            allowed = not reasons
        elif risk == "R1":
            required.append("explicit confirmation")
            if not request.dry_run:
                reasons.append("R1 operations require dry_run preview and explicit confirmation")
            allowed = request.dry_run and not reasons
        elif risk == "R2":
            required.extend(("target verification", "verified backup", "explicit confirmation", "rollback plan"))
            reasons.append("R2 mutations are disabled in this read-only Safe Ops release")
            allowed = False
        elif risk == "R3":
            required.extend(("offline break-glass", "dual approval", "incident reference", "audit verification"))
            reasons.append("R3 operations require offline break-glass, dual approval and audited execution")
            allowed = False
        else:
            allowed = False

        plan_material = {
            "schema": "highwall.safe-ops.plan.v1",
            "policy_version": POLICY_VERSION,
            "action": request.action,
            "targets": list(request.targets),
            "normalized_targets": normalized,
            "environment": request.environment,
            "dry_run": request.dry_run,
            "risk": risk,
        }
        plan_sha256 = hashlib.sha256(
            json.dumps(plan_material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return OpsDecision(
            allowed=allowed,
            action=request.action,
            risk=risk,
            reasons=tuple(dict.fromkeys(reasons)),
            requires_approval=tuple(dict.fromkeys(required)),
            normalized_targets=tuple(normalized),
            environment=request.environment,
            dry_run=request.dry_run,
            plan_sha256=plan_sha256,
        )

    def _normalize_target(self, raw: str) -> tuple[str, str]:
        if not self.allowed_roots:
            return "", "no allowed root is configured for this path operation"
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
            return "", "target contains unsupported control characters"
        normalized_text = unicodedata.normalize("NFKC", raw)
        if normalized_text != raw:
            return "", "target must already be in NFC-compatible normalized form"
        if len(normalized_text) > 1024:
            return "", "target exceeds the 1024 character limit"
        if any(ch in _WILDCARD_CHARS for ch in normalized_text):
            return "", "target must not contain wildcard characters"
        if _PERCENT_ESCAPE_RE.search(normalized_text):
            return "", "target must not contain percent-encoded path bytes"
        if normalized_text.startswith("~") or _ENV_REFERENCE_RE.search(normalized_text) or "`" in normalized_text:
            return "", "target must not contain shell expansion or environment references"
        if (
            normalized_text.startswith("\\\\")
            or normalized_text.startswith("//")
            or normalized_text.startswith("/dev/")
            or normalized_text.startswith("\\\\.\\")
        ):
            return "", "UNC, device and namespace targets are not allowed"
        _drive, tail = os.path.splitdrive(normalized_text)
        if ":" in tail:
            return "", "alternate data stream targets are not allowed"
        if any(part.endswith((" ", ".")) for part in Path(normalized_text).parts[1:]):
            return "", "target components must not end with a space or dot"

        path = Path(normalized_text)
        if ".." in path.parts:
            return "", "target must not contain parent-directory traversal"
        if not path.is_absolute():
            return "", "target must be an absolute path"
        try:
            normalized_path = Path(os.path.abspath(str(path)))
        except (OSError, ValueError):
            return "", "target path cannot be normalized"
        if not any(_is_within(normalized_path, root) for root in self.allowed_roots):
            return "", "target is outside every configured allowed root"

        parts = normalized_path.parts
        current = Path(parts[0])
        for index, part in enumerate(parts[1:], start=1):
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            except OSError:
                return "", "target path component cannot be inspected"
            attributes = getattr(info, "st_file_attributes", 0)
            if stat.S_ISLNK(info.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                return "", "target must not traverse a symbolic link or reparse point"
            if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                return "", "target path contains a non-directory component"
        return str(normalized_path), ""


def load_ops_plan(path: str | Path) -> OpsRequest:
    plan_path = Path(path)
    try:
        info = plan_path.lstat()
    except OSError as exc:
        raise SafeOpsError("plan file cannot be inspected") from exc
    attributes = getattr(info, "st_file_attributes", 0)
    if stat.S_ISLNK(info.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise SafeOpsError("plan file must not be a symbolic link or reparse point")
    if not stat.S_ISREG(info.st_mode):
        raise SafeOpsError("plan file must be a regular file")
    if info.st_size > MAX_PLAN_BYTES:
        raise SafeOpsError("plan file is too large")
    try:
        raw = plan_path.read_bytes()
    except OSError as exc:
        raise SafeOpsError("plan file cannot be read") from exc
    if len(raw) > MAX_PLAN_BYTES:
        raise SafeOpsError("plan file is too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafeOpsError("plan file is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise SafeOpsError("plan must be a JSON object")
    return OpsRequest.from_mapping(value)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SafeOpsError("plan contains a duplicate key")
        result[key] = value
    return result


def _contains_control(value: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _is_within(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((str(path), str(root)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(str(root))
