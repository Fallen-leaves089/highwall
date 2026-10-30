"""Compare effective configurations and classify deployment impact."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from .config import Config
from .config_report import build_config_report
from .reload_fields import changed_immutable_fields

EXIT_NO_CHANGES = 0
EXIT_RELOADABLE = 1
EXIT_RESTART_REQUIRED = 3
EXIT_SECURITY_REGRESSION = 4

_SET_LIKE_PATHS = (
    "policy.allowed_hosts",
    "policy.allowed_methods",
    "policy.allowed_path_prefixes",
    "policy.deny_path_prefixes",
    "policy.allowed_client_networks",
    "policy.denied_client_networks",
    "policy.trusted_proxies",
    "policy.allowed_origins",
    "policy.allowed_body_content_types",
    "policy.waf_rules",
)
_MODE_RANK = {"off": 0, "detect": 1, "monitor": 0, "block": 3, "throttle": 1, "tarpit": 2}
_TLS_VERSION_RANK = {"TLSv1_2": 1, "TLSv1_3": 2}


@dataclass(frozen=True)
class ConfigChange:
    path: str
    current: Any
    candidate: Any
    requires_restart: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "current": self.current,
            "candidate": self.candidate,
            "requires_restart": self.requires_restart,
        }


@dataclass(frozen=True)
class SecurityFinding:
    path: str
    severity: str
    message: str
    current: Any
    candidate: Any

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "severity": self.severity,
            "message": self.message,
            "current": self.current,
            "candidate": self.candidate,
        }


def _json_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sort_at_path(report: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    value: Any = report
    for part in parts[:-1]:
        if not isinstance(value, dict):
            return
        value = value.get(part)
    if not isinstance(value, dict):
        return
    items = value.get(parts[-1])
    if isinstance(items, list):
        items.sort(key=_json_key)


def _canonical_report(config: Config) -> dict[str, Any]:
    report = copy.deepcopy(build_config_report(config))
    report.pop("source", None)
    server = report.get("server")
    if isinstance(server, dict):
        server.pop("tls_enabled", None)
    for path in _SET_LIKE_PATHS:
        _sort_at_path(report, path)
    policy = report.get("policy", {})
    routes = policy.get("routes", []) if isinstance(policy, dict) else []
    if isinstance(routes, list):
        for route in routes:
            if not isinstance(route, dict):
                continue
            for field in ("methods", "allowed_client_networks"):
                values = route.get(field)
                if isinstance(values, list):
                    values.sort(key=_json_key)
    return report


def _flatten(value: Any, prefix: str = "", result: dict[str, Any] | None = None) -> dict[str, Any]:
    if result is None:
        result = {}
    if isinstance(value, dict):
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else key
            _flatten(value[key], path, result)
    else:
        result[prefix] = value
    return result


def _value(report: dict[str, Any], path: str) -> Any:
    value: Any = report
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _list_value(report: dict[str, Any], path: str) -> list[Any]:
    value = _value(report, path)
    return value if isinstance(value, list) else []


def _added(before: list[Any], after: list[Any]) -> list[Any]:
    return [item for item in after if item not in before]


def _removed(before: list[Any], after: list[Any]) -> list[Any]:
    return [item for item in before if item not in after]


def _finding(path: str, severity: str, message: str, current: Any, candidate: Any) -> SecurityFinding:
    return SecurityFinding(path, severity, message, current, candidate)


def _global_findings(
    before: dict[str, Any],
    after: dict[str, Any],
    regressions: list[SecurityFinding],
    review: list[SecurityFinding],
) -> None:
    def changed(path: str) -> tuple[Any, Any] | None:
        old = _value(before, path)
        new = _value(after, path)
        return (old, new) if old != new else None

    pair = changed("server.tls.enabled")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("server.tls.enabled", "high", "TLS was disabled for the listener", *pair))

    pair = changed("server.tls.min_version")
    if pair and _TLS_VERSION_RANK.get(str(pair[0]), 0) > _TLS_VERSION_RANK.get(str(pair[1]), 0):
        regressions.append(_finding("server.tls.min_version", "medium", "minimum TLS version was lowered", *pair))

    pair = changed("policy.waf_enabled")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("policy.waf_enabled", "high", "WAF blocking was disabled", *pair))

    pair = changed("policy.waf_mode")
    if pair and _MODE_RANK.get(str(pair[0]), 0) > _MODE_RANK.get(str(pair[1]), 0):
        regressions.append(_finding("policy.waf_mode", "high", "WAF mode was weakened", *pair))

    removed_rules = _removed(_list_value(before, "policy.waf_rules"), _list_value(after, "policy.waf_rules"))
    if removed_rules:
        regressions.append(
            _finding(
                "policy.waf_rules",
                "high",
                "WAF rules were removed: " + ", ".join(str(item) for item in removed_rules),
                _list_value(before, "policy.waf_rules"),
                _list_value(after, "policy.waf_rules"),
            )
        )

    for path, label in (
        ("policy.response_scan_mode", "response scanning"),
        ("policy.response_integrity_mode", "response integrity checking"),
    ):
        pair = changed(path)
        if pair and _MODE_RANK.get(str(pair[0]), 0) > _MODE_RANK.get(str(pair[1]), 0):
            regressions.append(_finding(path, "high", f"{label} was weakened", *pair))

    pair = changed("policy.response_scan_headers")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("policy.response_scan_headers", "medium", "response header scanning was disabled", *pair))

    pair = changed("audit.on_write_failure")
    if pair and pair[0] == "fail_closed" and pair[1] == "continue":
        regressions.append(_finding("audit.on_write_failure", "high", "audit failures no longer fail closed", *pair))

    pair = changed("threat_detection.agent_mode")
    if pair and pair[0] in {"block", "throttle"} and pair[1] == "score":
        regressions.append(
            _finding("threat_detection.agent_mode", "medium", "obvious-agent containment was disabled", *pair)
        )

    old_scan = _value(before, "policy.response_scan_max_bytes")
    new_scan = _value(after, "policy.response_scan_max_bytes")
    if isinstance(old_scan, int) and isinstance(new_scan, int) and new_scan < old_scan:
        regressions.append(
            _finding(
                "policy.response_scan_max_bytes",
                "medium",
                "response scan limit decreased",
                old_scan,
                new_scan,
            )
        )

    old_pins = {str(item.get("path")): item.get("sha256") for item in _list_value(before, "policy.integrity_pins") if isinstance(item, dict)}
    new_pins = {str(item.get("path")): item.get("sha256") for item in _list_value(after, "policy.integrity_pins") if isinstance(item, dict)}
    for removed_pin in sorted(set(old_pins) - set(new_pins)):
        regressions.append(
            _finding(
                "policy.integrity_pins",
                "high",
                f"integrity pin removed: {removed_pin}",
                old_pins[removed_pin],
                None,
            )
        )
    for changed_pin in sorted(path for path in set(old_pins) & set(new_pins) if old_pins[path] != new_pins[path]):
        review.append(
            _finding(
                "policy.integrity_pins",
                "medium",
                f"integrity pin changed: {changed_pin}",
                old_pins[changed_pin],
                new_pins[changed_pin],
            )
        )

    old_headers = _value(before, "policy.security_headers")
    new_headers = _value(after, "policy.security_headers")
    if isinstance(old_headers, dict) and isinstance(new_headers, dict):
        for removed_header in sorted(set(old_headers) - set(new_headers)):
            regressions.append(
                _finding(
                    "policy.security_headers",
                    "high",
                    f"security header removed: {removed_header}",
                    old_headers[removed_header],
                    None,
                )
            )
        for changed_header in sorted(
            name for name in set(old_headers) & set(new_headers) if old_headers[name] != new_headers[name]
        ):
            review.append(
                _finding(
                    "policy.security_headers",
                    "medium",
                    f"security header changed: {changed_header}",
                    old_headers[changed_header],
                    new_headers[changed_header],
                )
            )

    pair = changed("policy.effective_hsts")
    if pair and pair[0] is not None and pair[1] is None:
        regressions.append(_finding("policy.effective_hsts", "medium", "HSTS protection was removed", *pair))

    pair = changed("policy.read_only")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("policy.read_only", "high", "global read-only mode was disabled", *pair))

    pair = changed("rate_limit.enabled")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("rate_limit.enabled", "high", "rate limiting was disabled", *pair))

    pair = changed("policy.honeypot.enabled")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("policy.honeypot.enabled", "medium", "honeypot protection was disabled", *pair))

    pair = changed("threat_detection.enabled")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("threat_detection.enabled", "high", "threat detection was disabled", *pair))

    pair = changed("threat_detection.mode")
    if pair and _MODE_RANK.get(str(pair[0]), 0) > _MODE_RANK.get(str(pair[1]), 0):
        regressions.append(_finding("threat_detection.mode", "high", "threat containment mode was weakened", *pair))

    pair = changed("ddos_detection.enabled")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("ddos_detection.enabled", "high", "L7 DDoS detection was disabled", *pair))

    pair = changed("alerting.enabled")
    if pair and pair[0] is True and pair[1] is False:
        regressions.append(_finding("alerting.enabled", "medium", "security alerting was disabled", *pair))

    old_hosts = _list_value(before, "policy.allowed_hosts")
    new_hosts = _list_value(after, "policy.allowed_hosts")
    added_hosts = _added(old_hosts, new_hosts)
    if added_hosts:
        regressions.append(
            _finding(
                "policy.allowed_hosts",
                "high",
                "allowed Host authorities were added: " + ", ".join(str(item) for item in added_hosts),
                old_hosts,
                new_hosts,
            )
        )

    old_methods = _list_value(before, "policy.allowed_methods")
    new_methods = _list_value(after, "policy.allowed_methods")
    added_methods = _added(old_methods, new_methods)
    if added_methods:
        regressions.append(
            _finding(
                "policy.allowed_methods",
                "high",
                "allowed HTTP methods were added: " + ", ".join(str(item) for item in added_methods),
                old_methods,
                new_methods,
            )
        )

    old_prefixes = _list_value(before, "policy.allowed_path_prefixes")
    new_prefixes = _list_value(after, "policy.allowed_path_prefixes")
    if "/" in new_prefixes and "/" not in old_prefixes:
        regressions.append(
            _finding("policy.allowed_path_prefixes", "high", "all request paths became allowed", old_prefixes, new_prefixes)
        )
    else:
        added_prefixes = _added(old_prefixes, new_prefixes)
        if added_prefixes:
            regressions.append(
                _finding(
                    "policy.allowed_path_prefixes",
                    "high",
                    "allowed path prefixes were added: " + ", ".join(str(item) for item in added_prefixes),
                    old_prefixes,
                    new_prefixes,
                )
            )

    old_denied = _list_value(before, "policy.deny_path_prefixes")
    new_denied = _list_value(after, "policy.deny_path_prefixes")
    removed_denied = _removed(old_denied, new_denied)
    if removed_denied:
        regressions.append(
            _finding(
                "policy.deny_path_prefixes",
                "high",
                "denied path prefixes were removed: " + ", ".join(str(item) for item in removed_denied),
                old_denied,
                new_denied,
            )
        )

    old_clients = _list_value(before, "policy.allowed_client_networks")
    new_clients = _list_value(after, "policy.allowed_client_networks")
    if old_clients and not new_clients:
        regressions.append(
            _finding("policy.allowed_client_networks", "high", "client network filtering was disabled", old_clients, new_clients)
        )
    else:
        added_clients = _added(old_clients, new_clients)
        if added_clients:
            regressions.append(
                _finding(
                    "policy.allowed_client_networks",
                    "high",
                    "allowed client networks were added: " + ", ".join(str(item) for item in added_clients),
                    old_clients,
                    new_clients,
                )
            )

    old_blocked = _list_value(before, "policy.denied_client_networks")
    new_blocked = _list_value(after, "policy.denied_client_networks")
    removed_blocked = _removed(old_blocked, new_blocked)
    if removed_blocked:
        regressions.append(
            _finding(
                "policy.denied_client_networks",
                "high",
                "denied client networks were removed: " + ", ".join(str(item) for item in removed_blocked),
                old_blocked,
                new_blocked,
            )
        )

    old_proxy = _list_value(before, "policy.trusted_proxies")
    new_proxy = _list_value(after, "policy.trusted_proxies")
    added_proxy = _added(old_proxy, new_proxy)
    if added_proxy:
        regressions.append(
            _finding(
                "policy.trusted_proxies",
                "high",
                "trusted proxy networks were added: " + ", ".join(str(item) for item in added_proxy),
                old_proxy,
                new_proxy,
            )
        )

    old_origins = _list_value(before, "policy.allowed_origins")
    new_origins = _list_value(after, "policy.allowed_origins")
    if old_origins and not new_origins:
        regressions.append(
            _finding("policy.allowed_origins", "high", "Origin enforcement was disabled", old_origins, new_origins)
        )
    elif old_origins:
        added_origins = _added(old_origins, new_origins)
        if added_origins:
            regressions.append(
                _finding(
                    "policy.allowed_origins",
                    "high",
                    "allowed Origins were added: " + ", ".join(str(item) for item in added_origins),
                    old_origins,
                    new_origins,
                )
            )

    for path, label in (
        ("policy.reject_encoded_separators", "encoded separator rejection"),
        ("policy.reject_duplicate_headers", "duplicate header rejection"),
        ("policy.reject_get_body", "GET body rejection"),
    ):
        pair = changed(path)
        if pair and pair[0] is True and pair[1] is False:
            regressions.append(_finding(path, "high", f"{label} was disabled", *pair))
    for path, label in (
        ("policy.allow_path_parameters", "path parameter compatibility"),
        ("policy.allow_trailing_dot_or_space", "trailing dot/space compatibility"),
    ):
        pair = changed(path)
        if pair and pair[0] is False and pair[1] is True:
            regressions.append(_finding(path, "high", f"{label} was enabled", *pair))

    for path, label in (
        ("policy.max_request_line", "request-line limit"),
        ("policy.max_header_count", "header-count limit"),
        ("policy.max_header_bytes", "header-byte limit"),
        ("policy.max_body_bytes", "body-size limit"),
        ("policy.max_xff_hops", "X-Forwarded-For hop limit"),
    ):
        old_limit = _value(before, path)
        new_limit = _value(after, path)
        if isinstance(old_limit, int) and isinstance(new_limit, int) and new_limit > old_limit:
            regressions.append(_finding(path, "medium", f"{label} was increased", old_limit, new_limit))

    old_types = _list_value(before, "policy.allowed_body_content_types")
    new_types = _list_value(after, "policy.allowed_body_content_types")
    added_types = _added(old_types, new_types)
    if added_types:
        regressions.append(
            _finding(
                "policy.allowed_body_content_types",
                "medium",
                "allowed body content types were added: " + ", ".join(str(item) for item in added_types),
                old_types,
                new_types,
            )
        )


def _route_findings(
    before: dict[str, Any],
    after: dict[str, Any],
    regressions: list[SecurityFinding],
    review: list[SecurityFinding],
) -> None:
    old_routes = {
        str(route.get("path_prefix")): route
        for route in _list_value(before, "policy.routes")
        if isinstance(route, dict)
    }
    new_routes = {
        str(route.get("path_prefix")): route
        for route in _list_value(after, "policy.routes")
        if isinstance(route, dict)
    }

    def restricted(route: dict[str, Any]) -> bool:
        return (
            route.get("methods") is not None
            or route.get("read_only") is True
            or route.get("max_body_bytes") is not None
            or int(route.get("max_concurrent") or 0) > 0
            or float(route.get("rate") or 0) > 0
            or route.get("allowed_client_networks") is not None
        )

    for prefix in sorted(set(old_routes) - set(new_routes)):
        if restricted(old_routes[prefix]):
            regressions.append(
                _finding(
                    "policy.routes",
                    "high",
                    f"restricted route was removed: {prefix}",
                    old_routes[prefix],
                    None,
                )
            )

    for prefix in sorted(set(old_routes) & set(new_routes)):
        old = old_routes[prefix]
        new = new_routes[prefix]
        path = f"policy.routes[{prefix}]"

        if old.get("read_only") is True and new.get("read_only") is not True:
            regressions.append(_finding(path, "high", "route read-only mode was disabled", old.get("read_only"), new.get("read_only")))

        old_methods = old.get("methods")
        new_methods = new.get("methods")
        if old_methods is not None and new_methods is None:
            regressions.append(_finding(path, "high", "route method restriction was removed", old_methods, new_methods))
        elif isinstance(old_methods, list) and isinstance(new_methods, list):
            added_methods = _added(old_methods, new_methods)
            if added_methods:
                regressions.append(
                    _finding(path, "high", "route methods were added: " + ", ".join(str(item) for item in added_methods), old_methods, new_methods)
                )

        old_clients = old.get("allowed_client_networks")
        new_clients = new.get("allowed_client_networks")
        if old_clients is not None and new_clients is None:
            regressions.append(_finding(path, "high", "route client-network restriction was removed", old_clients, new_clients))
        elif isinstance(old_clients, list) and isinstance(new_clients, list):
            added_clients = _added(old_clients, new_clients)
            if added_clients:
                regressions.append(
                    _finding(path, "high", "route client networks were added: " + ", ".join(str(item) for item in added_clients), old_clients, new_clients)
                )

        old_body = old.get("max_body_bytes")
        new_body = new.get("max_body_bytes")
        if isinstance(old_body, int) and new_body is None:
            regressions.append(_finding(path, "medium", "route body-size limit was removed", old_body, new_body))
        elif isinstance(old_body, int) and isinstance(new_body, int) and new_body > old_body:
            regressions.append(_finding(path, "medium", "route body-size limit was increased", old_body, new_body))

        old_slots = int(old.get("max_concurrent") or 0)
        new_slots = int(new.get("max_concurrent") or 0)
        if old_slots > 0 and new_slots == 0:
            regressions.append(_finding(path, "high", "route concurrency limit was removed", old_slots, new_slots))
        elif old_slots > 0 and new_slots > old_slots:
            regressions.append(_finding(path, "medium", "route concurrency limit was increased", old_slots, new_slots))

        old_rate = float(old.get("rate") or 0)
        new_rate = float(new.get("rate") or 0)
        if old_rate > 0 and new_rate == 0:
            regressions.append(_finding(path, "high", "route rate limit was removed", old_rate, new_rate))
        elif old_rate > 0 and new_rate > old_rate:
            regressions.append(_finding(path, "medium", "route rate limit was increased", old_rate, new_rate))


def _review_findings(
    before: dict[str, Any],
    after: dict[str, Any],
    review: list[SecurityFinding],
) -> None:
    tls_stays_enabled = (
        _value(before, "server.tls.enabled") is True and _value(after, "server.tls.enabled") is True
    )
    if tls_stays_enabled:
        for path, label in (("server.tls.cert_file", "certificate file"), ("server.tls.key_file", "key file")):
            old_value = _value(before, path)
            new_value = _value(after, path)
            if old_value != new_value:
                review.append(
                    _finding(
                        path,
                        "medium",
                        f"TLS {label} changed; verify the new material before promoting this configuration",
                        old_value,
                        new_value,
                    )
                )

    old_upstream = (_value(before, "upstream.scheme"), _value(before, "upstream.host"), _value(before, "upstream.port"))
    new_upstream = (_value(after, "upstream.scheme"), _value(after, "upstream.host"), _value(after, "upstream.port"))
    if old_upstream != new_upstream:
        review.append(
            _finding(
                "upstream",
                "high",
                "upstream target changed; verify the destination before promoting this configuration",
                list(old_upstream),
                list(new_upstream),
            )
        )

    if _value(before, "admin.enabled") is False and _value(after, "admin.enabled") is True:
        review.append(
            _finding(
                "admin.enabled",
                "medium",
                "management endpoint was enabled; confirm it remains loopback-only",
                False,
                True,
            )
        )

    old_audit_path = _value(before, "audit.path")
    new_audit_path = _value(after, "audit.path")
    if old_audit_path != new_audit_path:
        review.append(
            _finding(
                "audit.path",
                "medium",
                "audit log path changed; verify evidence retention and file permissions",
                old_audit_path,
                new_audit_path,
            )
        )


def _security_findings(
    before: dict[str, Any],
    after: dict[str, Any],
) -> tuple[tuple[SecurityFinding, ...], tuple[SecurityFinding, ...]]:
    regressions: list[SecurityFinding] = []
    review: list[SecurityFinding] = []
    _global_findings(before, after, regressions, review)
    _route_findings(before, after, regressions, review)
    _review_findings(before, after, review)
    return tuple(regressions), tuple(review)


def build_config_diff(current: Config, candidate: Config) -> dict[str, Any]:
    """Return a JSON-serializable comparison of two effective configurations."""

    before = _canonical_report(current)
    after = _canonical_report(candidate)
    before_values = _flatten(before)
    after_values = _flatten(after)
    changed_paths = sorted(
        path
        for path in set(before_values) | set(after_values)
        if before_values.get(path) != after_values.get(path)
    )
    restart_paths = set(changed_immutable_fields(current, candidate)) & set(changed_paths)
    changes = tuple(
        ConfigChange(
            path=path,
            current=before_values.get(path),
            candidate=after_values.get(path),
            requires_restart=path in restart_paths,
        )
        for path in changed_paths
    )
    regressions, review = _security_findings(before, after)
    restart_fields = tuple(sorted(change.path for change in changes if change.requires_restart))
    reloadable_fields = tuple(change.path for change in changes if not change.requires_restart)
    if regressions:
        exit_code = EXIT_SECURITY_REGRESSION
    elif restart_fields:
        exit_code = EXIT_RESTART_REQUIRED
    elif changes:
        exit_code = EXIT_RELOADABLE
    else:
        exit_code = EXIT_NO_CHANGES
    return {
        "current": str(current.source) if current.source is not None else None,
        "candidate": str(candidate.source) if candidate.source is not None else None,
        "changed": bool(changes),
        "restart_required": list(restart_fields),
        "reloadable": list(reloadable_fields),
        "security_regressions": [finding.as_dict() for finding in regressions],
        "security_review": [finding.as_dict() for finding in review],
        "changes": [change.as_dict() for change in changes],
        "exit_code": exit_code,
    }
