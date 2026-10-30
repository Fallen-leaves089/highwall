"""Request policy enforcement and conservative application-layer signatures.

This is a defensive normalization layer, not a substitute for authentication,
authorization, output encoding, or upstream patching.
"""

from __future__ import annotations

import html
import ipaddress
import json
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Iterable

from .config import (
    ConfigError,
    HoneypotRoute,
    PolicyConfig,
    RouteConfig,
    canonicalize_host,
    canonicalize_origin,
)
from .errors import (
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    PayloadTooLarge,
    UnsupportedMediaType,
)
from .protocol import RequestHead, header_values, single_header

_MAX_DECODE_ROUNDS = 4
_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_VALID_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_ENCODED_SEPARATOR_RE = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_DOT_SEGMENT_RE = re.compile(r"(?:^|[/\\])\.\.?($|[/\\])")
_UNSAFE_PATH_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_PATH_FORWARD_SAFE = "/:@!$&'()*+,;=-._~"
_UTF8_CHARSETS = {"utf-8", "utf8", "us-ascii", "ascii"}
_AMBIGUOUS_BODY_PREFIXES = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff", b"\x00\x00\xff\xfe")


@dataclass(frozen=True)
class HeadInspection:
    method: str
    target: str
    path: str
    route_path: str
    query: str
    host: str
    client_ip: str
    content_type: str | None
    waf_hit: str | None
    charset: str | None = None
    route: RouteConfig | None = None
    honeypot: HoneypotRoute | None = None
    upstream_target: str = ""


@dataclass(frozen=True)
class WafHit:
    rule_id: str
    category: str


def normalize_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise BadRequest("invalid client address", rule_id="HW-XFF-1001") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def _is_trusted(address: ipaddress.IPv4Address | ipaddress.IPv6Address, policy: PolicyConfig) -> bool:
    return any(address in network for network in policy.proxy_networks)


def _check_client_network(client_ip: str, policy: PolicyConfig) -> None:
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError as exc:
        raise BadRequest("invalid client address", rule_id="HW-ACL-1003") from exc
    if any(address in network for network in policy.denied_client_networks):
        raise Forbidden("client network is explicitly denied", rule_id="HW-ACL-1002")
    if policy.allowed_client_networks and not any(address in network for network in policy.allowed_client_networks):
        raise Forbidden("client network is not allowed", rule_id="HW-ACL-1001")


def _check_route_client_network(client_ip: str, route: RouteConfig) -> None:
    if not route.allowed_client_networks:
        return
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError as exc:
        raise BadRequest("invalid client address", rule_id="HW-ACL-1103") from exc
    if not any(address in network for network in route.allowed_client_networks):
        raise Forbidden("client network is not allowed for this route", rule_id="HW-ACL-1101")


def _check_origin(head: RequestHead, policy: PolicyConfig) -> None:
    if not policy.allowed_origins:
        return
    origin_value = single_header(head.headers, "origin")
    if origin_value is not None:
        try:
            origin = canonicalize_origin(origin_value)
        except ConfigError as exc:
            raise BadRequest("invalid Origin header", rule_id="HW-CSRF-1003") from exc
        if origin not in policy.allowed_origins:
            raise Forbidden("Origin is not allowed", rule_id="HW-CSRF-1002")
    elif head.method in _UNSAFE_METHODS:
        raise Forbidden("unsafe method requires an Origin header", rule_id="HW-CSRF-1001")

    fetch_site = single_header(head.headers, "sec-fetch-site")
    if fetch_site is not None and fetch_site.strip().lower() == "cross-site" and head.method in _UNSAFE_METHODS:
        raise Forbidden("cross-site write requests are not allowed", rule_id="HW-CSRF-1004")


def resolve_client_ip(head: RequestHead, policy: PolicyConfig) -> str:
    peer = ipaddress.ip_address(normalize_ip(head.client_ip))
    values = header_values(head.headers, "x-forwarded-for")
    if len(values) > 1:
        raise BadRequest("multiple X-Forwarded-For headers", rule_id="HW-XFF-1002")
    if not values or not _is_trusted(peer, policy):
        return str(peer)
    parts = [part.strip() for part in values[0].split(",") if part.strip()]
    if not parts or len(parts) > policy.max_xff_hops:
        raise BadRequest("invalid X-Forwarded-For chain", rule_id="HW-XFF-1003")
    chain: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for part in parts:
        try:
            chain.append(ipaddress.ip_address(part))
        except ValueError as exc:
            raise BadRequest("invalid X-Forwarded-For address", rule_id="HW-XFF-1003") from exc
    chain.append(peer)
    for address in reversed(chain):
        if not _is_trusted(address, policy):
            return str(address)
    return str(chain[0])


def _decode_component(value: str, reject_encoded_separators: bool, where: str) -> str:
    current = value
    for _ in range(_MAX_DECODE_ROUNDS):
        if reject_encoded_separators and _ENCODED_SEPARATOR_RE.search(current):
            raise BadRequest(f"encoded path separators are not allowed in {where}", rule_id="HW-PATH-1001")
        try:
            decoded = urllib.parse.unquote(current, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise BadRequest(f"invalid UTF-8 escape in {where}", rule_id="HW-PATH-1002") from exc
        if decoded == current:
            return current
        current = decoded
    if _VALID_PERCENT_RE.search(current):
        raise BadRequest(f"excessive path encoding in {where}", rule_id="HW-PATH-1003")
    return current


def _check_path_segments(path: str) -> None:
    for segment in path.split("/"):
        for part in segment.split(";"):
            base = part.strip(" ")
            if base in {".", ".."}:
                raise BadRequest("dot segments are not allowed", rule_id="HW-PATH-1004")
    if _DOT_SEGMENT_RE.search(path):
        raise BadRequest("ambiguous dot segments", rule_id="HW-PATH-1004")


def _check_ambiguous_path(path: str, policy: PolicyConfig) -> None:
    if not policy.allow_path_parameters and ";" in path:
        raise BadRequest("path parameters are not allowed", rule_id="HW-PATH-1010")
    if policy.allow_trailing_dot_or_space:
        return
    for segment in path.split("/"):
        if segment and segment[-1] in {".", " "}:
            raise BadRequest("ambiguous trailing dot or space in path", rule_id="HW-PATH-1011")


def _routing_path(path: str, policy: PolicyConfig) -> str:
    current = path
    if policy.allow_path_parameters:
        current = "/".join(segment.split(";", 1)[0] for segment in current.split("/"))
    if policy.allow_trailing_dot_or_space:
        current = "/".join(segment.rstrip(" .") for segment in current.split("/"))
    return current


def _canonical_target(path: str, query_raw: str, has_query: bool) -> str:
    encoded = urllib.parse.quote(
        path,
        safe=_PATH_FORWARD_SAFE,
        encoding="utf-8",
        errors="strict",
    )
    # Keep the query delimiters and application semantics intact. The WAF scans a
    # repeatedly decoded view, so forwarding the original query cannot hide a
    # payload that the scanner has already inspected.
    return encoded + ("?" + query_raw if has_query else "")


def _normalize_target(target: str, policy: PolicyConfig) -> tuple[str, str, str, str]:
    if _PERCENT_ESCAPE_RE.search(target):
        raise BadRequest("invalid percent escape", rule_id="HW-PATH-1005")
    path_raw, separator, query_raw = target.partition("?")
    if not path_raw.startswith("/") or path_raw.startswith("//"):
        raise BadRequest("ambiguous path", rule_id="HW-PATH-1006")
    if "\\" in path_raw or "#" in target:
        raise BadRequest("unsafe path character", rule_id="HW-PATH-1007")
    path = _decode_component(path_raw, policy.reject_encoded_separators, "path")
    if path.startswith("//") or any(marker in path for marker in ("\\", "?", "#")) or _UNSAFE_PATH_CHARS_RE.search(path):
        raise BadRequest("unsafe decoded path", rule_id="HW-PATH-1008")
    _check_path_segments(path)
    normalized = unicodedata.normalize("NFKC", path)
    if normalized.startswith("//") or any(marker in normalized for marker in ("\\", "?", "#")) or _UNSAFE_PATH_CHARS_RE.search(normalized):
        raise BadRequest("normalized path contains ambiguous characters", rule_id="HW-PATH-1008")
    _check_path_segments(normalized)
    _check_ambiguous_path(normalized, policy)

    query = ""
    if separator:
        if _PERCENT_ESCAPE_RE.search(query_raw):
            raise BadRequest("invalid percent escape in query", rule_id="HW-PATH-1005")
        query = _decode_component(query_raw, False, "query")
        if _UNSAFE_PATH_CHARS_RE.search(query):
            raise BadRequest("unsafe decoded query", rule_id="HW-PATH-1009")
    route_path = _routing_path(normalized, policy)
    return normalized, query, route_path, _canonical_target(normalized, query_raw, bool(separator))


def _path_allowed(path: str, prefixes: Iterable[str]) -> bool:
    folded_path = path.casefold()
    for prefix in prefixes:
        if prefix == "/":
            return True
        base = prefix.rstrip("/").casefold()
        if folded_path == base or folded_path.startswith(base + "/"):
            return True
    return False


def _route_for_path(path: str, policy: PolicyConfig) -> RouteConfig | None:
    for route in policy.routes:
        if _path_allowed(path, (route.path_prefix,)):
            return route
    return None


def _honeypot_for_path(path: str, policy: PolicyConfig) -> HoneypotRoute | None:
    if not policy.honeypot.enabled:
        return None
    for route in policy.honeypot.routes:
        if route.path.casefold() == path.casefold():
            return route
    return None


def _denied_path(path: str, prefixes: Iterable[str]) -> bool:
    folded_path = path.casefold()
    for prefix in prefixes:
        base = prefix.rstrip("/").casefold()
        if base and folded_path.startswith(base):
            return True
    return False


def _parse_content_type(value: str) -> tuple[str, str | None]:
    parts = value.split(";")
    base = parts[0].strip().lower()
    if not base or "/" not in base:
        raise UnsupportedMediaType("invalid Content-Type", rule_id="HW-BODY-1001")
    charset: str | None = None
    for part in parts[1:]:
        key, separator, raw_value = part.partition("=")
        if not separator:
            raise UnsupportedMediaType("invalid Content-Type parameter", rule_id="HW-BODY-1001")
        parameter = key.strip().lower()
        parameter_value = raw_value.strip().strip('"').lower()
        if parameter != "charset":
            continue
        if charset is not None or not parameter_value or len(parameter_value) > 40:
            raise UnsupportedMediaType("invalid Content-Type charset", rule_id="HW-BODY-1001")
        if not re.fullmatch(r"[a-z0-9._-]+", parameter_value):
            raise UnsupportedMediaType("invalid Content-Type charset", rule_id="HW-BODY-1001")
        charset = parameter_value
    return base, charset


def _scan_head(head: RequestHead, path: str, query: str, policy: PolicyConfig) -> str | None:
    if not policy.waf_enabled or not policy.waf_rules:
        return None
    texts = [urllib.parse.unquote(path), urllib.parse.unquote_plus(query)]
    texts.extend(f"{name}: {value}" for name, value in head.headers)
    hit = inspect_texts(texts, policy.waf_rules)
    if hit is not None and policy.waf_mode == "block":
        raise Forbidden("request blocked by WAF", rule_id=hit.rule_id)
    return hit.rule_id if hit is not None else None


def validate_head(head: RequestHead, client_ip: str, policy: PolicyConfig) -> HeadInspection:
    _check_client_network(client_ip, policy)
    host_value = single_header(head.headers, "host")
    if host_value is None or not host_value:
        raise BadRequest("Host header is required", rule_id="HW-HOST-1001")
    try:
        host = canonicalize_host(host_value)
    except ConfigError as exc:
        raise BadRequest("invalid Host header", rule_id="HW-HOST-1002") from exc
    if host not in policy.allowed_hosts:
        raise Forbidden("Host is not in the allowlist", rule_id="HW-HOST-1003")

    path, query, route_path, upstream_target = _normalize_target(head.target, policy)
    honeypot = _honeypot_for_path(route_path, policy)
    if honeypot is not None:
        return HeadInspection(
            method=head.method,
            target=head.target,
            path=path,
            route_path=route_path,
            query=query,
            host=host,
            client_ip=client_ip,
            content_type=None,
            waf_hit=None,
            honeypot=honeypot,
            upstream_target=upstream_target,
        )

    if head.method not in policy.allowed_methods:
        raise MethodNotAllowed(
            "method is not allowed",
            rule_id="HW-METHOD-1001",
            allow=tuple(dict.fromkeys(policy.allowed_methods)),
        )
    if not _path_allowed(route_path, policy.allowed_path_prefixes):
        raise Forbidden("path is outside the allowed prefixes", rule_id="HW-PATH-1101")
    if _denied_path(route_path, policy.deny_path_prefixes):
        raise Forbidden("path is explicitly denied", rule_id="HW-PATH-1102")
    route = _route_for_path(route_path, policy)
    if route is not None:
        _check_route_client_network(client_ip, route)
        if route.methods is not None and head.method not in route.methods:
            raise MethodNotAllowed(
                "method is not allowed for this route",
                rule_id="HW-METHOD-1102",
                allow=tuple(dict.fromkeys(route.methods)),
            )
        if route.max_body_bytes is not None and head.content_length > route.max_body_bytes:
            raise PayloadTooLarge("request body exceeds the route limit", rule_id="HW-BODY-1105")
    if (policy.read_only or (route is not None and route.read_only)) and head.method in _UNSAFE_METHODS:
        raise Forbidden("gateway is in read-only mode", rule_id="HW-MODE-1001")
    _check_origin(head, policy)
    content_type_value = single_header(head.headers, "content-type")
    content_type, charset = _parse_content_type(content_type_value) if content_type_value else (None, None)
    if head.content_length > 0:
        if head.method in {"GET", "HEAD"} and policy.reject_get_body:
            raise BadRequest("body is not allowed for this method", rule_id="HW-BODY-1002")
        if content_type is None:
            raise UnsupportedMediaType("Content-Type is required for a body", rule_id="HW-BODY-1003")
        if content_type not in policy.allowed_body_content_types:
            raise UnsupportedMediaType("request body media type is not allowed", rule_id="HW-BODY-1004")
        if charset is not None and charset not in _UTF8_CHARSETS:
            raise UnsupportedMediaType("request body charset must be UTF-8 or ASCII", rule_id="HW-BODY-1006")
    waf_hit = _scan_head(head, path, query, policy)
    return HeadInspection(
        method=head.method,
        target=head.target,
        path=path,
        route_path=route_path,
        query=query,
        host=host,
        client_ip=client_ip,
        content_type=content_type,
        waf_hit=waf_hit,
        charset=charset,
        route=route,
        upstream_target=upstream_target,
    )


def _normalize_for_scan(value: str) -> str:
    current = value
    for _ in range(_MAX_DECODE_ROUNDS):
        try:
            decoded = urllib.parse.unquote_plus(current, encoding="utf-8", errors="replace")
        except (UnicodeDecodeError, ValueError):
            break
        if decoded == current:
            break
        current = decoded
    current = html.unescape(current)
    current = unicodedata.normalize("NFKC", current)
    return re.sub(r"\s+", " ", current.lower())


_SQLI_PATTERNS = [
    re.compile(r"(?:'|\"|`)\s*(?:or|and)\s+(?:['\"]?\w+['\"]?|\d+)\s*(?:=|like)\s*(?:['\"]?\w+['\"]?|\d+)", re.I | re.S),
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I | re.S),
    re.compile(
        r"\bunion(?:\s|/\*(?:[^*]|\*(?!/))*\*/)+(?:all(?:\s|/\*(?:[^*]|\*(?!/))*\*/)+)?select\b",
        re.I | re.S,
    ),
    re.compile(r"/\*!\d*\s*(?:union|select|or|and)\b", re.I | re.S),
    re.compile(r"\b(?:sleep|benchmark|pg_sleep)\s*\(", re.I | re.S),
    re.compile(r"\binformation_schema\b", re.I | re.S),
    re.compile(r"\b(?:drop|truncate|alter)\s+(?:table|database|schema)\b", re.I | re.S),
    re.compile(r"\bwaitfor\s+delay\b", re.I | re.S),
    re.compile(r"\bxp_cmdshell\b", re.I | re.S),
    re.compile(r"\b(?:load_file|into\s+(?:out|dump)file)\b", re.I | re.S),
    re.compile(r"\b(?:or|and)\s+1\s*=\s*1\b", re.I | re.S),
]

_XSS_PATTERNS = [
    re.compile(r"<\s*script\b", re.I | re.S),
    re.compile(r"\bjavascript\s*:", re.I | re.S),
    re.compile(r"\bon(?:error|load|click|mouseover|focus|submit|toggle|animationstart)\s*=", re.I | re.S),
    re.compile(
        r"\bonpointer(?:over|out|down|up|move|enter|leave|cancel|rawupdate|lockchange|lockerror|gotcapture|lostcapture)\s*=",
        re.I | re.S,
    ),
    re.compile(r"<\s*[a-z][^>]{0,512}\bon[a-z]{3,20}\s*=", re.I | re.S),
    re.compile(r"<\s*(?:iframe|object|embed|svg)\b", re.I | re.S),
    re.compile(r"\bdata:text/html", re.I | re.S),
    re.compile(r"\bdocument\.(?:cookie|domain|write|location)\b", re.I | re.S),
]

_TRAVERSAL_PATTERNS = [
    re.compile(r"\.{2,}[\x00-\x20]*[/\\]", re.I | re.S),
    re.compile(r"\.{2,}[\x00-\x20]*%(?:2f|5c)", re.I | re.S),
    re.compile(r"(?:^|[^.\w])\.{2,}[\x00-\x20]*(?:[;?#]|$)", re.I | re.S),
]

_CMDI_PATTERNS = [
    re.compile(r"(?:;|&&|\|\||\|)\s*(?:/bin/)?(?:ba|z|k|da)?sh\b", re.I | re.S),
    re.compile(r"(?:;|&&|\|\||\|)\s*(?:cmd(?:\.exe)?|powershell(?:\.exe)?)\b", re.I | re.S),
    re.compile(r"\$\([^)]{1,200}\)", re.I | re.S),
    re.compile(r"`[^`]{1,200}`", re.I | re.S),
    re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]{0,60}\s-e\b", re.I | re.S),
    re.compile(r"\b(?:wget|curl)\s+https?://", re.I | re.S),
    re.compile(r"\b(?:python|perl|ruby)\s+-c\b", re.I | re.S),
    re.compile(
        r"(?:;|&&|\|\||\|)\s*(?:cat|id|whoami|uname|ls|dir|type|curl|wget|ping|nslookup|dig)\b",
        re.I | re.S,
    ),
]

_JNDI_PATTERNS = [
    re.compile(r"\$\{jndi:(?:ldap|rmi|dns|http)s?:", re.I | re.S),
]

_SSRF_PATTERNS = [
    re.compile(r"\b(?:file|gopher|dict)://", re.I | re.S),
    re.compile(r"https?://(?:127\.|0\.0\.0\.0|169\.254\.169\.254|localhost\b|\[::1\])", re.I | re.S),
    re.compile(r"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)", re.I | re.S),
    re.compile(r"https?://(?:0x[0-9a-f]+|\d{8,10})(?:[:/]|$)", re.I | re.S),
    re.compile(r"https?://\[[^\]]*(?:::ffff:|::1\b|127\.)", re.I | re.S),
    re.compile(r"https?://[^/\s]+\.localhost\b", re.I | re.S),
    re.compile(r"https?://0(?:[:/]|$)", re.I | re.S),
]

_RULES: dict[str, tuple[str, list[re.Pattern[str]]]] = {
    "sqli": ("HW-WAF-SQLI-1001", _SQLI_PATTERNS),
    "xss": ("HW-WAF-XSS-1001", _XSS_PATTERNS),
    "traversal": ("HW-WAF-TRAVERSAL-1001", _TRAVERSAL_PATTERNS),
    "cmdi": ("HW-WAF-CMDI-1001", _CMDI_PATTERNS),
    "jndi": ("HW-WAF-JNDI-1001", _JNDI_PATTERNS),
    "ssrf": ("HW-WAF-SSRF-1001", _SSRF_PATTERNS),
}


def inspect_texts(values: Iterable[str], enabled_rules: Iterable[str]) -> WafHit | None:
    normalized: list[str] = []
    for value in values:
        base = _normalize_for_scan(value)
        normalized.append(base)
        without_comments = re.sub(r"/\*.*?\*/", " ", base, flags=re.S)
        if without_comments != base:
            normalized.append(re.sub(r"\s+", " ", without_comments))
    for category in enabled_rules:
        rule_entry = _RULES.get(category)
        if rule_entry is None:
            continue
        rule_id, patterns = rule_entry
        for text in normalized:
            for pattern in patterns:
                if pattern.search(text):
                    return WafHit(rule_id=rule_id, category=category)
    return None


def inspect_body(
    body: bytes,
    content_type: str | None,
    policy: PolicyConfig,
    charset: str | None = None,
) -> str | None:
    _reject_ambiguous_body_encoding(body)
    if not body or not policy.waf_enabled or not policy.waf_rules or content_type is None:
        return None
    if charset is not None and charset not in _UTF8_CHARSETS:
        raise UnsupportedMediaType("request body charset must be UTF-8 or ASCII", rule_id="HW-BODY-1006")
    text = body.decode("utf-8", errors="replace")
    values = [text]
    if content_type == "application/json":
        try:
            parsed = json.loads(text)
            canonical = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
            if canonical != text:
                values.append(canonical)
        except (json.JSONDecodeError, RecursionError, ValueError):
            pass
    hit = inspect_texts(values, policy.waf_rules)
    if hit is not None and policy.waf_mode == "block":
        raise Forbidden("request body blocked by WAF", rule_id=hit.rule_id)
    return hit.rule_id if hit is not None else None


def _reject_ambiguous_body_encoding(body: bytes) -> None:
    """Reject UTF-16/32 BOMs and NUL-bearing bodies before any text scan."""

    if not body:
        return
    if body.startswith(_AMBIGUOUS_BODY_PREFIXES) or b"\x00" in body:
        raise UnsupportedMediaType(
            "request body must be UTF-8 or ASCII without NUL bytes",
            rule_id="HW-BODY-1007",
        )
