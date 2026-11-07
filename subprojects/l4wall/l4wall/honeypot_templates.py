"""Bounded TCP honeypot templates.

These templates provide a synthetic banner and, where useful, a single
request/response exchange. They are deliberately not full protocol emulators:
they never read files, authenticate users, or contact another service.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HoneypotRule:
    expect: bytes
    reply: bytes


@dataclass(frozen=True)
class TcpHoneypotTemplate:
    name: str
    banner: bytes
    rules: tuple[HoneypotRule, ...] = ()
    default_reply: bytes = b""
    close_after_banner: bool = False
    close_after_reply: bool = True
    max_exchanges: int = 1


def _http_response(status: str, content_type: str, body: bytes) -> bytes:
    return (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii") + body


def _json_body(value: Any) -> bytes:
    return json.dumps(value, indent=2, ensure_ascii=True).encode("ascii") + b"\n"


def _mysql_handshake() -> bytes:
    payload = (
        b"\x0a"
        b"5.7.44-decoy\x00"
        + struct.pack("<I", 1)
        + b"abcdefgh"
        + b"\x00"
        + b"\xff\xf7"
        + b"\x21"
        + b"\x02\x00"
        + b"\xff\x81"
        + b"\x15"
        + (b"\x00" * 10)
        + b"mysql_native_password\x00"
    )
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


_GENERIC_HTTP = _http_response(
    "200 OK",
    "text/html; charset=utf-8",
    b"<!doctype html><html><head><title>Service</title></head>"
    b"<body><h1>Service available</h1></body></html>\n",
)

_DOCKER_HTTP = _http_response(
    "200 OK",
    "application/json",
    _json_body({"ApiVersion": "1.43", "Version": "24.0.7", "Os": "linux", "Arch": "amd64"}),
)

_ELASTICSEARCH_HTTP = _http_response(
    "200 OK",
    "application/json",
    _json_body(
        {
            "cluster_name": "decoy-cluster",
            "status": "yellow",
            "number_of_nodes": 3,
            "active_primary_shards": 12,
            "active_shards": 24,
            "unassigned_shards": 2,
        }
    ),
)

_KUBERNETES_HTTP = _http_response(
    "401 Unauthorized",
    "application/json",
    _json_body(
        {
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": "Unauthorized",
            "reason": "Unauthorized",
            "code": 401,
        }
    ),
)


def _template(
    name: str,
    *,
    banner: bytes = b"",
    rules: tuple[HoneypotRule, ...] = (),
    default_reply: bytes = b"",
    close_after_banner: bool = False,
    close_after_reply: bool = True,
    max_exchanges: int = 1,
) -> TcpHoneypotTemplate:
    return TcpHoneypotTemplate(
        name=name,
        banner=banner,
        rules=rules,
        default_reply=default_reply,
        close_after_banner=close_after_banner,
        close_after_reply=close_after_reply,
        max_exchanges=max_exchanges,
    )


HONEYPOT_TEMPLATES: dict[str, TcpHoneypotTemplate] = {
    "ssh": _template("ssh", banner=b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"),
    "telnet": _template(
        "telnet",
        banner=b"Ubuntu 22.04.4 LTS\r\nlogin: ",
        default_reply=b"Password: ",
    ),
    "ftp": _template(
        "ftp",
        banner=b"220 (vsFTPd 3.0.5)\r\n",
        default_reply=b"331 Please specify the password.\r\n",
    ),
    "smtp": _template(
        "smtp",
        banner=b"220 mail.internal.invalid ESMTP Postfix\r\n",
        default_reply=b"250-mail.internal.invalid\r\n250-PIPELINING\r\n250 AUTH LOGIN PLAIN\r\n",
    ),
    "pop3": _template(
        "pop3",
        banner=b"+OK Dovecot ready.\r\n",
        default_reply=b"-ERR [AUTH] Authentication failed.\r\n",
    ),
    "imap": _template(
        "imap",
        banner=b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] Dovecot ready.\r\n",
        default_reply=b"A1 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n",
    ),
    "redis": _template(
        "redis",
        rules=(
            HoneypotRule(b"PING", b"+PONG\r\n"),
            HoneypotRule(b"QUIT", b"+OK\r\n"),
        ),
        default_reply=b"-NOAUTH Authentication required.\r\n",
    ),
    "memcached": _template(
        "memcached",
        rules=(
            HoneypotRule(b"version", b"VERSION 1.6.21\r\n"),
            HoneypotRule(b"stats", b"STAT pid 1\r\nSTAT version 1.6.21\r\nEND\r\n"),
        ),
        default_reply=b"ERROR\r\n",
    ),
    "mysql": _template(
        "mysql",
        banner=_mysql_handshake(),
        default_reply=b"\x17\x00\x00\x02\xff\x15\x04#28000Access denied for user 'root'@'localhost'\x00",
    ),
    "postgresql": _template(
        "postgresql",
        default_reply=b"R\x00\x00\x00\x08\x00\x00\x00\x03",
    ),
    "mqtt": _template(
        "mqtt",
        rules=(HoneypotRule(b"\x10", b"\x20\x02\x00\x05"),),
        default_reply=b"\x20\x02\x00\x05",
    ),
    "vnc": _template(
        "vnc",
        banner=b"RFB 003.008\n",
        default_reply=b"\x01\x02",
    ),
    "rtsp": _template(
        "rtsp",
        default_reply=(
            b"RTSP/1.0 401 Unauthorized\r\n"
            b"CSeq: 1\r\n"
            b'WWW-Authenticate: Basic realm="camera"\r\n'
            b"Content-Length: 0\r\n\r\n"
        ),
    ),
    "sip": _template(
        "sip",
        default_reply=(
            b"SIP/2.0 401 Unauthorized\r\n"
            b"Via: SIP/2.0/UDP 127.0.0.1\r\n"
            b"From: <sip:probe@invalid>;tag=decoy\r\n"
            b"To: <sip:probe@invalid>;tag=decoy\r\n"
            b"Call-ID: decoy@invalid\r\n"
            b"CSeq: 1 OPTIONS\r\n"
            b"Content-Length: 0\r\n\r\n"
        ),
    ),
    "ldap": _template(
        "ldap",
        default_reply=b"0\x0c\x02\x01\x01a\x07\n\x01\x31\x04\x00\x04\x00",
    ),
    "modbus": _template(
        "modbus",
        default_reply=b"\x00\x01\x00\x00\x00\x03\x01\x81\x01",
    ),
    "socks5": _template("socks5", default_reply=b"\x05\xff"),
    "rdp": _template("rdp", default_reply=b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"),
    "rsync": _template(
        "rsync",
        banner=b"@RSYNCD: 31.0\n",
        default_reply=b"@ERROR: Unknown module\n",
    ),
    "irc": _template(
        "irc",
        banner=b":irc.internal.invalid NOTICE AUTH :*** Looking up your hostname\r\n",
        default_reply=b":irc.internal.invalid 464 * :Password incorrect\r\n",
    ),
    "amqp": _template("amqp", banner=b"AMQP\x00\x00\x09\x01"),
    "git": _template("git", banner=b"001e# service=git-upload-pack\n0000"),
    "http": _template("http", default_reply=_GENERIC_HTTP),
    "docker": _template("docker", default_reply=_DOCKER_HTTP),
    "elasticsearch": _template("elasticsearch", default_reply=_ELASTICSEARCH_HTTP),
    "kubernetes": _template("kubernetes", default_reply=_KUBERNETES_HTTP),
    "xmpp": _template(
        "xmpp",
        banner=(
            b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
            b"xmlns:stream='http://etherx.jabber.org/streams' "
            b"from='xmpp.internal.invalid' version='1.0'>"
        ),
        default_reply=(
            b"<stream:error><not-authorized "
            b"xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"
        ),
    ),
    "stomp": _template(
        "stomp",
        default_reply=b"ERROR\nmessage:authentication failed\n\n\x00",
    ),
}

HONEYPOT_TEMPLATE_NAMES = tuple(HONEYPOT_TEMPLATES)
