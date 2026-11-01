"""TLS termination with a bounded, fail-closed handshake."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass

from .config import L5Config
from .policy import ClientMetadata, L5Decision, L5Policy, certificate_sha256


class L5HandshakeError(OSError):
    """The TLS handshake failed before a policy decision could be made."""


class L5Denied(OSError):
    """The TLS session was rejected by L5 policy."""

    def __init__(self, decision: L5Decision) -> None:
        super().__init__("TLS session rejected by policy")
        self.decision = decision


@dataclass
class L5Connection:
    socket: ssl.SSLSocket
    decision: L5Decision

    def close(self) -> None:
        self.socket.close()


class L5Wall:
    """TLS handshake guard; L7 parsing and reverse proxying are out of scope."""

    def __init__(self, config: L5Config) -> None:
        self.config = config
        self.policy = L5Policy(config)
        self.context = build_tls_context(config)

    def wrap(self, raw_socket: socket.socket) -> L5Connection:
        previous_timeout = raw_socket.gettimeout()
        raw_socket.settimeout(self.config.handshake_timeout)
        started = time.monotonic()
        try:
            tls_socket = self.context.wrap_socket(raw_socket, server_side=True)
        except (ssl.SSLError, TimeoutError, OSError) as exc:
            try:
                raw_socket.close()
            except OSError:
                pass
            raise L5HandshakeError("TLS handshake failed or timed out") from exc

        elapsed_ms = int((time.monotonic() - started) * 1000)
        peer_cert = tls_socket.getpeercert(binary_form=True)
        metadata = ClientMetadata(
            tls_version=_tls_version_name(tls_socket.version() or ""),
            cipher=(tls_socket.cipher() or ("", "", 0))[0],
            alpn=tls_socket.selected_alpn_protocol() or "",
            sni=str(getattr(tls_socket, "_l5wall_sni", "") or ""),
            peer_cert_sha256=certificate_sha256(peer_cert) if peer_cert else "",
            handshake_ms=elapsed_ms,
        )
        decision = self.policy.evaluate(metadata)
        if not decision.allowed:
            tls_socket.close()
            raise L5Denied(decision)
        try:
            tls_socket.settimeout(previous_timeout)
        except OSError:
            pass
        return L5Connection(socket=tls_socket, decision=decision)


def build_tls_context(config: L5Config) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3 if config.min_version == "TLSv1_3" else ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        context.options |= ssl.OP_NO_RENEGOTIATION
    context.set_alpn_protocols(list(config.allowed_alpn))
    if config.mtls_mode == "required":
        context.verify_mode = ssl.CERT_REQUIRED
    elif config.mtls_mode == "optional":
        context.verify_mode = ssl.CERT_OPTIONAL
    else:
        context.verify_mode = ssl.CERT_NONE
    if config.client_ca_file is not None:
        context.load_verify_locations(cafile=str(config.client_ca_file))
    context.load_cert_chain(certfile=str(config.cert_file), keyfile=str(config.key_file))
    context.sni_callback = _capture_sni
    return context


def _capture_sni(ssl_socket: ssl.SSLSocket | ssl.SSLObject, server_name: str, _context: ssl.SSLContext) -> None:
    try:
        setattr(ssl_socket, "_l5wall_sni", server_name or "")
    except (AttributeError, TypeError):
        return


def _tls_version_name(value: str) -> str:
    return value.replace("TLSv", "TLS")
