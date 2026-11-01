# Security Policy

## Supported versions

`0.2.x` is the current preview line. There is no long-term support commitment yet.

## Reporting

Do not open a public issue for a suspected vulnerability. Report it privately to the maintainer with:

- affected version and platform;
- a minimal reproduction or configuration;
- impact and whether the issue is reachable without local access;
- any suggested fix.

## Scope

L5Wall is a TLS session guard, not a complete application firewall. The following are documented limitations unless they violate the invariants in `docs/THREAT_MODEL.md`:

- TLS termination performed by another component before L5Wall;
- bandwidth DDoS, SYN floods, QUIC floods and link-layer attacks;
- a compromised host that can read process memory or replace certificates/configuration;
- clients that present an allowed SNI/ALPN while sending malicious application traffic;
- non-loopback listeners or upstreams (the current `serve` preview rejects them);
- HTTP/2, HTTP/3, WebSocket, gRPC or application-layer vulnerabilities;
- private keys or configuration files readable by other local users.

## Secrets

The server private key is referenced by path and is never printed by `inspect`. Do not place private keys in logs, command-line arguments or committed configuration. Test TLS material is generated at runtime under the Git-ignored `tests/fixtures/` directory, is valid only for loopback tests, and must never be reused in a deployment or release artifact.
