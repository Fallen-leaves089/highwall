# HighWall v0.11.0 + L4Wall 0.1.0

[简体中文](RELEASE-v0.11.0.md) | English

Release date: 2026-10-30

## Overview

`v0.11.0` expands the repository from a single HTTP/1.1 gateway into a composable two-layer defense baseline:

- **L4Wall 0.1.0**: a fail-closed TCP connection-level gateway for admission, concurrency and rate limits, timeouts, byte caps, behavior scoring, bans, and audit.
- **HighWall 0.11.0**: continues to handle HTTP/1.1 Host/method/path policy, WAF, DLP, response integrity, L7 rate limits, and honeypots.
- **Composite deployment**: provides the `lite` chain and a `standard` edge-proxy skeleton. Neither treats “components deployed” as “all ingress covered.”

## Added

### L4Wall subproject

- Connection-level source allowlists and default deny.
- Per-IP concurrency caps, new-connection rates, and burst control.
- First-byte, idle, total-duration, and per-direction byte limits.
- Behavior signals for multi-listener fan-out, short connections, zero-byte probes, rejection storms, and regular timing.
- Two-stage scoring, timed containment, confirmed bans, and `offenders.json` persistence.
- JSONL audit, a loopback admin plane, health checks, and Prometheus text metrics.
- An optional private-network Redis shared-ban reader with versioned JSON, strict validation, capacity limits, TTL clamping, local-first merge, and failure isolation.

### Composite deployment and attack validation

- `scripts/attack_range.py`: a local loopback range with a 28-item matrix across L4Wall -> HighWall -> a stub upstream; supports an isolated WSL attacker instance and a long-running mode.
- `deploy/standard/`: HAProxy, Compose, a TLS variant, an upstream echo service, and a bypass verification script.
- `docs/STACK.md`: trust boundaries, trusted client IPs, direct-access blocking, ban synchronization, failure policy, and an acceptance checklist.
- `docs/ATTACK_TESTING.md`: the automated matrix, live results, fixed issues, and unverified items.

## Fixes and hardening

- When the global in-flight limit is exceeded, the `503` response now includes `Retry-After: 1` and `X-Request-ID`; the audit record includes `request_id`, `HW-SERVER-1001`, `status=503`, `detail=inflight_limit`, and the real response byte count.
- `l4wall inspect` no longer prints password or admin-token environment variable names, with a redaction regression test.
- The range raises the L4 per-direction byte cap to 2 MiB so the HighWall `413` boundary is observable.
- Release packaging includes `subprojects/`, so the sdist no longer omits L4Wall sources.

## Verification

- HighWall: 354 tests passed.
- L4Wall: 65 tests passed.
- Cross-layer attack/defense: 26 end-to-end tests passed.
- `ruff`, `mypy`, `compileall`, configuration checks, and installation in a clean virtual environment passed.
- PR CI: Ubuntu and Windows on Python 3.10/3.11/3.12, CodeQL, and static analysis all passed.
- Live matrix: 28/28 passed, 0 failed; 2 known boundary risks are recorded separately and are not counted as passes.
- 40-connection retest: 31 `200` responses, 1 traceable `503`, and 8 connections without an HTTP response; L4 admitted 32 and rejected 8 with `ip_capacity`.
- Audit correlation: request IDs for allowed and blocked in-flight requests matched the client `X-Request-ID` in 32/32 cases.
- Byte boundary: 1,048,491 bytes returned `200`; 1,048,577 bytes returned `413` (`HW-PROTO-1106`).

## Downloads

The files are in the **Assets** section of the [v0.11.0 release](https://github.com/Fallen-leaves089/highwall/releases/tag/v0.11.0). Verify them against `SHA256SUMS` before installation:

```bash
python -m pip install highwall-0.11.0-py3-none-any.whl
python -m pip install l4wall-0.1.0-py3-none-any.whl
```

## Container image

The `v0.11.0` tag builds a multi-architecture image and publishes it to GHCR:

```bash
docker pull ghcr.io/fallen-leaves089/highwall:0.11.0
```

- Digest (linux/amd64 + linux/arm64 OCI index): `sha256:efedb3b9cca32a65f086c1a2ba89ae3c268a45e7a94a4158acfa5e8cda6c2dfc`
- Build workflow: https://github.com/Fallen-leaves089/highwall/actions/runs/41005104183
- The image includes an SBOM, a GitHub provenance attestation, and a cosign keyless signature. Pin an immutable version in production instead of relying on `latest`.

## Compatibility

- The HighWall HTTP/1.1 configuration schema has no breaking changes; `v0.10.0` configurations remain usable.
- L4Wall is a separate process and a separate `0.1.0` package; HighWall does not load it in-process.
- In the `lite` topology, HighWall sees L4Wall as its peer address. Use the `standard` skeleton when real client identity is required.

## Boundaries and unverified items

- HighWall 0.11.0 and L4Wall 0.1.0 are alpha releases and have not received an independent third-party security audit.
- L4Wall does not handle bandwidth DDoS, SYN floods, UDP, or QUIC/HTTP3, and does not replace application authentication, authorization, or host EDR.
- The `standard` skeleton currently covers ingress, trusted client IPs, network closure, L7 protection, and acceptance checks. The L4Wall Controller, dynamic ban publishing, and multi-node HA remain future milestones.
- Shared bans currently have a reader only. Automatic publishing, conflict merging, and the Controller are not implemented.
- The full Docker/HAProxy container topology still needs integration testing in the target environment; loopback success does not prove production-topology success.
- Direct access to HighWall or the upstream bypasses the L4 ACL; network ACLs and listener addresses must make those paths unreachable to attackers.
- This release does not claim “no bypasses.” See `docs/ATTACK_TESTING.md` and `docs/STACK.md` for unverified items and residual risk.
