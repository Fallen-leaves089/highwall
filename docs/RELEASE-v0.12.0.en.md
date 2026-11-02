# HighWall 0.12.0 Alpha Pre-release

[简体中文](RELEASE-v0.12.0.md) | English

Status: GitHub pre-release (Alpha). This is a reviewable and testable pre-release, not a production release, and it carries no production support commitment. The latest stable version remains `0.11.0`; this release does not move `latest`.

## Included

- Exact client-IP plus request-shape enforcement keys; `/24` and `/64` are correlation-only and do not automatically widen bans.
- Read-only `highwall ops preview`; R2/R3 remain denied by default and no executor exists.
- `highwall capabilities --json` for the Python H1 baseline with explicit C0-C4 levels; native-core coverage is declared separately for H1/H2/H3.
- Standalone `subprojects/l5wall` 0.2.0: TLS termination, SNI/ALPN/mTLS policy, handshake timeout, loopback HTTP/1.1 bridge, SNI/Host consistency, and request-head/connection/byte bounds. L5Wall remains a standalone service release and is not folded into the Python wheel.
- The phase-1 `l5wall serve` path accepts loopback listeners and upstreams only and accepts only the `http/1.1` ALPN. H2/H3 are not presented as inspected.
- The loopback bridge does not preserve the original client IP; do not enable per-IP bans, source ACLs, or source-dependent rate limits behind it.
- Optional L4Wall `send_proxy_v2` emits a standard PROXY v2 TCP header upstream; the native core can require PROXY v2 and trust only explicitly configured proxy networks.
- Rust native B+D-4 core: TLS/QUIC, strict H1/H2/H3 parsing, H1 WebSocket, H2/H3 gRPC, compression/trailers, bounded-body WAF/DLP, exact-IP bans, mTLS/CRL, QUIC Retry, 0-RTT and migration disabled by default, and a QUIC client-network ACL.
- TCP and UDP are separate ingress paths: H1/H2 can pass through L4Wall and PROXY v2; H3 currently reaches the native QUIC listener directly without L4Wall.
- The Python image remains Python-only. The native core has a separate `Dockerfile.native`, runs as non-root, and does not pull Rust dependencies into the Python wheel or image.

## Release assets

The GitHub Release is expected to contain:

- `highwall-0.12.0-py3-none-any.whl` and `highwall-0.12.0.tar.gz`.
- Linux x86_64 native binary `highwall-native-core-0.12.0-linux-x86_64`.
- Windows x86_64 native binary `highwall-native-core-0.12.0-windows-x86_64.exe`.
- Native example configuration `highwall-native-config-0.12.0.example.json`.
- A `SHA256SUMS` file covering those assets.

The release workflow creates GitHub build provenance attestations for the assets. A separate container workflow publishes the Python-only image `ghcr.io/fallen-leaves089/highwall:0.12.0` for linux/amd64 and linux/arm64 with OCI provenance, SBOM, and a cosign signature; it is not a full B+D-4 image. `Dockerfile.native` is not published as a public GHCR image in this release; use the standalone binary from the Release for the native path.

## Verification

- Root Python suite: 384 tests passed; `coverage --branch` reported 81% total coverage, above the project's 80% gate. The native real-chain test is skipped by default and passes separately when explicitly enabled.
- L4Wall: 71 tests passed, including PROXY v2 encoding and upstream first bytes.
- L5Wall: 36 tests passed, including a real loopback TLS-to-HighWall chain, unknown ALPN, SNI/Host mismatch, malformed framing, oversized request heads, relay byte limits, and a cross-platform license consistency check.
- Native core: all 144 `cargo test --all-targets --locked` cases passed; `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, and the locked release build passed.
- `ruff`, `mypy` (30 root source files), `compileall`, parser fuzzing (2,000 iterations and 8,000 checks), example and strict configuration checks, and `highwall diff` passed.
- DSH first independent acceptance: 0 Critical, 0 High, 3 Medium, 8 Low, and 3 informational findings. The r5 directed retest found 0 Critical and 0 High: seven of eight scoped items closed (HWA-01/02/03/07/08/09/10); HWA-11 closed in the narrow r6 independent retest. HWA-04/05/06 were repeated by the maintainer's r7 repository tests, documented in [REGRESSION-R7-20261102.md](REGRESSION-R7-20261102.md). The r7 run is not DSH independent acceptance and must not be described as a DSH independent retest of those three items.
- Maintainer r7 directed results: all three HWA-04 duplicate-pseudo-header cases returned H3_MESSAGE_ERROR 270 with zero upstream hits; all four HWA-05 HEAD routes returned 200 with the correct Content-Length, a 0-byte body, and one upstream hit each; HWA-06 returned 200 with one upstream hit at 8192 bytes and 413 `HW-NATIVE-PROTOCOL-001` with zero upstream hits at 8193 bytes.
- The release-tag workflow repeats the root tests on Python 3.10-3.14 and repeats static analysis and tests on Linux and Windows native runners. Local results do not replace those remote results; check the Release and Container workflow runs before treating the pre-release as published.

## Deployment boundaries

- H1/H2/H3 remain declared at C3, not C4. Complete streaming backpressure saturation, QPACK blocking, real end-to-end WebSocket coverage, and broader slow-flow coverage remain incomplete.
- H3/UDP bypasses L4Wall. An application-level QUIC ACL does not replace a host firewall or security group. Deployments must add separate UDP source restrictions, rate limits, and ingress ACLs.
- A banned source can still complete a TLS/QUIC handshake before receiving HTTP 403. The current result proves application-layer rejection, not zero-cost pre-handshake blocking.
- Native bans are process-local with TTL and capacity bounds; they are lost on restart and not yet backed by a single-writer persistent state service.
- There is no independent attestation of the running process image; DSH's `runtime_process_image_evidence=false` / `process_image_independent_attestation=false` still applies. Release asset attestation proves build provenance, not that a particular running process is that build.
- The real Docker/HAProxy edge, the `standard` container topology, public distribution of the native image, a real multi-node state service, and audit-write-failure topology were not validated in this round. Docker remains an optional packaging/deployment layer and does not block the native executable path.
- Host firewall rules were not modified in this environment. Windows automatic rules can bind to an absolute binary path, so deployment must explicitly create and re-verify TCP/UDP Allow rules.
- This project has not completed an independent third-party security audit. DSH results are security-validation inputs, not an external audit certificate or production admission.

## Release gate and rollback

Do not label this version as a production release and do not describe C3 as C4 or complete protection. DSH's no-push recommendation for production release remains unchanged; this publication is limited to the Alpha pre-release and redacted, reproducible validation records.

Rollback: keep production on a pinned `0.11.0` artifact and its digest; do not depend on `latest`. To evaluate 0.12.0, use a fixed release asset, verify `SHA256SUMS` and build provenance, and complete an isolated ingress, real-source, H3/UDP network-blocking, and rollback exercise before any promotion.
