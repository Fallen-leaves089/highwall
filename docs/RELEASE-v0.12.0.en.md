# HighWall 0.12.0.dev0 development snapshot (unreleased)

[简体中文](RELEASE-v0.12.0.md) | English

Status: unreleased development snapshot; not a production release and without a production support commitment.

## Included

- Exact client-IP plus request-shape enforcement keys; `/24` and `/64` are correlation-only and do not automatically widen bans.
- Read-only `highwall ops preview`; R2/R3 remain denied by default and no executor exists.
- `highwall capabilities --json` for the Python H1 baseline with explicit C0-C4 levels; native-core coverage is declared separately for H1/H2/H3.
- Standalone `subprojects/l5wall` 0.2.0: TLS termination, SNI/ALPN/mTLS policy, handshake timeout, loopback HTTP/1.1 bridge, SNI/Host consistency, and request-head/connection/byte bounds.
- The phase-1 `l5wall serve` path accepts loopback listeners and upstreams only and accepts only the `http/1.1` ALPN. H2/H3 are not presented as inspected.
- The loopback bridge does not preserve the original client IP; do not enable per-IP bans, source ACLs, or source-dependent rate limits behind it.
- Optional L4Wall `send_proxy_v2` emits a standard PROXY v2 TCP header upstream; the native core can require PROXY v2 and trust only explicitly configured proxy networks.
- Rust native B+D-4 core: TLS/QUIC, strict H1/H2/H3 parsing, H1 WebSocket, H2/H3 gRPC, compression/trailers, bounded-body WAF/DLP, exact-IP bans, mTLS/CRL, QUIC Retry, 0-RTT and migration disabled by default, and a QUIC client-network ACL.
- TCP and UDP are separate ingress paths: H1/H2 can pass through L4Wall and PROXY v2; H3 currently reaches the native QUIC listener directly without L4Wall.
- The Python image remains Python-only. The native core has a separate `Dockerfile.native`, runs as non-root, and does not pull Rust dependencies into the Python wheel or image.

## Verification

- Root Python suite: full regression passed; the native real-chain test is skipped by default and passes separately when explicitly enabled, at 81% branch coverage.
- L4Wall: 71 tests passed, including PROXY v2 encoding and upstream first bytes.
- L5Wall: 34 tests passed, including a real loopback TLS-to-HighWall chain, unknown ALPN, SNI/Host mismatch, malformed framing, oversized request heads, and relay byte limits.
- Native core: all 143 `cargo test --all-targets --locked` cases passed; `cargo fmt`, `cargo clippy --locked -D warnings`, and the locked release build passed.
- DSH first independent acceptance: 0 Critical, 0 High, 3 Medium, 8 Low, and 3 informational findings. The r5 directed retest found 0 Critical and 0 High: seven of eight scoped items closed (HWA-01/02/03/07/08/09/10); HWA-11 closed in the narrow r6 retest, and HWA-04/05/06 were not retested in r5/r6. See [DSH-R5-RESULTS-20261101.md](DSH-R5-RESULTS-20261101.md) and [DSH-R6-RESULTS-20261101.md](DSH-R6-RESULTS-20261101.md).
- The explicitly enabled real L4Wall-to-native chain passed one test, validating PROXY v2 source recovery and upstream delivery.
- `ruff`, `mypy`, `compileall`, parser fuzzing, example and strict configuration checks, and `highwall diff` passed.
- CI now has a locked `native-core` job and a `Dockerfile.native` image-build check. Local configuration validation passes; remote execution status is determined by the release PR CI run.

## Still uncovered

- The r5/r6 directed closures are not full acceptance: HWA-11 closed only in a narrow scope; H3/UDP bypasses L4Wall; banned sources can still complete TLS/QUIC handshakes before receiving HTTP 403; H1/H2/H3 remain C3-only; and there is no complete WebSocket/gRPC coverage, QPACK/flow saturation, management/Safe Ops/audit-failure evidence, or real container-topology validation. Directed results are not production admission.
- Native H1/H2/H3 are declared C3, not C4. Standardized JA3/JA4, real end-to-end WebSocket coverage, QPACK blocking, streaming backpressure saturation, and some slow-flow attacks remain incomplete.
- Native bans are process-local with TTL and capacity bounds; they are lost on restart and not yet backed by a single-writer persistent state service.
- H3 bypasses L4Wall. An application-level QUIC ACL does not replace a host firewall or security group, so deployment must add network-layer source restrictions.
- The Docker/HAProxy edge, the `standard` container topology, the native image build, and a real multi-node state service are unverified. Docker is an optional packaging/deployment layer; the Docker daemon was unavailable, but this does not block the native executable path.
- Firewall rules were not modified in this environment. Validation showed that Windows automatic rules can bind to an absolute binary path, so deployment must explicitly create and re-verify TCP/UDP Allow rules.

## Release gate

Do not label this snapshot as a production `v0.12.0` release and do not describe C3 as C4 or complete protection. r5 supports manual release review, and HWA-11 closed in the narrow r6 retest. A formal production release review still requires confirmation of the remaining residual scope, build/process provenance binding, real container-topology validation, and deployment network controls. DSH explicitly recommends no push for production release; public source and redacted test records have separate authorization.
