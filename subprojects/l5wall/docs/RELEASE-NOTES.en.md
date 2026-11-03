# L5Wall 0.2.1

Release date: 2026-11-03

L5Wall 0.2.1 is a lifecycle-reliability patch release for `0.2.0`. It is the TLS session-layer subproject in the HighWall repository, with its own version, test matrix, threat model, deployment guide, and release workflow.

## Fixes

- The listener no longer treats transient accept failures as an exit signal. `EINTR`, `ECONNABORTED`, Windows socket resets, `EMFILE`/`ENFILE`, and buffer or memory exhaustion are logged and retried with exponential backoff from 50 ms to 1 s; the backoff resets after a successful accept.
- Fatal accept failures now raise `L5ProxyError` explicitly instead of returning silently and being masked by a supervisor restart policy.
- On `SIGTERM`, the listener stops accepting new work, drains in-flight connections for up to `shutdown_timeout`, and only then force-closes the remainder. The default is 8 seconds.
- Regression coverage now includes connection storms, transient and fatal fault injection, in-flight draining, and drain-deadline expiry.

## Status

- Coverage: **C1**, incomplete.
- Maturity: **Alpha**, not independently audited, not production-ready.
- Runtime dependency: Python 3.10+ standard library only.

It terminates TLS, enforces SNI/ALPN allowlists, minimum TLS versions, mTLS, SNI/Host consistency, and bounded HTTP/1.1 forwarding. It does not implement standard JA3/JA4, 0-RTT policy, QUIC, H2/H3 inspection, or a pre-handshake TCP budget. Do not describe it as complete L5/L7 protection.

## Artifacts

- `l5wall-0.2.1-py3-none-any.whl`
- `l5wall-0.2.1.tar.gz`
- `SHA256SUMS`
- `ghcr.io/fallen-leaves089/l5wall:0.2.1` (`linux/amd64`, `linux/arm64`)

The image is signed with cosign keyless signing and carries GitHub provenance and SBOM attestations. Verify `SHA256SUMS` before installation.

## Install

```bash
python3 -m venv /opt/l5wall
/opt/l5wall/bin/pip install --no-cache-dir ./l5wall-0.2.1-py3-none-any.whl
/opt/l5wall/bin/l5wall --version
```

See [DEPLOYMENT.md](https://github.com/Fallen-leaves089/highwall/blob/main/subprojects/l5wall/docs/DEPLOYMENT.md) for the full deployment procedure.

## Boundaries

- `serve` only permits loopback listeners and loopback upstreams. Container deployment requires host networking or a shared network namespace.
- The original client IP is not forwarded. Do not enable per-IP bans, source ACLs, or source-based rate limits behind this bridge.
- Only `http/1.1` ALPN is accepted. H2/H3 is never downgraded and presented as inspected.
- A TLS-terminating proxy must not sit in front of L5Wall; the real client handshake metadata would already be lost.

## Verification

- 42 standard-library `unittest` cases pass, including listener fault injection, connection storms, graceful draining, and drain-deadline expiry.
- `ruff`, `mypy`, and `l5wall check` pass.
- Wheel/sdist build and installation smoke checks pass; release artifacts contain no test certificates, private keys, or test directories.
- Certificates, SPDX license metadata, and NOTICE are included.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
