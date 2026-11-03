# L4Wall 0.1.0

Release date: 2026-11-03

L4Wall is the standalone TCP L4 protection gateway in the HighWall repository. It provides connection admission, concurrency and rate limits, timeouts, byte caps, behavioral scoring, bans, and audit records. Version `0.1.0` is now published under its own tag and GitHub Release instead of being bundled into a HighWall release.

## Release provenance

- This release reuses the exact L4Wall `0.1.0` wheel and sdist from the official `v0.11.0` release. The packages were not rebuilt or modified.
- The release tag points to the `v0.11.0` source commit `18e9f7e79870681b915fe85fb051a6a06b2378d2`; the assets are the official L4Wall attachments from that release, not a build of the current `main` branch.
- Later L4Wall changes on `main` are not part of this release, including the subsequent PROXY v2 sender support.
- The historical sdist retains the `tests/` and `l4wall.egg-info` entries from its original build. They were left unchanged to preserve byte-for-byte compatibility. Future `l4wall-v*` releases will run test, cache, secret, and license checks.
- The historical assets have no GitHub artifact attestation. This release only states that their SHA-256 digests match the official `v0.11.0` asset records; it does not claim build provenance.

## Artifacts

- `l4wall-0.1.0-py3-none-any.whl`
- `l4wall-0.1.0.tar.gz`
- `SHA256SUMS` (these two L4Wall files only)

SHA-256:

```text
7bbbb9ad244ea5df911c697545e35089a15d3aa470fd4a497709d5d8df9b98bc  l4wall-0.1.0-py3-none-any.whl
5c5759e2a1f694b5296128622bbc3d31551097988cb1d85adaa1d8af46698dcf  l4wall-0.1.0.tar.gz
```

The only distribution channel is the **Assets** section of this release. L4Wall has no GHCR image, PyPI package, or other download channel, and its packages do not contain HighWall, L5Wall, or native-core binaries.

## Status

- Version: `0.1.0`
- Maturity: **Alpha / MVP**
- Runtime: Python 3.10+, standard library only
- Coverage: connection-level TCP protection; no TLS or HTTP payload inspection
- Audit and production readiness: not independently audited and not production-ready

The historical `v0.11.0` verification record reports 65 passing L4Wall tests. This standalone publication additionally checks artifact hashes, clean virtual-environment installation, the CLI version, and a generated configuration.

## Install

Download all three assets, verify them, and install the wheel:

```bash
sha256sum -c SHA256SUMS
python3 -m venv /opt/l4wall
/opt/l4wall/bin/pip install --no-cache-dir ./l4wall-0.1.0-py3-none-any.whl
/opt/l4wall/bin/l4wall --version
/opt/l4wall/bin/l4wall init --path ./config.json
/opt/l4wall/bin/l4wall check --config ./config.json
```

Read the [L4Wall README](https://github.com/Fallen-leaves089/highwall/blob/main/subprojects/l4wall/README.md), [deployment baseline](https://github.com/Fallen-leaves089/highwall/blob/main/subprojects/l4wall/docs/DEPLOYMENT.md), and [threat model](https://github.com/Fallen-leaves089/highwall/blob/main/subprojects/l4wall/docs/THREAT_MODEL.md) before deployment.

## Boundaries

- It does not handle bandwidth DDoS, SYN floods, UDP, QUIC/HTTP3, or carrier-side congestion.
- It does not parse HTTP or provide authentication, authorization, WAF, DLP, TLS termination, or JA3/JA4.
- It protects only explicitly configured listeners. Direct access to HighWall or an upstream bypasses L4Wall; listener addresses and network ACLs must close those paths.
- Shared bans in `0.1.0` are reader-only. Automatic publishing, a controller, conflict merging, and HA are not implemented.
- It cannot protect an already compromised host. If an attacker can modify configuration, audit state, or process memory, the L4 boundary has already failed.

## License

Apache-2.0. See the repository root for the license and NOTICE; future standalone builds will also include both files in the wheel and sdist.
