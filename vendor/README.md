# Vendored dependencies

The generated third-party license inventory for the native core, including the
complete license texts for normal and build dependencies, is in
[`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). The source and patch
provenance for the vendored crates is recorded below.

After changing `subprojects/native-core/Cargo.lock`, regenerate the inventory
with `python scripts/generate_third_party_notices.py`.

## h2 0.4.20

- Source: crates.io package `h2` version `0.4.20`.
- License: MIT; the upstream `LICENSE` is preserved in `vendor/h2/LICENSE`.
- Local patch: reject `SETTINGS_INITIAL_WINDOW_SIZE` values above `2^31-1`
  during frame parsing and return connection error `FLOW_CONTROL_ERROR` (3)
  instead of the generic `PROTOCOL_ERROR` (1).
- Reason: HWA-10 showed that the server failed closed but did not match RFC 9113
  section 6.5.2, creating an interoperability and protocol-conformance gap.
- Update rule: when upgrading `h2`, remove this patch and first verify that the
  inbound SETTINGS parser maps an oversized initial window to
  `FLOW_CONTROL_ERROR`. Re-run the raw HTTP/2 malformed-SETTINGS regression
  before accepting the upgrade.

## h3 0.0.8

- Source: crates.io package `h3` version `0.0.8`.
- License: MIT; the upstream `LICENSE` is preserved in `vendor/h3/LICENSE`.
- Local patch: reject duplicate HTTP/3 pseudo-headers instead of accepting the
  last value, and reject pseudo-headers that appear after regular header fields.
- Reason: HWA-04 showed that duplicate pseudo-headers could change the effective
  request authority or path while the application-level parser only saw the last
  value. The fix is applied at the wire-decoding boundary so every H3 consumer in
  this project gets the stricter behavior.
- Update rule: when upgrading `h3`, remove this patch and first verify that
  upstream rejects duplicate pseudo-headers in QPACK-decoded field lists. Re-run
  the raw HTTP/3 duplicate-pseudo-header regression before accepting the upgrade.

## h3-quinn 0.0.10

- Source mirror: crates.io package `h3-quinn` version `0.0.10`. The upstream
  license is preserved in `vendor/h3-quinn/LICENSE`.
- The runtime build still resolves `h3-quinn` from crates.io. This source copy is
  present because the published `h3` crate's unit-test module includes
  `../../../h3-quinn/src/lib.rs` by path. Keeping the mirror makes the vendored
  parser tests reproducible without editing the global Cargo cache.
