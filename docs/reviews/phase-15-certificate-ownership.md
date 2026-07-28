# Phase 15 certificate ownership metadata

Date: 2026-07-28

Status: library metadata unit complete; Phase 15 remains in progress

Implementation commit: `edcb53b`

## Scope

`ApiObject<CertificateSpec>` binds a stable object/owner identity to enabled state, bounded explicit
shares, and one opaque `certificate_ref`. Strict deserialization rejects unknown fields and future
versions. The contract has no chain, private key, ACME credential, secret reference, raw
configuration, or insecure-verification field.

`compile_certificate_metadata` runs normal configuration validation, resolves the referenced static
or ACME certificate, and requires it on exactly one HTTPS listener. Returned metadata contains only
owner/share IDs, enabled state, canonical public host coverage, listener ID, and certificate ID.
Custom `Debug` prints enabled state and counts only.

`select_managed_https_policy` accepts exact or single-label wildcard coverage, requires owner or
explicit sharing, and rejects missing coverage, unauthorized use, and ambiguous authorized matches.
It returns the existing `ManagedHttpsPolicy` consumed by the Proxy Host compiler. It performs no
secret resolution, filesystem/network access, issuance, persistence, revision creation, or runtime
activation.

## Evidence

Tests cover strict secret-free JSON, unknown private-key fields, owner and shared-owner selection,
exact and wildcard coverage, cross-label rejection, unauthorized selection, missing certificate,
ambiguous selection, and redacted debug output.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; pre-existing transitive warning |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 322 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| certificate-focused tests | passed: 4 |
| `git diff --check` | passed |

## Decision

Secret-free ownership metadata and deterministic selection meet this library unit's gate. Phase 15
remains in progress. Certificate persistence, dedicated RBAC, API/CLI contracts, Proxy Host
candidate binding, and managed-HTTPS endpoint integration remain mandatory.
