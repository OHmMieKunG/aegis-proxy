# Phase 15 typed candidate preview review

Recorded: 2026-07-22

Implementation commit: `d3de105`

Decision: preview unit complete; Phase 15 remains in progress

## Scope

`preview_proxy_host_candidate` consumes an already compiled `ProxyHostCandidate` and active
`Config`. It revalidates inputs and returns a deterministic typed summary plus fully redacted
candidate configuration. It adds no API/CLI route, storage, audit event, activation, schema,
dependency, or runtime mutation.

## Output contract

Summary contains contract/object/owner identity, seven Proxy Host fields, generated route/listener/
upstream/endpoint IDs, canonical SHA-256 candidate hash, active/candidate route fingerprints, and
typed `hot_reload` or `restart_required` classification. Disabled objects have no generated runtime
resources. Full candidate clone passes the existing `aegisproxy_config::redacted` transform before
serialization.

## Safety boundary

- Candidate content hash performs mandatory canonical semantic validation.
- Active configuration receives independent semantic validation.
- Generated resource relationships are checked before preview.
- Preview types contain no secret resolver or mutation handle.
- Production preview module imports no runtime handle, activation coordinator, revision store,
  filesystem, environment, or network API.
- Custom `Debug` summarizes typed fields/counts and omits candidate configuration.
- Pure `hot_reload_compatible` reuses exact runtime listener/restart rules; runtime method still uses
  the same helper.

## Tests

- Same candidate and active configuration serialize identically.
- Secret-reference canary is absent; redaction marker is present.
- Original candidate remains unchanged after preview.
- Enabled preview reports deterministic generated resources and changed route fingerprint.
- Disabled preview reports no generated resources and unchanged fingerprint.
- Invalid active configuration fails closed.
- Restart-only listener difference reports `restart_required` without changing active input.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 278 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed; 2,439 lines |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| manifest/schema/OpenAPI comparison against `cbd18c4` | passed: unchanged |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` future-incompatibility warning remains pre-existing. Optional
Cargo audit/deny/nextest/machete/llvm-cov/fuzz commands and Markdown tools remain unavailable as
recorded in `STATUS.md`; no unavailable check is claimed as passed.

## Compatibility and performance

Change is additive. TOML/JSON schema, defaults, manifests, lockfile, OpenAPI, existing API routes,
and activation behavior are unchanged. Preview performs bounded linear resource lookup, one
canonical serialization/hash, route fingerprinting, and one necessary redacted configuration clone.
No performance improvement is claimed.

## Limitations and next unit

No typed field-level diff exists. No high-level endpoint persists or activates candidate. Preview
does not perform RBAC; caller must authorize before compilation/preview. Next unit adds deterministic
typed field-level differences without exposing raw configuration or secret references.
