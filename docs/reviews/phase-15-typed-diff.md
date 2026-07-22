# Phase 15 typed field-level diff review

Recorded: 2026-07-22

Implementation commit: `2617f0e`

Decision: typed-diff unit complete; Phase 15 remains in progress

## Scope and contract

`diff_proxy_host_previews` compares an optional current `ProxyHostPreviewSummary` with one candidate
summary. It returns `ProxyHostDiff`, a deterministic owner-scoped change set. It adds no API/CLI
route, persistence, audit event, activation, schema, dependency, or runtime mutation.

The closed field vocabulary is domain, forward host, forward port, forward protocol, automatic
HTTPS, opaque access-policy reference, enabled state, and generated resources. Creation emits
`add`, changed values emit `replace`, and disabling emits `remove` for generated resources. At most
eight changes exist. Field order is fixed in code and never depends on map or set iteration.

## Identity and security boundary

- Current and candidate API versions must both equal `v1`.
- Current and candidate object and owner IDs must match; mismatch fails closed.
- Values use a closed serializable enum rather than raw JSON, raw configuration, or arbitrary paths.
- Access-policy content, credentials, secret resolvers, and plaintext secret fields are absent.
- Generated values contain only canonical route/listener/upstream/endpoint identifiers.
- The function accepts immutable summaries and has no runtime, revision, audit, filesystem,
  environment, DNS, or network handle.
- Disabled state explicitly removes generated resources, so a caller cannot mistake it for an
  active route.

Public callers must still perform authentication and RBAC before compilation. This library unit does
not replace authorization, revision creation, durable audit, or explicit activation.

## Tests

- Identical inputs produce identical ordered serialization and unchanged objects produce no changes.
- Creation produces the exact bounded field order.
- Enabled-to-disabled produces an enabled replacement and generated-resource removal.
- Owner mismatch and unsupported version fail closed.
- Serialized output excludes password, private-key, API-token, and secret-reference field names.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 281 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` future-incompatibility warning remains pre-existing. Optional
Cargo audit/deny/nextest/machete/llvm-cov/fuzz commands and Markdown tools remain unavailable as
recorded in `STATUS.md`; no unavailable check is claimed as passed.

## Compatibility and performance

The change is additive. TOML/JSON schema, defaults, manifests, lockfile, OpenAPI, existing API routes,
and activation behavior are unchanged. Diff work is a fixed eight-field comparison with a bounded
result. No performance improvement is claimed.

## Known limitations and next unit

The diff is library-only and compares preview summaries supplied by an authorized caller. High-level
object persistence, complete ownership/RBAC enforcement, API-token scopes, and typed endpoints do
not exist yet. The next unit establishes complete control-plane authorization scopes before any
high-level mutation endpoint is exposed.
