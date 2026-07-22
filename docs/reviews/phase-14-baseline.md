# Phase 14 modularization baseline

Recorded: 2026-07-22

## Repository and toolchain

- Branch: `dev`
- Baseline commit: `10aae8c`
- Working tree: clean
- Remote: `origin` (`https://github.com/OHmMieKunG/aegis-proxy.git`)
- Rust: `rustc 1.97.0 (2d8144b78 2026-07-07)`
- Cargo: `cargo 1.97.0 (c980f4866 2026-06-30)`
- Workspace members: `proxy-admin`, `proxy-config`, `proxy-core`, `proxy-secrets`, `proxy-tls`,
  and `rust-proxy`
- Existing modified files: none

## Concentration baseline

Counts include comments and blank lines. “Production region” ends immediately before the inline
`#[cfg(test)]` module; “test region” includes that attribute and module wrapper.

| File | Total lines | Production region | Inline test region |
|---|---:|---:|---:|
| `crates/proxy-core/src/lib.rs` | 5,415 | 2,280 | 3,135 |
| `crates/proxy-core/src/runtime.rs` | 1,278 | 782 | 496 |
| `crates/proxy-core/src/telemetry.rs` | 1,109 | 988 | 121 |
| `crates/proxy-config/src/lib.rs` | 4,749 | 3,483 | 1,266 |
| `crates/proxy-admin/src/server.rs` | 2,159 | 1,945 | 214 |

Existing responsibility modules already cover ACME, middleware, providers, routing, TCP,
upstream health/DNS/pools/circuits, audit, authentication, backup, secrets, and TLS. Phase 14 must
reuse those boundaries and avoid speculative layers.

## Test baseline

`cargo test --workspace --all-features` passed with 268 tests passed and two intentionally ignored:

- `runtime::tests::benchmark_atomic_reload`: manual release-mode benchmark.
- `tests/pebble.rs::issues_with_all_supported_challenges`: requires Docker-backed Pebble.

No baseline test failed. Five crate doctest targets contain no doctests.

## Validation baseline

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 268 passed, 2 ignored |
| `cargo test --workspace --doc` | passed: no doctests |
| shipped configuration corpus | 7 valid accepted; 3 invalid rejected |

Cargo emitted the existing future-incompatibility warning for transitive
`proc-macro-error2 2.0.1`; it is not introduced by Phase 14.

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, and `cargo fuzz`
are unavailable in this environment: Cargo reports `no such command` for each. Their absence does
not block test-only extraction, but unavailable required release evidence must remain recorded.

## Invariants and execution order

1. Extract inline tests without renaming tests or changing assertions.
2. Split only cohesive production responsibilities already present in the call graph.
3. Preserve public API, OpenAPI paths, configuration schema/defaults/fingerprints, error mapping,
   request-validation order, route selection, trust processing, middleware stages, egress policy,
   reload/shutdown behavior, telemetry labels, and audit gates.
4. Add no dependency, protocol, provider, GUI, authentication, or persistence feature.
5. Compare final tests, public symbols, manifests, schemas, and module sizes against this baseline.
