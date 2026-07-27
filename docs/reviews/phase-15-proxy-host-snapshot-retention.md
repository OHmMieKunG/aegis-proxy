# Phase 15 typed Proxy Host snapshot retention

Date: 2026-07-27

Status: unit complete; Phase 15 remains in progress

Implementation commit: `788b5a2`

## Scope and model

This unit coordinates strict typed desired-state snapshots with existing configuration revision
retention. It adds no endpoint, schema, dependency, activation path, or runtime behavior.

`RevisionStore::list` is the authority after its existing durable pruning rules protect active,
previous, journal-target, age-floor, and count-floor revisions. `ProxyHostStore` receives only that
immutable metadata list. At Admin startup and immediately before binding a new typed candidate or
rollback forward revision it:

1. validates retained revision IDs, optional binding hashes, and uniqueness;
2. reads at most 1,000 snapshot entries in deterministic filename order;
3. rejects unexpected entry types, names, permissions, schemas, identities, hashes, or canonical
   object order;
4. preserves every snapshot with matching retained bound metadata; and
5. durably removes only fully validated snapshots whose revision metadata is absent.

All entries are validated before deletion begins. A missing snapshot for retained bound metadata
remains an activation/rollback failure; reconciliation does not invent typed state.

## Safety and reliability

- Revision pruning completes before its retained list is used, so snapshot deletion never drives
  revision retention.
- The existing bounded administrative mutation permit prevents concurrent typed mutations from
  racing pre-bind reconciliation.
- Startup performs reconciliation before serving the private Admin socket.
- Tampering or a symlink fails closed before a valid orphan is removed.
- Snapshot files contain only the strict seven-field Proxy Host contract; reconciliation receives
  IDs and binding hashes and has no secret, environment, DNS, network, runtime, or activation
  handle.
- Blocking directory work remains inside existing `spawn_blocking` boundaries.
- Revision and snapshot directories are separate file transactions. A crash may leave a harmless
  non-active orphan, which the next startup or binding removes. No cross-directory atomicity is
  claimed.
- No unsafe code, new dependency, unbounded collection, telemetry label, or plaintext-bearing
  error was added.

## Tests and review

Focused tests cover retained preservation, stale removal, restart idempotence, tampered binding
rejection before deletion, symlink rejection, hard-cap exhaustion, and reclaimed capacity.
Existing revision retention, bound activation, typed rollback, private Admin CLI, configuration,
and runtime suites remain green. Three read-only reviews found no blocking security,
authorization, compatibility, or maintainability issue. A real-store pruning integration test was
identified as optional follow-up; the existing revision tests and reconciliation tests cover each
side of the narrow boundary without adding a broad fixture.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 302 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed: 2,439 output lines |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| candidate reconciliation tests | passed: 3 |
| `cargo test -p aegisproxy-admin --all-features` | passed: 49 |
| private Admin CLI integration | passed |
| `git diff --check` | passed |

The existing transitive `proc-macro-error2 2.0.1` future-incompatibility warning remains
non-blocking. `cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`,
`cargo fuzz`, `markdownlint`, and `lychee` remain unavailable as recorded in `STATUS.md`.

## Compatibility, limitations, and decision

Configuration and typed object schemas, defaults, manifests, lockfile, OpenAPI, CLI, action
vocabulary, public APIs, and data-plane behavior are unchanged. Retention reuses existing file
formats and pruning authority. It intentionally does not repair missing snapshots or delete
invalid state.

The coordinated snapshot-retention unit meets its bounded cleanup, preservation, tamper
fail-closed, restart, compatibility, and available-validation gates. Phase 15 remains in progress;
Access Policy and certificate ownership, remaining domain contracts, compatibility policy,
transport split, and the full authorization/security review remain.
