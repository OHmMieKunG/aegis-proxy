# Phase 15 Access Policy recovery gate

Date: 2026-07-27

Status: recovery-gate unit complete; Phase 15 remains in progress

Implementation commit: `697f530`

## Boundary

`AccessPolicyStore` distinguishes a failure before atomic rename from a failure syncing the parent
directory after rename. A pre-rename failure restores in-memory state and permits retry. A
post-rename failure returns `Indeterminate`, retains the visible new state, and sets a process-local
recovery gate while holding the same mutex used by every policy mutation.

Create, update, and delete check that gate only after acquiring the mutation mutex. No waiting
writer can pass a stale check after another writer reports indeterminate durability. Later writes
return `RecoveryRequired`; owner-scoped reads remain available. A fresh store open strictly reloads
whichever complete old or new atomic file is visible and starts with a clear gate.

This unit adds no API route, audit mutation, revision, activation, runtime publication, secret
access, network operation, schema change, dependency, or configuration default.

## Evidence

Focused tests cover create, update, and delete post-rename failures, matching visible in-memory
state, blocked subsequent mutations, strict reopen state, and continued mutability after ordinary
pre-rename rollback. Three read-only reviews found no blocking source or compatibility defect. A
process-crash durability campaign remains Phase 21 failure-testing work.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; pre-existing transitive warning |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 318 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| Access Policy focused tests | passed: 16 |
| `git diff --check` | passed |

## Decision

The recovery gate is complete. Phase 15 remains in progress. Audited owner-scoped Access Policy
create landed in `926eb68` and maps both durability errors fail closed. Update/delete and Proxy
Host policy wiring remain.
