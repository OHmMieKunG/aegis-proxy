# Phase 15 Access Policy scopes and startup ownership

Date: 2026-07-27

Status: preparation unit complete; Phase 15 remains in progress

Implementation commit: `8eb1c73`

## Scope

This unit adds four explicit actions: `read_access_policies`, `create_access_policy`,
`update_access_policy`, and `delete_access_policy`. Viewer and Auditor are read-only. Operator may
read and perform non-activating CRUD. Admin retains all actions. Bearer tokens require the same
role-and-explicit-scope intersection as every existing action; legacy tokens gain no scope.

The CLI accepts the corresponding kebab-case scope names for token issuance and serializes the
canonical underscore names. OpenAPI has the exact same 27-value closed vocabulary and bounded
scope arrays. This is additive contract preparation: no Access Policy path, handler, request, or
response schema was added.

Administration opens and exclusively owns the Access Policy store in blocking initialization
before binding the private socket. Invalid, insecure, corrupt, or already-owned state returns the
fixed `AdminServerError::AccessPolicies`; Admin fails closed while the data plane remains isolated.
The retained store handle has no route capable of reading or mutating it.

## Security and compatibility

No runtime, revision, activation, audit, configuration, middleware, or secret behavior changed.
The startup error contains no source path or stored bytes. Existing roles and token scopes retain
their behavior; new permissions are never inferred for an existing token. Operator mutation
matches the existing non-activating Proxy Host CRUD ceiling, while activation, rollback, identity,
audit, backup, and restore authority remain unchanged.

Three read-only reviews verified least privilege, complete Rust/CLI/OpenAPI mapping, fail-closed
startup, endpoint absence, compatibility, and focused test coverage. Initial review requested
startup mapping and cross-surface drift tests; both were added and no blocker remains.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; existing transitive warning |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 318 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed: 2,440 output lines |
| RBAC focused tests | passed: 2 |
| OpenAPI scope/route contract test | passed |
| invalid Access Policy startup test | passed |
| private Admin CLI scope round trip | passed |
| `git diff --check` | passed |

The existing `proc-macro-error2 2.0.1` future-incompatibility warning and unavailable optional
tools remain recorded in `STATUS.md`.

## Decision and next boundary

The scope/startup preparation unit meets its authorization, startup isolation, compatibility,
contract parity, review, and validation gates. Owner-scoped list/get landed next in `ef115a6`.
Phase 15 remains in progress. Mutation routes remain blocked until durable audit ordering and
recovery for an indeterminate post-rename store result are defined and tested.
