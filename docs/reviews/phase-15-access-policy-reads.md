# Phase 15 Access Policy reads

Date: 2026-07-27

Status: read-only endpoint unit complete; Phase 15 remains in progress

Implementation commit: `ef115a6`

## Scope and behavior

`GET /v1/access-policies` returns globally ID-ordered records owned by the authenticated principal.
`GET /v1/access-policies/{id}` returns one owned record with its numeric generation as a strong
ETag. Invalid IDs, missing IDs, and other-owner IDs all return the same not-found boundary. Both
routes require role permission plus exact `read_access_policies` token scope when bearer
authentication is used.

The CLI exposes `access-policy list` and `access-policy get`. OpenAPI defines the strict read
paths, the stored generation envelope, optional shared-owner array, and exact 63-byte middleware
reference grammar. Audited create landed later in `926eb68`; update/delete remain absent.

## Isolation and security

Handlers perform authorization before owner and object lookup. Store calls run through
`spawn_blocking` and invoke only owner-scoped `list`/`get`. Reads cannot compile middleware,
resolve credentials, persist objects, create revisions, write audit mutation intent, activate
configuration, or access runtime mutation. Response objects have no field capable of carrying
plaintext secrets. Cross-owner not-found prevents existence disclosure.

Tests use two owned policies and one other-owner shared policy. They verify stable filtering/order,
owned GET, cross-owner not-found, invalid-ID rejection, exact `ETag: "2"`, denial for a token lacking
the read scope, and list/get success for an explicitly scoped token.

Three read-only reviews verified authorization, owner isolation, side-effect freedom, route and
CLI behavior, schema compatibility, and test coverage. Review found an OpenAPI middleware length
mismatch; the schema now uses a dedicated `MiddlewareRef` matching Rust. No blocker remains.

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
| checked OpenAPI route/scope/schema test | passed |
| private Admin CLI integration | passed |
| `git diff --check` | passed |

The existing `proc-macro-error2 2.0.1` warning and unavailable optional tools remain recorded in
`STATUS.md`.

## Decision and remaining boundary

The read-only endpoint unit meets its authorization, ownership, non-disclosure, deterministic
ordering, ETag, secret isolation, transport-contract, compatibility, review, and validation gates.
Phase 15 remains in progress. Create landed later after audit ordering, active-configuration
validation, and indeterminate-write recovery. Update/delete and Proxy Host reference enablement
remain absent.
