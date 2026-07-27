# Phase 15 Access Policy update/delete

Date: 2026-07-27

Status: update/delete unit complete; Phase 15 remains in progress

Implementation commit: `334916d`

## Contract and ordering

`PUT` and `DELETE /v1/access-policies/{id}` require their exact role-and-token-scope intersection,
durable audit intent, exact active-revision `If-Match`, and exact
`X-Aegis-Object-Generation`. Authorization and audit intent precede request-body parsing. Update
also requires path/body identity and principal/owner equality, then compiles replacement metadata
against active canonical middleware before generation CAS. Delete resolves only within the
authenticated owner. Cross-owner and missing objects are both not found.

The CLI exposes the same contracts through `access-policy update --expect REV --generation N ID
FILE` and `access-policy delete --expect REV --generation N ID`. OpenAPI records both operations,
headers, strict object schema, stored-record responses, and update ETag.

## Isolation and failure behavior

The handlers store only the strict secret-free Access Policy object. They create no candidate or
configuration revision and cannot call runtime activation. Stale active revisions or object
generations fail before persistence. Invalid replacement middleware leaves the previous generation
unchanged. Store conflicts fail closed; indeterminate durability or a raised recovery gate returns
unavailable with a fixed audit code and blocks later writes until restart reconciliation.

## Evidence

The private Admin CLI integration covers denied scopes before malformed-body parsing, stale active
revision, stale generation, path/body mismatch, owner mismatch, cross-owner delete, invalid
middleware replacement, update ETag, successful generation increment and delete, unchanged active
revision/revision count, unchanged durable state after failures, and intent/success/failure/denial
audit outcomes. Existing configuration and runtime tests remain unchanged.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; pre-existing transitive warning |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 318 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| private Admin CLI integration | passed |
| checked OpenAPI contract | passed |
| `git diff --check` | passed |

## Decision

Access Policy update/delete are complete. Phase 15 remains in progress. Proxy Host policy
references remain blocked until policy desired state and authorization are bound into immutable
typed candidates and revalidated at activation.
