# Phase 15 Access Policy create

Date: 2026-07-27

Status: create unit complete; Phase 15 remains in progress

Implementation commit: `926eb68`

## Contract and ordering

`POST /v1/access-policies` and `access-policy create --expect <revision> <json-file>` persist one
strict secret-free `ApiObject<AccessPolicySpec>`. The endpoint requires the exact
`create_access_policy` role-and-token-scope intersection and records durable audit intent before
content-type validation or JSON deserialization. It then requires exact active-revision
`If-Match`, principal/owner equality, and successful metadata compilation against the active
canonical configuration.

Only after those checks does the bounded store create generation one. The response is
`201 Created`, contains `StoredAccessPolicy`, and returns the quoted object generation as `ETag`.
Duplicate IDs are object conflicts. Missing/incompatible middleware, malformed JSON, unsupported
versions, unknown fields, and owner mismatch fail closed. Indeterminate or recovery-required
storage returns a generic unavailable response with a distinct safe audit code.

## Isolation

Creation stores only owner/share IDs, enabled state, and opaque middleware IDs. It resolves no
credential, performs no network or DNS work, creates no configuration revision or candidate, and
cannot activate or mutate runtime state. The active revision is checked before validation and
again immediately before persistence. The existing single administrative mutation permit
serializes it with other Admin mutations.

## Evidence

The private CLI integration verifies exact scoped success, authorization before malformed-body
handling, owner denial, missing middleware rejection, stale revision rejection, duplicate
conflict, generation ETag, unchanged active revision and revision count, unchanged store state for
all failed cases, and durable intent/success/failure/denial audit outcomes. OpenAPI tests verify the
operation, request schema, stored response, and ETag contract. Three read-only reviews found no
blocking security, compatibility, or test defect.

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

Access Policy create is complete. Phase 15 remains in progress. Update/delete and Proxy Host policy
reference wiring remain unavailable.
