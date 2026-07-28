# Phase 15 Access Policy candidate binding

Date: 2026-07-28

Status: dependency-binding unit complete; Phase 15 remains in progress

Implementation commit: `20449a3`

## Scope and mapping

Typed Proxy Host create, update, and delete collect every opaque `access_policy_ref` from complete
desired state. `AccessPolicyStore::candidate_dependencies` returns one immutable, ID-ordered
snapshot containing exact policy generations and secret-free policy objects, plus compiler metadata.
Missing records remain absent so the existing compiler returns its fail-closed missing-policy error.
The aggregate compiler applies owner/share/enabled and middleware-stage validation and produces the
normal canonical `Config`.

`ProxyHostStore::binding_hash_with_access_policies` hashes canonical complete Proxy Host objects and
canonical referenced policy records. The strict private candidate file stores both sets. Disabled
Proxy Hosts remain in desired state, bind their references, and generate no active route.

## Activation and rollback boundary

Compilation and binding cannot activate runtime state or persist configuration revisions themselves.
Admin-only activation loads the bound snapshot, snapshots current dependencies, requires exact
record equality, recompiles through semantic validation, verifies the immutable configuration
revision, and delegates only to the existing atomic activation coordinator. Missing, changed,
disabled, unauthorized, malformed, or recovery-uncertain policy state fails before publication.

Rollback applies the same dependency equality check to the historical snapshot before creating a
new forward revision. Policy owners remain free to update or revoke policy desired state; that
change invalidates stale dependent candidates and rollback targets instead of letting consumers pin
the policy. The existing process-wide mutation permit serializes policy changes with candidate and
activation transactions.

## Determinism, limits, and secrets

Objects and policies use stable `BTreeSet`/ID order. Hashes change for policy generation or content
changes and do not depend on input order. Candidate bytes use the existing bounded transaction
limit, covering the independently bounded 2 MiB Proxy Host and 1 MiB Access Policy stores.
Candidate `Debug` exposes only hash and counts. Policy records contain only IDs, owner/sharing,
enabled state, and opaque middleware IDs; no middleware body or credential can enter the binding,
preview, error, audit record, or runtime log.

Legacy typed snapshots without `access_policies` deserialize as an empty list and retain their
original binding hash. New policy-bearing snapshots are additive private derived state but are not
readable by older binaries; downgrade requires the matching binary/state backup.

## Tests and validation

Tests cover canonical policy ordering, generation and same-generation content drift, file tamper,
legacy missing-field loading, policy-bearing create/update/activation/rollback flow, active route
middleware application, and stale-policy activation rejection with unchanged active revision.
Existing compiler, ownership, token-scope, audit, revision, rollback, configuration corpus, and
runtime tests remain in the workspace run.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; pre-existing transitive warning |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 319 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| candidate-binding focused tests | passed: 2 |
| private Admin CLI integration | passed |
| `git diff --check` | passed |

Cargo continues to report the pre-existing `proc-macro-error2 2.0.1` future-incompatibility warning.
Optional unavailable tools remain listed in `STATUS.md`; none is claimed as passed.

## Decision and remaining work

Revision-bound Access Policy use satisfies this unit's deterministic binding, ownership,
authorization, semantic-validation, secret-isolation, compatibility, and runtime-nonmutation gates.
Phase 15 remains in progress. Typed certificate ownership, remaining domain objects/contracts,
migration compatibility, transport split, and full authorization/security review remain mandatory.
