# Phase 15 typed Access Policy ownership

Date: 2026-07-27

Status: library unit complete; Phase 15 remains in progress

Implementation commit: `f23468b`

## Scope

This unit defines a strict, secret-free Access Policy object and converts it into immutable metadata
already consumed by Proxy Host compilation. It adds no persistence, endpoint, action scope,
OpenAPI/CLI route, activation path, middleware body, or GUI behavior.

## Contract and mapping

`ApiObject<AccessPolicySpec>` reuses the exact `v1` envelope, stable object ID, and owner ID. Its
spec contains:

- `enabled`;
- zero to 128 unique explicit shared-owner IDs, excluding the owner; and
- one to 64 unique canonical middleware references.

Middleware IDs use the existing configuration identifier grammar and 63-byte bound. Unknown
fields, unsupported versions, invalid IDs, empty policies, duplicates, self-sharing, and oversized
collections fail closed.

`compile_access_policy_metadata` validates the complete canonical configuration before resolving
references. It accepts existing IP policy, client/principal rate limit, in-flight limit, BasicAuth,
and ForwardAuth definitions. It rejects missing resources, other middleware kinds, duplicate fixed
stages, multiple authentication stages, and principal rate limiting without exactly one
authentication stage. IDs are sorted and shares use `BTreeSet`, so equivalent input order produces
equal metadata.

## Ownership and secret boundary

The Proxy Host compiler authorizes only the policy owner or an explicitly shared owner. Disabled
and missing policies return the same unavailable class; an unshared existing policy returns the
internal unauthorized class. Complete candidate semantic validation still enforces listener
requirements, so BasicAuth or ForwardAuth cannot attach to HTTP.

Metadata contains only owner/share IDs, an enabled flag, and middleware IDs. Its fields are private,
construction is through the validated compiler, public getters expose only safe metadata, and
`Debug` exposes only enabled state and counts. Middleware definitions—including BasicAuth secret
references—remain in validated configuration and never enter the object, metadata, errors, or
debugging.

Policy IDs must be globally unique once persistence exists because `AccessPolicyRef` and compiler
indexes intentionally use one opaque object ID. Future create/update handlers must bind the
authenticated owner, enforce generation/revision CAS and distinct action scopes, and record durable
audit intent before mutation.

## Tests and validation

Tests cover strict unknown-field/version/ID behavior; exact collection and identifier bounds;
empty, duplicate, and self-shared rejection; secret canaries; input-order determinism; every allowed
stage category; missing and incompatible middleware; duplicate authentication; principal rate
without auth; invalid canonical configuration; owner/shared/unshared behavior; aggregate Proxy Host
compilation; semantic validation; and HTTP authentication rejection.

Three read-only reviews found no remaining blocking security, test, compatibility, or
maintainability issue for the explicit library-only scope.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 309 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed: 2,439 output lines |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| Access Policy focused tests | passed: 7 |
| `cargo test -p aegisproxy-admin --all-features` | passed: 56 |
| private Admin CLI integration | passed |
| `git diff --check` | passed |

The existing transitive `proc-macro-error2 2.0.1` future-incompatibility warning remains
non-blocking. Optional tools remain unavailable as recorded in `STATUS.md`.

## Compatibility, limitations, and decision

Configuration schema/defaults, manifests, lockfile, persisted state, OpenAPI, CLI, action
vocabulary, endpoints, and data-plane behavior are unchanged. The pre-release public Rust
`AccessPolicyMetadata` field literal is replaced by a validated constructor and safe getters; this
intentional source migration prevents unvalidated metadata construction.

The library contract unit meets its strictness, ownership, sharing, determinism, stage
compatibility, secret isolation, semantic-validation, and available-validation gates. It is not an
operator-usable Access Policy feature. Phase 15 and production assessment remain incomplete.
