# Phase 15 Access Policy store

Date: 2026-07-27

Status: persistence unit complete; Phase 15 remains in progress

Implementation commit: `58f30dc`

## Scope and boundary

This unit adds bounded durable storage for the existing secret-free
`ApiObject<AccessPolicySpec>` contract. It adds no HTTP or CLI route, RBAC action, audit mutation,
configuration revision, activation, middleware definition, credential resolution, or GUI behavior.
Proxy Host endpoints continue to reject Access Policy references.

`AccessPolicyStore` owns one private JSON file under an exclusive process registration and `fs2`
filesystem lock. Records use one globally unique object ID, stable `BTreeMap` order, an exact
object-local generation starting at one, and owner-scoped list/get. Create, update, and delete hold
one bounded mutation lock and use generation/owner compare-and-swap.

## Canonical and durable representation

The strict schema version is one. Unknown fields, unsupported versions, generation zero, duplicate
global IDs, invalid contracts, noncanonical share/middleware order, symlinks, unexpected file
types, broad Unix permissions, more than 1,024 records, and files above 1 MiB fail closed.

Create and update validate before sorting share IDs and middleware references. Semantically
equivalent reordered updates return the existing generation without rewriting bytes. Pretty JSON
serialization follows global object-ID order. Stored records contain only owner/share IDs, enabled
state, and opaque middleware IDs.

The immediate parent is a real private directory and the data and lock files are mode `0600` on
Unix. Replacement writes and syncs a random exclusive temporary file, renames it atomically, then
syncs the parent directory. Failure before rename restores the in-memory mutation. A failure after
rename returns the distinct `Indeterminate` error and retains the new in-memory state so memory
matches the visible durable file. The store now gates every subsequent mutation after that error
until restart reconciliation reloads the visible atomic file; reads remain available. Endpoint
integration must map both durability states fail closed and must not report that no change occurred.

## Isolation and compatibility

The store has no runtime, activation, revision, audit, network, DNS, environment, secret resolver,
or plaintext credential capability. `Debug` exposes only record count. Metadata compilation
validates the canonical configuration once outside the store lock and returns only validated
secret-free policy metadata.

The TOML configuration schema, defaults, fingerprints, OpenAPI, CLI, data-plane behavior, and
persisted Proxy Host/revision formats are unchanged. `fs2` was already locked and used by
`aegisproxy-config`; `aegisproxy-admin` now declares it directly for cross-process store ownership.

## Tests and review

Focused tests cover canonical/idempotent ordering; globally unique IDs; owner-scoped reads;
same-owner and cross-owner conflicts; stale generation; concurrent same-generation CAS; restart
after update/delete; exact count capacity; serialized byte capacity and rollback; strict schema,
unknown-field, duplicate-ID, and generation tamper; file and parent symlinks/permissions; exclusive
ownership; and pre-rename plus post-rename failures for create, update, and delete.

Three read-only reviews found and then verified fixes for exclusive ownership, parent trust,
post-rename failure semantics, canonical persistence, concurrency, and failure-path coverage. No
blocking finding remains for this storage-only boundary.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 317 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed: 2,440 output lines |
| Access Policy store focused tests | passed: 8 |
| `cargo test -p aegisproxy-admin --all-features` | passed: 64 |
| private Admin CLI integration and configuration corpus | passed in workspace run |
| `git diff --check` | passed |

The existing transitive `proc-macro-error2 2.0.1` future-incompatibility warning remains
non-blocking. Optional unavailable tools remain recorded in `STATUS.md`.

## Decision and remaining work

The persistence unit satisfies its canonicalization, ownership, CAS, bounded-resource, strict
restart, atomic replacement, secret isolation, compatibility, test, and review gates. Phase 15
remains in progress. Dedicated RBAC actions and token-scope contracts landed next in `8eb1c73`;
the recovery gate landed in `697f530`. Durable audited endpoints and Proxy Host policy wiring remain
mandatory before the object becomes operator-usable.
