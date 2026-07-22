# Phase 15 typed Proxy Host candidate binding

Date: 2026-07-22

Status: unit complete; Phase 15 remains in progress

Implementation commit: `80a7f27`

## Scope

This unit binds every typed Proxy Host configuration candidate to the complete immutable typed
desired state that produced it. It hardens activation and supplies the missing historical input for
future typed rollback. It does not expose rollback or change active runtime behavior by itself.

## Persistence model

`RevisionMetadata.binding_hash` is an optional lowercase SHA-256. Low-level configuration
revisions keep `None`, serialize exactly as before, and remain usable by low-level operations.
Typed candidate creation computes the hash over strict schema version 1 plus canonical
owner/object-ordered `ApiObject<ProxyHostSpec>` values. Configuration deduplication now includes the
optional binding, so equal runtime configuration with different disabled typed objects creates
distinct revision identity.

The corresponding immutable JSON snapshot is written under
`<state_dir>/admin/proxy-host-candidates/<revision>.json`. Each file is at most 2 MiB, contains at
most 4,096 objects, uses mode `0600` in a mode-`0700` directory, rejects symlinks and unknown/future
fields, and is created without overwrite. The directory is hard-bounded to 1,000 entries. Existing
identical content is accepted idempotently; different content for one revision fails closed.

Snapshot files contain no object generation. Generations remain concurrency metadata of current
desired state, not historical product state.

## Mutation and activation ordering

Typed create/update/delete now use this order:

```text
compile complete desired objects
→ hash canonical typed state
→ create immutable bound configuration revision
→ write immutable typed snapshot
→ recheck active revision
→ epoch-CAS current desired-state mutation
```

A snapshot or revision write failure cannot mutate desired or active state. A later object-store
failure may leave only an auditable non-active bound candidate.

Typed activation loads and validates configuration metadata, revision content, and the bound typed
snapshot. It requires the binding hash to match both metadata and canonical snapshot content, then
requires bound objects to equal the complete current desired-state objects before existing
configuration-hash and epoch checks. A low-level unbound candidate, missing snapshot, hash mismatch,
tampered object, stale object set, or invalid permission cannot activate through the typed route.

## Security and reliability review

- Hashes and strict schemas detect content changes within the process account's protected state
  boundary; they are not a substitute for host integrity.
- Disabled objects participate in the binding even though they generate no route.
- Revision IDs are validated before forming paths; traversal and symlinks fail closed.
- Candidate `Debug` shows only binding hash and object count, never full configuration or secrets.
- The seven-field Proxy Host contract cannot carry secret plaintext.
- Blocking serialization and filesystem work stays in `spawn_blocking` at request boundaries.
- Stable ordered inputs eliminate hash-map nondeterminism.
- All collections and files have explicit bounds.
- No unsafe code, dependency, network, DNS, environment, or secret-resolver access was added.

## Tests

Tests cover stable hashes across input order, strict restart loading, idempotent binding, revision
path traversal rejection, wrong expected hash, snapshot tampering, metadata-hash tampering, bound
versus unbound deduplication, distinct typed bindings for equal configuration, end-to-end file
creation, and activation refusal after snapshot tampering. Existing typed create/update/delete and
activation behavior remains covered by the private CLI integration.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 297 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| revision binding tests | passed |
| object-store binding tests | passed |
| private Admin CLI integration | passed |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` retains its existing future-incompatibility warning. Optional
Cargo tools and Markdown tools remain unavailable as recorded in `STATUS.md`.

## Compatibility, limits, and completion decision

Configuration schema/defaults, Cargo manifests, lockfile, public data-plane behavior, typed object
schema, CLI, OpenAPI paths, and action vocabulary are unchanged. Revision metadata is additively
extended with an omitted-by-default optional field; old metadata loads with `None`. The public Rust
metadata struct gains this field during the pre-release Phase 15 contract cycle.

Snapshot retention is bounded but not yet coordinated with configuration revision pruning. At the
1,000-file cap, typed candidate creation fails closed until an approved cleanup operation exists.
This must be resolved before Phase 15 exit. Current low-level rollback still does not restore typed
desired state. A crash-safe typed rollback transaction is the next unit.

The candidate-binding unit meets its gate. Phase 15 remains in progress and production remains
NO-GO.
