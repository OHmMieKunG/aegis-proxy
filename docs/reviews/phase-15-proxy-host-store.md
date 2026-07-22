# Phase 15 Proxy Host store review

Recorded: 2026-07-22

Implementation commit: `5c8898b`

Decision: desired-state store unit complete; Phase 15 remains in progress

## Scope

This unit adds a bounded durable store for strict typed Proxy Host desired state. It adds no API
route, CLI command, audit mutation, revision creation, activation, runtime change, database,
dependency, or low-level configuration-schema field.

## Contract

`StoredProxyHost` wraps `ApiObject<ProxyHostSpec>` with an object-local generation. Generation starts
at one and increments only after exact-generation update. Delete also requires exact generation.
Owner and object IDs are immutable identity because changing either selects a different key.

Contract shape validation now requires canonical lowercase ASCII public domains and canonical DNS
or IP forward hosts before storage. Strict Serde types continue rejecting unknown fields, invalid
IDs, future API versions, unsupported protocols, and zero ports.

## Durable representation

Store file is strict JSON:

- schema version exactly 1;
- at most 4,096 objects;
- at most 2 MiB on read and write;
- stable owner/object ordering;
- no zero generation;
- no duplicate owner/object identity;
- no duplicate domain across owners, including disabled objects.

Existing file must be regular, non-symlink, and private. Parent is mode `0700` and file is mode
`0600` on Unix. Writes use a private random create-new temporary file, file fsync, same-directory
rename, then parent-directory fsync.

## Ownership and concurrency

Nested `BTreeMap<owner_id, BTreeMap<object_id, record>>` gives owner-scoped deterministic reads.
Get/list cannot cross owner namespace without explicitly supplying another owner ID; future handlers
must always use authenticated principal owner. One bounded mutex serializes control-plane mutations.
Update and delete reject stale generations. Create rejects claimed IDs and domains.

## Failure behavior

Memory changes happen under lock and are reversed when serialization, limit, temporary write,
rename, or directory sync fails. Existing durable bytes remain the source of truth after restart.
Malformed or insecure stored state fails open of the store; it is never silently skipped or repaired.

## Security and runtime isolation

Proxy Host contract has no secret field. Store `Debug` reports only object count and omits path and
objects. Store has no secret resolver, environment access, network client, compiler context, audit
writer, revision store, activation coordinator, or runtime handle. Persisting desired state cannot
change active proxy behavior.

The store validates contract shape, not active-configuration semantics. Future mutation handlers
must compile and semantically validate before writing, then use existing audited revision and
activation services. Subsequent commit `d1514dd` opens this store for owner-scoped list/get and
uses metadata-only claims during validation/preview; it still exposes no mutation.

## Tests

- Create, owner-indexed sorted list, cross-owner absence, durable reopen, and stable byte ordering.
- Exact generation update/delete and stale-generation rejection.
- In-memory restoration after forced atomic replacement failure.
- Duplicate identity and cross-owner duplicate-domain rejection.
- Unknown field, future store version, and broad permission rejection.
- Canonical domain/upstream shape regression coverage.
- Existing compiler, preview, endpoint, revision, runtime, configuration, and security suites.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 291 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` retains its existing future-incompatibility warning. Optional
tools remain unavailable as recorded in `STATUS.md`.

## Compatibility and limits

TOML schema/defaults, manifests, lockfile, OpenAPI, CLI, and runtime behavior are unchanged. Store
schema is pre-release and has no migration command yet. Store is single-process; AegisProxy's one
process and existing state-directory ownership provide the intended writer model.

## Remaining Phase 15 work

Compile all stored desired state plus a proposed mutation into one canonical candidate before adding
audited CAS mutations; create a canonical configuration revision before explicit activation; add
update diffs and delete behavior; then implement remaining typed objects, ownership matrix,
contracts, migrations, and security review.

## Completion decision

Desired-state persistence boundary meets this unit's bounded durability and isolation gate. Phase 15
remains in progress; production assessment remains NO-GO.
