# Phase 15 aggregate Proxy Host compiler review

Recorded: 2026-07-22

Implementation commit: `35d7d38`

Decision: aggregate compiler unit complete; Phase 15 remains in progress

## Scope

`compile_proxy_hosts` transforms explicit current and complete desired Proxy Host sets into one
canonical semantically validated configuration candidate. It adds no API route, CLI command,
persistence, audit event, revision, activation, runtime change, network operation, dependency, or
configuration-schema field.

## Contract and determinism

- Current objects identify namespaces already reserved by durable control-plane state.
- Desired objects represent the complete post-change state, never a partial patch.
- Both sets are bounded to 4,096 and canonicalized by owner then object ID.
- Duplicate identities, duplicate domains, generated-ID collisions, invalid domains/upstreams,
  missing policy/certificate metadata, and semantic failure reject the whole candidate.
- Stable ordered maps/sets make input iteration order irrelevant.
- Enabled objects generate one route, group, and endpoint; disabled objects retain typed state and
  generate nothing.
- Retained manual configuration is cloned once into output; semantic validation runs once after all
  generated resources are added.

## Managed-resource safety

Generated names remain SHA-256-derived from immutable owner/object identity. Only identities in the
current set may reserve an existing generated namespace. A reserved namespace is removable only
when route, group, and endpoint all exist together with exact generated IDs and compiler-shaped
relationships. A missing trio is valid pending state. Partial, malformed, cross-linked, endpoint
takeover, or retained-reference state fails closed. A new desired identity cannot cause a manual
collision to be stripped.

This separation supports create, update, disable, and delete candidates without dropping another
stored-but-not-active object. It does not prove mutation ordering; audited store/revision mutation is
the next unit.

## Security and isolation

Context contains validated configuration, opaque policy metadata, certificate IDs, and template IDs
only. It has no authorization decision, plaintext secret, store, audit writer, revision service,
activation coordinator, runtime handle, filesystem, environment, DNS, or network client. Caller
must authorize object-set changes before compilation. Candidate `Debug` exposes counts only.

## Tests and compatibility

Tests prove deterministic output across input order, owner/object ordering, preservation of pending
objects, replacement and disable behavior, manual takeover rejection, tampered shape rejection,
duplicate rejection, and final semantic validation. Existing single-object compiler and complete
workspace regressions remain green. Production portion of `compile.rs` ends at line 706; its larger
file count includes focused unit tests and remains below the 1,200-line production-module guidance.

Configuration schema/defaults, manifests, lockfile, OpenAPI, CLI, persisted store schema, low-level
APIs, and data-plane behavior are unchanged.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 294 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` retains its existing future-incompatibility warning. Optional
tools remain unavailable as recorded in `STATUS.md`.

## Remaining Phase 15 work

Audited owner-scoped generation-CAS mutations; typed revision/activation/rollback endpoints;
access-policy and certificate ownership; remaining objects/contracts; migration and compatibility
tests; full authorization/security review.

## Completion decision

Aggregate compilation meets this unit's determinism, pending-state preservation, managed-resource,
semantic-validation, compatibility, and isolation gate. Phase 15 remains in progress; production
assessment remains NO-GO.
