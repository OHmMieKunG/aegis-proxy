# Changelog

AegisProxy has not published a supported release.

## Unreleased

- Implemented Rust reverse-proxy foundation through historical phases 0–13.
- Rebased documentation around verified current state and phases 14–21.
- Adopted user-first GUI and typed-control-plane direction with secret isolation.
- Completed behavior-preserving modularization: focused tests and domain-owned core, configuration,
  and administration modules now replace oversized mixed-responsibility files.
- Began Phase 15 with a strict fail-closed `v1` object envelope and library-only Proxy Host contract;
  it is not yet exposed as an administrative endpoint.
- Added side-effect-free deterministic Proxy Host compilation into canonical validated configuration
  candidates, with fail-closed ownership, policy, domain, identifier, and certificate checks.
- Added deterministic typed Proxy Host candidate previews with mandatory semantic validation,
  secret-reference redaction, generated-resource summaries, fingerprints, and restart classification.
- Added bounded deterministic Proxy Host field differences with typed values, stable ordering,
  identity checks, and explicit generated-resource add/remove operations.
- Required explicit API-token action scopes, enforced as role-and-scope intersection; legacy
  unscoped records load deny-all and token metadata remains hash-free.
- Added private owner-aware Proxy Host validation and redacted preview endpoints plus CLI commands;
  authorization precedes typed deserialization and these endpoints cannot persist or activate.
- Added bounded private Proxy Host desired-state storage with strict schema loading, deterministic
  owner indexing, generation compare-and-swap, atomic replacement, and write-failure rollback.
- Added owner-scoped Proxy Host list/get API and CLI operations with exact token scope, generation
  ETags, and stored identity/domain conflict checks for typed validation and preview.
- Added deterministic aggregate Proxy Host compilation that preserves complete pending desired state
  and rejects unreserved, partial, or tampered generated-resource collisions.
- Fixed administrative mutation authorization to enforce explicit bearer-token scopes, preventing a
  role-allowed but out-of-scope token from creating candidates or changing state.
- Added complete desired-state snapshots with process-local epoch CAS so concurrent typed mutations
  cannot persist a candidate compiled from stale object state.
- Added audited owner-scoped Proxy Host creation that compiles and validates complete desired state,
  writes an immutable candidate, then persists generation-one desired state without activation.
- Added audited Proxy Host update/delete with exact object-generation and complete-store epoch CAS,
  immutable non-active candidates, distinct action scopes, and CLI/OpenAPI contracts.
- Added Admin-only typed Proxy Host candidate activation. It recompiles complete current desired
  state, verifies the immutable candidate hash, serializes mutations, and delegates publication to
  the existing atomic activation coordinator; stale, orphaned, repeated, or unauthorized requests
  fail without runtime change.
- Bound typed candidates to strict immutable desired-state snapshots through a validated metadata
  hash. Creation persists the binding before desired-state mutation, and activation rejects
  missing, mismatched, or tampered bindings.
- Added Admin-only typed Proxy Host forward rollback with an exact revision precondition, distinct
  token scope, bound historical desired state, private crash-recovery journal, and existing atomic
  activation coordinator.
- Coordinated typed desired-state snapshot retention with authoritative configuration revision
  pruning; startup and pre-bind reconciliation remove only validated orphan snapshots and reject
  malformed or tampered state before deletion.
- Added a strict secret-free Access Policy ownership contract and validated metadata compiler for
  existing canonical IP, limit, and authentication middleware stages. Public endpoints remain
  disabled until owned persistence and RBAC wiring land.
- Added bounded private Access Policy persistence with global IDs, canonical records, owner-scoped
  reads, generation CAS, exclusive ownership, strict restart checks, and atomic replacement.
- Added dedicated Access Policy read/create/update/delete token scopes and fail-closed private
  startup ownership; no Access Policy route is exposed yet.
- Added owner-scoped Access Policy list/get API and CLI operations with exact read scope, stable
  ordering, generation ETags, and cross-owner not-found behavior.
- Blocked Access Policy writes after indeterminate post-rename durability failures until restart
  reconciliation, preventing retries against uncertain state.
- Added audited owner-scoped Access Policy creation with active-revision concurrency, semantic
  middleware validation, generation ETags, CLI/OpenAPI contracts, and no runtime activation.
- Added audited owner-scoped Access Policy update/delete with active-revision and object-generation
  concurrency, semantic update validation, cross-owner not-found behavior, and no runtime
  activation.
- Enabled side-effect-free Proxy Host validation/preview for owned or explicitly shared Access
  Policy references.
- Bound referenced Access Policy generations and canonical content into typed Proxy Host candidate
  snapshots; activation and rollback reject missing or changed dependencies before runtime
  publication.
- Added a strict secret-free Certificate ownership contract and deterministic managed-HTTPS
  selection metadata for existing certificate identities and HTTPS listeners.
- Added bounded typed Certificate persistence, exact owner-scoped CRUD permissions and CLI,
  managed-HTTPS selection, typed renewal, and separate runtime certificate status routes.
- Added strict Stream Host and file/DNS Discovery Source contracts, deterministic no-I/O compilers,
  bounded owner-scoped stores, exact scopes, previews, non-active candidates, and CLI commands.
- Added deterministic schema-2 unified typed snapshots, canonical preview/activation/rollback
  routes, exact Access Policy and Certificate dependency binding, and schema-1 compatibility
  limited to deprecated Proxy Host aliases.
- Added bounded encrypted Stored Credentials with write-only create/rotation values, redacted
  owner-scoped metadata, exact scopes, CLI lifecycle, and ciphertext removal on revoke.
- Added durable Users, read-only built-in Roles, exact identity/token scopes, and subject-bound
  token issuance; disabled users cannot authenticate and legacy subjectless tokens gain nothing.
- Generalized schema-2 candidate preview differences across every typed object and dependency using
  closed field-name allowlists with no raw values or secret-bearing representation.
- Prevented low-level configuration activation and rollback from accepting typed-bound revisions.
- Fixed token revocation CLI parsing for valid generated token IDs that begin with a hyphen.
- Split Phase 15 transport, candidate-store, compiler/test, Access Policy/test, and CLI dispatch
  ownership without changing API, schema, defaults, fingerprints, or dependencies.
- Froze the exact 52-action role matrix, authorization-before-deserialization ordering,
  cross-owner hiding, legacy-token behavior, and schema-1/schema-2 route separation in regression
  coverage. Phase 15 completion remains pending independent API/security review.
- Fixed the Phase 15 maintainer-review findings: accepted requests retain bounded execution and
  mutation/audit ownership after response timeout, operational JSON is authorized before strict
  parsing, and User mutations preserve not-found, invalid-request, and conflict responses.

See [`STATUS.md`](STATUS.md) and [`docs/history/`](docs/history/README.md).
