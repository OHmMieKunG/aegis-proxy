# Changelog

AegisProxy has not published a supported release.

## Unreleased

- Added bounded stable-ID Proxy Locations to applied and draft Proxy Hosts. Exact and
  segment-aware prefix paths compile across every parent domain with deterministic precedence,
  explicit upstreams, parent-policy inheritance or authorized override, structured browser
  controls, zero-location migration, and exact Phase 17.1 active-binding compatibility.
- Added bounded ordered multiple-domain Proxy Hosts across applied and draft APIs, deterministic
  IDNA normalization, whole-state conflict checks, one exact route per domain with one shared
  upstream, all-domain certificate coverage, browser add/remove/reorder controls, and strict
  singular-record migration that preserves exact legacy active candidate bindings. Managed HTTPS
  coverage rejection now has a stable `certificate_coverage_failed` API code and names the entered
  domain set in the browser without attempting activation.
- Implemented Rust reverse-proxy foundation through historical phases 0–13.
- Rebased documentation around verified current state and the active roadmap.
- Reset the product roadmap around NPMPlus-compatible daily management workflows, with Caddy-style
  certificate automation and Traefik-style providers treated as selective later additions.
- Added an evidence-linked NPMPlus compatibility matrix and product-direction analysis covering
  reuse, typed object evolution, draft/apply recovery, migration, and explicitly unsupported raw
  Nginx behavior.
- Restored file/DNS provider reconciliation under typed startup without enabling live TOML reload.
  Provider-derived revisions retain the exact typed desired-state binding, activate through the
  existing transactional coordinator, resume after restart, and preserve the active
  last-known-good runtime on rejected output or activation failure.
- Added fail-closed durable HMAC audit coverage for provider reconciliation intent, validation,
  candidate creation, activation, rollback, failure, and no-change outcomes under an explicit
  system/provider actor without recording provider payloads or secrets.
- Added the Proxy Host browser lifecycle: task-oriented create/edit, enable/disable, duplicate,
  confirmed delete, dual-CAS conflict reporting, and one-click Save and apply over the existing
  immutable typed candidate and transactional activation APIs. Failed activation is reported as
  saved but not active while the last-known-good runtime remains in service.
- Added a Proxy Host persistence recovery gate. Known pre-rename failures remain retryable;
  indeterminate post-rename durability blocks later mutations and candidate compilation until a
  strict restart reload succeeds. The typed API returns `recovery_required`, and the browser
  reports the uncertain outcome without attempting activation.
- Added durable inactive Proxy Host drafts in one schema-v2 store file with deterministic schema-v1
  migration, independent draft CAS, exact base-generation promotion, restart preservation, and the
  existing recovery gate. The typed API and browser now support Save draft, resumed edit, discard,
  Save and apply, and owner-scoped desired/draft/active status without compiling or activating a
  draft.
- Established a reproducible focused Chromium command using the version-matched pinned Playwright
  image and read-only repository mount; the Proxy Host lifecycle, destructive-permission, and
  recovery-required scenarios execute in a real browser.
- Distinguished structured activation failure from a lost or unclassified browser response: only
  a proved backend failure claims the previous runtime remains active; an unknown response asks the
  operator to refresh before inferring routing state. Draft actions are now visible to roles with
  draft mutation permission even when activation and destructive actions remain unavailable.
- Added real Unix-socket HTTP adversarial coverage for cross-owner and provider-owned draft access,
  stale promotion/discard, and scoped-token denials. Production image builds now run the existing
  React Router reachability gate before compiling the SPA.
- Completed the bounded Proxy Host Save-and-apply failure campaign. Immutable revisions and typed
  bindings now use atomic no-replace publication, active-pointer uncertainty and durable rollback
  failure have distinct recovery outcomes, and terminal mutation/activation audit uncertainty is
  reported without misrepresenting active routing. Deterministic tests cover candidate, pointer,
  rollback, restart, audit, and browser desired-versus-active boundaries.
- Dispositioned GHSA-qwww-vcr4-c8h2 for independent review after confirming that the only patched
  React Router release requires an unbounded React/router migration. Added a production Vite
  module-graph gate proving the affected RSC server handler is absent from the client-only static
  SPA; the unchanged scanner finding remains reported pending a compatible upgrade.
- Adopted user-first GUI and typed-control-plane direction with secret isolation.
- Completed behavior-preserving modularization: focused tests and domain-owned core, configuration,
  and administration modules now replace oversized mixed-responsibility files.
- Added a strict fail-closed `v1` object envelope and typed Proxy Host contract.
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
  existing canonical IP, limit, and authentication middleware stages.
- Added bounded private Access Policy persistence with global IDs, canonical records, owner-scoped
  reads, generation CAS, exclusive ownership, strict restart checks, and atomic replacement.
- Added dedicated Access Policy read/create/update/delete token scopes, fail-closed private startup
  ownership, and owner-scoped routes.
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
- Began Phase 16 with the embedded React/Vite packaging ADR and default-disabled restart-only
  loopback web/OIDC configuration, including exact-origin, issuer, group-conflict, and
  secret-redaction validation.
- Added minimal web availability status and an audited Admin/Unix-peer-only first-run setup-token
  API/CLI contract. One 256-bit ten-minute token is retained only as a process-memory SHA-256
  digest, bound to the peer's `uid-<uid>` owner, and returned once with `no-store`; the RBAC and
  scope vocabulary now contains 53 actions.
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
- Froze the exact 53-action role matrix, authorization-before-deserialization ordering,
  cross-owner hiding, legacy-token behavior, and schema-1/schema-2 route separation in regression
  coverage. Phase 15 is complete for roadmap progression under the recorded owner exception;
  independent API/security review remains a production gate.
- Fixed the Phase 15 maintainer-review findings: accepted requests retain bounded execution and
  mutation/audit ownership after response timeout, operational JSON is authorized before strict
  parsing, and User mutations preserve not-found, invalid-request, and conflict responses.
- Added the default-disabled loopback OIDC browser boundary with bounded discovery/exchange,
  rotating server-side sessions, strict origin/CSRF/cookie controls, and Unix/bearer separation.
- Added crash-recoverable SHA-256 issuer/subject fingerprint binding to durable Users, audited JIT
  provisioning and role synchronization, disabled-user enforcement, and one-use first-run setup.
- Added the generated OpenAPI React/Vite administration client and optional `web-ui` embedding:
  role-aware task routes, the seven-field Proxy Host candidate workflow, typed CRUD, revisions,
  durable audit records, backup validation, read-only settings, responsive layouts, and axe checks.
- Added a clean Node UI image stage and a pinned Linux host-network evaluation stack with real
  Keycloak, Playwright, typed activation, and Host-header traffic coverage.
- Added fail-closed daemon startup reconciliation that compiles durable typed desired state over
  the mounted restart-time TOML base and restores an exact bound Proxy Host revision.

See [`STATUS.md`](STATUS.md) and [`docs/history/`](docs/history/README.md).
