# Phase 15 Proxy Host update/delete review

Recorded: 2026-07-22

Implementation commit: `7e8b47d`

Decision: typed update/delete unit complete; Phase 15 remains in progress

## Scope

This unit adds audited owner-scoped update and delete for persisted Proxy Hosts. Each operation
builds complete post-mutation desired state, compiles and semantically validates it, persists an
immutable non-active configuration candidate, then applies an epoch-checked object-store mutation.
No endpoint activates runtime. No dependency, TOML schema field, public listener, database,
access-policy object, or certificate-policy object was added.

## API and CLI contract

- `PUT /v1/proxy-hosts/{id}` strictly accepts `ApiObject<ProxyHostSpec>` and returns updated stored
  object, generation ETag, and immutable candidate metadata.
- `DELETE /v1/proxy-hosts/{id}` returns deleted stored object and candidate metadata.
- Both require exact active-revision `If-Match` and canonical positive
  `X-Aegis-Object-Generation`.
- CLI commands are `proxy-host update --expect REV --generation N ID FILE` and
  `proxy-host delete --expect REV --generation N ID`.
- Bearer authorization uses distinct `update_proxy_host` and `delete_proxy_host` actions. Existing
  tokens gain no scope automatically.

## Ordering and candidate boundary

```text
authorization and audit intent
-> active revision and object generation preconditions
-> owner/path/body validation
-> complete stable object snapshot
-> aggregate compile and semantic validation
-> immutable non-active revision
-> snapshot-epoch plus object-generation store CAS
-> audit outcome
```

Update replaces exactly one matching owner/object record in complete desired state. Delete removes
exactly one. Existing aggregate compiler removes only structurally verified generated namespaces,
retains pending objects, rejects manual/tampered collisions, and validates final canonical config.
Disabled updates generate no runtime resources. Candidate creation never publishes runtime state.

## Ownership and failure behavior

Authorization runs before JSON deserialization or object lookup. Update requires path ID, body ID,
body owner, and principal owner to agree. Delete searches only authenticated owner namespace;
cross-owner and missing IDs share not-found behavior. Invalid or duplicate generation headers fail
closed. Stale generation is rejected before candidate creation; epoch CAS catches concurrent changes
after compilation.

Candidate persists before desired-state mutation, preventing durable object state without a
candidate. A late store failure can leave only an immutable non-active candidate, identified by
failure audit and eligible for normal revision retention. Audit intent failure prevents mutation.
Success/failure/denial records contain action, stable resource ID, revisions, and fixed error code,
not object body or credentials.

## Security and compatibility evidence

- Scoped operator token lacking new actions cannot create revisions or mutate objects.
- Local owner update advances generation one to two and persists exact strict object.
- Stale update/delete return conflict and leave revision/object/runtime state unchanged.
- Cross-owner update is forbidden before candidate creation.
- Delete removes only owned object and returns prior generation.
- Create, update, and delete all leave active revision unchanged.
- Existing unknown-field, unsupported-version, domain, upstream, semantic-validation, secret
  canary, audit, revision, rollback, request-validation, and runtime suites remain green.
- Existing persisted store schema, TOML schema/defaults, manifests, lockfile, low-level API, and
  data-plane behavior remain compatible. OpenAPI/CLI/action vocabulary intentionally expand.

No unsafe code, secret resolver, network/DNS operation, environment read, runtime handle in
compiler/store, high-cardinality telemetry, or unbounded collection was introduced. Blocking
filesystem and compilation work remains off Tokio worker threads.

## Validation

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
| admin CLI mutation integration | passed |
| Python/PyYAML OpenAPI parse | passed |
| CLI update/delete help contract | passed |
| added-line secret-pattern review | passed; no candidate secret match |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` retains its existing future-incompatibility warning. Optional
tools remain unavailable as recorded in `STATUS.md`.

## Module-size exception

Phase 15 transport growth brings `crates/proxy-admin/src/server/handlers.rs` to 1,499 lines and
`crates/rust-proxy/src/main.rs` to 1,232. Both still have one cohesive ownership: private HTTP
orchestration and CLI dispatch. Splitting them while endpoint contracts are still changing would
mix behavior-preserving movement into this security mutation. This is an explicit temporary
exception to approximate 1,200-line guidance. Split typed Proxy Host transport and CLI dispatch
after Phase 15 contracts stabilize and before Phase 15 exit.

## Remaining work and decision

Typed activation/rollback must verify candidate against complete current desired state. Phase 15
also still needs access-policy/certificate ownership, remaining domain objects and contracts,
migration/compatibility coverage, the module split above, and full authorization/security review.

Update/delete satisfy exact scope, owner isolation, active-revision and object-generation
preconditions, complete-state compilation, immutable candidate, dual CAS, audit, secret isolation,
and non-activation gates. Phase 15 remains in progress; production assessment remains NO-GO.
