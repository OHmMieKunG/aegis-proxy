# Phase 15 Proxy Host create review

Recorded: 2026-07-22

Implementation commits: `f204012`, `068f408`

Decision: typed create unit complete; Phase 15 remains in progress

## Scope and motivation

This unit adds the first high-level mutation: create one owned Proxy Host desired-state object and
its immutable canonical candidate. It connects existing typed contracts, aggregate compiler,
semantic validator, revision store, audit log, RBAC, and object store without introducing another
activation path. It adds no update, delete, automatic activation, access-policy object,
certificate-policy object, database, network listener, dependency, or TOML schema field.

## Files and ownership

- `crates/proxy-admin/src/object_store.rs`: complete desired-state snapshot and epoch CAS.
- `crates/proxy-admin/src/proxy_host.rs`: endpoint-facing aggregate preparation over active config.
- `crates/proxy-admin/src/rbac.rs`: exact `create_proxy_host` action.
- `crates/proxy-admin/src/server.rs` and `server/{handlers,support,tests}.rs`: private route,
  transaction ordering, strict content type, safe errors, and contract tests.
- `crates/rust-proxy/src/main.rs`: `proxy-host create` CLI and token-scope vocabulary.
- `crates/rust-proxy/tests/admin_cli.rs`: authorization, persistence, revision, and non-activation
  integration evidence.
- `config/schema/admin-openapi.yaml`: checked request, response, and scope contract.

## Typed input and mapping

Input remains strict `ApiObject<ProxyHostSpec>` with API version, immutable object/owner identity,
and seven common fields: domain, forward host, forward port, protocol, automatic HTTPS,
access-policy reference, and enabled state. Unknown fields, future versions, invalid IDs, invalid
domains/upstreams, zero ports, unsupported protocols, unavailable policy/certificate metadata, and
semantic conflicts fail closed.

`prepare_proxy_host_set` selects the existing single HTTP listener and all-HTTP upstream template,
then calls `compile_proxy_hosts(current, desired, context)`. Existing deterministic generated IDs,
disabled-object omission, egress policy, route conflict, and semantic validation behavior are
unchanged. Endpoint preparation currently rejects managed HTTPS and access-policy references
because their typed owned metadata is not available.

## Candidate and transaction boundary

```text
authenticated principal
-> exact create_proxy_host role/scope authorization
-> durable audit intent
-> exact active-revision If-Match
-> strict JSON and owner equality
-> complete desired-state snapshot
-> aggregate compile and semantic validation
-> immutable configuration revision
-> object-store epoch CAS
-> durable audit outcome
```

Compilation is side-effect free. Revision creation writes an immutable non-active candidate.
`create_if_epoch` persists generation-one desired state only if no intervening typed-object mutation
changed the process-local epoch. Active revision is checked before and after candidate creation.
The endpoint returns HTTP 201, object-generation ETag, stored object, and candidate metadata; it
never invokes activation coordinator or changes runtime state.

## Determinism and concurrency

Snapshot records are owner/object ordered. Aggregate compilation uses ordered maps and one final
semantic-validation pass. Same snapshot, object, and active configuration produce same candidate
bytes and hash. Store mutex and epoch CAS reject stale complete-state compilation. Object generation
remains the durable per-object CAS. Epoch intentionally resets at process restart because no
in-flight request survives restart.

## Ownership, policy, and conflicts

Authorization happens before JSON deserialization. Effective bearer permission is role intersected
with explicit token scope. Principal owner must equal object owner. Aggregate compiler and store
both reject object/domain collision; compiler also rejects generated-ID/manual-resource takeover.
Missing or unauthorized policy metadata fails rather than becoming public access. Public errors are
fixed envelopes and do not disclose another owner's object or policy contents.

## Disabled, TLS, and secret behavior

Disabled objects persist as desired state but generate no active route/group/endpoint in candidate.
Create never activates, so enabled objects also remain inactive until a separately authorized
revision activation. Managed HTTPS expresses desired policy only at compiler level and fails at the
current endpoint until typed certificate ownership exists. Input contract has no credential field;
compiler context has metadata only; candidate serialization uses opaque configured references; and
errors/audit records contain no object body or secret.

## Error model and failure ordering

- malformed JSON/content type and invalid candidate: `invalid_request`;
- owner or exact-scope denial: `forbidden`;
- stale active revision: `revision_conflict`;
- stale object epoch or duplicate object/domain: `object_conflict`;
- durable dependency failure: generic `unavailable` or `internal_error`.

Audit intent must persist before parsing or mutation. Candidate revision is persisted before object
state, so no durable object can exist without its immutable candidate. A late store conflict/failure
can leave an immutable non-active orphan candidate; failure audit identifies it and normal revision
retention may prune it. This is safer than compensating by deleting immutable history.

## Tests and security evidence

- Store tests prove stable snapshot order, epoch advancement only after durable success, stale-epoch
  rejection, write-failure stability, and restart reset.
- RBAC tests cover the 19-action deny-by-default role matrix and explicit canonical token scopes.
- Admin CLI integration proves an out-of-scope operator token cannot create a revision or object.
- Authorized local create returns generation one, persists exact typed object and immutable
  candidate, leaves active revision unchanged, and becomes visible only within owner-scoped reads.
- Existing aggregate compiler tests cover deterministic complete-state compilation, conflicts,
  disabled objects, semantic validation, revision isolation, and secret canaries.
- Strict unknown-field and unsupported-version contract tests remain green.

No unsafe code, dependency, unbounded collection, network/DNS operation, environment read,
secret-bearing telemetry, or runtime mutation was added. Blocking filesystem, serialization, and
compilation work runs through bounded administration requests and `spawn_blocking`.

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
| configuration corpus integration test | passed |
| Python/PyYAML OpenAPI parse and route check | passed |
| added-line secret-pattern review | passed; no candidate secret match |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` retains its existing future-incompatibility warning. Optional
tools remain unavailable as recorded in `STATUS.md`.

## Compatibility and known limits

Existing TOML schema/defaults, manifests, lockfile, runtime protocol behavior, low-level endpoints,
and persisted Proxy Host schema remain compatible. OpenAPI and CLI intentionally add create and the
new action scope. Pre-release consumers must add `create_proxy_host` explicitly to bearer tokens;
existing explicit scopes retain meaning.

Create does not bind a durable desired-state revision ID to the object store, expose update/delete,
or prove a candidate still matches desired state at later activation. Typed activation must compile
or verify the complete current desired state before publication. Access-policy and managed-HTTPS
creation remain fail-closed. Single-process epoch is not a cluster coordination primitive.

## Remaining Phase 15 work

1. Audited owner-scoped generation-CAS update and delete.
2. Typed activation/rollback with complete desired-state candidate verification.
3. Access-policy and certificate objects plus ownership/sharing rules.
4. Remaining domain objects, endpoints, OpenAPI/CLI contracts, and authorization matrix.
5. Migration/compatibility tests and full API/security review.

## Completion decision

Typed create satisfies authorization-first, ownership, complete-state compilation, semantic
validation, immutable candidate, audit, epoch CAS, secret isolation, and non-activation gates.
Phase 15 remains in progress and production assessment remains NO-GO.

Subsequent commit `7e8b47d` applies same immutable-candidate ordering and store-epoch CAS to
separately scoped update/delete, with an additional exact object-generation precondition.
