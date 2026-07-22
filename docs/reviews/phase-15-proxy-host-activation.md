# Phase 15 Proxy Host candidate activation

Date: 2026-07-22

Status: unit complete; Phase 15 remains in progress

Implementation commit: `7c6f613`

## Scope and motivation

This unit adds the first high-level activation operation without creating another runtime or
revision system. Typed create/update/delete still produce immutable non-active revisions. An
administrator may activate one only after AegisProxy proves it is the canonical configuration for
the complete current Proxy Host desired state.

Typed rollback, managed HTTPS, access-policy objects, and other Phase 15 domain objects remain out
of this unit.

## Files and boundaries

- `crates/proxy-admin/src/server/handlers.rs`: verified activation orchestration.
- `crates/proxy-admin/src/server/support.rs`: one bounded permit serializes audited mutations.
- `crates/proxy-admin/src/server.rs`: route, fixed error, and permit ownership.
- `crates/proxy-admin/src/rbac.rs`: exact `activate_proxy_host` action, Admin-only.
- `crates/proxy-admin/src/compile.rs` and `proxy_host.rs`: identify compiler-owned upstream pools
  so later desired-state compilation can safely use the original manual template.
- `crates/rust-proxy/src/main.rs`: private Unix-socket CLI operation.
- `config/schema/admin-openapi.yaml`: checked route and 22-action scope vocabulary.
- `crates/rust-proxy/tests/admin_cli.rs`: end-to-end authorization, conflict, audit, and activation
  evidence.

The boundary is:

```text
authenticated Admin request
→ exact action and scope
→ durable audit intent under mutation serialization
→ active-revision CAS
→ complete desired-state snapshot
→ canonical aggregate compilation and semantic validation
→ immutable revision content-hash equality
→ unchanged desired-state epoch
→ existing atomic activation coordinator
→ durable audit outcome
```

Neither compiler nor object store owns an activation handle. No candidate is published directly.

## Candidate verification and determinism

The handler loads every stored Proxy Host in stable owner/object order and recompiles the complete
set against the active configuration. Aggregate compilation strips only structurally verified
compiler-owned resources for current objects, preserves retained manual configuration, rebuilds
enabled objects with deterministic IDs, and runs the existing semantic validator. The canonical
configuration hash must equal the immutable candidate revision hash.

This equality rejects stale candidates after create/update/delete, candidates unrelated to current
desired state, and tampered revision content. The candidate ID may not equal the active revision;
repeated activation fails as `candidate_conflict` rather than rewriting revision pointers.

## Authorization, ownership, and concurrency

`activate_proxy_host` is a distinct action. `Admin` permits it; Viewer, Auditor, and Operator do
not. Bearer authorization remains the intersection of role and explicit scope. A principal also
must have stable owner metadata, but activation is intentionally global and Admin-only because the
candidate represents every owner's complete desired state. Per-owner activation is deferred until
candidate ownership and approval metadata can prove safe isolation.

All authorized administrative mutations acquire one semaphore permit before durable audit intent
and retain it through final audit outcome. This prevents object mutation between candidate
verification and activation. Existing request concurrency and timeout bounds also bound waiters.
The activation coordinator independently applies active-revision compare-and-swap, preparation,
probation, publication, and rollback behavior.

## Disabled state and post-activation mutation

Disabled objects stay in desired-state storage but produce no active route or upstream. Candidate
verification recompiles this rule. A regression test also proves that after activating a generated
pool, a later update/delete can distinguish compiler-owned pools from the one manual upstream
template and rebuild the next candidate safely.

## Secret and error model

The request carries an opaque revision ID and active revision. Compilation sees typed objects,
validated configuration, and metadata only; it performs no secret resolution, environment read,
DNS, network, or filesystem access. The handler compares hashes and emits fixed API error codes.
Configuration, secret references, policy contents, filesystem paths, and credentials do not enter
errors or audit fields.

Safe outcomes include `revision_conflict`, `object_conflict`, `candidate_conflict`, `not_found`,
`forbidden`, and fixed unavailable/internal failures. Missing and invalid revisions are not
activated.

## Tests and compatibility

Tests prove:

- Admin local peer can activate a freshly compiled complete candidate.
- Operator bearer token without the new Admin-only permission is denied.
- An older candidate is rejected after desired state changes and active revision is unchanged.
- Repeating activation of the active candidate is rejected and active state is unchanged.
- Update/delete continue working after a typed candidate becomes active.
- Activation emits durable `proxy_host_activate` audit events.
- Roles and token scopes remain deny-by-default with an exact 22-action vocabulary.
- Checked OpenAPI and CLI contracts include only the intended additive operation.
- Existing workspace protocol, configuration, revision, and administration tests still pass.

TOML/JSON configuration schema, defaults, Cargo manifests, lockfile, persisted Proxy Host schema,
and public data-plane behavior are unchanged. The OpenAPI, CLI, and RBAC vocabularies intentionally
add typed activation.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 295 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| Proxy Host preparation tests | passed: 4 |
| Admin RBAC/server tests | passed |
| Admin CLI integration | passed |
| Python/PyYAML OpenAPI route/scope check | passed |
| CLI activation help contract | passed |
| added-line secret-pattern review | passed; no match |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` retains its existing future-incompatibility warning. Optional
Cargo tools `nextest`, `audit`, `deny`, `machete`, `llvm-cov`, and `fuzz`, plus `markdownlint` and
`lychee`, were unavailable and are not reported as passed.

## Security, reliability, and performance review

- No unsafe code, dependency, network call, DNS lookup, secret resolution, or new unbounded
  collection was added.
- Mutation serialization closes the store-check/activation race; active revision CAS remains a
  second independent check.
- Blocking store/revision reads and compilation run through `spawn_blocking`.
- Complete configuration cloning and hashing occur only in bounded control-plane work.
- The implementation uses indexed stable stores and ordered compiler inputs; it introduces no
  nondeterministic map iteration or hot-path work.
- No performance improvement is claimed; no benchmark was needed for this correctness unit.

## Known limitations and completion decision

At the activation commit, typed candidate revisions did not retain a durable typed desired-state
snapshot. Subsequent commit `80a7f27` adds that binding and makes activation require it; see
[typed candidate binding](phase-15-proxy-host-candidate-binding.md). Crash-safe high-level rollback
still needs a transaction restoring both desired objects and runtime configuration. Access-policy
and managed-HTTPS endpoints still fail closed. Activation is global and Admin-only. Historical
low-level configuration activation/rollback remains available separately.

Phase 15 growth places `server/handlers.rs` at 1,629 lines and CLI `main.rs` at 1,257 lines. Their
transport ownership is an explicit temporary exception; split them after Phase 15 contracts
stabilize and before Phase 15 exit.

The typed activation unit meets its gate. Phase 15 is not complete. Its binding dependency is now
implemented; crash-safe forward rollback remains next.
