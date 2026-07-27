# Phase 15 typed Proxy Host rollback

Date: 2026-07-22

Status: unit complete; Phase 15 remains in progress

Implementation commits: `69a5fe3`, `b7a053b`

## Scope

This unit adds Admin-only forward rollback for typed Proxy Host desired state. It restores a
strict historical bound object snapshot, compiles it against the current manual configuration,
creates a new immutable bound revision, and activates only through the existing atomic activation
coordinator. It does not rewrite history, expose a generic object import, or add GUI behavior.

## Contract and authorization

`POST /v1/proxy-hosts/revisions/{id}/rollback` and
`rust-proxy proxy-host rollback --expect CURRENT REVISION` accept only an opaque retained revision
ID. The request requires exact active-revision `If-Match`, Admin role, and the distinct
`rollback_proxy_host` token scope. Operator tokens cannot acquire or use this action. The action
vocabulary is now 23 values; existing tokens receive no new scope automatically.

The target must be a retained typed revision with valid metadata and a strict private candidate
snapshot whose canonical hash matches `binding_hash`. Low-level unbound revisions, missing files,
wrong permissions, malformed state, tampering, and already-active targets fail closed.

## Forward-revision and desired-state transaction

Rollback uses this order:

```text
authorize and record durable audit intent
→ load and verify historical bound typed snapshot
→ compile target objects against current active manual configuration
→ semantic validation
→ create a new immutable bound forward revision and snapshot
→ recheck active revision
→ write private desired-state rollback journal
→ replace current typed desired state
→ activate through the existing coordinator
→ remove journal after successful activation
→ record durable audit success
```

The historical revision never becomes active directly. The new revision source records the opaque
historical ID, and its active pointer, runtime configuration, and typed desired state converge on
the same forward revision. Existing manual resources are retained from the current active
configuration; only compiler-owned Proxy Host resources are rebuilt.

Current object identities restored by rollback advance their generation. An object absent from
current desired state is restored at generation one, matching normal create semantics. Disabled
objects remain in desired state but compile to no active route.

## Crash recovery

`<state_dir>/admin/proxy-host-rollback.json` is a strict schema-v1 recovery journal containing the
bounded previous and target secret-free typed records plus target forward revision. It is written
mode `0600` under the private Admin directory, rejects symlinks, unknown fields, invalid IDs,
oversize content, and broad permissions, and is fsynced before desired state changes.

While the journal exists, all administrative mutation is denied. On Admin startup, recovery reads
the durable active revision:

- if it equals the target forward revision, target desired state is retained;
- otherwise previous desired state is restored.

The journal is removed and its parent directory fsynced only after convergence. Activation
failure restores previous desired state. If activation reports that its own recovery is required,
the typed journal is deliberately retained so startup can reconcile both transactions. A journal
commit or abort failure leaves mutation blocked rather than permitting divergent changes.

## Security and reliability review

- Compilation and snapshot loading run before desired-state replacement and cannot publish runtime
  state.
- Only the established activation coordinator can switch the active revision.
- Role and explicit token scope are checked before target lookup, preventing an unauthorized token
  from probing historical typed state.
- Historical snapshots contain only the seven-field Proxy Host contract and cannot contain secret
  plaintext.
- API errors and audit records use fixed codes and opaque revision IDs; they do not include object
  contents, configuration, filesystem paths, or credentials.
- Strict binding, canonical order, and semantic validation prevent silent domain/resource
  overwrite.
- The object mutex and process-wide mutation permit serialize journal creation with normal object
  writes. The store also checks the journal while holding its object lock.
- Blocking filesystem and compilation work runs through `spawn_blocking` at request/startup
  boundaries.
- Files, objects, actions, and serialized bytes remain explicitly bounded.
- No unsafe code, dependency, network request, DNS lookup, environment read, secret resolution, or
  high-cardinality telemetry was added.
- Binding hashes detect accidental or same-account state changes but do not replace host integrity
  controls.

## Tests

Focused tests cover journal abort, mutation blocking, restart recovery selecting previous versus
target state, journal cleanup, bound versus unbound target rejection, Operator denial, forward
revision identity, generation advancement, desired-state restoration, runtime activation, audit
recording, and existing activation/configuration behavior.

The integration run exposed an existing CLI parsing defect: URL-safe random token IDs can begin
with `-`, which Clap previously interpreted as an option during revocation. `b7a053b` accepts hyphen
values at that generated-ID boundary and adds a deterministic parser regression test.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 299 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| `cargo test -p aegisproxy-admin --all-features` | passed: 46 |
| private Admin CLI integration | passed in three repeated targeted runs and full workspace run |
| OpenAPI Python/PyYAML contract check | passed: rollback path and 23 scopes |
| rollback CLI help contract check | passed |
| `git diff --check` | passed |

One pre-fix targeted CLI run failed at token revocation with exit 2. The generated ID began with a
hyphen; the root cause and deterministic regression are fixed in `b7a053b`. Subsequent repeated and
workspace runs passed.

`cargo audit` and `cargo deny check` could not run because Cargo reports `no such command`.
`cargo nextest`, `cargo machete`, `cargo llvm-cov`, `cargo fuzz`, `markdownlint`, and `lychee` are
also unavailable. The transitive `proc-macro-error2 2.0.1` future-incompatibility warning remains
pre-existing and non-blocking for this unit.

## Compatibility and limitations

The TOML schema, defaults, manifests, lockfile, data-plane behavior, and strict seven-field Proxy
Host object schema are unchanged. OpenAPI, CLI, and the action vocabulary add typed rollback. Old
tokens remain valid but lack the new scope. Low-level rollback remains separate and cannot be used
through this typed endpoint.

Subsequent unit `788b5a2` coordinates the independently capped snapshot directory with
configuration revision retention. A restored object that was deleted and recreated can reuse
generation one; cross-restart durable tombstone generations are not implemented.
Access-policy/certificate ownership and the remaining typed objects also remain incomplete.
Transport modules exceed size guidance and must be split before Phase 15 exits.

## Completion decision

The crash-safe typed Proxy Host rollback unit meets its authorization, binding, forward-history,
activation-isolation, recovery, compatibility, and available-validation gates. Phase 15 remains in
progress and production assessment remains NO-GO.
