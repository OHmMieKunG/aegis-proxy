# Phase 15 Proxy Host read integration review

Recorded: 2026-07-22

Implementation commit: `d1514dd`

Decision: owner-scoped read unit complete; Phase 15 remains in progress

## Scope and boundary

Administration now opens bounded `ProxyHostStore` at `<state_dir>/admin/proxy-hosts.json`.
Authenticated principals may list or get only their typed Proxy Host desired state. Validation and
preview consume metadata-only stored claims so duplicate object IDs or domains fail rather than
overwrite. This unit adds no create, update, delete, audit mutation, revision creation, activation,
runtime change, dependency, or TOML-schema field.

```text
authenticated principal -> exact read scope -> owner-scoped store read
authenticated principal -> validate/preview -> stored claims -> compiler -> semantic validator
```

Neither path reaches revision or activation services.

## API, CLI, and authorization

- `GET /v1/proxy-hosts` returns stable object-ID order for authenticated owner.
- `GET /v1/proxy-hosts/{id}` returns one owned object and its generation ETag.
- `rust-proxy proxy-host list|get` call these private Unix-socket routes.
- Bearer tokens need `read_proxy_hosts`; role and scope must both allow it.
- Viewer, auditor, operator, and admin may read only their owner namespace.
- Missing owner metadata is forbidden. Invalid, absent, and cross-owner IDs return not found.

Administrative action vocabulary now contains 18 stable snake-case values. Existing token-file
schema remains version 1; old scope values and their relative canonical order remain valid.

## Conflicts, secrets, and runtime isolation

`ProxyHostClaims` contains only `(owner_id, object_id)` identities and canonical domain ownership.
Validation/preview receives an immutable snapshot. Claimed IDs and domains fail closed; no record is
replaced. Stored objects contain no secret field. List/get returns typed desired state and generation
only; no hashes, tokens, policy contents, certificate keys, secret references, paths, or runtime
configuration are added. Errors remain fixed envelopes.

Store open validates schema, bounds, permissions, and contents before administration starts.
Corrupt or insecure typed state fails administration startup and is never skipped. Reads clone at
most bounded state and run off Tokio workers. Active runtime and revision pointer remain unchanged.
Existing configuration schema, defaults, manifests, lockfile, data-plane behavior, and low-level
APIs remain unchanged. OpenAPI and CLI intentionally add read contracts.

Typed mutation is deferred. Compiling one proposed object from active configuration could omit
another persisted but not-yet-activated object. Next unit must compile aggregate desired state
deterministically before any store mutation endpoint can be safe.

## Tests and validation

- Store tests cover stable owner reads, cross-owner absence, claims, reopen, and bounds.
- Admin CLI integration preloads two owners, proves one-owner list/get and generation, proves exact
  token scope, and rejects a persisted-domain conflict.
- RBAC tests cover the 18-action deny-by-default matrix.
- OpenAPI route coverage and YAML parsing pass.

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
| Python/PyYAML OpenAPI parse | passed |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` retains its existing future-incompatibility warning. Optional
tools remain unavailable as recorded in `STATUS.md`.

## Completion decision

Owner-scoped read integration meets this unit's authorization, isolation, conflict, compatibility,
and validation gate. Phase 15 remains in progress; production assessment remains NO-GO.
