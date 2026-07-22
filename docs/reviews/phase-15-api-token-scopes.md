# Phase 15 API-token scope review

Recorded: 2026-07-22

Implementation commit: `81bd500`

Decision: API-token scope unit complete; Phase 15 remains in progress

## Scope

The existing private administration API now requires every newly issued bearer token to contain a
nonempty explicit action-scope set. The authorization decision is `role allows action AND token
scope contains action`. Kernel-authenticated local peers retain their existing fixed admin role and
do not become bearer tokens.

This unit changes the existing token endpoint, CLI, checked OpenAPI, private token records, and safe
metadata. It adds no high-level Proxy Host endpoint, database, public listener, or secret export.

## Contract and persistence

- At this unit's commit, `Action` was the single serialized 17-action vocabulary used by RBAC and
  scopes; later typed reads add `read_proxy_hosts` as the eighteenth value.
- `TokenScopes` sorts actions canonically and rejects empty, duplicate, or role-exceeding issuance.
- Persisted nonempty scopes must already be strictly ordered, unique, and role-valid.
- Token metadata contains ID, role, scopes, expiry, and revocation only at this unit's commit.
- Plaintext still appears once at issuance; only Argon2id hashes persist.
- Unknown token IDs still pay the fallback Argon2id verification cost.

Token-file schema remains version 1. A missing legacy `scopes` field becomes an empty deny-all set.
It authenticates only far enough to receive authorization denial and must be explicitly replaced by
an authorized local peer. This prevents automatic privilege carry-forward.

## Security evidence

- Empty and duplicate scopes fail closed for new tokens.
- A scope outside the selected role fails closed.
- Every bearer request requires both role and explicit scope.
- An admin-role token with only `read_status` cannot activate configuration.
- Legacy empty-scope admin tokens cannot read status.
- Local Unix peer authorization behavior is unchanged.
- CLI integration proves a scoped read succeeds and identity mutation is denied.
- CLI integration proves viewer-to-activation scope escalation is rejected.
- OpenAPI exposes no password hash or private-key field.
- No new dependency or unsafe code was introduced.

## Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 284 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| `cargo test -p rust-proxy --test admin_cli --all-features` | passed |
| OpenAPI YAML parse with Python/PyYAML | passed |
| `rust-proxy token create --help` | passed; scopes are required and enumerated |
| `git diff --check` | passed |

Ruby YAML validation was unavailable because `ruby` is not installed; Python/PyYAML parsed the same
file successfully. Transitive `proc-macro-error2 2.0.1` continues to emit its pre-existing future
warning. Optional tools remain unavailable as listed in `STATUS.md`.

## Compatibility, limits, and next unit

Configuration schema, defaults, manifests, lockfile, runtime behavior, and existing non-token API
routes are unchanged. Token creation intentionally requires scopes. Legacy tokens become deny-all,
with explicit replacement documented in
[`configuration/migrations.md`](../configuration/migrations.md).

Subsequent commit `00cfa32` adds owner metadata to newly issued tokens and owner-aware read-only
Proxy Host validation/preview endpoints. Subsequent commit `d1514dd` adds the eighteenth action,
`read_proxy_hosts`, for owner-scoped desired-state reads. Typed mutation remains absent.

> Security correction — 2026-07-22
>
> Review after aggregate compilation found `begin_mutation` checked role permission without checking
> a bearer token's explicit scope. Commit `106f2fa` routes mutation authorization through the same
> role-and-scope intersection and adds integration proof that an operator token lacking
> `create_candidate` cannot create an immutable revision. Earlier broad “every bearer request”
> wording was not fully evidenced until this correction.

Subsequent commit `068f408` adds nineteenth action `create_proxy_host`. Existing tokens do not gain
it; typed create requires exact role-and-scope intersection and audit intent before deserialization.
