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

- `Action` is the single serialized 17-action vocabulary used by RBAC and scopes.
- `TokenScopes` sorts actions canonically and rejects empty, duplicate, or role-exceeding issuance.
- Persisted nonempty scopes must already be strictly ordered, unique, and role-valid.
- Token metadata contains ID, role, scopes, expiry, and revocation only.
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

Typed-object ownership enforcement and high-level Proxy Host endpoints remain absent. The next unit
adds owner-aware Proxy Host validation and preview endpoints using the existing compiler, preview,
diff, RBAC, audit, revision, and activation boundaries.
