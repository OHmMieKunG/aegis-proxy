# Contributing

AegisProxy is pre-release. Discuss architecture, schema, security-boundary, dependency, or roadmap
changes before implementation. Small fixes need focused regression evidence.

## Checks

Use stable Rust 1.88 or newer:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
```

Run applicable checks from [`docs/development/testing.md`](docs/development/testing.md). Report
unavailable tools; do not suppress valid failures.

## Rules

- Preserve validation order, single route match, bounds, redaction, egress, activation, audit.
- Add no first-party unsafe Rust without dedicated ADR and review evidence.
- Avoid unrelated formatting, refactors, dependencies, and generated output.
- Update STATUS only for verified behavior and PLAN only for roadmap decisions.
- Preserve dated evidence under `docs/history/`.
- Never commit credentials, private keys, real certificates, `.env`, or production details.

Product name is `AegisProxy`; executable remains `rust-proxy` until an implementation ADR and
migration authorize rename.
