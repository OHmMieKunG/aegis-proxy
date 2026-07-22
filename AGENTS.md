# Repository agent guide

## Source of truth

1. Executable source and tests.
2. Manifests and schemas.
3. [`STATUS.md`](STATUS.md) for verified current state.
4. [`PLAN.md`](PLAN.md) for future work.
5. ADRs for decisions; `docs/history/` for dated evidence only.

Read STATUS, active phase, relevant ADRs, and affected tests before changes.

## Layout

- `proxy-core`: data plane, routing, middleware, upstreams, runtime.
- `proxy-config`: schema, validation, providers, revisions.
- `proxy-tls`, `proxy-secrets`: TLS, ACME, certificates, secrets.
- `proxy-admin`: private API, RBAC, audit, backup.
- `rust-proxy`: CLI and process wiring.

## Required checks

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
cargo tree -e features
```

Run applicable config, integration, fuzz, audit, deny, container, and deployment checks. Report
unavailable commands and environmental failures exactly; never claim an unrun check passed.

## Security boundaries

- Keep `#![forbid(unsafe_code)]`; avoid blocking Tokio workers.
- Parsed Hyper messages are HTTP framing boundary.
- Normalize target, authority, forwarding, and protected headers before policy/upstream work.
- Match once; errors and rewrites never rematch.
- Destinations come only from validated config/providers and pass egress checks.
- Secrets use approved references, stay redacted, and never enter logs, previews, audits, errors.
- Administration remains private Unix socket; mutations require RBAC, revision, durable audit.
- Queues, tasks, bodies, connections, parsers, labels, and provider state remain bounded.

## Change discipline

Phase 14 refactors preserve behavior: extract tests first, move one responsibility at a time, and
do not change API/schema/fingerprints/defaults. Avoid unrelated edits, speculative abstractions,
dependencies, generated files, and historical rewrites. Update STATUS for current behavior and
PLAN for future work; do not duplicate them.
