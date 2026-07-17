# AegisProxy

Security-first Rust reverse proxy. Initial scope: one Tokio process, strict TOML, HTTP/1.1, HTTP/2, WebSocket, gRPC forwarding, TLS termination, TCP passthrough, bounded reload, and private administration.

Status: implementation in progress. See [`PLAN.md`](PLAN.md) and [`docs/implementation-readiness-review.md`](docs/implementation-readiness-review.md).

Operator guides: [configuration v1](docs/configuration-v1.md), [configuration reload](docs/config-reload.md), [ACME certificates](docs/operations/acme.md), and [TLS key recovery](docs/tls-key-recovery.md).

## Local checks

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

No public administrative listener or production deployment is provided by the repository defaults.
