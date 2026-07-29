# AegisProxy

AegisProxy is a pre-release Rust reverse proxy and application gateway. Current code provides a
secure typed foundation; planned work adds NPMPlus-like usability, Caddy-style automation, and
Traefik-style infrastructure integration without bypassing validation or secret controls.

## Current maturity

Suitable for controlled local and staging evaluation. Not production-ready. Independent protocol
and security review, long fuzz/soak, release automation, artifact signing, SBOM,
multi-architecture validation, and representative recovery testing remain blockers.

Verified capabilities include HTTP/1.1 and HTTP/2, WebSocket, gRPC, HTTPS termination, upstream
TLS, raw TCP, TLS passthrough, strict TOML, deterministic routing, bounded balancing and health,
transactional reload/rollback, ACME, fixed-stage middleware, private administration,
metrics/tracing/audit, file/A/AAAA discovery, and external-load-balancer fleet checks.
Phase 15 provides the owner-scoped typed control plane. The current Phase 16 working tree adds
optional loopback browser administration, OIDC sessions, first-run identity binding, an embedded
React client, and fail-closed typed desired-state reconciliation at process startup.

Major gaps include automatic HTTPS, Docker/Kubernetes providers, PROXY protocol, client mTLS,
HTTP/3, gRPC-Web, automated restore, live provider reconciliation after typed startup, complete
Proxy Host lifecycle controls in the GUI, complete real-system failure coverage, release workflow,
and production evidence. See [`STATUS.md`](STATUS.md) for exact status and [`PLAN.md`](PLAN.md) for
the active roadmap.

## Architecture

One Tokio process and binary use Hyper for HTTP, Rustls for TLS, strict typed configuration,
immutable runtime snapshots, file-backed revisions, age-encrypted secret material, and a private
Unix-socket administration API. `AegisProxy` is product name; `rust-proxy` remains current
executable name.

## Quick development check

Requires stable Rust 1.88 or newer:

```bash
cargo run -q -p rust-proxy -- validate --config config/examples/minimal.toml
cargo test --workspace --all-features
```

Run a local upstream on `127.0.0.1:9000`, then:

```bash
cargo run -p rust-proxy -- run --config config/examples/minimal.toml
curl -H 'Host: example.test' http://127.0.0.1:8080/
```

Port `9000` must be free and serve intended content; an existing process may return unrelated
files or cause `Address already in use`.

For the disposable Linux browser/Keycloak workflow, use the
[evaluation stack](deploy/evaluation/README.md).

## Documentation

- [Verified status](STATUS.md)
- [Roadmap](PLAN.md)
- [Documentation index](docs/README.md)
- [Installation](docs/operations/installation.md)
- [Configuration reference](docs/configuration/reference.md)
- [Private administration](docs/operations/admin.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

No parity, vulnerability-free, production, HA, or performance claim is made.
