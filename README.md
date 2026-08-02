# AegisProxy

AegisProxy is a pre-release, self-hosted reverse-proxy manager written in Rust. Its product
workflow targets NPMPlus-compatible host, certificate, access-control, and administration
capabilities, while its independent Rust core uses typed configuration, transactional activation,
and safe automatic defaults. Optional infrastructure discovery is additive and does not replace
the primary GUI-managed workflow.

Compatibility concerns important user-visible workflows and outcomes. It does not mean Nginx
configuration, NPMPlus database or private API compatibility, copied implementation, arbitrary
Nginx directives, or a pixel-identical UI. The current
[compatibility matrix](docs/product/npmplus-compatibility-matrix.md) documents evidence and gaps;
complete parity is not claimed.

## Current maturity

Suitable for controlled local and staging evaluation. Not production-ready. Independent protocol
and security review, long fuzz/soak, release automation, artifact signing, SBOM,
multi-architecture validation, and representative recovery testing remain blockers.

Verified capabilities include HTTP/1.1 and HTTP/2, WebSocket, gRPC, HTTPS termination, upstream
TLS, raw TCP, TLS passthrough, strict TOML, deterministic routing, bounded balancing and health,
transactional reload/rollback, ACME, fixed-stage middleware, private administration,
metrics/tracing/audit, file/A/AAAA discovery, and external-load-balancer fleet checks.
Phase 15 provides the owner-scoped typed control plane. Current Phase 16 work adds optional
loopback browser administration, OIDC sessions, first-run identity binding, an embedded React
client, and fail-closed typed desired-state reconciliation at process startup.

Highest-priority gaps are live provider reconciliation after typed startup; Proxy Host
edit/enable/disable/delete/duplicate and simplified Save/apply workflows; Proxy Locations;
Redirection and Dead Hosts; complete certificate/access/restore/migration workflows; controlled
failure coverage; release engineering; and production evidence. Docker/Kubernetes providers and
broader gateway work are intentionally later. See [`STATUS.md`](STATUS.md) for exact status and
[`PLAN.md`](PLAN.md) for the active roadmap.

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
- [Product direction](docs/product/npmplus-direction-reset.md)
- [NPMPlus compatibility matrix](docs/product/npmplus-compatibility-matrix.md)
- [Documentation index](docs/README.md)
- [Installation](docs/operations/installation.md)
- [Configuration reference](docs/configuration/reference.md)
- [Private administration](docs/operations/admin.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

No complete-parity, vulnerability-free, production, HA, or performance claim is made.
