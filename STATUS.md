# AegisProxy verified status

Verification date: 2026-07-22
Branch: `dev`
Commit: `aadac76a1618bdf9926ec37705b657fe64cdd430`
Working tree at verification start: clean and equal to `origin/dev`

## Release status

**Pre-release; production NO-GO.** Current code is suitable for controlled local and staging
evaluation. Historical validation does not replace independent review or production-topology
evidence.

## Implemented

- HTTP/1.1, HTTP/2, WebSocket, gRPC, streaming, trailers, cancellation, graceful shutdown.
- HTTPS termination, upstream TLS, static encrypted certificates, raw TCP, TLS passthrough.
- Strict TOML, semantic validation, deterministic host/path/method/header routing.
- Round-robin, smooth weighted, random, power-of-two balancing, active/passive health, retries,
  circuits, connection/request limits, endpoint drain.
- Immutable revisions, atomic activation, probation, rollback, file/SIGHUP reload, explicit
  last-known-good recovery.
- ACME HTTP-01, Cloudflare DNS-01, TLS-ALPN-01, wildcard DNS certificates, encrypted account/key
  state, bounded renewal, and prior working-certificate retention.
- Fixed-stage middleware, Basic auth, ForwardAuth, IP policy, rate limiting, CORS, headers,
  rewrites, compression, maintenance, and static errors.
- Private Unix API/CLI, fixed RBAC, hash-only API tokens, concurrency checks, audit, backup creation,
  restore validation, status, metrics, and node drain.
- JSON logs, OpenMetrics, optional OTLP tracing, request correlation, HMAC-chained audit.
- Bounded file and DNS A/AAAA providers; external-load-balancer fleet checks.
- Eight fuzz targets and broad unit/integration/security regression coverage.

## Partial or experimental

- ACME requires explicit low-level issuer/challenge policy; common automatic HTTPS is Phase 17.
- SSE uses generic streaming and skips compression but lacks a focused protocol test.
- Administration is typed but TOML/revision oriented; high-level domain APIs are Phase 15.
- Preview returns redacted config, fingerprints, and activation class; field-level diff is absent.
- Restore validates archives but does not extract or activate them.
- Fleet operation uses external orchestration; no cluster or consensus exists.
- Fuzzing has dated smoke evidence, not long campaigns. Reload benchmark is narrow and dated.

## Absent or deferred

- Web GUI, first-run wizard, GUI CRUD, browser sessions, progressive disclosure, UI tests.
- Native OIDC/OAuth2, API-token scopes, renewal history, unified secret rotation.
- Docker, Kubernetes, Consul, SRV discovery, provider approval/conflict workflow.
- PROXY v1/v2, client mTLS, sticky sessions, least-connections, backup upstreams, gRPC-Web,
  HTTP/3, UDP proxying.
- Automated restore, CI/release workflow, SBOM, signing/provenance, multi-architecture release,
  automated container scanning.

## Immediate phase

[Phase 14 behavior-preserving modularization](PLAN.md#phase-14--behavior-preserving-modularization).
Large modules include `crates/proxy-core/src/lib.rs` (5,415 lines),
`crates/proxy-config/src/lib.rs` (4,749), and `crates/proxy-admin/src/server.rs` (2,159). Phase 14
must preserve behavior.

## Release blockers

- Phase 14–21 exit criteria for shipped scope.
- Independent application-security and reverse-proxy protocol reviews.
- No unresolved critical/high findings and signed residual-risk decision.
- Long fuzz and soak evidence.
- Target-host confinement, capacity, upgrade, restore, canary, and rollback drills.
- Reproducible multi-architecture artifacts, SBOM, signing/provenance, and supply-chain gates.

## Verification results

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 268 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| valid configuration corpus | seven accepted |
| invalid configuration corpus | three rejected as expected |
| local Markdown link scan | 97 files, zero broken relative targets after rebaseline |
| `cargo tree -e features` | passed; 2,441 output lines including two lock-wait messages |

## Unavailable or incomplete checks

- `cargo audit` and `cargo deny check`: Cargo reports `no such command`. Dated Elysium results are
  not current scans.
- Docker/Compose: Docker Desktop reports WSL integration unavailable.
- `systemd-analyze verify`: sandbox blocked its credential sockets with `Operation not permitted`;
  unit validation did not complete.
- `cargo fuzz`: Cargo reports `no such command`; dated smoke evidence is not current execution.
- `markdownlint` and `lychee`: commands not found. Repository-local relative-link scan passed.
- Pebble, long fuzz/soak, AppArmor enforcement, independent review, SBOM, signing, and container
  scan were not run during this verification.

Cargo warns that transitive `proc-macro-error2 2.0.1` contains code rejected by a future Rust
release. Dated exception: [dependency review](docs/security/dependency-unsafe-review.md).

## Evidence

- [Repository documentation audit](docs/reviews/repository-documentation-audit.md)
- [Architecture](docs/architecture/overview.md)
- [Testing](docs/development/testing.md)
- [Threat/control matrix](docs/security/threat-control-matrix.md)
- [Historical evidence](docs/history/README.md)

High-level user guides remain absent until Phase 15 defines stable objects and Phase 16 implements
GUI behavior. Current operator docs describe low-level CLI/TOML workflows.
