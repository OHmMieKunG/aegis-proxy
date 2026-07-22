# AegisProxy verified status

Verification date: 2026-07-22
Branch: `work/autonomous-roadmap`
Verification basis: Phase 14 plus Phase 15 compiler `fa7913f`, preview service `d3de105`, and typed
diff `2617f0e`
Working tree at Phase 14 start: clean at `10aae8c`

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
- Phase 15 has a strict library-only `v1` envelope, deterministic Proxy Host compiler, safe
  side-effect-free typed preview, and bounded field-level diff. Existing primitives validate
  ownership, references, domains, conflicts, listener/certificate policy, generated configuration,
  redaction, fingerprints, restart classification, and owner/object identity during diff. No
  high-level endpoint, object persistence service, or complete scope matrix exists yet.
- Preview returns redacted config, fingerprints, and activation class; a separate pure function
  produces the ordered typed diff. Neither can persist or activate candidates.
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

[Phase 15 stable typed control plane](PLAN.md#phase-15--stable-typed-control-plane). Phase 14
completed behavior-preserving modularization: inline tests are focused files, production ownership
is split by domain, and no production Rust module exceeds 1,200 measured lines. See the
[completion evidence](docs/reviews/phase-14-completion.md).

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
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 281 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| valid configuration corpus | seven accepted |
| invalid configuration corpus | three rejected as expected |
| changed documentation link targets | passed; every added/changed relative target exists |
| `cargo tree -e features` | passed; 2,439 output lines |
| Phase 15 manifest/schema/OpenAPI comparison against `2d533a8` | passed; no differences |

## Unavailable or incomplete checks

- `cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, and `cargo llvm-cov`: Cargo reports
  `no such command`. Dated Elysium audit/deny results are not current scans.
- Docker/Compose: Docker Desktop reports WSL integration unavailable.
- `systemd-analyze verify`: sandbox blocked its credential sockets with `Operation not permitted`;
  unit validation did not complete.
- `cargo fuzz`: Cargo reports `no such command`; dated smoke evidence is not current execution.
- `markdownlint` and `lychee`: shell reports `command not found`; changed targets were checked
  directly, but a repository-wide automated Markdown scan was not rerun.
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
