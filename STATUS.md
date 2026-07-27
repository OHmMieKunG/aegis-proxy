# AegisProxy verified status

Verification date: 2026-07-27
Branch: `work/autonomous-roadmap`
Verification basis: Phase 14 plus Phase 15 compiler `fa7913f`, preview service `d3de105`, typed diff
`2617f0e`, API-token scopes `81bd500`, owned Proxy Host endpoints `00cfa32`, typed object store
`5c8898b`, owner-scoped typed reads `d1514dd`, aggregate compiler `35d7d38`, mutation-scope fix
`106f2fa`, desired-state snapshot CAS `f204012`, audited typed create `068f408`, audited typed
update/delete `7e8b47d`, verified typed activation `7c6f613`, and immutable typed candidate binding
`80a7f27`, crash-safe typed rollback `69a5fe3`, token-ID CLI fix `b7a053b`, coordinated typed
snapshot retention `788b5a2`, typed Access Policy ownership metadata `f23468b`, and bounded Access
Policy persistence `58f30dc`, dedicated Access Policy scopes/startup wiring `8eb1c73`, and
owner-scoped Access Policy reads `ef115a6`.

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
- Private Unix API/CLI, fixed RBAC, explicitly scoped hash-only API tokens, concurrency checks,
  audit, backup creation, restore validation, status, metrics, and node drain.
- Mutation audit authorization uses the same role-and-explicit-token-scope intersection as reads;
  an out-of-scope bearer request records denial before any candidate or state mutation.
- JSON logs, OpenMetrics, optional OTLP tracing, request correlation, HMAC-chained audit.
- Bounded file and DNS A/AAAA providers; external-load-balancer fleet checks.
- Eight fuzz targets and broad unit/integration/security regression coverage.

## Partial or experimental

- ACME requires explicit low-level issuer/challenge policy; common automatic HTTPS is Phase 17.
- SSE uses generic streaming and skips compression but lacks a focused protocol test.
- Administration remains primarily TOML/revision oriented; high-level domain APIs are Phase 15.
- Phase 15 has a strict library-only `v1` envelope, deterministic Proxy Host compiler, safe
  side-effect-free typed preview, and bounded field-level diff. Existing primitives validate
  ownership, references, domains, conflicts, listener/certificate policy, generated configuration,
  redaction, fingerprints, restart classification, and owner/object identity during diff. Existing
  low-level API tokens use a complete 27-action role-and-scope intersection. Private typed Proxy
  Host validation and preview endpoints authenticate and authorize before JSON deserialization,
  enforce principal ownership, reject persisted identity/domain conflicts, and cannot persist or
  activate. The bounded private typed object store is opened at administration startup and exposes
  owner-scoped stable list/get operations under the exact `read_proxy_hosts` action; it supports
  generation CAS internally. Audited typed create compiles complete desired state, creates an
  immutable non-active revision, then persists the object through store-epoch CAS under exact
  active-revision `If-Match`; scoped denial and candidate rejection leave desired/runtime state
  unchanged. A side-effect-free aggregate compiler deterministically rebuilds complete desired
  state, preserves pending objects, and removes only structurally verified namespaces reserved by
  current stored objects. Audited update/delete require exact object generation plus complete-store
  epoch CAS, persist immutable non-active candidates before desired-state changes, and leave runtime
  unchanged. Admin-only typed activation now recompiles the complete stored desired set, verifies
  candidate content, serializes administrative mutations, and invokes only the existing atomic
  activation coordinator. Stale, orphaned, repeated, or unauthorized candidates cannot change the
  runtime. Typed candidate revision metadata now binds a strict private immutable snapshot of the
  complete desired objects; mismatched or tampered bindings fail activation. Admin-only typed
  rollback loads one bound historical snapshot, creates and activates a new forward revision, and
  uses a private recovery journal to converge desired state with the durably active revision after
  interruption. Typed snapshot reconciliation now follows the authoritative retained configuration
  revisions at Admin startup and before new snapshot binding; it removes only fully validated
  orphan snapshots and fails closed on malformed or tampered state. Certificate/access-policy
  certificate persistence and a complete ownership matrix do not exist yet. A strict Access Policy
  contract now compiles owner/share/enable metadata and canonical access-control middleware IDs,
  rejecting missing, duplicate-stage, incompatible, invalid, or secret-bearing shapes. Its bounded
  private store provides global IDs, owner-scoped reads, canonical serialization, generation CAS,
  exclusive ownership, strict restart validation, and atomic replacement. Administration owns the
  store lock at startup and has distinct read/create/update/delete role-and-token scopes. No Access
  Policy list/get API and CLI are owner-scoped under exact read permission, return stable
  secret-free records and generation ETags, and hide cross-owner existence. Mutation routes remain
  absent; Proxy Host endpoints still reject policy references until durable audited mutation and
  reference wiring exist.
- Preview returns redacted config, fingerprints, and activation class; a separate pure function
  produces the ordered typed diff. Neither can persist or activate candidates.
- Restore validates archives but does not extract or activate them.
- Fleet operation uses external orchestration; no cluster or consensus exists.
- Fuzzing has dated smoke evidence, not long campaigns. Reload benchmark is narrow and dated.

## Absent or deferred

- Web GUI, first-run wizard, GUI CRUD, browser sessions, progressive disclosure, UI tests.
- Native OIDC/OAuth2, renewal history, unified secret rotation.
- Docker, Kubernetes, Consul, SRV discovery, provider approval/conflict workflow.
- PROXY v1/v2, client mTLS, sticky sessions, least-connections, backup upstreams, gRPC-Web,
  HTTP/3, UDP proxying.
- Automated restore, CI/release workflow, SBOM, signing/provenance, multi-architecture release,
  automated container scanning.

## Immediate phase

[Phase 15 stable typed control plane](PLAN.md#phase-15--stable-typed-control-plane). Phase 14
completed behavior-preserving modularization: inline tests are focused and production ownership is
split by domain. At Phase 14 completion no production Rust module exceeded 1,200 measured lines.
Phase 15 endpoint growth now places `server/handlers.rs` at 1,933 lines and CLI `main.rs` at 1,309;
their single transport-orchestration ownership is an explicit temporary exception that must be
split after Phase 15 contracts stabilize. See the [completion evidence](docs/reviews/phase-14-completion.md).

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
| `cargo test --workspace --all-features` | passed: 318 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| valid configuration corpus | seven accepted |
| invalid configuration corpus | three rejected as expected |
| changed documentation link targets | passed; every added/changed relative target exists |
| `cargo tree -e features` | passed; 2,440 output lines |
| Phase 15 config-schema comparison against `2d533a8` | passed; no differences |
| Phase 15 manifest comparison against `2d533a8` | expected differences; Admin now directly declares already-locked `fs2` for Access Policy ownership |
| Admin OpenAPI | checked in Rust and parsed with Python/PyYAML; includes typed rollback and 27 token scopes |

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
- [Typed rollback review](docs/reviews/phase-15-proxy-host-rollback.md)
- [Typed snapshot retention review](docs/reviews/phase-15-proxy-host-snapshot-retention.md)
- [Typed Access Policy ownership review](docs/reviews/phase-15-access-policy-ownership.md)
- [Typed Access Policy store review](docs/reviews/phase-15-access-policy-store.md)
- [Typed Access Policy scope review](docs/reviews/phase-15-access-policy-scopes.md)
- [Typed Access Policy read review](docs/reviews/phase-15-access-policy-reads.md)
- [Historical evidence](docs/history/README.md)

High-level user guides remain absent until Phase 15 defines stable objects and Phase 16 implements
GUI behavior. Current operator docs describe low-level CLI/TOML workflows.
