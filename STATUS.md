# AegisProxy verified status

Verification date: 2026-07-28
Branch: `chore/phase-15-closeout`
Verification basis: Phase 14 plus Phase 15 compiler `fa7913f`, preview service `d3de105`, typed diff
`2617f0e`, API-token scopes `81bd500`, owned Proxy Host endpoints `00cfa32`, typed object store
`5c8898b`, owner-scoped typed reads `d1514dd`, aggregate compiler `35d7d38`, mutation-scope fix
`106f2fa`, desired-state snapshot CAS `f204012`, audited typed create `068f408`, audited typed
update/delete `7e8b47d`, verified typed activation `7c6f613`, and immutable typed candidate binding
`80a7f27`, crash-safe typed rollback `69a5fe3`, token-ID CLI fix `b7a053b`, coordinated typed
snapshot retention `788b5a2`, typed Access Policy ownership metadata `f23468b`, and bounded Access
Policy persistence `58f30dc`, dedicated Access Policy scopes/startup wiring `8eb1c73`, and
owner-scoped Access Policy reads `ef115a6`. Post-rename Access Policy durability failures now gate
all later policy writes until restart reconciliation (`697f530`); audited owner-scoped creation is
available through the API and CLI (`926eb68`), with dual-concurrency update/delete following in
`334916d`. Proxy Host validation/preview can now resolve one owned or explicitly shared policy
without persistence (`c12f1c3`). Typed candidates bind exact referenced policy generations and
content; activation and rollback revalidate current policy state (`20449a3`).
Typed certificate ownership and managed-HTTPS selection metadata (`edcb53b`) now have bounded
private persistence, exact owner-scoped CRUD permissions, API/CLI operations, and separated runtime
status and direct-renewal routes.
Strict typed Stream Hosts and file/DNS Discovery Sources now compile deterministically without
source I/O, persist in bounded owner-scoped stores, expose exact CRUD/preview/CLI contracts, and
create schema-2 unified typed-bound non-active candidates. Unified snapshots cover complete Proxy
Hosts, Stream Hosts, Discovery Sources, and exact referenced Access Policy and Certificate records;
canonical typed preview, Admin-only activation, and forward rollback are available while the old
Proxy Host routes accept only schema-1 snapshots.
Low-level configuration activation and rollback reject typed-bound revisions, preventing broad
configuration scopes from bypassing typed authorization.
Stored Credentials now encrypt bounded write-only values to configured age recipients, persist
only ciphertext and safe metadata, expose owner-scoped CRUD/rotation/revocation through exact
scopes and CLI, and remove usable ciphertext on revoke. Responses never expose plaintext or
ciphertext.
Durable Users now bind identity/owner equality to a fixed built-in role and enabled state; Roles
are read-only. New tokens require an enabled `user_ref`, inherit that user's role and owner, and
accept only an explicit role-bounded scope subset. Disabling a user blocks its subject tokens while
legacy subjectless automation tokens remain parseable without gaining new scopes.
Unified candidate preview now emits stable add/update/remove records for every typed domain and
bound dependency. Updates expose only closed per-kind field-name allowlists; object values,
configuration secrets, ciphertext, and internal paths cannot enter the diff.
Current Phase 15 closeout work keeps accepted requests running under their bounded in-flight
permits after a response deadline so blocking mutations cannot outlive
serialization or terminal audit, and shutdown drains those permits before the administrative
service exits. Token, backup, and restore JSON now passes exact action
authorization, durable audit intent, and exact content-type validation before deserialization.
User mutations preserve missing, invalid, stale, capacity, and unavailable error classes.

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
  low-level API tokens use a complete 52-action role-and-scope intersection. Private typed Proxy
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
  orphan snapshots and fails closed on malformed or tampered state. A strict library-only
  certificate object now binds an owner and explicit shares to one opaque existing certificate ID.
  Metadata compilation copies no key/chain references, requires exactly one HTTPS listener, and
  selects exact or single-label wildcard coverage fail closed. Bounded private persistence,
  owner-scoped API/CLI operations, Proxy Host wiring, and isolated runtime-certificate routes are
  implemented. A strict Access Policy
  contract now compiles owner/share/enable metadata and canonical access-control middleware IDs,
  rejecting missing, duplicate-stage, incompatible, invalid, or secret-bearing shapes. Its bounded
  private store provides global IDs, owner-scoped reads, canonical serialization, generation CAS,
  exclusive ownership, strict restart validation, and atomic replacement. Administration owns the
  store lock at startup and has distinct read/create/update/delete role-and-token scopes. Access
  Policy list/get API and CLI are owner-scoped under exact read permission, return stable
  secret-free records and generation ETags, and hide cross-owner existence. An indeterminate
  post-rename durability failure blocks all later store mutations until a
  restart reloads the visible atomic file; reads remain available. Audited create requires exact
  active-revision concurrency, authorizes before parsing, validates middleware references against
  active configuration, persists generation one, and never creates or activates a configuration
  revision. Update/delete require the active revision and exact object generation, preserve
  owner-scoped not-found behavior, validate updates before persistence, and likewise create no
  configuration revision or runtime activation. Proxy Host validation/preview resolve referenced
  policies through secret-free metadata. Create/update/delete bind each referenced policy's exact
  canonical generation and content into the immutable candidate. Activation and rollback require
  current records to match those bindings before compilation or publication; policy drift rejects
  stale work without changing runtime state. Policy mutation remains independently owner-authorized
  and invalidates old dependent candidates rather than being pinned by consumers.
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
split by domain. Phase 15 closeout has split the expanded handlers, candidate store, compilers,
Access Policy tests, and CLI administration dispatch; no production Rust module exceeds 1,200
measured lines. The 52-action matrix, authorization-before-deserialization ordering, owner hiding,
schema-1/schema-2 route separation, legacy-token behavior, and candidate recovery are covered.
The original maintainer-review findings plus the follow-up shutdown-drain and
capacity-classification findings are fixed in the current working tree. Phase 15 remains open for a
replacement commit, independent review of that exact candidate, and final immutable evidence.
Phase 16 browser work has not started.

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
| `cargo test --workspace --all-features` | passed: 339 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| valid configuration corpus | seven accepted |
| invalid configuration corpus | three rejected as expected |
| changed documentation link targets | passed: seven changed Markdown files; every relative target exists |
| `cargo tree -e features` | passed; 2,440 output lines |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| Phase 15 OpenAPI/config-schema/manifest/lock comparison against `dev@eb107ec` | passed; no differences |
| Admin OpenAPI | checked in Rust and parsed with Python/PyYAML; includes typed rollback and 52 token scopes |
| Phase 15 production-module size gate | passed; largest measured module is 1,129 lines |
| authorization/ownership/migration/secret/tamper/recovery coverage | passed in the 86-test Admin suite and CLI integration |

## Unavailable or incomplete checks

- `cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, and `cargo llvm-cov`: Cargo reports
  `no such command`. Dated Elysium audit/deny results are not current scans.
- Docker and Compose both report: `The command 'docker' could not be found in this WSL 2 distro.`
- `systemd-analyze verify deploy/systemd/aegisproxy.service deploy/ha/aegisproxy@.service` exits 1
  because `/usr/local/bin/rust-proxy` is not installed in this validation environment.
- `cargo fuzz`: Cargo reports `no such command`; dated smoke evidence is not current execution.
- `markdownlint` and `lychee`: shell reports `command not found`; changed targets were checked
  directly, but a repository-wide automated Markdown scan was not rerun.
- Pebble, long fuzz/soak, AppArmor enforcement, independent review, SBOM, signing, container build,
  and container scan were not run during this verification.

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
- [Typed Access Policy recovery-gate review](docs/reviews/phase-15-access-policy-recovery-gate.md)
- [Typed Access Policy create review](docs/reviews/phase-15-access-policy-create.md)
- [Typed Access Policy update/delete review](docs/reviews/phase-15-access-policy-update-delete.md)
- [Typed Access Policy preview wiring review](docs/reviews/phase-15-access-policy-preview-wiring.md)
- [Typed Access Policy candidate-binding review](docs/reviews/phase-15-access-policy-candidate-binding.md)
- [Typed certificate ownership review](docs/reviews/phase-15-certificate-ownership.md)
- [Historical evidence](docs/history/README.md)

High-level user guides remain absent until Phase 15 defines stable objects and Phase 16 implements
GUI behavior. Current operator docs describe low-level CLI/TOML workflows.
