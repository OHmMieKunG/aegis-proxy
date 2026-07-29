# AegisProxy verified status

Verification date: 2026-07-29
Branch: `feat/phase-16-gui-mvp`
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
Phase 16 adds browser OIDC sessions (`1b395ba`), durable setup identity binding (`7b0aa7a`), the
embedded typed client shell (`eaf5025`), administration workflows (`ea499b8`), and browser
regression coverage (`4ddef29`). Closed asset-cache and exact action allowlists are in `9205971`.
The current working tree adds typed startup reconciliation and its focused, daemon, and Compose
restart regressions; it is not yet an immutable reviewed candidate.
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
Phase 15 candidate `efcd0c3` keeps accepted requests running under their bounded in-flight
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

## Repository readiness audit remediation

The 2026-07-29 Phase 0–16 audit added a clean Node UI stage, a pinned Linux host-network evaluation
stack, and a real-system Playwright smoke. Docker Desktop's Linux engine built the image and passed
real Keycloak login, one-use setup with session/CSRF rotation, GUI validate/preview/create/schema-2
activation, and Host-header traffic. Runtime testing also fixed strict CA-secret permissions,
Keycloak import/profile configuration, standard OIDC callback parameters, quoted UI ETags, and the
GUI's schema-2 activation route.

Controlled-test GO remains withheld. Normal `run --config` startup now reconciles durable typed
objects over the mounted restart-time TOML base, resumes or creates an immutable bound revision,
and fails closed when the overlay is invalid. Focused reconciliation, real-daemon typed-route, and
rebuilt Compose restart regressions pass for the manual Proxy Host path. Audit found that typed
startup also disables the only file/DNS provider reconciliation task; provider-backed groups stay
on static fallback and runtime provider status cannot advance. That P0, missing Proxy Host
edit/disable/delete controls, and the incomplete failure campaign keep controlled-test GO closed.
`npm audit --audit-level=high` still reports two high React Router RSC/server-mode findings;
applicability is not independently dispositioned.

## Implemented

- HTTP/1.1, HTTP/2, WebSocket, gRPC, streaming, trailers, cancellation, graceful shutdown.
- HTTPS termination, upstream TLS, static encrypted certificates, raw TCP, TLS passthrough.
- Strict TOML, semantic validation, deterministic host/path/method/header routing.
- Round-robin, smooth weighted, random, power-of-two balancing, active/passive health, retries,
  circuits, connection/request limits, endpoint drain.
- Immutable revisions, atomic activation, probation, rollback, file/SIGHUP reload, explicit
  last-known-good recovery.
- Typed startup reconciliation compiles durable Proxy Host, Stream Host, and Discovery Source
  desired state over the mounted restart-time base, resumes or creates an exact bound revision,
  and fails startup when reconciliation is invalid. Typed mode does not hot-reload that base.
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
- Typed startup currently omits the provider reconciliation task. File and DNS providers therefore
  remain on their static endpoints whenever typed desired state selects this startup mode. This is
  a release-critical regression, not an approved operating mode.
- Browser administration exposes the common Proxy Host create/deploy path, but Proxy Host
  edit/disable/delete controls and task-specific forms for secondary typed resources remain
  incomplete.
- Phase 15 has a strict library-only `v1` envelope, deterministic Proxy Host compiler, safe
  side-effect-free typed preview, and bounded field-level diff. Existing primitives validate
  ownership, references, domains, conflicts, listener/certificate policy, generated configuration,
  redaction, fingerprints, restart classification, and owner/object identity during diff. Existing
  low-level API tokens use a complete 53-action role-and-scope intersection. Private typed Proxy
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

- Multiple OIDC issuers, public/LAN browser bind, durable browser sessions, custom roles, renewal
  history, and unified secret rotation.
- Docker, Kubernetes, Consul, SRV discovery, provider approval/conflict workflow.
- PROXY v1/v2, client mTLS, sticky sessions, least-connections, backup upstreams, gRPC-Web,
  HTTP/3, UDP proxying.
- Automated restore, CI/release workflow, SBOM, signing/provenance, multi-architecture release,
  automated container scanning.

## Immediate phase

Finish [Phase 16](PLAN.md#phase-16--npmplus-style-gui-mvp). First restore provider reconciliation
under typed startup without restoring TOML hot reload or bypassing typed revision binding. Then run
the controlled failure campaign and obtain independent application-security and usability review.
Phase 17 and production status remain blocked.

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
| `cargo check --workspace --all-targets --all-features` | passed with generated UI assets embedded |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 362 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| valid configuration corpus | seven accepted |
| invalid configuration corpus | three rejected as expected |
| repository Markdown links | passed: all relative targets across 135 Markdown files exist |
| `cargo tree -e features` | passed; 3,005 output lines |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| Phase 15 OpenAPI/config-schema/manifest/lock comparison against `dev@eb107ec` | passed; no differences |
| Admin OpenAPI | checked in Rust and parsed with Python/PyYAML; includes OIDC setup binding and 53 token scopes |
| Phase 15 production-module size guidance | current largest measured production module is 1,230 lines; below the 1,500-line rationale threshold |
| `npm ci`; typecheck; generated-client drift; production build | passed; npm 9.2 emitted the recorded Redocly engine warning |
| Playwright Chromium/axe suite | passed: 5 scenarios in the pinned Playwright container |
| Docker Desktop Linux evaluation stack | image built; Keycloak, upstream, and proxy healthy |
| Real Keycloak/GUI smoke | passed login, setup rotation, validate, preview, create, schema-2 activation, and Host-header traffic |
| Proxy restart durability | passed reconciliation/resume/fail-closed tests and rebuilt Compose traffic before/after proxy restart |
| `npm audit` | completed: 2 high findings in React Router's unused RSC/server-mode paths; no critical findings |
| authorization/ownership/migration/secret/tamper/recovery coverage | passed in the 106-test Admin suite and CLI integration, including typed startup, OIDC binding permissions, collision, recovery, disabled-user, setup-token, audit, and canary checks |

## Unavailable or incomplete checks

- `cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, and `cargo llvm-cov`: Cargo reports
  `no such command`. Dated Elysium audit/deny results are not current scans.
- Docker Desktop's Linux engine is available to the Linux client and was used for the image,
  Compose, and restart checks. Desktop host networking still did not expose loopback listeners to
  Windows/WSL.
- `systemd-analyze verify deploy/systemd/aegisproxy.service deploy/ha/aegisproxy@.service` exits 1
  because `/usr/local/bin/rust-proxy` is not installed in this validation environment.
- `cargo fuzz`: Cargo reports `no such command`; dated smoke evidence is not current execution.
- `markdownlint` and `lychee`: unavailable; a direct repository-wide relative-link check passed.
- `trivy`, `grype`, `syft`, and `cosign`: unavailable, so container scanning, SBOM generation, and
  signature verification were not run.
- Direct local Playwright launch currently fails because `libnspr4.so` is unavailable; the same
  five scenarios pass in the pinned Playwright container.
- Pebble, long fuzz/soak, AppArmor enforcement, independent review, SBOM, signing, and container
  scan were not run during this verification.

Cargo warns that transitive `proc-macro-error2 2.0.1` contains code rejected by a future Rust
release. Dated exception: [dependency review](docs/security/dependency-unsafe-review.md).

## Evidence

- [Phase 0–16 repository readiness audit](docs/reviews/repository-readiness-phase-0-16.md)
- [Phase 16 implementation candidate](docs/reviews/phase-16-completion.md)
- [Historical repository documentation audit](docs/history/validation/repository-documentation-audit-2026-07-22.md)
- [Phase 15 completion](docs/reviews/phase-15-completion.md)
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

Task-focused browser guidance is available in
[web administration](docs/guides/web-administration.md).
