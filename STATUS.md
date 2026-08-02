# AegisProxy verified status

Verification date: 2026-08-01
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
HEAD `22c6e07` adds typed startup reconciliation and its focused, daemon, and Compose restart
regressions; it is not yet an immutable reviewed release candidate.
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
The 2026-07-29 product reset audit inspected the product documents, ADRs, Phase 14–16 evidence,
typed object contracts/stores, compiler/activation/startup paths, UI routes/client/browser tests,
configuration/deployment/certificate/provider/backup documentation, and current upstream NPMPlus
workflow baseline. That reset changed documentation only; the subsequent working-tree Phase 16 P0
implements typed-startup provider reconciliation.

Working tree at Phase 14 start: clean at `10aae8c`

## Product direction

AegisProxy now targets an
[NPMPlus-compatible reverse-proxy-management product](docs/product/npmplus-direction-reset.md)
with an independent Rust-native core. NPMPlus defines the primary terminology and ordinary host,
certificate, access, and administration workflows. Caddy-style automatic HTTPS and Traefik-style
providers are selective later additions. Generic gateway, ingress, service-mesh, and provider
expansion is deferred until the agreed
[compatibility baseline](docs/product/npmplus-compatibility-matrix.md) is complete.

Compatibility is a workflow/outcome target, not Nginx configuration, database, private API,
implementation, source-code, or pixel-level compatibility. Complete parity is not claimed.

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
objects over the mounted restart-time TOML base, resumes the exact active bound revision instead of
a newer draft, and fails closed when the overlay is invalid. The managed runtime now owns exactly
one provider reconciliation task in file-managed and typed modes. Typed Discovery Sources resume
after restart through bound provider revisions and transactional activation while typed mode keeps
TOML restart-only. Focused startup and real-daemon restart tests cover changed provider output,
manual-object coexistence, inactive drafts, unchanged live TOML, and joined SIGTERM shutdown.
The seven-field Proxy Host browser lifecycle now covers edit, enable, disable, duplicate, confirmed
delete, stale conflict, saved-not-active activation failure, and persistence uncertainty without
requiring candidate mechanics. A ProxyHostStore indeterminate post-rename result now gates all
later mutations and compilation until restart validates the visible durable file. The bounded
Save-and-apply failure campaign now distinguishes immutable candidate publication, active-pointer
uncertainty, rollback failure, and terminal audit durability without losing or misreporting the
last-known-good runtime. The working tree now adds schema-v2 inactive Proxy Host drafts with exact
draft/base/applied CAS, deterministic schema-v1 migration, explicit application-state reads, and
restart-safe Save draft/discard/promotion. Independent-style local security and usability review
accepts the bounded Phase 16 scope with release conditions; external human signoff remains open.
`npm audit --audit-level=high` still reports two high package entries for the one React Router RSC
advisory GHSA-qwww-vcr4-c8h2. The only patched Router release requires React 19 and has no matching
`react-router-dom` release; the audit-suggested downgrade is affected by the preceding related CVE.
The [formal disposition](docs/security/react-router-advisory-disposition.md) classifies the affected
RSC server path as unreachable in the static client-only SPA and adds a production import/module-
graph gate. The scanner finding remains visible; local independent-style review accepts the
disposition conditionally, while external human review remains required before release.

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
- One supervisor-owned provider coordinator runs in file-managed and typed-startup modes. Typed
  provider revisions copy the exact immutable typed binding, use canonical validation and
  transactional activation, preserve the active last-known-good runtime on failure, and resume
  typed Discovery Sources after restart.
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

- ACME requires explicit low-level issuer/challenge policy; the product certificate lifecycle is
  Phase 18.
- SSE uses generic streaming and skips compression but lacks a focused protocol test.
- Browser administration exposes the complete seven-field Proxy Host create/edit/enable/disable/
  duplicate/confirmed-delete Save-and-apply lifecycle. It reports stale conflicts, saved desired
  state versus active runtime, and recovery-required persistence uncertainty without exposing
  candidate or generation mechanics in the ordinary path. Durable inactive drafts can be created,
  edited, discarded, or promoted through exact CAS; they survive restart outside compilation and
  provider reconciliation. Multiple domains, locations, and task-specific forms for secondary
  typed resources remain incomplete.
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
- Typed object persistence is not fully uniform. `TypedStore`, `AccessPolicyStore`, and
  `ProxyHostStore` preserve visible state and gate later writes after an indeterminate post-rename
  directory-sync failure. Proxy Host mutation snapshots also fail closed so uncertain desired
  state cannot be compiled or activated. `ProxyHostStore` still lacks the shared store's explicit
  same-process path ownership registration; that narrower difference does not justify a broad
  store rewrite.
- `ProxyHostStore` file schema 2 separates applied records from inactive drafts in one atomic file.
  Schema-1 files load all existing records as applied with an empty draft set; candidate binding
  schemas and hashes remain unchanged. Draft generations are independent, promotion checks the
  exact applied base and desired epoch, and the existing post-rename recovery gate blocks both
  namespaces plus compilation on uncertainty.
- Low-level TOML configuration uses schema version 1. Separately, deprecated typed snapshot schema
  1 covers Proxy Hosts only, while unified snapshot schema 2 binds Proxy Hosts, Stream Hosts,
  Discovery Sources, and exact Access Policy/Certificate dependencies.
- The checked-in generated TypeScript client matches the current admin OpenAPI. Existing drift
  validation remains the only generated-client source of truth.
- The largest measured production module is approximately 1,230 lines, below the recorded
  1,500-line rationale threshold. Module size alone does not justify a Phase 16 refactor.
- Restore validates archives but does not extract or activate them.
- Fleet operation uses external orchestration; no cluster or consensus exists.
- Fuzzing has dated smoke evidence, not long campaigns. Reload benchmark is narrow and dated.

## Absent or deferred

- Multiple Proxy Host domains, Proxy Locations, Redirection Hosts, Dead Hosts, typed advanced host
  controls, and a browser retry-apply workflow. Ordinary Save draft, discard, and Save and apply are
  implemented in the working tree.
- End-to-end certificate request/import/assignment/revocation, force HTTPS, HSTS, DNS credential,
  access-list ordering, basic-auth credential, and supported ForwardAuth task workflows.
- NPM/NPMPlus import, settings mutation, automated restore, and complete operational compatibility.
- Multiple OIDC issuers, public/LAN browser bind, durable browser sessions, custom roles, renewal
  history, and unified secret rotation.
- Docker, Kubernetes, Consul, SRV discovery, provider approval/conflict workflow.
- PROXY v1/v2, client mTLS, sticky sessions, least-connections, backup upstreams, gRPC-Web,
  HTTP/3, UDP proxying.
- Automated restore, CI/release workflow, SBOM, signing/provenance, multi-architecture release,
  automated container scanning.

## Immediate phase

Phase 16 is accepted with documented release conditions. The typed-startup
provider P0 and Proxy Host create/edit/enable/disable/duplicate/delete Save-and-apply UI are
implemented in the working tree. The ProxyHostStore recovery gate, stable API error, and uncertainty
UI are implemented with deterministic failure injection. Typecheck, generated-client drift,
production build, and five focused real-Chromium Proxy Host scenarios pass using the pinned
Playwright image. The bounded failure campaign and its
[boundary matrix](docs/reviews/phase-16-save-apply-failure-campaign.md) are implemented; final
workspace and browser regression results are recorded below. The draft/application-state model is
implemented under [ADR-0031](docs/adr/0031-proxy-host-draft-application-state.md); independent
application-security and operator-usability reviews now accept the bounded implementation. The
React Router finding has an accepted local non-reachability disposition and a production-image
enforcement gate. Provider changes now use the durable HMAC audit chain; adversarial real HTTP
authorization, least-privilege draft discovery, and activation-response uncertainty are covered.
This is independent-style local evidence, not external certification. Production status remains
blocked by the release conditions below.

## Release blockers

- Phase 16–23 exit criteria for shipped scope; completed Phase 14–15 evidence remains binding.
- Independent application-security and reverse-proxy protocol reviews.
- No unresolved critical/high findings and signed residual-risk decision.
- Long fuzz and soak evidence.
- Target-host confinement, capacity, upgrade, restore, canary, and rollback drills.
- Reproducible multi-architecture artifacts, SBOM, signing/provenance, and supply-chain gates.

## Verification results

| Command | Result |
|---|---|
| `git diff --check` | passed |
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets` | passed; transitive warning below |
| `cargo check --workspace --all-targets --all-features` | passed with generated UI assets embedded |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 381 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| valid configuration corpus | seven accepted |
| invalid configuration corpus | three rejected as expected |
| repository Markdown links | passed: all relative targets across 144 Markdown files exist |
| `cargo tree -e features` | passed; 3,005 output lines |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| Phase 15 OpenAPI/config-schema/manifest/lock comparison against `dev@eb107ec` | recorded by Phase 15 closeout; not rerun during the product reset |
| Admin OpenAPI | Rust route/schema regression passed; prior PyYAML inspection records OIDC setup binding and 53 token scopes |
| Phase 15 production-module size guidance | current largest measured production module is 1,230 lines; below the 1,500-line rationale threshold |
| UI typecheck, generated-client stability, router reachability gate, and production build | passed; generated output was byte-stable, Vite built 26 modules, and the gate found no RSC server entry/symbol or dynamic import; 279.16 kB JavaScript before gzip |
| Focused Proxy Host Playwright scenarios | passed in pinned Playwright 1.62.0 Noble Chromium: 5 passed, including least-privilege draft discovery and activation-response uncertainty |
| Full Playwright browser suite | passed in the same pinned Chromium environment: 9 passed |
| Production container build | passed as `aegisproxy:phase16-review`; the final manifest list is `sha256:61cc0dfb2a20af25cb765a23dfcfa912b662b9bf5c5875692078a5c5a38c1095`, and the web stage enforced generated-client byte stability, `security:router`, typecheck, and Vite build |
| Docker Desktop Linux evaluation stack | not rerun during this remediation; the readiness audit records the earlier healthy Keycloak, upstream, and proxy stack |
| Real Keycloak/GUI smoke | not rerun during the product reset; the readiness audit records login, setup rotation, validate, preview, create, schema-2 activation, and Host-header traffic |
| Proxy/provider restart durability | typed active-versus-draft reconciliation and real-daemon changed-provider restart tests passed; typed TOML remained restart-only and SIGTERM joined; prior rebuilt-Compose traffic evidence was not rerun |
| `npm --prefix ui audit --audit-level=high` | exited 1: 2 high package entries for one advisory, GHSA-qwww-vcr4-c8h2; no compatible patch was applied; independent-style review accepts the formal non-reachability disposition subject to its documented assumptions, expiry, and production gate |
| authorization/ownership/migration/secret/tamper/recovery coverage | passed in the 117-test Admin suite and CLI integration, including draft schema migration/CAS/recovery/promotion, ProxyHostStore/candidate/audit failure injection, typed startup, OIDC binding permissions, collision, disabled-user, setup-token, audit, and canary checks |

## Unavailable or incomplete checks

- `cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, and `cargo llvm-cov`: their
  executables and Cargo subcommands are unavailable. Dated Elysium audit/deny results are not
  current scans.
- Docker Desktop's Linux engine is available to the Linux client and was used for the image,
  Compose, and restart checks. Desktop host networking still did not expose loopback listeners to
  Windows/WSL.
- `systemd-analyze verify deploy/systemd/aegisproxy.service deploy/ha/aegisproxy@.service` exits 1
  because `/usr/local/bin/rust-proxy` is not installed in this validation environment.
- `cargo fuzz`: Cargo reports `no such command`; dated smoke evidence is not current execution.
- `markdownlint` and `lychee`: unavailable; a direct repository-wide relative-link check passed.
- `trivy`, `grype`, `syft`, and `cosign`: unavailable, so container scanning, SBOM generation, and
  signature verification were not run.
- Direct host Playwright execution remains unsuitable because generated cache/output ownership and
  Chromium system libraries vary. The documented pinned-container command uses a read-only
  repository mount, container-local output, and the host production preview; all five focused
  Proxy Host scenarios execute and pass there.
- Pebble, long fuzz/soak, AppArmor enforcement, independent review, SBOM, signing, and container
  scan were not run during this verification.

Cargo warns that transitive `proc-macro-error2 2.0.1` contains code rejected by a future Rust
release. Dated exception: [dependency review](docs/security/dependency-unsafe-review.md).

## Evidence

- [NPMPlus product direction](docs/product/npmplus-direction-reset.md)
- [NPMPlus compatibility matrix](docs/product/npmplus-compatibility-matrix.md)
- [Phase 0–16 repository readiness audit](docs/reviews/repository-readiness-phase-0-16.md)
- [Phase 16 implementation candidate](docs/reviews/phase-16-completion.md)
- [Phase 16 Save-and-apply failure campaign](docs/reviews/phase-16-save-apply-failure-campaign.md)
- [React Router RSC advisory disposition](docs/security/react-router-advisory-disposition.md)
- [Phase 16 independent-style security review](docs/reviews/phase-16-independent-security-review.md)
- [Phase 16 operator-usability review](docs/reviews/phase-16-operator-usability-review.md)
- [Phase 16 final acceptance](docs/reviews/phase-16-final-acceptance.md)
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
