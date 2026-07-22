# AegisProxy roadmap

Status: active roadmap
Updated: 2026-07-22

AegisProxy targets NPMPlus-like usability, Caddy-inspired automation and safe defaults,
Traefik-inspired providers and routing concepts, and a secure Rust data plane. Inspiration does
not imply feature parity or copied implementation.

[`STATUS.md`](STATUS.md) records verified current behavior. Historical phases 0–13 and the original
greenfield plan remain under [`docs/history/`](docs/history/README.md). This file describes future
work only.

## Product rules

Every supported feature must provide both:

1. A safe common workflow in the web GUI.
2. Complete supported behavior through a versioned typed control plane, subject to RBAC, audit,
   least privilege, validation, and secret isolation.

Protected material is represented by opaque references such as `secret_ref`, `certificate_ref`,
`credential_ref`, and `provider_credential_ref`. Secret inputs are write-only. APIs may expose
metadata, ownership, fingerprints, scope, creation, expiration, last use, rotation, replacement,
and revocation, but never original protected plaintext.

A normal Proxy Host workflow asks only for domain, forward host or IP, forward port, upstream
protocol, HTTPS choice, access policy, and enabled state. AegisProxy derives safe redirect,
certificate, forwarding, WebSocket, pooling, limit, timeout, health, activation, and recovery
defaults. Advanced concepts use progressive disclosure.

## Preserved architecture

- One Rust process and binary per node; Tokio, Hyper, and Rustls.
- Safe Rust, strict typed configuration, immutable snapshots, and transactional activation.
- Private Unix-socket administration by default.
- No generic forward proxy, client-selected upstream, arbitrary runtime plugin, script, or shell.
- No database until a separate ADR proves file-backed state inadequate.
- No embedded clustering or shared writable state.
- HTTP/3 and any named UDP protocol require independent ADR, threat model, and review.

## Phase 14 — Behavior-preserving modularization

**Status:** complete on 2026-07-22. Evidence:
[`docs/reviews/phase-14-completion.md`](docs/reviews/phase-14-completion.md).

**Objective:** reduce ownership and review risk in oversized modules without behavior change.

**Scope:** extract inline tests first; split `crates/proxy-core/src/lib.rs`,
`crates/proxy-config/src/lib.rs`, `crates/proxy-admin/src/server.rs`, runtime, revision, and telemetry
along existing responsibilities.
Production modules should normally stay below 1,000 lines; modules above 1,500 require recorded
ownership and split rationale. This is guidance, not a mechanical lint.

**Non-goals:** no GUI, API/schema/default change, feature, dependency, optimization, or performance
claim.

**Dependencies:** current passing workspace, integration suite, ADRs, schemas, and archived evidence.

**Deliverables:** smaller modules, extracted tests, ownership map, and unchanged public contracts.

**Security requirements:** preserve request-validation order, single route match, secret redaction,
egress checks, audit gates, fixed middleware stages, and resource bounds.

**Tests:** before/after format, check, Clippy, unit, integration, doc, configuration corpus,
fuzz-build, OpenAPI-route, and targeted protocol regressions.

**Documentation:** update architecture and workspace ownership; report measured sizes only.

**Risks and mitigations:** refactor drift; move one responsibility at a time, compare public
API/schema/fingerprints, and keep every change behavior-preserving.

**Acceptance criteria:** no public API, OpenAPI path, schema meaning, configuration fingerprint,
listener behavior, default, dependency, unsafe code, or test behavior changes.

**Exit criteria:** independent diff review finds no feature/security-boundary change and every
available gate passes.

## Phase 15 — Stable typed control plane

**Status:** in progress. Baseline:
[`docs/reviews/phase-15-baseline.md`](docs/reviews/phase-15-baseline.md). Initial strict `v1` object
envelope, Proxy Host contract, and deterministic canonical compiler exist. Compiler evidence:
[`docs/reviews/phase-15-proxy-host-compiler.md`](docs/reviews/phase-15-proxy-host-compiler.md).
Private owner-aware validation, preview, list, get, audited create/update/delete, and verified
candidate activation endpoints are available.
Reads use durable typed desired state; validation and preview neither persist typed objects nor
activate candidates. Create persists one owned object plus an immutable candidate but never
activates it. Update/delete apply the same non-activation rule.

**Completed units:** strict object envelope; stable object IDs and ownership metadata; seven-field
Proxy Host contract; opaque access-policy reference; side-effect-free Proxy Host compiler into the
existing canonical configuration model; semantic validation and candidate/revision isolation tests;
safe deterministic typed candidate preview with mandatory redaction and restart classification;
bounded ordered typed field-level diff with owner/object identity checks; explicit deny-by-default
API-token scopes enforced as the intersection of role and scope; stable owner identity persisted
with new tokens; private owner-aware Proxy Host validation and redacted preview endpoints with CLI
coverage and authorization-before-deserialization.
Bounded durable Proxy Host desired-state storage now provides strict schema/version loading,
owner-indexed reads, deterministic serialization, object-local generation CAS, private permissions,
and rollback of in-memory mutation when atomic persistence fails. Administration opens this store,
exposes owner-scoped stable list/get operations with object-generation ETags under the exact
`read_proxy_hosts` scope, and includes stored identity/domain claims in validation and preview.
The side-effect-free aggregate compiler accepts explicit current and complete desired object sets,
orders them by owner/object ID, preserves pending objects, strips only complete compiler-shaped
resources reserved by current objects, rejects manual/tampered collisions, and validates once.
The store exposes a complete process-local epoch snapshot for mutation CAS. Typed create requires
the exact active revision, exact `create_proxy_host` role/scope intersection, matching owner,
durable audit intent, aggregate compilation and semantic validation, immutable revision creation,
then epoch-checked desired-state persistence. It never activates runtime state.
Update/delete additionally require exact object generation, replace or remove one object from the
complete desired set, create an immutable candidate, then use the same epoch CAS. They never
activate runtime state.
Admin-only typed activation recompiles the complete stored desired set against the active manual
configuration, requires exact active-revision CAS, verifies immutable candidate content, rejects
stale/orphan/repeated candidates, and delegates to the existing atomic activation coordinator.
All administrative mutations are serialized while their durable audit transaction is open.
Typed candidates now carry an optional validated desired-state binding hash in immutable revision
metadata. Typed create/update/delete persist a strict private owner/object-ordered snapshot before
changing desired state; activation requires that snapshot to equal complete current desired state.
Admin-only typed rollback loads one retained bound snapshot, compiles it against current manual
configuration, creates a new bound forward revision, journals previous and target desired state,
and delegates publication to the existing activation coordinator. Startup recovery converges the
object store according to the durable active revision; unresolved recovery blocks mutation.

**Remaining units:** coordinate typed snapshot retention with configuration revision pruning;
access-policy and certificate objects; remaining domain objects; remaining OpenAPI and CLI
contracts; migration/compatibility policy and tests; transport module split; full
authorization/security review.

**Objective:** provide versioned high-level objects usable by GUI and advanced automation.

**Scope:** Proxy Hosts, Stream Hosts, Certificates, Access Policies, Users, Roles, Stored
Credentials, Discovery Sources, Revisions, Backups, and runtime status; versioned JSON contracts;
field-level validation/diff; optimistic concurrency; preview, activation, rollback, and audit;
opaque secret references; explicit API-token scopes and ownership rules. Expert configuration must
use the same validation, secret, revision, activation, RBAC, and audit path.

**Non-goals:** no GUI, browser session, public admin bind, raw bypass, database, plugin execution,
or plaintext secret export.

**Dependencies:** Phase 14 boundaries and existing private administration/revision infrastructure.

**Deliverables:** versioned API, domain DTOs, migration policy, RBAC/scope matrix, secret-reference
contract, field-level diff, CLI coverage, and compatibility tests.

**Security requirements:** write-only secrets, one-time token display, deny-by-default RBAC,
object ownership, constant-time token checks, strict payload bounds, durable mutation audit, and no
alternate activation path.

**Tests:** contract/golden, complete authorization matrix, secret canaries, stale revision, diff,
backup/restore validation, audit outage, scope escalation, ownership, migration, and rollback.

**Documentation:** control-plane, object, secret-reference, compatibility, migration, and error
references.

**Risks and mitigations:** domain and TOML models diverge; compile both through one canonical
validated model and reject bypass routes.

**Acceptance criteria:** every supported field is typed or explicitly unsupported; GUI and
automation share authorization/activation; protected plaintext never appears in reads, logs,
traces, audits, previews, or backups; field-level diff and exact revision checks pass.

**Exit criteria:** API/security review approves versioning, RBAC, secret isolation, and
compatibility policy.

## Phase 16 — NPMPlus-style GUI MVP

**Objective:** make common reverse-proxy administration safe without low-level proxy knowledge.

**Scope:** first-run administrator setup; dashboard; Proxy Hosts; Stream Hosts; Certificates;
Access Policies; Users/Roles; Health; Logs; Revisions; one-click forward rollback; Backups; Settings;
progressive disclosure.

**Non-goals:** no direct file editing, plaintext secret retrieval, public unauthenticated UI,
raw plugin controls, or UI-only behavior missing from the typed API.

**Dependencies:** Phase 15 API/RBAC/scopes/audit/secrets/errors. Frontend stack and packaging require
a dedicated ADR before dependencies are added.

**Deliverables:** accessible responsive UI, generated client, secure first-run flow, Proxy Host
wizard, role-aware navigation, revision preview/diff, backup validation, and browser suite.

**Security requirements:** secure rotated sessions, exact origins, CSRF, CSP, output encoding, safe
cookies, no browser secret storage, dependency scanning, and no implicit internal trust.

**Tests:** first-run race, roles, CSRF, XSS, fixation/expiry, stale revision, secret
non-disclosure, accessibility, responsive layouts, API outage, rollback, and backup workflows.

**Documentation:** publish task-focused user guides only after behavior exists.

**Risks and mitigations:** browser/supply-chain surface; minimize dependencies, keep UI a direct API
client, and require independent application-security review.

**Acceptance criteria:** new user creates a safe Proxy Host using seven common fields; advanced
fields stay hidden until requested; UI permissions equal API role; keyboard, screen-reader,
contrast, and responsive checks pass.

**Exit criteria:** usability and application-security review of immutable candidate has no
unresolved critical/high finding.

## Phase 17 — Caddy-style automation

**Objective:** turn existing ACME, reload, and recovery primitives into safe automatic HTTPS.

**Scope:** automatic HTTPS selection, HTTP-to-HTTPS redirect, issuance/renewal, safe challenge and
issuer selection, renewal history/alerts, graceful activation, and last-known-good recovery.

**Non-goals:** no second ACME implementation, silent CA/environment switch, wildcard outside
DNS-01, insecure TLS fallback, plaintext key export, or issuance guarantee.

**Dependencies:** Phases 15–16 and existing ACME/certificate/runtime code.

**Deliverables:** derived defaults, automation policy, GUI flow, typed overrides, renewal history,
failure visibility, and migration from explicit-only policies.

**Security requirements:** preserve key/name/validity/environment/lifetime/storage/ownership checks,
challenge isolation, and prior-certificate retention.

**Tests:** automatic selection, redirect loops, wildcard rules, all challenges, CA/DNS outage,
renewal races, staging protection, prior-certificate retention, GUI/API parity, and Pebble cycles.

**Documentation:** automatic HTTPS, overrides, DNS credentials, recovery, and alert guides.

**Risks and mitigations:** surprising defaults; preview every derived action, permit typed override,
and never activate weaker or partial policy.

**Acceptance criteria:** common Proxy Host HTTPS needs no challenge/SNI knowledge; preview explains
derived actions; simulated failures preserve valid active material.

**Exit criteria:** ACME/TLS review and accelerated multi-cycle renewal campaign pass.

## Phase 18 — Traefik-style providers

**Objective:** expand dynamic discovery while treating provider data as untrusted.

**Scope:** existing file/A/AAAA providers plus Docker, DNS/SRV, Kubernetes, approval/conflict
policies, reconciliation, provider health, and stale-object cleanup.

**Non-goals:** no Docker socket in proxy process, default workload exposure, arbitrary labels or
scripts, provider validation bypass, unrequested Consul integration, or embedded cluster.

**Dependencies:** Phase 15 domain objects and current provider/activation coordinator. Every
privileged provider requires its own ADR and threat review.

**Deliverables:** provider contracts, least-privilege adapters, namespaces, conflict/approval
engine, status, cleanup, GUI/API controls, and reconciliation audit.

**Security requirements:** default exposure false, bounded metadata, explicit namespaces,
destination revalidation, credential references, no secret labels, and last-known-good retention.

**Tests:** event storms, malicious metadata, privilege loss, conflicts, approval, stale cleanup,
replay, rebinding, helper isolation, GUI/API parity, and source outage.

**Documentation:** provider model, permissions, threat boundaries, deployment, troubleshooting,
and migration.

**Risks and mitigations:** provider privilege/churn; isolate privileged access, debounce, require
approval, and run all output through canonical validation/activation.

**Acceptance criteria:** invalid, stale, conflicting, or unapproved state cannot replace active
policy; proxy has no Docker socket; every object has source/ownership evidence.

**Exit criteria:** provider-specific security review and failure campaign pass.

## Phase 19 — Advanced gateway controls

**Objective:** add advanced routing and policy without weakening common workflows.

**Scope:** advanced matching, middleware builder, native authentication where justified, rate
limits, headers, CORS, compression, retries, circuits, least-connections/backup policies, and richer
health.

**Non-goals:** no arbitrary ordering, runtime scripts/plugins, unreviewed regex, unbounded body
buffering, or unsafe retry defaults.

**Dependencies:** Phases 15–18 and existing fixed-stage middleware/pool state.

**Deliverables:** typed policies, compatibility rules, GUI progressive disclosure, status/metrics,
and interaction matrix.

**Security requirements:** fixed stages, bounded keys/queues/bodies, trusted identity only,
protected headers, fail-closed authentication, and no retry after response bytes.

**Tests:** matcher conflicts, middleware interactions, auth bypass, rate exhaustion, compression
exclusions, retry duplication, circuit recovery, distribution, and reload-state reuse.

**Documentation:** advanced routing and policy guides with defaults and failure semantics.

**Risks and mitigations:** interaction explosion; compile typed policies into fixed stages and reject
ambiguous combinations before activation.

**Acceptance criteria:** every supported option exists in API and GUI; common workflow needs none;
invalid ordering/combinations fail before activation.

**Exit criteria:** interaction matrix and security review pass under bounded load.

## Phase 20 — Protocol and reverse-proxy parity

**Objective:** close justified protocol gaps after product workflows stabilize.

**Scope:** PROXY protocol, client mTLS, sticky sessions, HTTP/3, gRPC-Web, and evidenced gaps.

**Non-goals:** no parity-for-marketing, generic UDP, generic CONNECT, open proxy, or client-selected
destination. Every protocol needs a named use case and ADR.

**Dependencies:** stable control/GUI, Phase 19 policy, target network/load balancer, and independent
protocol reviewers.

**Deliverables:** protocol ADRs, isolated listeners/features, typed policy, interoperability
fixtures, observability, deployment controls, and rollback switches.

**Security requirements:** trusted PROXY peers, mTLS identity policy, replay/amplification controls,
bounded QUIC state, migration policy, and no cross-protocol downgrade.

**Tests:** malformed/fuzz corpus, interoperability, trust bypass, replay, migration, loss/reorder,
drain, resource abuse, and disabled-feature isolation.

**Documentation:** compatibility matrices, deployment requirements, failure behavior, threat models.

**Risks and mitigations:** protocol complexity; isolate and disable each transport until accepted,
and allow removal without affecting HTTP/1.1/2 or TCP TLS.

**Acceptance criteria:** named interoperability/abuse suites pass; disabled protocols open no
listener or dependency surface; independent reviewers accept residual risk.

**Exit criteria:** protocol-specific acceptance and operational rollback drills pass.

## Phase 21 — Production readiness

**Objective:** produce independently reviewed, reproducible release and recovery evidence.

**Scope:** CI/release workflows, benchmarks, long fuzz/soak, security/protocol review, SBOM,
signatures, provenance, scanning, multi-architecture artifacts, upgrades, migrations,
backup/restore, canary, rollback, and support envelope.

**Non-goals:** no unsupported production-ready, vulnerability-free, parity, HA, or performance
claim.

**Dependencies:** all shipped feature phases, protected release infrastructure, representative
staging, qualified independent reviewers, and named support owners.

**Deliverables:** release pipeline, signed artifacts/checksums, SBOM/provenance, scan evidence,
benchmark/soak results, compatibility matrix, runbooks, migrations, recovery drills, release notes,
and residual-risk approval.

**Security requirements:** short-lived release identity, two-person promotion, immutable artifacts,
advisory/license/source gates, secret-free output, independent review, and no unresolved
critical/high findings.

**Tests:** exact-artifact full suite, multi-architecture smoke, confinement, long fuzz/soak,
protocol interoperability, upgrade/downgrade, restore, forced rollback, renewal, provider failure,
and canary traffic.

**Documentation:** final manuals, release notes, support policy, migration/recovery, known limits,
residual risks, and artifact verification.

**Risks and mitigations:** environment gaps and late findings; remain NO-GO until evidence exists,
roll forward fixes, and repeat invalidated gates.

**Acceptance criteria:** exact artifacts pass supported-target gates; independent reviews close
critical/high findings; long fuzz/soak and recovery drills pass; unfamiliar operators can install,
configure, back up, restore, upgrade, and roll back; performance claims include reproducible data.

**Exit criteria:** product, engineering, security, operations, and release owners approve exact
immutable scope and residual risk. Until then, production assessment remains NO-GO.

## Immediate phase

Phase 15. Later work must not enter early unless strictly required to implement or test its typed
control-plane contracts.
