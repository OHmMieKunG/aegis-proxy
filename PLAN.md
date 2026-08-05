# AegisProxy roadmap

Status: active roadmap
Updated: 2026-08-01

AegisProxy is a self-hosted, NPMPlus-compatible reverse-proxy manager with an independent
Rust-native proxy core. NPMPlus defines the primary product terminology and daily workflows.
Existing AegisProxy security and transactional architecture defines the implementation boundary.
Caddy-style automatic HTTPS and Traefik-style providers are selective additions, not equal parity
programs.

Compatibility means supported user-visible workflows and outcomes. It does not mean Nginx
configuration, NPMPlus database, private API, implementation, source-code, or pixel-level
compatibility. See the [product-direction reset](docs/product/npmplus-direction-reset.md) and
[compatibility matrix](docs/product/npmplus-compatibility-matrix.md).

[`STATUS.md`](STATUS.md) records verified current behavior. Historical phases 0–13 and the original
greenfield plan remain under [`docs/history/`](docs/history/README.md). Dated review evidence is not
rewritten when this roadmap changes.

## Product rules

Every supported product capability must have:

1. a simple task-oriented GUI workflow;
2. a versioned typed control-plane operation with exact RBAC, ownership, audit, validation,
   concurrency, migration, and error behavior;
3. deterministic compilation into the one canonical validated runtime snapshot;
4. runtime or operational evidence for the advertised outcome.

An underlying primitive alone is not compatibility completion. Normal Proxy Host editing asks for
domain names, forward scheme, host or IP, port, HTTPS/certificate choice, access policy, and
enabled state. Advanced controls use progressive disclosure and bounded typed fields.

Protected input is write-only and represented by approved opaque references. Plaintext, hashes,
usable ciphertext, internal paths, and protected values never enter reads, logs, traces, previews,
diffs, audits, errors, or unencrypted backups.

## Preserved architecture

- One Rust process and binary per node using Tokio, Hyper, and Rustls.
- Safe Rust, parsed-Hyper framing, strict typed configuration, immutable snapshots, and
  transactional activation.
- Immutable candidates, exact binding, atomic publication, last-known-good service, forward
  rollback, and durable terminal audit.
- Owner-aware typed objects, fixed role/action enforcement, explicit API-token scopes, OIDC
  identity binding, and private Unix-socket administration.
- Bounded file-backed state unless a separate evidence-backed ADR proves it inadequate.
- No generic forward proxy, client-selected upstream, arbitrary Nginx configuration, runtime
  plugin, script, shell, provider-direct activation, or plaintext secret export.
- No generic gateway, ingress-controller, service-mesh, Kubernetes, fleet, or plugin-platform
  expansion before the agreed NPMPlus daily-workflow baseline.

## Phase 14 — Behavior-preserving modularization

**Status:** complete on 2026-07-22. Evidence:
[Phase 14 completion](docs/reviews/phase-14-completion.md) and
[baseline](docs/reviews/phase-14-baseline.md).

**Objective and outcome:** reduce ownership and review risk in oversized production modules without
changing behavior, public contracts, schemas, defaults, fingerprints, dependencies, or runtime
semantics.

**Completed scope:** tests were extracted before responsibility-based splits across core,
configuration, administration, runtime, revision, and telemetry ownership. Production modules
normally target fewer than 1,000 lines; a module above 1,500 lines requires an ownership and split
rationale rather than an automatic rewrite.

**Preserved requirements:** request-validation ordering, one route match, secret redaction, egress
checks, audit gates, fixed middleware stages, resource bounds, protocol behavior, and all available
workspace/configuration/fuzz/OpenAPI gates.

**Exit:** completed under the recorded independent review and validation evidence. Later module
growth is not permission for an unrelated refactor.

## Phase 15 — Stable typed control plane

**Status:** complete on 2026-07-28 under the recorded project-owner progression exception.
Evidence: [Phase 15 completion](docs/reviews/phase-15-completion.md) and
[baseline](docs/reviews/phase-15-baseline.md). Independent application-security review remains a
production gate.

**Objective and outcome:** provide versioned high-level objects for GUI and automation without an
alternate configuration, authorization, secret, revision, or activation path.

**Completed scope:** strict `v1` object envelope; seven-field Proxy Host; deterministic aggregate
compiler; typed validation, preview, bounded diff, CRUD, candidate binding, activation, and forward
rollback; owner/generation/epoch concurrency; Access Policy and Certificate ownership bindings;
Stream Host and file/DNS Discovery Source objects; encrypted write-only Stored Credentials; durable
Users and fixed Roles; schema-2 unified snapshots; exact API-token action scopes; and low-level
activation rejection of typed-bound revisions.

**Preserved requirements:** owner/share checks, authorization before deserialization, immutable
candidate content, exact dependency generations, atomic activation, crash-recovery journals,
secret-free metadata, fail-closed recovery gates, audit, and one canonical runtime compiler.

**Exit:** completed for roadmap progression. Historical implementation detail and exact validation
remain in `docs/reviews/`; this roadmap does not reclassify or erase that work.

## Phase 16 — Direction reset and controlled GUI baseline

**Status:** accepted with documented release conditions. The prior GUI implementation candidate and its verified evidence remain in
[Phase 16 completion review](docs/reviews/phase-16-completion.md). Product direction is reset by
the current product documents. The typed-startup provider lifecycle P0 is implemented with focused
restart evidence. The task-oriented Proxy Host lifecycle, Save-and-apply browser flow, and
post-rename ProxyHostStore recovery gate are implemented. Four focused scenarios execute in real
Chromium through the version-matched pinned Playwright image. The bounded Save-and-apply failure
campaign now covers desired persistence, immutable candidate publication and binding, activation
CAS/preparation/pointer durability, rollback, terminal audit, restart, and browser reporting.
GHSA-qwww-vcr4-c8h2 now has a formal non-reachability disposition and a repeatable production
module-graph gate because the only patched Router release requires an unbounded React/router
migration. Durable inactive Proxy Host drafts, exact promotion, schema-v1 migration, and
desired/draft/active browser status are implemented under ADR-0031. Independent application-
security/usability review accepted the completed Phase 16 scope. Provider reconciliations now use
the durable HMAC audit chain, least-privilege operators can discover draft-only actions, the
browser distinguishes a proved activation failure from an unavailable activation response, real
Unix-socket HTTP tests cover adversarial draft authorization, and every production image runs the
Router reachability gate. External human review and production release engineering remain later
release conditions; this independent-style local review is not external certification.

**Objective:** establish a trustworthy NPMPlus-compatible baseline around the existing typed
control plane.

**User outcome:** an operator can create, preview, save, apply, edit, enable, disable, duplicate,
delete, and roll back a Proxy Host without learning candidate IDs or revision mechanics.

**Scope:** restore provider reconciliation under typed startup; complete Proxy Host lifecycle UI;
add Save and apply, Save draft, Preview changes, Discard draft, and advanced History presentation;
define active/draft recovery semantics; align ProxyHostStore post-rename recovery
with existing fail-closed stores; run the controlled failure campaign; resolve or disposition
current dependency/security findings; publish the product contract and compatibility matrix.

**Non-goals:** no Proxy Location, Redirection Host, Dead Host, new certificate lifecycle, expanded
access semantics, provider family, database, or broad store abstraction.

**Dependencies:** completed Phases 14–15, ADR-0029, ADR-0030, the canonical compiler, candidate
repository, activation coordinator, typed startup reconciler, and current embedded UI.

**Deliverables:** completed provider-coordinator lifetime fix; exact desired/draft/active status and
recovery semantics; task-oriented Proxy Host actions; advanced-only revision mechanics;
ProxyHostStore failure injection and recovery gate; controlled failure report; dependency
disposition; product documents.

**Security requirements:** no TOML hot reload in typed mode; providers use ownership, validation,
candidate binding, audit, and activation; desired persistence never displaces last-known-good
runtime on failure; indeterminate state blocks mutation; duplicate uses normal create authorization;
no secret value appears in UI state or diagnostics.

**Migration requirements:** preserve existing seven-field objects and schema-1 read compatibility.
Bind or reconstruct the exact currently active unified typed snapshot during upgrade; if active
state is ambiguous, fail closed rather than activating the latest desired object set. Schema-1
Proxy Host records migrate as applied with no drafts; candidate binding hashes remain valid.

**GUI requirements:** replace Create candidate/Activate candidate as the normal workflow; add list
row actions and confirmations; distinguish draft, active, saved-not-applied, and recovery-required;
offer draft discard; retain candidate/revision identifiers only in advanced history.

**API requirements:** preserve existing staged behavior when mutation mode is omitted; add an
optional draft/apply mode and high-level application state to typed mutations; preview must accept
the proposed operation and concurrency context without writes; every new action has exact
OpenAPI/RBAC/audit coverage.

**Runtime requirements:** start the existing provider coordinator in both file-managed and
typed-startup modes using the active bound configuration; keep restart-time TOML immutable in typed
mode; restart from the exact active bound snapshot rather than a newer draft; keep the old active
runtime after compile, verification, or activation failure.

**Implemented evidence:** the managed-runtime supervisor now owns one reconciliation task in both
modes. Typed provider candidates inherit the exact bound desired-state snapshot, use the existing
revision CAS and activation coordinator, and resume typed file discovery after restart without
watching TOML. Focused tests cover exact active-versus-draft startup, changed provider output after
restart, manual Proxy Host coexistence, restart-only TOML, file-mode reload regression, invalid and
stale provider retention, and joined shutdown. The browser now reuses typed create/update/delete
and unified activation for create, edit, enable, disable, and confirmed delete; duplicate is a new
disabled unsaved form. Structured conflict and post-save activation-failure states avoid exposing
candidate mechanics or claiming the desired state is active. A known pre-rename Proxy Host store
failure restores memory and remains retryable; an indeterminate post-rename parent-sync failure
sets a recovery gate, prevents further mutations and compilation, and clears only after restart
strictly reloads durable generations. The API and browser expose `recovery_required` without
claiming success or attempting activation. Typecheck, client drift, and production build pass.
The focused lifecycle, destructive-permission, and recovery-required scenarios pass in Chromium
using the pinned Playwright 1.62.0 Noble image. The
[failure campaign](docs/reviews/phase-16-save-apply-failure-campaign.md) records exact
desired/candidate/active/audit/recovery outcomes. New deterministic hooks prove immutable
candidate failure before and after publication, active-pointer prepublication failure and
post-rename uncertainty, post-publication durability rollback, rollback-failure gating, terminal
audit uncertainty, exact-active restart after newer desired disable/delete, and accurate browser
blocking/copy. `ProxyHostStore` schema 2 now persists applied and inactive draft namespaces in one
atomic file. Save draft changes neither desired epoch nor runtime; exact promotion checks draft,
base-applied, desired-epoch, and active-revision CAS before normal activation. Schema-1 records load
as applied, drafts survive restart outside compiler/provider snapshots, and browser application
state distinguishes active, pending desired, draft, and recovery-required outcomes.

**Tests:** typed startup with manual file/DNS provider and typed Discovery Source; provider
failure/staleness; restart with active state plus newer draft; create/edit/enable/disable/duplicate/
delete/apply/rollback browser paths; stale object and revision CAS; failure before/after desired
fsync, candidate bind, active-pointer commit, audit terminal record, and parent-directory sync;
secret canaries; dependency reachability and production build.

**Documentation:** product direction, compatibility matrix, web administration, startup/provider
behavior, draft/apply recovery, dependency disposition, controlled failure results, STATUS, and
operator troubleshooting.

**Risks and mitigations:** watcher extraction could create a second publication path, and draft
semantics could activate unintended state on restart. Reuse one coordinator and activation
pipeline, bind exact active snapshots, journal state transitions, and fail closed on ambiguity.

**Acceptance criteria:** file/DNS status advances under typed startup; invalid provider output
cannot publish; all Proxy Host lifecycle actions work through typed operations; ordinary UI exposes
no candidate requirement; Save draft remains inactive across restart; failed Save and apply leaves
old runtime active and a recoverable desired state; failure injection proves mutation gating; no
applicable unresolved critical/high finding remains without signed disposition.

**Exit criteria:** satisfied for roadmap progression. Controlled runtime evaluation, the browser
suite, failure campaign, dependency disposition, and independent-style application-security and
operator-usability reviews accept the implemented scope with no unresolved Medium-or-higher Phase
16 blocker. External human review, long fuzz/soak, supply-chain artifacts, and production drills
remain release-stage conditions and do not make the product production-ready.

## Phase 17 — NPMPlus core host model

**Phase 17.1 multiple-domain unit:** bounded ordered exact domains are implemented through the
typed contract, singular-record migration, legacy active-binding verification, compiler,
certificate coverage, API/client, browser forms, drafts, restart, and compatibility evidence.
The remaining Phase 17 host families are explicitly outside this unit.

**Phase 17.2 Proxy Locations unit:** embedded stable-ID exact/prefix locations are implemented over
the existing runtime matcher and parent Proxy Host draft/CAS/candidate/activation boundary. Paths,
upstreams, count, policy inheritance/override, migration, exact-active compatibility, browser
editing, and failure behavior are bounded under ADR-0033. Redirection and Dead Hosts remain future
Phase 17 units.

**Objective:** implement the core NPMPlus host families and complete Proxy Host behavior through
bounded Rust-native objects.

**User outcome:** an operator can manage multi-domain Proxy Hosts, per-path locations, redirects,
and deliberate 404 hosts entirely through the GUI.

**Scope:** additive multiple domains; nested Proxy Locations; top-level Redirection Hosts and Dead
Hosts; complete host lifecycle; typed advanced forwarding, caching, buffering, compression, header,
timeout, WebSocket/gRPC, and common-protection controls where runtime design is approved; domain,
path, ownership, sharing, and generated-resource conflicts.

**Non-goals:** no raw Nginx directives, filesystem/PHP hosting, arbitrary regex or middleware
ordering, certificate issuance, expanded access-policy semantics, UDP, or generic gateway objects.

**Dependencies:** Phase 16 active/draft and lifecycle foundation, Phase 15 object envelope/compiler,
fixed-stage middleware, canonical route conflict validation, and compatibility matrix.

**Deliverables:** versioned Proxy Host additions; nested `ProxyLocation`; `RedirectionHost`;
`DeadHost`; bounded terminal 404 primitive; host forms/list actions; importer mappings; end-to-end
evidence and matrix updates.

**Security requirements:** canonical IDNA/domain handling, deterministic path precedence, owner and
share enforcement, no open redirects, no protected-header or request-target bypass, bounded cache/
body/state, and one route match without rematching after errors or rewrites.

**Migration requirements:** existing singular-domain Proxy Hosts load as one-element ordered domain
lists; legacy active candidate hashes remain verifiable without automatic activation. Existing
hosts and drafts migrate to zero locations; Phase 17.1 active hashes remain verifiable. New object
files are additive. Import maps only recognized safe fields and reports unsupported Nginx content
without executing it.

**GUI requirements:** Hosts navigation with Proxy, Redirection, 404, and Streams views; simple
common forms; nested location editor; progressive Advanced sections; lifecycle, conflict, preview,
draft/apply, and rollback feedback.

**API requirements:** versioned CRUD/validate/preview/apply/rollback operations, exact actions,
generation/revision preconditions, owner-scoped reads, closed diffs, and deterministic errors for
each host family and nested location.

**Runtime requirements:** compile all objects together into one canonical snapshot; reuse redirect
and proxy primitives; add only a bounded fixed 404 terminal action; preserve WebSocket/gRPC/
streaming behavior and last-known-good activation.

**Tests:** multiple-domain canonicalization and certificate conflicts; exact/prefix location
precedence and access inheritance; generated ID collisions; redirect loops/status/path/query;
fixed 404; cache/streaming exclusions if caching ships; owner/share and CAS matrices; restart,
rollback, API contracts, UI accessibility, and end-to-end traffic.

**Documentation:** object/reference guides, supported advanced alternatives, import limitations,
host recipes, conflict rules, migration, and compatibility evidence.

**Risks and mitigations:** Nginx expectations can expand the schema without bound. Implement only
matrix-backed outcomes, compile into fixed stages, reject ambiguous combinations, and explicitly
record unsupported directives.

**Acceptance criteria:** representative Proxy Host, Location, Redirection, and Dead Host workflows
work through GUI/API/runtime; existing objects migrate without behavior change; conflicts fail
before persistence or activation; raw configuration is neither accepted nor interpreted.

**Exit criteria:** every Phase 17 matrix row is Complete or explicitly accepted as Intentionally
different, and contract/security/end-to-end review passes.

## Phase 18 — Certificate and automatic HTTPS lifecycle

**Objective:** turn existing ACME, TLS, storage, renewal, and recovery primitives into a complete
safe certificate workflow.

**User outcome:** an operator can request, import, assign, renew, revoke, troubleshoot, and recover
certificates, including wildcard DNS certificates, without low-level ACME configuration.

**Scope:** lifecycle-aware Certificate; typed DNS Provider Credential; request/import/assignment/
renewal/revocation; HTTP-to-HTTPS redirect; HSTS/subdomain controls; challenge/issuer choice;
wildcard DNS; renewal status/history/failure recovery; safe Caddy-inspired defaults and explicit
advanced overrides.

**Non-goals:** no second ACME implementation, silent CA/environment switch, non-DNS wildcard,
insecure TLS fallback, plaintext key export, arbitrary DNS scripts, or issuance guarantee.

**Dependencies:** Phases 16–17 host/apply workflows, current ACME manager, encrypted certificate and
credential storage, TLS validation, and certificate ownership bindings.

**Deliverables:** additive certificate lifecycle contract; DNS credential metadata; forms and
status; assignment and redirect compiler behavior; renewal/revocation operations; migration;
failure recovery and compatibility evidence.

**Security requirements:** write-only keys and DNS tokens; name/key/chain/validity/environment/
ownership checks; least-privilege DNS scope; bounded challenges; cleanup; prior-certificate
retention; no partial or weaker activation; durable terminal audit.

**Migration requirements:** retain existing certificate identities, opaque references, ACME
accounts, encrypted material, and renewal ownership. Add lifecycle metadata without reimporting or
reading keys. Ambiguous assignments remain inactive.

**GUI requirements:** request/import wizard; host certificate selector; force-HTTPS/HSTS controls
with warnings; DNS credential create/rotate/revoke; renewal status/history; retry and recovery
actions; no low-level challenge details in the common path.

**API requirements:** versioned request/import/assign/renew/revoke/status operations; write-only
uploads; owner/share authorization; exact concurrency; redacted errors/previews/diffs; idempotent
retry where safe.

**Runtime requirements:** reuse the current ACME manager and atomic certificate publication;
derive redirects/listeners only after usable HTTPS material exists; retain last-known-good
certificate and route behavior on issuer, DNS, storage, or activation failure.

**Tests:** all supported challenges, wildcard rules, mocked CA/DNS outage, credential cleanup and
rotation, import validation, assignment ambiguity, redirect loops, HSTS acknowledgement, renewal
races/backoff, accelerated multi-cycle renewal, restart, rollback, Pebble integration, and secret
canaries.

**Documentation:** automatic HTTPS, certificate lifecycle, DNS credentials, safe defaults,
advanced overrides, status/failure recovery, migration, privacy, and matrix evidence.

**Risks and mitigations:** automation can surprise users or cause issuance/redirect outages.
Preview derived actions, use staging safeguards and backoff, retain working material, and never
activate incomplete HTTPS policy.

**Acceptance criteria:** common certificate workflows complete in GUI and API; preview explains
derived HTTPS actions; failures preserve working service and material; protected values never
appear in output.

**Exit criteria:** ACME/TLS/security review and accelerated renewal/failure campaigns pass, and all
Phase 18 matrix rows are Complete or accepted as Intentionally different.

## Phase 19 — Access control and security parity

**Objective:** provide NPMPlus-compatible access and common security outcomes through bounded typed
policy.

**User outcome:** an operator can order allow/deny rules, configure basic or forward
authentication, and apply reviewed rate/header/common-protection controls to hosts and locations.

**Scope:** ordered network rules; explicit all/any semantics; basic authentication; approved
ForwardAuth presets and custom bounded endpoint; rate limiting; security headers; common-protection
preset; optional CrowdSec/AppSec integration only after separate review.

**Non-goals:** no raw access snippets, arbitrary middleware order, executable WAF rules, plaintext
password reads, unsafe regex, unbounded request buffering, or identity-header trust from clients.

**Dependencies:** Phase 17 host/location assignments, existing Access Policy ownership/binding,
Stored Credentials, fixed middleware stages, egress policy, and Phase 18 HTTPS guarantees where
authentication requires them.

**Deliverables:** additive typed Access Policy; migration from middleware references; credential
workflow; policy editor; compiler and interaction matrix; supported ForwardAuth presets;
security-integration decision/evidence; matrix updates.

**Security requirements:** exact evaluation order; fail-closed authentication; HTTPS where
required; off-path password verification; trusted identity-header replacement; SSRF/redirect
allowlists; bounded timeouts/bodies/keys/state; privacy and outage policy for external integration.

**Migration requirements:** preserve legacy middleware-reference policies until deterministic
conversion. A policy may use either legacy references or the new typed form, never both.
Unconvertible policy remains explicit and inactive rather than weakened.

**GUI requirements:** ordered rule editor; basic-user credential workflow; ForwardAuth selection;
policy assignment/inheritance; progressive rate/header controls; preview of effective order;
clear denial/outage diagnostics without secret disclosure.

**API requirements:** typed rules/auth/combine contracts, exact CRUD/apply actions and CAS,
write-only credential values, effective-policy preview, closed diff fields, and owner/share
authorization for host/location use.

**Runtime requirements:** compile into existing fixed stages; do not permit reorder; preserve
single authentication stage, protected headers, egress checks, and bounded limiters; optional
external security integration remains isolated.

**Tests:** ordered allow/deny and all/any matrices; location inheritance; auth bypass; password and
credential canaries; ForwardAuth SSRF, redirect, timeout, denial, and header spoofing; rate
exhaustion; reload/restart; owner/share/CAS; optional integration outage/privacy; browser and
end-to-end traffic.

**Documentation:** access semantics, basic/forward authentication, supported providers, credential
rotation, security presets, failure policy, privacy, migration, and matrix evidence.

**Risks and mitigations:** ambiguous semantics can grant access. Use one closed evaluator,
effective-policy preview, exhaustive table tests, reject incompatible combinations, and fail
closed.

**Acceptance criteria:** representative NPMPlus access workflows have GUI/API/runtime evidence;
ordered behavior is deterministic; authentication failures never fall through; no secret or
trusted identity value leaks.

**Exit criteria:** authorization/security review and interaction matrix pass under bounded load,
and Phase 19 matrix rows are Complete or explicitly accepted.

## Phase 20 — Operational compatibility

**Objective:** complete the daily administration, recovery, migration, and support workflows
expected from an NPMPlus-compatible product.

**User outcome:** an unfamiliar operator can install, configure users/settings, inspect audit and
logs, back up, restore, migrate, upgrade, troubleshoot, and recover AegisProxy.

**Scope:** typed Settings; user lifecycle and reviewed permissions; useful audit/log views;
protected backup and redacted manifest; staged restore; upgrade; NPM/NPMPlus dry-run import;
installation/recovery manuals; representative operator usability tests; API/automation coverage.

**Non-goals:** no database, NPM database reuse, direct Nginx import/execution, local password/TOTP
store without a separate case, embedded clustering, unsupported in-place downgrade, or production
claim.

**Dependencies:** Phases 16–19 product objects and activation semantics, file-backed stores,
backup/restore validation, OIDC, audit/telemetry, packaging, and versioned migrations.

**Deliverables:** Settings contract; complete user/permission workflows; audit/log query UX;
versioned backup manifest; staged restore/rollback; importer and compatibility report; upgrade and
recovery paths; task manuals; usability evidence.

**Security requirements:** hostile archive/import handling; path traversal and decompression bounds;
write-only secrets; privilege migration review; exact restore/import preview and authorization;
durable audit; redacted logs; private state permissions; rollback on partial failure.

**Migration requirements:** version every durable format; preserve current file-backed objects,
identity bindings, tokens, credentials, revisions, and backups; import supported NPM/NPMPlus fields
into typed objects and report unsupported directives; never mutate source data.

**GUI requirements:** task-oriented Settings, Users/Permissions, Audit, Logs, Backups/Restore,
Import, Health, and recovery screens; progress and terminal results; no required absolute internal
paths or candidate IDs.

**API requirements:** versioned settings, identity, audit/log query, backup, restore stage/preview/
apply, import dry-run/apply, upgrade status, and recovery operations with exact scopes, CAS,
idempotency, and audit.

**Runtime requirements:** settings declare restart/reload class; restore/import compile complete
desired state and activate atomically; last-known-good runtime remains on failure; upgrade and
recovery preserve exact active state.

**Tests:** hostile archives, traversal, size/version rejection, secret canaries, permission
escalation, dry-run/apply equivalence, source immutability, restore interruption/rollback, upgrade
and supported downgrade boundaries, audit/log redaction, identity/session invalidation, and
representative operator journeys.

**Documentation:** install, settings, users/permissions, logs/audit, backup/restore, migration,
upgrade, troubleshooting, disaster recovery, known incompatibilities, and matrix evidence.

**Risks and mitigations:** import/restore can corrupt or expose durable state. Stage into private
bounded storage, validate and preview completely, preserve source and active state, journal apply,
and require explicit recovery on ambiguity.

**Acceptance criteria:** a fresh operator completes install, core configuration, backup, restore,
migration dry-run/apply, upgrade, and rollback using supported docs and UI; exact API automation is
available; unsupported Nginx behavior is reported rather than interpreted.

**Exit criteria:** representative usability, migration, upgrade, backup/restore, recovery, and
security campaigns pass, and Phase 20 matrix rows are complete or explicitly accepted.

## Phase 21 — Streams and protocol completion

**Objective:** complete justified stream workflows and make evidence-backed decisions on transport
extensions.

**User outcome:** an operator can manage and troubleshoot TCP/TLS-passthrough streams; approved
UDP, PROXY protocol, or client-mTLS capabilities are equally typed and safe.

**Scope:** friendly TCP workflow; exact listener/target/SNI behavior; protocol status; separate ADR
and threat model for UDP, PROXY protocol, and client mTLS; implementation only for approved
decisions; interoperability evidence.

**Non-goals:** no generic UDP, CONNECT, open proxy, client-selected destination, trusted arbitrary
PROXY sender, opportunistic client-cert policy, HTTP/3, or parity-for-marketing.

**Dependencies:** Phase 16 activation/recovery, Phase 17 host navigation/conflicts, Phase 18
certificate lifecycle for any mTLS, current TCP/TLS-passthrough runtime, target load balancers, and
independent protocol reviewers.

**Deliverables:** Stream Host task form and status; protocol ADRs/threat models; approved typed
schema/API/runtime controls; deployment/rollback switches; fixtures and compatibility evidence.

**Security requirements:** unique bounded listeners, egress validation, connection limits and
backpressure, exact trusted PROXY peers, client-CA ownership/revocation, UDP anti-spoof/amplification
controls, no cross-protocol downgrade.

**Migration requirements:** current TCP/TLS-passthrough objects remain unchanged. Approved optional
fields default disabled. Rejected capabilities are recorded as Intentionally different without
changing state.

**GUI requirements:** simple TCP/TLS-passthrough form, status and troubleshooting, lifecycle and
apply actions; approved extensions appear only behind Advanced with trust warnings.

**API requirements:** preserve current Stream Host CRUD/preview/apply; add only approved versioned
fields/actions with exact scope, CAS, validation, status, and audit.

**Runtime requirements:** preserve bounded half-close/backpressure and TLS ClientHello parsing;
isolate each approved transport feature so disabling it opens no listener or trust surface.

**Tests:** TCP half-close, cancellation, drain, backpressure, SNI conflicts, malformed ClientHello,
restart/rollback, destination abuse, interoperability, fuzz corpus, and feature-specific trust,
spoofing, replay, amplification, loss/reorder, and disabled-surface tests.

**Documentation:** stream workflows, protocol compatibility, deployment trust, failure behavior,
ADRs/threat models, migration, rollback, and matrix evidence.

**Risks and mitigations:** transport features enlarge unauthenticated attack surface. Require a
named use case and independent decision, isolate code/listeners, bound state, and permit rejection
without blocking established TCP.

**Acceptance criteria:** TCP workflow is complete; each optional protocol is either approved with
full GUI/API/runtime/security evidence or explicitly rejected/deferred; disabled features expose no
surface.

**Exit criteria:** protocol-specific interoperability, abuse, fuzz, and rollback reviews pass for
the exact shipped scope.

## Phase 22 — Optional dynamic infrastructure integration

**Objective:** add Traefik-inspired discovery only as an optional source of typed proposed state.

**User outcome:** an operator can observe, approve, promote, and troubleshoot discovered services
without providers bypassing GUI-managed desired state.

**Scope:** complete file/DNS reconciliation; typed Provider and Discovered Service; Docker and
Kubernetes adapters; source ownership/freshness; conflicts; approval/promotion; stale cleanup;
provider health; bounded middleware/provider metadata.

**Non-goals:** no Docker socket in the proxy process, default workload exposure, direct runtime
mutation, arbitrary labels/annotations, scripts, ingress-controller parity, Consul without a
separate case, cluster consensus, or provider-owned secrets outside Stored Credentials.

**Dependencies:** Phase 16 shared provider coordinator and active/draft semantics, Phase 17 product
objects, Phase 19 policies, current file/DNS providers, privilege-isolated helpers, and a separate
ADR/threat review for each privileged provider.

**Deliverables:** provider/proposal contracts; Discovery Source migration; least-privilege adapters;
approval/conflict engine; promotion workflow; status and cleanup; GUI/API; reconciliation audit and
failure evidence.

**Security requirements:** default exposure false; explicit namespaces and owners; bounded
metadata/events/state; credential references; no secret labels; destination revalidation; helper
isolation; canonical compile/candidate/activation; last-known-good retention.

**Migration requirements:** convert existing Discovery Sources into equivalent Providers with
stable ownership and behavior. Existing manually managed hosts remain authoritative unless an
explicit conflict policy and approval says otherwise.

**GUI requirements:** advanced Providers area with health, observations, diffs, conflicts,
approval/promotion, ownership, freshness, and cleanup; no provider controls in the normal host
workflow unless a host is explicitly source-managed.

**API requirements:** versioned provider CRUD, observation reads, approval/rejection/promotion,
conflict resolution, health, and reconciliation actions with exact scopes, generations,
idempotency, and audit.

**Runtime requirements:** provider adapters perform observation only; promotion writes ordinary
typed desired objects; every publication uses the one canonical validation/binding/activation
path; outage or stale data cannot silently replace active policy.

**Tests:** event storms, malicious metadata, privilege loss, reconnect/replay, DNS rebinding,
conflicts, approval races, stale cleanup, source deletion, helper isolation, restart, last-known-
good behavior, owner/scope matrix, and GUI/API/runtime parity.

**Documentation:** provider model, permissions, deployment, threat boundaries, approval/conflict
semantics, migration, failure recovery, and troubleshooting.

**Risks and mitigations:** privileged providers can expose workloads or flap desired state. Isolate
access, debounce and bound events, require approval by default, retain provenance, and reject any
output that cannot compile normally.

**Acceptance criteria:** proxy process has no Docker socket; invalid, stale, conflicting, or
unapproved observations cannot replace active policy; every promoted object has source/ownership
evidence and follows normal activation.

**Exit criteria:** provider-specific security review and controlled failure campaigns pass for
each shipped adapter.

## Phase 23 — Production release engineering

**Objective:** produce independently reviewed, reproducible release, deployment, and recovery
evidence.

**User outcome:** operators receive verifiable artifacts and tested install, upgrade, backup,
restore, canary, rollback, and support procedures.

**Scope:** CI/release workflow; reproducible builds; SBOM; signatures/provenance; checksums;
multi-architecture images; dependency/license/source and vulnerability scanning; exact-artifact
tests; upgrade/restore/canary drills; long fuzz/soak; protocol review; independent application-
security review; support envelope.

**Non-goals:** no vulnerability-free, complete-parity, HA, or performance claim beyond exact
evidence; no release while critical/high findings or required independent reviews remain open.

**Dependencies:** completed shipped scope from Phases 16–22, protected release infrastructure,
representative staging, supported target matrix, named owners, and qualified independent reviewers.

**Deliverables:** protected pipeline; reproducible signed artifacts; SBOM/provenance/scan evidence;
release notes and compatibility matrix; long-run results; recovery drills; support policy; signed
residual-risk approval.

**Security requirements:** short-lived release identity, two-person promotion, immutable artifacts,
secret-free logs/artifacts, advisory/license/source gates, independent review, and no unresolved
critical/high findings without explicit release-blocking disposition.

**Migration requirements:** test every supported durable version and upgrade path against exact
release artifacts; document downgrade limits; prove backup/restore before and after upgrade.

**GUI requirements:** production UI assets are generated reproducibly from the locked dependency
graph, pass accessibility/security checks, and expose supported-version and recovery information.

**API requirements:** freeze and test supported OpenAPI versions, generated-client drift,
deprecation/migration policy, artifact compatibility, and automation examples.

**Runtime requirements:** exact artifacts pass supported architecture/network confinement,
protocol, resource, canary, rollback, renewal, provider-failure, and last-known-good campaigns.

**Tests:** full workspace/UI/integration suite on exact artifacts; reproducibility comparison;
multi-architecture smoke; long fuzz/soak; protocol interoperability; vulnerability scan;
install/upgrade/restore/forced rollback; renewal; provider outage; canary traffic; operator drills.

**Documentation:** release/install/upgrade/restore manuals, artifact verification, SBOM/provenance,
support policy, known limits, residual risks, incident/recovery procedures, and final compatibility
evidence.

**Risks and mitigations:** environment gaps and late findings invalidate prior evidence. Keep
production NO-GO, roll forward fixes, rebuild immutable artifacts, and repeat every invalidated
gate.

**Acceptance criteria:** exact supported artifacts are reproducible, signed, scanned, and pass the
target matrix; independent reviews close critical/high findings; long campaigns and recovery drills
pass; unfamiliar operators complete supported lifecycle tasks.

**Exit criteria:** product, engineering, security, operations, and release owners approve the exact
immutable scope and residual risk. Until then, production remains NO-GO.

## Phase 24 — Post-parity differentiation

**Objective:** consider differentiated capabilities only after the agreed NPMPlus baseline is
complete.

**User outcome:** mature operators may opt into additional automation, scale, and observability
without weakening the primary reverse-proxy-manager workflow.

**Scope:** separately justified advanced load balancing, broader discovery, richer observability,
declarative GitOps, fleet orchestration, and selected Caddy/Traefik-inspired capabilities.

**Non-goals:** no automatic backlog activation, speculative plugin platform, generic service mesh,
or change that makes common host management depend on optional infrastructure.

**Dependencies:** compatibility matrix baseline entirely Complete or explicitly accepted as
Intentionally different, Phase 23 production evidence, measured user need, and separate
architecture/security decisions.

**Deliverables:** one scoped proposal at a time with product case, contract, migration, GUI/API/
runtime design, ADR/threat model where applicable, tests, operations, and rollback.

**Security requirements:** retain all established ownership, secret, provider, egress, resource,
candidate, activation, and audit boundaries; optional features default disabled and isolated.

**Migration requirements:** each proposal is additive or supplies a reversible explicit migration;
core NPMPlus-compatible objects remain supported.

**GUI requirements:** optional capability remains behind progressive disclosure and never obscures
the primary Hosts/Certificates/Access/Operations information architecture.

**API requirements:** versioned typed operations only; no raw execution or alternate activation
path.

**Runtime requirements:** reuse canonical compilation and atomic activation; isolate optional state
and permit rollback/removal without impairing core proxying.

**Tests:** proposal-specific correctness, abuse, migration, rollback, disabled-surface, load,
failure, GUI/API/runtime parity, and operational evidence.

**Documentation:** measured need, supported outcome, limitations, migration, deployment, recovery,
security decision, and updated compatibility/product positioning.

**Risks and mitigations:** post-parity scope can recreate a generic gateway roadmap. Require a
named operator outcome, evidence, smallest design, and independent approval before scheduling.

**Acceptance criteria:** the proposal solves a measured need, preserves core workflows and
boundaries, and passes its exact product/security/operational gates.

**Exit criteria:** each capability exits independently; Phase 24 has no blanket parity or platform
completion claim.

## Immediate implementation unit

Complete Proxy Host edit, enable, disable, delete, and duplicate browser workflows in one
reviewable branch. Reuse the existing typed API, ownership/generation CAS, candidate binding,
audit, and activation path; do not begin Proxy Locations or Redirection Hosts in that unit.
