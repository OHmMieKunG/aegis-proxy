# NPMPlus product-direction reset

Status: product contract and roadmap input

Updated: 2026-07-29

Comparison baseline: NPMPlus
[`f6a4db4`](https://github.com/ZoeyVid/NPMplus/commit/f6a4db4da1a78407c423a4e3f3576c380aba88c5)

## Product definition

AegisProxy is a self-hosted, NPMPlus-compatible reverse-proxy manager written in Rust. It offers a
simple web interface for managing proxy hosts, redirects, dead hosts, streams, certificates,
access controls, and operational settings. Its independent Rust-native data plane selectively
adds safe automatic HTTPS and infrastructure discovery without exposing unsafe implementation
escape hatches.

The product hierarchy is:

1. NPMPlus defines primary user-facing terminology and workflow expectations.
2. Existing AegisProxy security and transactional architecture constrains the implementation.
3. Caddy contributes automatic HTTPS, certificate automation, and safe defaults.
4. Traefik contributes optional providers, discovery, and composable middleware.
5. Generic gateway, ingress-controller, service-mesh, and plugin-platform work waits until the
   agreed NPMPlus daily-workflow baseline is complete.

Compatibility concerns supported workflows and observable outcomes. It does not mean Nginx
configuration compatibility, NPMPlus database compatibility, identical API routes, identical
algorithms, copied source code, arbitrary Nginx directives, or a pixel-identical UI. Public
documentation must say **NPMPlus-compatible** or **NPMPlus-inspired** and must not claim complete
parity until the [compatibility matrix](npmplus-compatibility-matrix.md) proves it.

## Architectural assessment

The repository already contains the difficult security and runtime foundation. Replacing it would
increase risk without improving the target workflows:

- Tokio, Hyper, and Rustls provide HTTP/1.1, HTTP/2, WebSocket, gRPC, streaming, HTTPS termination,
  upstream TLS, TCP proxying, and TLS passthrough.
- Strict typed configuration compiles deterministically into one validated runtime snapshot.
- Immutable candidates, revisions, exact activation checks, atomic publication, forward rollback,
  and audit provide a stronger activation boundary than a direct configuration editor.
- Typed owner-aware objects, fixed roles, explicit API-token scopes, encrypted Stored Credentials,
  write-only secret input, OIDC sessions, and first-run identity binding already establish the
  control-plane security boundary.
- File-backed stores remain bounded and durable. No observed product gap currently proves a
  database is required.

The reset is primarily a product-boundary change: keep those primitives and wrap them in ordinary
host, certificate, access, and operations workflows.

## Preserve, wrap, extend, or stop

| Disposition | Existing area | Decision |
|---|---|---|
| Preserve unchanged | Rust data plane and protocol framing | Keep Hyper parsing as the HTTP framing boundary, one route match, bounded streaming, egress checks, and Rustls/Tokio ownership. |
| Preserve unchanged | Canonical configuration compiler and runtime snapshot | Every GUI, API, migration, and provider operation must compile through the same semantic validation and activation path. |
| Preserve unchanged | Candidate, revision, activation, rollback, audit, and secret boundaries | Simplify the presentation, not the security or transaction semantics. |
| Preserve unchanged | Owner-aware objects, role/scope intersection, OIDC identity binding, and Unix-socket administration | Extend only through versioned actions and reviewed authorization matrices. |
| Preserve unchanged | File-backed persistence | Add bounded metadata or journals where required; do not add a database without a separate evidence-backed ADR. |
| Wrap | Seven-field Proxy Host | Retain the simple contract as the normal editor and hide generated resource, candidate, and revision details. |
| Wrap | Access Policy middleware references | Present typed ordered access and authentication controls; compile them into the existing fixed middleware stages. |
| Wrap | ACME, certificate storage, and renewal primitives | Add request/import/assignment/status/recovery workflows without exposing key material or low-level issuer mechanics by default. |
| Wrap | Backup creation and restore validation | Present protected backup, staged validation, preview, restore, and recovery tasks rather than absolute-path-oriented primitives. |
| Extend | Proxy Host domains and locations | Add multiple domain names and nested typed locations with safe defaults and deterministic conflict checks. |
| Extend | Host families | Add typed Redirection Host and Dead Host objects; reuse the fixed redirect primitive and add only the bounded terminal 404 behavior that is missing. |
| Extend | Access semantics | Add ordered allow/deny rules, basic authentication, bounded forward authentication, and explicit combination semantics. |
| Extend | Certificates and DNS credentials | Add lifecycle intent and typed DNS-provider metadata over the existing encrypted credential store. |
| Extend | Operations | Add settings mutations, useful audit/log views, complete restore, upgrade, and NPM/NPMPlus import workflows. |
| Extend later | Streams | Complete the TCP workflow; decide UDP, PROXY protocol, and client mTLS independently through ADRs and threat models. |
| Extend later | Providers | Promote current Discovery Sources into a typed provider/proposal model after core workflows are complete. |
| Replace incrementally | Current candidate-first browser workflow | Replace the ordinary two-step Create/Activate presentation with Save and apply, while keeping candidate mechanics internally and in advanced history. |
| Replace incrementally | Raw JSON secondary-resource forms | Replace them with task-specific forms as each compatibility workflow is implemented. Keep raw read-only diagnostics only where useful. |
| Deprecate | ProxyHost-only schema-1 candidate routes | Preserve bounded read/migration compatibility while schema-2 unified routes are adopted; do not add features to the deprecated path. |
| Defer | Docker/Kubernetes, broader discovery, GitOps, fleet orchestration, richer load balancing | Revisit in Phases 22 and 24 after daily NPMPlus workflows. |
| Never support | Arbitrary Nginx configuration, scripts, shell hooks, runtime plugins, client-selected upstreams, or provider-direct activation | These bypass typed validation, ownership, egress, secret, activation, or audit boundaries. |
| Not a product goal | NPMPlus database/API/internal compatibility and pixel-identical UI | Provide migration and workflow compatibility instead. |

## Product object model

All mutable objects retain the current versioned `ApiObject<T>` envelope, stable ID, owner ID,
bounded generation compare-and-swap, and deny-unknown-fields parsing.

### `ProxyHost`

Keep the existing workflow fields:

- bounded ordered `domains` (first value is primary)
- `forward_protocol`
- `forward_host`
- `forward_port`
- `automatic_https`
- `access_policy_ref`
- `enabled`

Add versioned optional fields with defaults rather than replacing the remaining workflow:

- `locations`, default empty.
- bounded typed forwarding, header, caching, buffering, timeout, WebSocket, gRPC, HSTS, redirect,
  and common-protection controls behind Advanced.

The compiler continues to generate internal routes, groups, endpoints, listeners, middleware
references, and fingerprints. Those identifiers are not normal product fields.

### `ProxyLocation`

`ProxyLocation` is nested in one Proxy Host so ownership and lifecycle remain atomic. It has a
stable location ID, enabled state, bounded exact-or-prefix path match, forward scheme/host/port,
access-policy inheritance or one explicit override, and the same bounded advanced controls as its
parent where meaningful.

Regex/named Nginx locations, arbitrary directives, filesystem roots, PHP execution, and embedded
file serving are not supported. Additional matcher kinds require an explicit typed contract and
security review.

### `RedirectionHost`

Add a top-level owner-aware object with domain names, target scheme (`http`, `https`, or preserve),
target host, status (`301`, `302`, `307`, or `308`), path/query preservation, typed HTTPS/HSTS
settings, and enabled state. It compiles into the existing exclusive fixed redirect stage and must
reject loops, unsafe targets, and ambiguous domain ownership.

### `DeadHost`

Add a top-level owner-aware object with domain names, enabled state, and typed HTTPS/HSTS settings.
It returns one fixed safe 404 response. Implement that as a bounded canonical terminal response,
not arbitrary response content or configuration.

### `StreamHost`

Preserve the current listen port, TCP/TLS-passthrough protocol, forward target, exact SNI list, and
enabled state. Add only product metadata such as a description when useful. UDP, PROXY protocol,
and client mTLS remain Phase 21 decisions.

### `AccessPolicy`

Evolve the current secret-free ownership wrapper into a typed policy with:

- exact ordered network allow/deny rules;
- one authentication mode: none, basic, or approved forward authentication;
- explicit all/any combination semantics;
- optional bounded rate-limit and security-header policy references.

Basic-auth password input is write-only and becomes an approved secret reference. Reads, previews,
diffs, audits, backups, and errors expose no plaintext, password hash, or usable ciphertext. The
current middleware-reference representation remains a migration input until converted; a policy
must not ambiguously contain both representations.

### `Certificate` and `DnsProviderCredential`

Extend Certificate from an ownership binding to lifecycle intent: domain names, managed ACME or
imported source, issuer/challenge selection, optional DNS credential reference, assignment, and
redacted observed status. Existing certificate references migrate without reimporting keys.

`DnsProviderCredential` is typed metadata over Stored Credential: provider kind, display label,
optional zone scope, enabled/expiry/rotation metadata, and a write-only value. It never returns
plaintext or ciphertext.

### `User`, `Role`, and `Settings`

Keep OIDC-first user binding, display name, enabled state, and four built-in roles. Phase 20 may
add closed resource/action permissions and custom role objects only after an authorization
migration and escalation review. Effective token permission remains role intersected with its
explicit scopes.

Add one versioned Settings singleton containing only supported product settings and their
restart/reload class. It is not a raw configuration blob.

### `Provider` and `DiscoveredService`

Evolve Discovery Source into a Provider contract for file, DNS, Docker, or Kubernetes inputs.
Provider output creates bounded source-owned `DiscoveredService` observations containing source
identity, endpoints, freshness, conflicts, and approval state. Promotion creates or updates an
ordinary typed host through the normal desired-state and activation pipeline. Observation alone
never changes runtime state.

### `BackupManifest`

Expose a redacted manifest/status object with format version, creation time, object counts, size,
and compatibility metadata. Never expose archive contents, internal absolute paths, secret
material, or encryption recipients. Restore stages, validates, previews, and applies a versioned
operation through the same authorization and audit boundary.

## Bounded alternatives to Nginx advanced configuration

| NPMPlus expectation | AegisProxy alternative |
|---|---|
| Custom Nginx locations | Nested typed `ProxyLocation` with bounded match and forwarding fields. |
| Caching toggle | Typed response-cache policy with bounded size, eligibility, TTL, and explicit protocol exclusions; implement only after a safe runtime design exists. |
| Block common exploits | Versioned common-protection preset using existing normalization, protected-header, target, and forwarding controls. |
| Advanced headers | Closed request/response header operations that cannot alter protected framing, authority, identity, or forwarding headers. |
| Auth-request snippets | Typed ForwardAuth endpoint, allowlisted redirect hosts, bounded headers/timeouts, egress validation, and credential references. |
| Buffering/compression controls | Typed bounded modes constrained by streaming, WebSocket, gRPC, body, and memory safety rules. |
| Custom error/dead host | Fixed bounded terminal responses; no templates, file paths, or executable content. |
| Stream directives | Individually approved typed transport fields backed by ADR and threat-model evidence. |
| CrowdSec/AppSec | Optional external integration with bounded metadata, failure policy, privacy documentation, and separate review. |

Nginx-specific directives, rewrite-language semantics, arbitrary regex/location precedence,
filesystem/PHP/fancy-index serving, disabling request-target safety, and arbitrary module behavior
cannot or should not be reproduced.

## Activation workflow

The normal GUI operations are:

- **Save and apply**
- **Save draft**
- **Preview changes**
- **Disable**
- **Enable**
- **Duplicate**
- **Delete**
- **Roll back**

Duplicate pre-fills a new typed create form; it does not require a special backend abstraction.
Enable and disable are normal typed updates. Candidate hashes and revision IDs remain available to
automation and advanced troubleshooting but are hidden from the normal editor.

`Save and apply` preserves this internal order:

1. authorize;
2. parse and validate;
3. durably persist desired intent;
4. compile the complete desired state;
5. create an immutable bound candidate;
6. verify the candidate;
7. atomically activate;
8. record one terminal audit result.

Existing mutations stage an immutable candidate before desired-state persistence, and current typed
startup reconciles the latest desired store. Phase 16 must change that coordination before a true
draft workflow is advertised.

The control plane records high-level state as `draft`, `active`, `saved_not_applied`, or
`recovery_required`. Existing create/update/delete operations gain an optional mutation mode;
omitting it preserves current staged behavior for automation.

### Crash and failure semantics

- Failure before desired-state durability leaves previous desired and active state unchanged.
- Persistence followed by compile, candidate, verification, or activation failure leaves the new
  desired state as `saved_not_applied`; the last-known-good active revision keeps serving.
- A successful active-pointer commit makes the exact bound snapshot authoritative on restart.
  Recovery finishes the journal and terminal audit without reinterpreting a newer draft.
- Indeterminate persistence or activation fails closed, exposes `recovery_required`, and blocks
  later mutations until active pointer, desired status, and journal converge.
- Rollback creates a forward revision and restores desired state from the selected bound snapshot.
- Startup restores the exact active bound typed snapshot. It must not activate a later draft merely
  because that draft is newest in the desired store.

The GUI shows Retry apply and Revert draft after a saved-but-not-applied outcome. It never silently
discards desired intent or activates an unverified partial state.

## Current technical-debt findings

### Release-critical startup/provider regression

Typed startup calls the revision-managed runtime path directly. The `ProviderCoordinator` is owned
by the TOML watcher path, so selecting typed startup disables file/DNS polling and leaves provider
status at static fallback. The first implementation unit must extract existing provider
coordination from watcher ownership and start it in both modes without restoring TOML hot reload or
creating an unbound activation path.

### GUI lifecycle and information architecture

The Proxy Host page supports validation, preview, candidate creation, and activation. It does not
offer edit, enable/disable, delete, or duplicate. Revisions and candidate IDs are first-class
navigation and button concepts. Phase 16 must finish lifecycle actions and move those mechanics
behind normal Save/Preview/History language.

### Snapshot versions

Low-level TOML uses configuration schema version 1. Separately, typed candidate snapshot schema 1
contains only Proxy Hosts and is deprecated; schema 2 binds Proxy Hosts, Stream Hosts, Discovery
Sources, and exact Access Policy/Certificate dependencies. Documentation and migrations must not
confuse these version domains.

### Browser dependency

The installed React Router dependency is reported by `npm audit` under
[GHSA-qwww-vcr4-c8h2](https://github.com/advisories/GHSA-qwww-vcr4-c8h2). The advisory concerns
unstable React Server Component APIs; this repository uses a static `createBrowserRouter` SPA and
does not import the RSC/server APIs. Reachability lowers immediate applicability but does not close
the dependency finding. Phase 16 requires a safe upgrade, upstream resolution, or signed residual
risk disposition.

### Persistence consistency

`TypedStore` and `AccessPolicyStore` distinguish post-rename parent-directory sync failure as
indeterminate, preserve visible state, and block later writes until restart reconciliation.
`ProxyHostStore` instead restores in-memory state on the generic persistence error path and does
not use the shared store's explicit single-owner lock. If rename succeeded before directory sync
failed, memory and visible disk state may diverge. Phase 16 should align this one store with the
existing fail-closed pattern and add failure injection. Do not replace specialized domain/epoch,
candidate-binding, or rollback-journal behavior with a speculative generic abstraction.

### Store and module ownership

Access Policy and Proxy Host stores duplicate some bounded persistence mechanics, while Stream
Host, Discovery Source, Certificate, User, and Stored Credential reuse `TypedStore`. Consolidation
is justified only after semantics agree and only when it removes a demonstrated recovery or
security risk. Current production modules remain below the recorded 1,500-line rationale threshold;
the largest observed module is approximately 1,230 lines. Module size alone is not a refactor
request.

### API/client drift

The checked-in generated TypeScript client currently matches the admin OpenAPI schema. Keep the
existing drift gate; do not introduce a second API model or hand-maintained client types.

## Compatibility and migration risks

| Rework | Classification | Migration | Security boundary | Compatibility risk |
|---|---|---|---|---|
| Proxy Host multiple domains | Public contract; singular input migration to bounded plural output | One-element list; legacy active hashes retained | Existing ownership/conflict/compiler boundary | Medium, implemented under ADR-0032 |
| Proxy Host locations and advanced fields | Public contract; additive schema | Safe defaults for existing objects | Existing ownership/conflict/compiler boundary | Medium |
| Redirection Host and Dead Host | New public contracts; additive schema/runtime | New objects; importer mapping later | Domain ownership and terminal-response safety | Medium |
| Ordered Access Policy | Public contract evolution | Convert existing middleware refs without reading secrets | Authentication, authorization, and network policy | High |
| Certificate lifecycle and DNS credentials | Public contract evolution | Preserve opaque certificate and credential references | Private keys, DNS authority, issuance, and renewal | High |
| Draft/apply and active-state recovery | Public API plus internal transaction change | Bind current active typed revision during upgrade; fail closed if ambiguous | Activation, audit, durability, and rollback | High |
| User, Role, and Settings | Additive public contracts | Preserve built-in roles and subject bindings | Privilege escalation and restart policy | High |
| Provider and Discovered Service | Additive public contracts | Discovery Source conversion with stable ownership | Privileged discovery, approval, egress, and activation | High |
| Backup, restore, and import | Additive public operations | Versioned archive and hostile-input migration | Secrets, path traversal, rollback, and audit | High |
| Frontend information architecture | User-visible workflow change | No data migration | Role/action visibility and secret handling | Medium |
| ProxyHostStore recovery alignment | Internal refactor | No schema change | Atomic durability and mutation gating | Low if incremental |
| Raw Nginx configuration rejection | Intentional incompatibility | Importer reports unsupported directives | Prevents validation and execution bypass | Documented |

## First implementation unit

Restore provider reconciliation under typed startup in one reviewable branch:

1. move the existing provider polling/coordinator lifetime out of the TOML watcher owner;
2. start it for both file-managed and typed-startup runtimes using the active bound configuration;
3. keep restart-time TOML immutable in typed mode;
4. route provider publications through existing canonical validation, candidate binding, audit, and
   activation;
5. test a manual provider and typed Discovery Source alongside a typed Proxy Host across restart,
   including invalid/stale provider output and last-known-good retention.

This P0 precedes GUI lifecycle work because provider-backed routes currently stop reconciling when
typed desired state exists.
