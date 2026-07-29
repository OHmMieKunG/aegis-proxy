# Control plane

## Current implementation

Administration uses HTTP/1 over a private Unix socket. Peer credentials and optional hash-only API
tokens authenticate requests. Fixed roles authorize actions; tokens additionally require each
explicit action scope, so effective permission is role intersection scope. Mutations require exact
quoted `If-Match`, durable HMAC-chained audit intent, validated candidate state, and atomic
activation.
An accepted request owns one bounded in-flight permit until its handler finishes. The configured
request deadline can return `504` to the caller, but it does not cancel an accepted handler or
release mutation serialization while non-cancelable blocking storage work is still running. Every
mutation therefore reaches terminal audit before its permit is released, including after client
disconnect or response timeout.

Current API supports low-level validation, redacted preview, candidates, activation, revisions,
rollback, routes/upstreams/providers/certificates/status, token management, certificate renewal,
backup creation, and restore validation. Owner-scoped typed APIs cover Proxy Hosts, Stream Hosts,
Discovery Sources, Certificates, Access Policies, write-only Stored Credentials, Users, and
immutable Roles. Runtime-changing typed mutations create non-active schema-2 candidates; verified
Admin-only activation and forward rollback remain explicit. Restore does not extract state.
Default-disabled browser administration uses a separate loopback TCP listener with one exact
`http://localhost:PORT` origin. OIDC Authorization Code with PKCE, bounded discovery/token
responses, server-side sessions, exact Host/Origin/fetch metadata, CSRF, and secure cookies form a
separate authentication boundary; Unix peers and bearer tokens are rejected there. Issuer/subject
identities persist only as SHA-256 fingerprints bound to durable Users and owners. First-run
binding redeems the Admin Unix peer's ten-minute hash-only setup token through a crash-recovery
journal. Embedded React assets use only the versioned API; asset or browser failure does not stop
the Unix listener or data plane.

At process startup, durable typed objects are compiled over the validated mounted TOML base and
bound to an exact resumed or new revision before listeners start. The base is restart-only once
typed state exists. Current working-tree limitation: that startup path does not start the file/DNS
provider reconciliation task, so provider-backed groups remain on static fallback until the
release-blocking runtime defect is fixed.

Phase 15 now includes a library-only strict Proxy Host object and side-effect-free compiler. Caller
RBAC supplies immutable owner, object, domain, policy, listener, certificate, and upstream-template
metadata. Compiler emits a full canonical `Config` candidate, then invokes existing semantic
validation. It cannot persist, activate, access runtime state, resolve DNS, or read secrets. Existing
revision and activation services remain sole durable/runtime path.

Compiled Proxy Hosts can now produce a deterministic typed preview containing desired fields,
generated resource IDs, canonical candidate hash, route fingerprints, and hot-reload/restart class.
Preview revalidates active and candidate configuration, returns only a redacted configuration clone,
and has no runtime, persistence, audit, filesystem, environment, or network handle. A separate pure
typed diff compares owner/object-matched preview summaries using a fixed eight-field vocabulary and
stable order. It never accepts raw JSON or configuration values and cannot persist or activate.
`POST /v1/proxy-hosts/validate` requires `validate_config`; `POST /v1/proxy-hosts/preview` requires
`preview_config`. Custom principal extractors enforce token role/scope before JSON deserialization.
Request owner must equal Unix peer's stable `uid-<uid>` owner or owner stored with its bearer token.
Preparation runs off async worker and accepts exactly one configured HTTP listener and one all-HTTP
upstream template. Access-policy and managed-HTTPS requests fail closed until typed ownership
metadata exists. These validation and preview handlers expose no mutation, audit mutation,
revision, or activation handle. They include immutable identity/domain claims from durable desired
state, so a new object cannot silently replace a persisted object or domain.

`ProxyHostStore` is a separate library boundary for desired state. It stores strict schema-v1 JSON
under a caller-selected private path, limits state to 4,096 objects and 2 MiB, indexes by owner then
object ID, rejects duplicate domains globally, and uses object-local monotonic generations for
compare-and-swap update/delete. Stable ordered serialization is fsynced before atomic rename; an
in-memory mutation is restored if persistence fails. Store has no compiler context, audit writer,
revision service, activation coordinator, runtime handle, or network access. Administration opens
it at `<state_dir>/admin/proxy-hosts.json`; `GET /v1/proxy-hosts` and
`GET /v1/proxy-hosts/{id}` return only authenticated owner's records under `read_proxy_hosts`.
Single-object responses carry generation ETags. Typed create/update/delete consume a complete stable
snapshot, compile and validate post-mutation state, create an immutable revision, then use snapshot
epoch as a store CAS. Update/delete also require exact object generation. None activates runtime.

`compile_proxy_hosts` is the non-persistent aggregate boundary needed before mutation. Caller passes
current stored objects separately from complete desired objects. Only current identities reserve
generated namespaces; a new desired identity cannot claim a manual route/group/endpoint. Existing
reserved resources are removed only when their route, group, and endpoint form a complete compiler
shape. Missing resources are allowed for pending state; partial or tampered shapes fail closed.
Desired objects are owner/object ordered and rebuilt over retained manual configuration before one
semantic-validation pass. Compiler owns no store, revision, activation, runtime, filesystem,
environment, DNS, network, or secret handle.

`POST /v1/proxy-hosts` is an orchestration boundary, not a compiler shortcut. Authorization and
durable audit intent precede strict JSON parsing. Exact active-revision `If-Match`, principal owner,
complete-state compilation, semantic validation, and revision persistence all succeed before the
epoch-checked object write. Failure can leave an immutable non-active orphan candidate, but never a
durable object without its candidate. Activation remains available only through the established
revision coordinator and is not performed by this endpoint.

Each typed candidate revision stores an optional lowercase SHA-256 `binding_hash` in immutable
revision metadata. New mutations write schema 2 under the private bounded
`admin/proxy-host-candidates` directory. Its canonical hash covers complete Proxy Hosts, Stream
Hosts, Discovery Sources, disabled objects, and exact referenced Access Policy and Certificate
records. Schema-1 Proxy-Host-only snapshots remain readable without rewrite. Low-level
configuration candidates remain unbound. Identical configuration with different typed state is
not deduplicated into one revision.
The configuration revision store remains the retention authority. Admin startup and typed
candidate creation reconcile the bounded snapshot directory against its retained metadata.
Reconciliation validates every entry before deletion, preserves every retained matching binding,
and removes only snapshots whose revision metadata is already absent. Tampering, unexpected entry
types, and retained binding mismatches fail closed. The separate file transactions intentionally
provide restart-safe eventual cleanup rather than claiming cross-directory atomicity.

`ApiObject<AccessPolicySpec>` binds one globally unique policy ID to an owner,
explicit shared-owner IDs, enabled state, and opaque canonical middleware IDs. It contains no
middleware definitions or credentials. `compile_access_policy_metadata` validates canonical
configuration and accepts only IP policy, client/principal rate limit, in-flight limit, BasicAuth,
and ForwardAuth stages. It canonicalizes order and rejects missing resources, duplicate fixed
stages, multiple authentication stages, and principal rate limiting without authentication.
Proxy Host compilation still performs complete route/listener semantic validation. A bounded
private store persists canonical secret-free objects with exact generation CAS and owner-scoped
reads. It holds an exclusive process and filesystem lock, rejects insecure or malformed restart
state, and distinguishes pre-commit failure from indeterminate post-rename durability. The private
Admin service opens this store before binding its socket and has distinct read/create/update/delete
RBAC and token scopes. Owner-scoped list/get return only secret-free records under exact read
permission; cross-owner get is not-found and object generation is the ETag. A post-rename durability
failure blocks all later policy mutations until restart reloads the visible atomic file. Mutation
create requires exact active-revision `If-Match`, exact create scope, owner equality, durable audit
intent, and semantic middleware validation before storage. It returns generation one and never
creates or activates a configuration revision. Update/delete use distinct exact scopes, additionally
require `X-Aegis-Object-Generation`, preserve owner-scoped not-found behavior, and validate
replacement middleware before generation CAS. They also create no configuration revision or
runtime activation.

Proxy Host validation, preview, candidate creation, update, and delete load only referenced
policies' secret-free metadata, fail closed during policy-store recovery, and rely on compiler
owner/share/enabled checks. Candidate bindings include canonical exact policy records and
generations alongside complete Proxy Host desired state. Activation and rollback snapshot current
dependencies, require exact equality with the binding, then recompile through normal semantic
validation. Missing, changed, disabled, or newly unauthorized policy state rejects stale work
before publication. Policy owners may update or revoke policies; consumers cannot pin them.
The process-wide administrative mutation permit serializes policy mutation with candidate creation
and activation.

`ApiObject<CertificateSpec>` binds owner, explicit shares, enabled
state, and one opaque existing certificate ID. Metadata compilation validates canonical
configuration, retains only covered hosts plus exactly one HTTPS listener/certificate ID pair, and
copies no certificate-chain or private-key reference. Selection requires enabled exact or
single-label wildcard coverage, owner/share authorization, and one unambiguous match. The private
API exposes bounded owner-scoped CRUD; observed status and direct runtime renewal remain isolated
under `/v1/runtime/certificates`.

`PUT` and `DELETE /v1/proxy-hosts/{id}` follow the same ordering. They require
`X-Aegis-Object-Generation` in addition to active-revision `If-Match`. Update enforces path/body
identity and owner equality; delete resolves only within authenticated owner. Stale generation or
store epoch returns fixed conflict without desired/runtime mutation.

`POST /v1/config/typed-candidates/{id}/activate` is the canonical typed activation boundary. It
requires Admin role plus exact `activate_typed_candidate` scope for tokens and exact
active-revision `If-Match`.
While the durable mutation audit is open, a single bounded permit serializes administrative
mutations. The handler snapshots every stored Proxy Host, recompiles the complete desired set
against the active configuration, compares canonical content hashes with the immutable revision,
requires the bound snapshot and policy records to equal complete current state, then invokes the
existing activation coordinator. Missing, stale, orphaned, already-active, tampered, or unauthorized
candidates fail without publication. The compiler itself still has no activation or persistence
capability. Operator activation stays disabled until candidates carry safe ownership and approval
metadata.

`POST /v1/config/typed-revisions/{id}/rollback` is the canonical typed rollback boundary. It
requires Admin role, exact `rollback_typed_revision` token scope, and exact active-revision CAS. The target must
have valid bound typed desired state and policy records equal to current dependencies. The handler
compiles that historical object set against the
current manual configuration, creates a new immutable bound forward revision, journals previous
and target object records, then invokes the same activation coordinator. It never activates the
historical revision directly or rewrites history. Activation failure restores previous objects;
an indeterminate activation retains the journal and blocks mutation. Startup selects target versus
previous desired state from the durable active revision before serving Admin requests.
The former Proxy Host activation and rollback paths are deprecated schema-1-only aliases; their
existing token scopes gain no schema-2 authority.

Machine contract: [`config/schema/admin-openapi.yaml`](../../config/schema/admin-openapi.yaml).
The checked contract requires nonempty canonical scopes when creating tokens and returns only token
ID, role, owner ID, scopes, expiry, and revocation metadata after the one-time plaintext response.
Token creation, backup creation, and restore validation accept a bounded raw body, authorize and
write audit intent first, require one exact `application/json` content type, and only then
deserialize. User-store conflicts remain `409`, invalid objects remain `400`, and missing users
remain `404`.

## Target model

Phase 15 provides stable high-level objects shared by GUI and automation. Phase 16 adds GUI as a
removable API client. Both compile through the existing strict validation, revision, secret, audit,
and activation path. No separate GUI-owned authorization or state is allowed.

Protected fields use opaque, write-only references. APIs expose lifecycle metadata, not plaintext.
See [ADR-0029](../adr/0029-user-first-control-plane-and-gui.md) and
[secret handling](../security/secret-handling.md).
