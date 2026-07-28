# Control plane

## Current implementation

Administration uses HTTP/1 over a private Unix socket. Peer credentials and optional hash-only API
tokens authenticate requests. Fixed roles authorize actions; tokens additionally require each
explicit action scope, so effective permission is role intersection scope. Mutations require exact
quoted `If-Match`, durable HMAC-chained audit intent, validated candidate state, and atomic
activation.

Current API supports low-level validation, redacted preview, candidates, activation, revisions,
rollback, routes/upstreams/providers/certificates/status, token management, certificate renewal
requests, backup creation, and restore validation. It also exposes owner-scoped typed Proxy Host
list/get, non-persistent validation/preview, audited create/update/delete of desired state plus a
non-active immutable candidate, verified Admin-only candidate activation, and Admin-only typed
forward rollback. Restore does not extract state. No TCP/public admin listener or web GUI exists.

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
revision metadata. Before desired-state mutation, administration writes a strict schema-v1,
owner/object-ordered snapshot under the private bounded `admin/proxy-host-candidates` directory.
The hash covers schema version and the complete seven-field object set, including disabled objects
that generate no runtime resources. Low-level configuration candidates remain unbound. Identical
configuration with different typed state is not deduplicated into one revision.
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

`PUT` and `DELETE /v1/proxy-hosts/{id}` follow the same ordering. They require
`X-Aegis-Object-Generation` in addition to active-revision `If-Match`. Update enforces path/body
identity and owner equality; delete resolves only within authenticated owner. Stale generation or
store epoch returns fixed conflict without desired/runtime mutation.

`POST /v1/proxy-hosts/candidates/{id}/activate` is the only typed activation boundary. It requires
Admin role plus exact `activate_proxy_host` scope for tokens and exact active-revision `If-Match`.
While the durable mutation audit is open, a single bounded permit serializes administrative
mutations. The handler snapshots every stored Proxy Host, recompiles the complete desired set
against the active configuration, compares canonical content hashes with the immutable revision,
requires the bound snapshot and policy records to equal complete current state, then invokes the
existing activation coordinator. Missing, stale, orphaned, already-active, tampered, or unauthorized
candidates fail without publication. The compiler itself still has no activation or persistence
capability. Operator activation stays disabled until candidates carry safe ownership and approval
metadata.

`POST /v1/proxy-hosts/revisions/{id}/rollback` is the separate typed rollback boundary. It requires
Admin role, exact `rollback_proxy_host` token scope, and exact active-revision CAS. The target must
have valid bound typed desired state and policy records equal to current dependencies. The handler
compiles that historical object set against the
current manual configuration, creates a new immutable bound forward revision, journals previous
and target object records, then invokes the same activation coordinator. It never activates the
historical revision directly or rewrites history. Activation failure restores previous objects;
an indeterminate activation retains the journal and blocks mutation. Startup selects target versus
previous desired state from the durable active revision before serving Admin requests.

Machine contract: [`config/schema/admin-openapi.yaml`](../../config/schema/admin-openapi.yaml).
The checked contract requires nonempty canonical scopes when creating tokens and returns only token
ID, role, owner ID, scopes, expiry, and revocation metadata after the one-time plaintext response.

## Target model

Phase 15 adds stable high-level objects shared by GUI and automation. Phase 16 adds GUI as a
removable API client. Both compile through the existing strict validation, revision, secret, audit,
and activation path. No separate GUI-owned authorization or state is allowed.

Protected fields use opaque, write-only references. APIs expose lifecycle metadata, not plaintext.
See [ADR-0029](../adr/0029-user-first-control-plane-and-gui.md) and
[secret handling](../security/secret-handling.md).
