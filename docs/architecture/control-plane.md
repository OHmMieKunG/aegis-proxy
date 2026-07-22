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
list/get plus non-persistent validation and preview. Restore does not extract state. No TCP/public
admin listener or web GUI exists.

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
metadata exists. Endpoints expose no mutation, audit mutation, revision, or activation handle.
Validation and preview include immutable identity/domain claims from durable desired state, so a
new object cannot silently replace a persisted object or domain.

`ProxyHostStore` is a separate library boundary for desired state. It stores strict schema-v1 JSON
under a caller-selected private path, limits state to 4,096 objects and 2 MiB, indexes by owner then
object ID, rejects duplicate domains globally, and uses object-local monotonic generations for
compare-and-swap update/delete. Stable ordered serialization is fsynced before atomic rename; an
in-memory mutation is restored if persistence fails. Store has no compiler context, audit writer,
revision service, activation coordinator, runtime handle, or network access. Administration opens
it at `<state_dir>/admin/proxy-hosts.json`; `GET /v1/proxy-hosts` and
`GET /v1/proxy-hosts/{id}` return only authenticated owner's records under `read_proxy_hosts`.
Single-object responses carry generation ETags. No endpoint mutates the store.

`compile_proxy_hosts` is the non-persistent aggregate boundary needed before mutation. Caller passes
current stored objects separately from complete desired objects. Only current identities reserve
generated namespaces; a new desired identity cannot claim a manual route/group/endpoint. Existing
reserved resources are removed only when their route, group, and endpoint form a complete compiler
shape. Missing resources are allowed for pending state; partial or tampered shapes fail closed.
Desired objects are owner/object ordered and rebuilt over retained manual configuration before one
semantic-validation pass. Compiler owns no store, revision, activation, runtime, filesystem,
environment, DNS, network, or secret handle.

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
