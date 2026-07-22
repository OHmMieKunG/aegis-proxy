# Control plane

## Current implementation

Administration uses HTTP/1 over a private Unix socket. Peer credentials and optional hash-only API
tokens authenticate requests. Fixed roles authorize actions. Mutations require exact quoted
`If-Match`, durable HMAC-chained audit intent, validated candidate state, and atomic activation.

Current API supports validation, redacted preview, candidates, activation, revisions, rollback,
routes/upstreams/providers/certificates/status, token management, certificate renewal requests,
backup creation, and restore validation. It is low-level and TOML/revision oriented. Restore does
not extract state. No TCP/public admin listener or web GUI exists.

Phase 15 now includes a library-only strict Proxy Host object and side-effect-free compiler. Caller
RBAC supplies immutable owner, object, domain, policy, listener, certificate, and upstream-template
metadata. Compiler emits a full canonical `Config` candidate, then invokes existing semantic
validation. It cannot persist, activate, access runtime state, resolve DNS, or read secrets. Existing
revision and activation services remain sole durable/runtime path. No high-level API route exposes
this compiler yet.

Compiled Proxy Hosts can now produce a deterministic typed preview containing desired fields,
generated resource IDs, canonical candidate hash, route fingerprints, and hot-reload/restart class.
Preview revalidates active and candidate configuration, returns only a redacted configuration clone,
and has no runtime, persistence, audit, filesystem, environment, or network handle. A separate pure
typed diff compares owner/object-matched preview summaries using a fixed eight-field vocabulary and
stable order. It never accepts raw JSON or configuration values and cannot persist or activate.
Public typed endpoints remain incomplete.

Machine contract: [`config/schema/admin-openapi.yaml`](../../config/schema/admin-openapi.yaml).

## Target model

Phase 15 adds stable high-level objects shared by GUI and automation. Phase 16 adds GUI as a
removable API client. Both compile through the existing strict validation, revision, secret, audit,
and activation path. No separate GUI-owned authorization or state is allowed.

Protected fields use opaque, write-only references. APIs expose lifecycle metadata, not plaintext.
See [ADR-0029](../adr/0029-user-first-control-plane-and-gui.md) and
[secret handling](../security/secret-handling.md).
