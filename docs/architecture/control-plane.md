# Control plane

## Current implementation

Administration uses HTTP/1 over a private Unix socket. Peer credentials and optional hash-only API
tokens authenticate requests. Fixed roles authorize actions. Mutations require exact quoted
`If-Match`, durable HMAC-chained audit intent, validated candidate state, and atomic activation.

Current API supports validation, redacted preview, candidates, activation, revisions, rollback,
routes/upstreams/providers/certificates/status, token management, certificate renewal requests,
backup creation, and restore validation. It is low-level and TOML/revision oriented. Preview does
not produce a field-level diff. Restore does not extract state. No TCP/public admin listener or web
GUI exists.

Machine contract: [`config/schema/admin-openapi.yaml`](../../config/schema/admin-openapi.yaml).

## Target model

Phase 15 adds stable high-level objects shared by GUI and automation. Phase 16 adds GUI as a
removable API client. Both compile through the existing strict validation, revision, secret, audit,
and activation path. No separate GUI-owned authorization or state is allowed.

Protected fields use opaque, write-only references. APIs expose lifecycle metadata, not plaintext.
See [ADR-0029](../adr/0029-user-first-control-plane-and-gui.md) and
[secret handling](../security/secret-handling.md).
