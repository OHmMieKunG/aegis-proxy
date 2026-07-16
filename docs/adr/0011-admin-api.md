# ADR-0011: Administrative API

Status: Accepted for Phase 8 | Date: 2026-07-16

## Context
Operators need validation, preview, activation, rollback, status, and backup.
## Constraints
Private by default; mutations require audit and revision concurrency.
## Options considered
REST/JSON; gRPC; file-only administration.
## Decision
Versioned REST/JSON over a Unix socket, optional private mTLS later.
## Rationale
CLI and future UI can share a simple inspectable contract.
## Consequences
API schemas and RBAC become compatibility surfaces.
## Security implications
Separate listener, body/time/rate limits, authn/RBAC, redacted errors.
## Reliability implications
Admin failure does not stop the data plane; mutation audit failure blocks mutation.
## Operational implications
Local CLI works without exposing a public port.
## Migration implications
`/v1` stays additive; breaking changes require a new version/ADR.
## Alternatives rejected
Public dashboard and direct mutable internal object API.
## Revisit conditions
Fleet control requires streaming or a multi-language generated protocol.
