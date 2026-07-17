# ADR-0011: Administrative API

Status: Accepted for Phase 8 | Date: 2026-07-16 | Amended: 2026-07-17

## Context
Operators need validation, preview, activation, rollback, certificate status, and backup. The original Phase 6 roadmap also named ACME admin endpoints before this API's Phase 8 authentication, authorization, audit, and transport dependencies exist.
## Constraints
Private by default; mutations require audit and revision concurrency.
## Options considered
REST/JSON in Phase 8; gRPC; file-only administration; an ACME-specific endpoint in Phase 6; moving the complete authenticated admin plane into Phase 6.
## Decision
Versioned REST/JSON over a Unix socket, optional private mTLS later. Phase 6 provides local CLI renewal/status and an internal status model only. ACME REST endpoints are added in Phase 8 with the common authentication, RBAC, mutation audit, limits, and optimistic-concurrency controls.
## Rationale
CLI and future UI can share a simple inspectable contract. An early ACME-only endpoint would either be unauthenticated/unaudited or duplicate security plumbing that Phase 8 must replace.
## Consequences
API schemas and RBAC become compatibility surfaces. Remote ACME automation waits until Phase 8; local Phase 6 operation remains available through the CLI and the daemon's single certificate owner.
## Security implications
Separate listener, body/time/rate limits, authn/RBAC, redacted errors.
## Reliability implications
Admin failure does not stop the data plane; mutation audit failure blocks mutation.
## Operational implications
Local CLI works without exposing a public port.
## Migration implications
`/v1` stays additive; breaking changes require a new version/ADR.
## Alternatives rejected
Public dashboard, direct mutable internal object API, an ad hoc ACME endpoint without the common security boundary, and prematurely moving the entire admin plane into Phase 6.
## Revisit conditions
Fleet control requires streaming or a multi-language generated protocol.
