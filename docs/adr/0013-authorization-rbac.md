# ADR-0013: Server-side RBAC

Status: Accepted for Phase 8 | Date: 2026-07-16

## Context
Validation/preview and activation have different operational risk.
## Constraints
Deny by default; every mutation is auditable.
## Options considered
Viewer/operator/admin roles; endpoint-only auth; external policy engine.
## Decision
Use fixed server-side viewer, auditor, operator, and admin permissions in v1.
Users bind one identity/owner to one immutable built-in role and enabled state. New API tokens name
an enabled user, inherit that role and owner, and grant only an explicit action subset. Built-in
roles are read-only; custom roles are unsupported.
## Rationale
Small explicit matrix is easier to review than a generic policy engine.
## Consequences
Fine-grained tenant roles wait for a demonstrated requirement.
## Security implications
Checks occur on the server per operation/resource; claims are allowlisted.
## Reliability implications
Unauthorized or stale mutations fail without changing runtime state.
## Operational implications
Audit records include actor, action, object, revision, and outcome.
## Migration implications
New roles require additive compatibility and matrix tests.
## Alternatives rejected
Email-domain authorization and client-enforced roles.
## Revisit conditions
Multi-tenant administration is approved.
