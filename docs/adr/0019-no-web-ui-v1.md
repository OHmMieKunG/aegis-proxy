# ADR-0019: Separate web UI later

Status: Accepted | Date: 2026-07-16

## Context
UI improves usability but adds browser sessions, XSS/CSRF, and frontend supply chain.
## Constraints
Core release must remain CLI/API operable and private.
## Options considered
Bundled UI; separate UI; no UI initially.
## Decision
No UI in v1; evaluate a separate frontend in Phase 10.
## Rationale
Stable API/RBAC/audit evidence should precede browser exposure.
## Consequences
CLI/docs carry onboarding burden.
## Security implications
No browser attack surface in core; future UI gets independent review.
## Reliability implications
UI failure cannot affect data plane.
## Operational implications
Admin socket remains the default.
## Migration implications
Generated API types prevent contract drift.
## Alternatives rejected
Dashboard public exposure and UI-owned authorization.
## Revisit conditions
Product approval and staffed security/frontend ownership.
