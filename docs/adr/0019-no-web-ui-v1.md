# ADR-0019: Keep web UI outside initial release

Status: Superseded by ADR-0029 on 2026-07-22
Date: 2026-07-19

This decision accurately records the earlier initial-release boundary. Product direction now
requires a user-friendly GUI over the typed control plane. Original rationale remains below for
traceability; browser security and independent-review requirements still apply.

## Context

Phase 10 is an explicit decision gate, not mandatory UI implementation. Phases
8 and 9 provide a complete private API/CLI, RBAC, durable audit, backup,
OpenAPI, health, metrics, dashboards, and operator runbooks. Current repository
evidence contains no measured workflow that requires browser administration.
Independent administrative application-security review and representative
staging observability drills also remain open release gates.

A web UI would add browser sessions, OIDC redirects, cookies, CSRF, XSS,
clickjacking, CSP, frontend dependencies, generated-client drift, and a new
deployment origin. Adding that surface without a product owner, staffed
frontend/security ownership, and review evidence would contradict initial
release scope.

## Constraints

- One Rust process and one deployable core binary remain initial-release scope.
- CLI/API must provide full operation without browser code.
- Administrative interfaces remain private by default.
- UI implementation requires explicit product and security approval.
- No UI may weaken API RBAC, audit, optimistic concurrency, or secret handling.
- Phase 10 acceptance requires independent application-security review before
  shipping any UI.

## Options considered

1. Bundle a UI into `rust-proxy`.
2. Add a separate frontend and OIDC/session gateway now.
3. Close Phase 10 without UI and retain CLI/API operation.

## Decision

Select option 3. No web UI, JavaScript workspace, browser session gateway,
OIDC integration, UI packaging, or frontend dependency enters initial release.
Phase 10 closes at this decision. Existing CLI, private API, OpenAPI contract,
Grafana dashboard, and runbooks remain operator surfaces.

## Rationale

Option 3 is smallest design meeting demonstrated needs and preserves approved
security boundary. No evidence justifies new browser and frontend supply-chain
risk. Required UI acceptance criteria cannot be truthfully satisfied without
an implemented UI and independent review; therefore UI must not ship.

## Consequences

- Initial release remains browser-free.
- CLI and API documentation carry configuration and administration workflows.
- Grafana remains read-only operational visualization, not control plane.
- No frontend build, lockfile, SBOM, CSP, CSRF, browser test, or session
  lifecycle enters current repository.
- Phase 11 may proceed independently when separately requested.

## Security implications

Browser-session, CSRF, XSS, clickjacking, redirect-origin, and frontend
dependency attack surfaces stay absent. API authentication, authorization,
audit, limits, and Unix-socket isolation remain authoritative. Operators must
not expose the private admin socket through an ad hoc browser bridge.

## Reliability implications

No frontend or session gateway can fail, consume resources, or block data-plane
operation. CLI/API availability remains isolated from public proxy listeners.

## Operational implications

Operators use `rust-proxy` CLI, private `/v1` API, OpenAPI, runbooks, and
read-only Grafana integration. Remote access still requires a reviewed private
transport; no public admin origin is created.

## Migration implications

None for current users. A future UI must be a removable API client. It may not
own authorization or introduce state required by CLI/API operation. Breaking
API requirements need their own versioned configuration/API decision.

## Alternatives rejected

- Bundled UI: violates one-binary minimal attack-surface direction and couples
  frontend lifecycle to data plane.
- Separate UI now: lacks demonstrated product need, staffed ownership, OIDC
  design, browser security tests, dependency scans, and independent review.
- Public Grafana/admin bridge: turns observability or private administration
  into an unintended control-plane exposure.
- UI-owned authorization: duplicates and risks bypassing server-side RBAC.

## Revisit conditions

Reopen only when all exist:

- explicit product and security approval;
- measured operator workflows not adequately served by CLI/API;
- named frontend and security owners;
- private-origin and OIDC/session threat model;
- locked dependency/SBOM/scanning plan;
- complete role, CSRF, XSS, CSP, accessibility, and stale-revision test plan;
- independent application-security review capacity;
- proof UI remains optional and removable.
