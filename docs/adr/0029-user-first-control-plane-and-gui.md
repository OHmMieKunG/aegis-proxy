# ADR-0029: User-first GUI over one typed control plane

Status: Accepted
Date: 2026-07-22

## Context

Current AegisProxy is capable but requires low-level TOML and CLI/API knowledge. Product direction
prioritizes NPMPlus-like usability, Caddy-style automation, and Traefik-style dynamic infrastructure
without weakening Rust data-plane or secret boundaries. ADR-0019 deferred UI for the earlier
initial-release scope; that product decision is now superseded.

## Constraints

- Common workflows must be safe in GUI.
- Complete supported behavior must remain available through typed control plane.
- GUI cannot bypass RBAC, audit, validation, optimistic concurrency, or atomic activation.
- Protected plaintext cannot be retrieved after creation, except one-time API-token display.
- Administration stays private by default.
- Current one-process data-plane architecture remains until separately changed.

## Options considered

1. Keep CLI/TOML as primary product interface.
2. Build UI with direct file/state access and separate policy logic.
3. Build stable high-level typed API, then make GUI a removable client of that API.

## Decision

Select option 3. Phase 15 creates versioned high-level domain objects and opaque secret references.
Phase 16 creates NPMPlus-style GUI using only that API. Advanced low-level configuration remains
available but passes the same validation, secret, revision, authorization, audit, and activation
pipeline. Internal router/service/middleware/provider terminology is introduced progressively.

Protected values use references such as `secret_ref`, `certificate_ref`, `credential_ref`, and
`provider_credential_ref`. Secret fields are write-only. Reads expose safe metadata and lifecycle
controls, never original private material.

## Rationale

One authoritative control plane prevents GUI/API drift and security bypass. High-level objects make
common workflows understandable while preserving complete typed automation. Existing data-plane,
revision, and audit mechanisms can be reused.

## Consequences

- GUI becomes mandatory roadmap scope, not initial current capability.
- Control-plane stabilization precedes frontend dependencies.
- Common Proxy Host creation needs seven user-facing fields; safe defaults derive lower-level
  policy.
- CLI/API remain fully functional without GUI.
- Frontend stack requires a later implementation ADR.

## Security implications

Browser sessions add CSRF, XSS, clickjacking, origin, cookie, and dependency threats. Phase 16 must
implement strict session/origin/CSP/CSRF controls and independent review. Server-side RBAC remains
authoritative. GUI receives no privileged implicit trust or secret plaintext.

## Reliability implications

UI failure does not stop data plane or direct API/CLI. All changes still use candidate validation,
atomic activation, probation, rollback, and last-known-good recovery.

## Operational implications

Operators gain task-oriented GUI plus complete automation API. Private administration remains
default; remote deployment needs an approved authenticated transport and origin model.

## Migration implications

Existing TOML remains supported through explicit compatibility policy. High-level objects compile
to canonical validated runtime state. No in-place state rewrite or database is introduced by this
decision.

## Alternatives rejected

CLI-only operation no longer meets product usability goals. UI direct file/state access duplicates
policy, bypasses audit/concurrency, and risks secret exposure.

## Revisit conditions

Revisit if one API cannot represent supported behavior, file-backed state fails measured control-
plane requirements, or independent review finds browser integration cannot meet the boundary.
