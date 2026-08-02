# Phase 16 implementation candidate

Date: 2026-07-29  
Branch: `feat/phase-16-gui-mvp`  
Release decision: **production NO-GO**

> This is immutable-candidate evidence for the commits below. Subsequent working-tree packaging,
> restart, and provider findings are recorded in the
> [Phase 0–16 repository readiness audit](repository-readiness-phase-0-16.md).

The later working-tree [Save-and-apply failure campaign](phase-16-save-apply-failure-campaign.md)
adds systematic persistence, candidate, activation-pointer, rollback, audit, restart, and browser
evidence without changing this dated candidate record.

The later working-tree [Proxy Host draft/application-state evidence](phase-16-proxy-host-drafts.md)
adds durable inactive drafts, additive schema migration, exact promotion, restart exclusion, and
browser transitions without changing this dated candidate record.

The later [React Router advisory disposition](../security/react-router-advisory-disposition.md)
adds a repeatable client-only import/module-graph check and upgrade analysis. It does not alter this
candidate, remove the scanner finding, or constitute independent acceptance.

The final working-tree remediation and independent-style disposition are recorded separately in
[Phase 16 final acceptance](phase-16-final-acceptance.md). That later evidence does not rewrite this
dated implementation candidate or constitute external certification.

## Candidate

- `1b395ba` — browser OIDC sessions and listener boundary
- `7b0aa7a` — durable OIDC setup identity binding
- `eaf5025` — embedded typed client shell and generation pipeline
- `ea499b8` — setup and administration workflows
- `4ddef29` — secure responsive browser coverage
- `9205971` — closed static-asset and typed-action allowlists

The implementation provides the Phase 16 routes and acceptance workflow without adding a Node
production runtime, alternate authorization path, settings mutation, operational-log stream, or
automated restore.

## Local verification

- Rust formatting, workspace check, all-feature Clippy, all-feature tests, doctests, and feature
  tree pass. The workspace suite reports 359 passed and two intentionally ignored.
- The fuzz workspace manifest builds.
- Admin OpenAPI parses and the checked generated TypeScript client has no drift.
- Clean npm install, TypeScript check, and Vite production build pass.
- Five Playwright Chromium scenarios pass: role/navigation/XSS/storage/axe/keyboard, Proxy Host
  preview/create/activate, first-run redemption, phone layout, and exact delete-action gating.
- `npm audit` completes with no critical finding and two high entries caused by the locked React
  Router RSC/server-mode advisory. This client is a static SPA and does not enable RSC, but local
  non-applicability is not independent disposition.

The host lacks Chromium's normal system libraries and `npx playwright install-deps chromium`
cannot authenticate to `sudo`. Browser tests passed with exact Ubuntu `libnspr4`, `libnss3`, and
`libasound2t64` packages extracted into a temporary user-owned directory. `cargo audit` and
`cargo deny` are not installed. Docker, long fuzz/soak, and independent review were not run.

## Open gates

Phase 16 is not complete for production release until independent application-security and
usability reviewers report no unresolved critical/high findings. Review must cover OIDC
discovery/exchange, first-run races and recovery, binding collisions, audit failure, session
rotation/invalidation, CSRF/origin/Host enforcement, embedded cache/fallback/CSP behavior,
role-aware deep links, keyboard/screen-reader/contrast/responsive behavior, and dependency
advisory applicability.
