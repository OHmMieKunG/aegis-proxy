# ADR-0030: Embedded React web administration

Status: Accepted
Date: 2026-07-28

## Context

Phase 16 adds an optional browser client over the stable typed control plane. The UI must preserve
one Rust production process, remain removable, and add no alternate authorization, ownership,
validation, audit, concurrency, or activation path.

Browser administration introduces a new origin, OIDC redirects, server-side sessions, CSRF, XSS,
clickjacking, caching, frontend dependency, and asset-packaging risks. The existing Unix listener
must retain peer and bearer authentication without accepting browser sessions.

## Decision

- Build `ui/` with TypeScript, React, Vite, React Router Data mode, `openapi-typescript`, and
  `openapi-fetch`.
- Use React Router loaders/actions and native component state. Do not add a server-side JavaScript
  runtime, Next.js, Redux, TanStack Query, Formik, a component framework, external fonts,
  analytics, CDN assets, or unsafe HTML rendering.
- Build Vite assets before release Cargo builds and embed them in `rust-proxy` behind a `web-ui`
  Cargo feature using the already locked `rust-embed` dependency. Production runs only
  `rust-proxy`; generated `ui/dist/` remains untracked.
- Serve UI assets, OIDC routes, browser sessions, and `/v1` from one Axum listener. This listener is
  default-disabled, loopback-only, and uses one configured exact `http://localhost:PORT` origin.
  It does not trust forwarded host/proto headers and does not enable CORS.
- Keep the Unix administration listener separate. Unix peers and API bearer tokens are invalid on
  the browser listener; browser sessions are invalid on the Unix listener.
- Treat browser-listener and OIDC configuration as restart-only.
- Require OIDC Authorization Code with PKCE-S256, state, nonce, exact issuer/audience/redirect
  validation, bounded discovery/JWKS/token responses, Rustls HTTPS, and no HTTP redirects.
- Keep OIDC access and refresh tokens outside browser and durable state. Browser sessions remain
  bounded server memory and disappear on restart.
- Require exact Origin, same-origin fetch metadata, and a session-bound CSRF token before unsafe
  request-body parsing.
- Serve hashed assets with immutable caching; serve HTML, authentication, and session responses
  with `no-store`. SPA fallback applies only to valid UI paths, never `/v1` or `/auth`.
- Apply a strict CSP, `frame-ancestors 'none'`, `base-uri 'none'`, `object-src 'none'`,
  `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and restrictive Permissions
  Policy.

## Configuration contract

`[admin.web]` is disabled by default. Its bind address must be loopback with a nonzero port, and
its origin must be exactly `http://localhost:` plus the same port. Enabling it requires
`[admin.web.oidc]`, an HTTPS issuer, bounded client ID, secret references for client credentials and
optional CA bundle, a top-level groups claim, and disjoint bounded group lists for the four built-in
roles. At least one Admin group is required.

## Consequences

- CLI and Unix API remain complete when the UI feature is absent or disabled.
- A clean frontend build becomes a release-packaging prerequisite only when `web-ui` is enabled.
- OpenAPI-generated TypeScript becomes an immutable checked contract with a drift gate.
- Browser failure cannot stop the data plane or Unix administration.
- Phase 16 adds a JavaScript lockfile and dependency/SBOM review surface but no Node production
  runtime.

## Alternatives rejected

- A separate UI service adds another production runtime and cross-origin/session boundary.
- Next.js server features are unnecessary, while static export adds framework surface without
  improving the one-origin embedded design.
- Direct file or store access would duplicate policy and bypass the typed control plane.
- Public or LAN binding exceeds the loopback-plus-tunnel Phase 16 boundary.

## Revisit conditions

Revisit only for measured need for public/LAN binding, multiple identity providers, a separate
frontend deployment, custom roles, or a production JavaScript server. Each requires a new threat
model and ADR.
