# Workspace ownership

This map describes production ownership after Phase 14. Public behavior remains defined by source,
tests, schemas, and `STATUS.md`; module boundaries are not separate runtime services.

## Crates

| Crate | Ownership |
|---|---|
| `proxy-core` | HTTP/TCP data plane, routing, middleware, upstream state, reload, and shutdown |
| `proxy-config` | strict schema, semantic validation, providers, conflicts, redaction, and revisions |
| `proxy-tls` | Rustls policy, identity selection/storage, and ACME protocol/state |
| `proxy-secrets` | approved secret references and encrypted envelopes |
| `proxy-admin` | private Unix API, RBAC, tokens, audit, backup, and restore validation |
| `rust-proxy` | CLI, process wiring, telemetry initialization, and fleet gate |

## Core data plane

- `proxy-core/src/lifecycle.rs`: startup, managed reload, last-known-good recovery, listener
  lifecycle, and shutdown coordination.
- `proxy-core/src/http.rs`: TLS preparation, HTTP connection serving, request pipeline, upstream
  exchange, and upgrade handling.
- `proxy-core/src/request.rs`: framing/target rejection, hop-header removal, challenge response,
  URI construction, and bounded body helpers.
- `proxy-core/src/upstream_runtime.rs`: client/pool construction and active health work.
- Existing `route`, `middleware`, `upstream`, `tcp`, `provider`, `runtime`, and `telemetry` modules
  retain their focused ownership.
- `proxy-core/src/tests/` groups integration-style unit tests by reload, routing, middleware,
  upstream, TLS/auth, streaming/lifecycle, and TCP/security behavior.

## Configuration

- `proxy-config/src/schema.rs`: serialized configuration types and defaults.
- `proxy-config/src/lib.rs`: bounded parsing and top-level validation orchestration.
- `validation_platform.rs`: admin, provider, observability, and metric-cardinality checks.
- `validation_middleware.rs`: middleware contracts and mutation ordering constraints.
- `validation_acme.rs`: issuer, challenge, certificate, and DNS credential-reference checks.
- `validation_routing.rs`: routes, transports, upstream policy, egress, names, paths, and IDs.
- `proxy-config/src/tests/` groups contract tests by the same domains.

## Administration

- `proxy-admin/src/server.rs`: API state, extractors, response contracts, router, and service bounds.
- `proxy-admin/src/server/handlers.rs`: read and mutation endpoint handlers.
- `proxy-admin/src/server/support.rs`: mutation audit flow, preconditions, authorization helpers,
  candidate loading, and private socket lifecycle.
- `proxy-admin/src/server/tests.rs`: API contract, auth-boundary, rate, OpenAPI, and socket tests.

## Refactor rules

Keep behavior-preserving moves separate from features. Preserve request validation order, route
single-match behavior, typed schema/defaults, OpenAPI paths, revision fingerprints, RBAC/audit
gates, secret redaction, telemetry labels, and graceful lifecycle semantics. Prefer cohesive
production modules below about 800 lines; modules above 1,200 need recorded rationale.
