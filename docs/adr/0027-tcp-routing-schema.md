# ADR-0027: TCP routing schema

Status: Accepted for Phase 4 | Date: 2026-07-16

## Context
The approved plan requires raw TCP proxying and TLS passthrough, but schema v1 only named a gated `tcp` listener. It did not distinguish plaintext TCP routing from bounded TLS ClientHello inspection, and HTTP-only endpoint URLs could not represent a raw transport destination.

## Constraints
Schema v1 must remain strict and deterministic. Client input must never select an arbitrary destination. Plain TCP has no application metadata suitable for routing. TLS passthrough may use only the canonical SNI exposed by the bounded Rustls acceptor from ADR-0016. HTTP and raw TCP pools must not be mixed.

## Options considered
1. Add separate `tcp_routes` and `tcp_upstreams` top-level objects.
2. Reuse routes and upstream groups with explicit listener and endpoint transport discriminators.
3. Treat every `tcp` listener as TLS passthrough and infer transport from route matchers.

## Decision
Reuse the existing route and upstream-group objects with explicit protocol values. `protocol = "tcp"` accepts exactly one default route. `protocol = "tls_passthrough"` accepts exact or single-label wildcard `hosts` as SNI matchers plus at most one explicit default route. Both require groups whose endpoints use `tcp://host:port` with an explicit port. HTTP/HTTPS routes require only `http://` or `https://` endpoints. A route cannot mix HTTP-family and TCP-family listeners. TCP-family routes reject HTTP path, method, header, middleware, and priority fields.

## Rationale
This is the smallest typed extension that preserves existing identifiers, balancing, health, DNS, circuit, and egress-policy behavior. Explicit listener and endpoint schemes prevent inference and cross-protocol reuse. Separate top-level models would duplicate most service policy without improving the first-release boundary.

## Consequences
The `hosts` field means HTTP authority names on HTTP-family listeners and TLS SNI names on `tls_passthrough` listeners. Plain TCP supports one destination policy per listener. Operators needing protocol sniffing, ALPN routing, or mixed HTTP/TCP on one bind need a later schema version.

## Security implications
Unknown or missing SNI fails closed unless an explicit default exists. SNI is only a selector among configured routes and never becomes a host or port. Cross-family route and upstream references are rejected. Raw TCP has no implicit catch-all and cannot use HTTP middleware.

## Reliability implications
TCP routes reuse bounded upstream selection and health state. Listener conflicts remain rejected. A connection is pinned to one selected endpoint and is never rematched after connect or relay failure.

## Operational implications
`tcp` and `tls_passthrough` are separate listener types and cannot share a bind. Configuration preview exposes the transport choice without inspecting secrets.

## Migration implications
This is a pre-release schema-v1 completion. Existing valid HTTP configuration is unchanged. Any pre-release `tcp` configuration was previously rejected and therefore has no active behavior to preserve.

## Alternatives rejected
Separate L4 service objects add duplication and migration surface before a demonstrated need. Implicit TLS detection is ambiguous and can downgrade or misroute malformed traffic. ALPN and arbitrary ClientHello predicates are deferred because they expand conflict analysis and interoperability risk.

## Revisit conditions
Mixed protocol listeners become a requirement; L4 policies diverge substantially from HTTP upstream groups; ALPN routing is required; PROXY protocol is approved; or schema v2 is otherwise introduced.
