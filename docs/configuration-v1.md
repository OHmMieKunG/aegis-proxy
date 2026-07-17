# Configuration schema v1

`schema_version = 1` is the only accepted version. The TOML parser rejects duplicate keys and unknown fields recursively; semantic validation by `rust-proxy validate` remains authoritative over the companion JSON Schema.

## Compatibility policy

- Patch releases may add validation for inputs that were unsafe, ambiguous, or previously documented as unsupported.
- New optional fields with safe defaults require a minor release. Existing v1 documents continue to parse.
- New required fields, field removals/renames, changed meanings, or weaker security defaults require a new schema version and an explicit migration command.
- Future schema versions fail closed on older binaries. There is no automatic downgrade or silent fallback.
- `rust-proxy fmt` emits a normalized validated document and preserves secret references. `rust-proxy preview` is the safe export: it redacts secret-reference metadata and includes the compiled route fingerprint.

## Routing rules

- Host values are lowercase canonical ASCII DNS labels. Operators must supply valid IDNA A-labels (`xn--...`); Unicode U-labels are rejected. A wildcard covers one leftmost label only.
- Paths are canonical ASCII. Exact paths may end in `/`; prefixes may not, except `/`. Configuration rejects percent escapes, backslashes, repeated separators, query/fragment text, and dot segments.
- At request time, valid percent escapes are checked once. RFC unreserved bytes are decoded, preserved escapes are uppercased, and encoded slash/backslash/control/dot-segment forms fail before routing or upstream connection.
- Precedence is numeric priority, exact/wildcard/catch-all host, exact/prefix/catch-all path and length, then method/header specificity. Declaration order is never a tie-breaker.
- Catch-all behavior requires `default = true`, empty matchers, and zero priority. One default route is allowed per listener.
- Query and regex matching are not part of v1.
- `tcp` listeners require exactly one explicit default route. `tls_passthrough` listeners route by exact or single-label wildcard `hosts`, interpreted as SNI, with exact matches preferred. Missing or unknown SNI closes the flow unless an explicit default route exists.
- TCP-family routes use only `tcp://host:port` endpoints and reject HTTP matchers, middleware, priority, retry configuration, TLS client options, and mixed HTTP/TCP endpoint groups.
- Raw tunnels use bounded connect, idle, and total-lifetime timeouts. TLS passthrough additionally bounds ClientHello capture to 16 KiB and uses the global TLS handshake timeout.

## Current activation gates

The schema defines bounded Phase 4 upstream DNS, health, retry, circuit, drain, weighting, and algorithm policies. Multiple endpoints, DNS A/AAAA names, round-robin, smooth weighted round-robin, random, power-of-two selection, passive health, supervised active HTTP/TCP health checks, group-local circuit breakers, and bounded retries are active. DNS resolution caps concurrent work, answers, TTL, lookup time, and stale lifetime; rejects an entire mixed answer set when any address violates egress policy; and revalidates stored addresses immediately before connection. Retries require an idempotent method, exclude WebSocket and gRPC, buffer only a body with a known exact size within `replay_body_bytes`, retry only connection/header-timeout failures, and obey attempt and total-time budgets. Active probes run immediately, use threshold hysteresis, have deterministic interval jitter, share the bounded `limits.max_health_checks` semaphore, and stop during shutdown. Circuit breakers use a bounded rolling sample and a strict half-open concurrency budget. `max_in_flight` defaults to 1024 per upstream group, the schema caps the aggregate at 100000, and excess work receives 503 without a waiting queue; a slot remains held through the response body, WebSocket, or raw TCP connection. Beginning endpoint drain immediately excludes new selections; active guards then receive the bounded `drain_timeout_secs` window. Phase 5 snapshot replacement invokes the same contract for removed or transport-changed endpoints. Upstream URLs require explicit ports.

Phase 6 ACME automation is active for explicit issuers and HTTP-01, DNS-01, or TLS-ALPN-01 certificate policies. The only DNS adapter is a compile-time Cloudflare adapter with an explicit zone ID and secret-reference token. Orders, DNS answers, challenge state, account state, renewal work, and certificate publication are bounded. There is no automatic challenge or CA fallback. See [ACME operations](operations/acme.md).

Phase 7 route middleware includes a non-queuing `in_flight_limit` stage keyed by the trusted client identity. `max_requests` bounds the route policy, `max_per_client` must not exceed it, and `status` is restricted to 429 or 503. The aggregate configured route capacity cannot exceed 100000. Permits span upstream waits, response streaming, and WebSocket lifetime; cancellation releases them.

Configuration never silently accepts an inactive policy. Trusted-proxy settings and middleware objects remain gated by their assigned phases. TCP routing uses the explicit model in [ADR 0027](adr/0027-tcp-routing-schema.md); bounded TLS ClientHello capture follows [ADR 0016](adr/0016-clienthello-parser.md), with no handwritten parser.

Configured egress denies override allows. Literal addresses are checked during validation. Configured DNS answers pass the same policy at refresh and immediately before connection. A refresh failure retains the last allowed set only through its configured stale deadline; startup fails if the initial lookup has no fully allowed answer set.

## Commands

```text
rust-proxy validate --config config/examples/minimal.toml
rust-proxy preview --config config/examples/tls.toml
rust-proxy fmt --config config/examples/minimal.toml
rust-proxy validate --config config/examples/tcp.toml
```

The preview output is deliberately not re-applicable because secret references are replaced. Formatting does not resolve or print secret values, but it preserves configured environment names and file paths and should be handled as operational configuration.

## Machine-readable schema

[`config/schema-v1.json`](../config/schema-v1.json) describes syntax, types, common bounds, and unknown-field rejection for editor/tooling use. TOML-only representation details and cross-object constraints—duplicate binds, references, route overlaps, egress policy, certificate relationships, and phased feature gates—require the real offline validator.
