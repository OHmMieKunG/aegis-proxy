# Configuration reference: schema v1

`schema_version = 1` is the only accepted version. The TOML parser rejects duplicate keys and unknown fields recursively; semantic validation by `rust-proxy validate` remains authoritative over the companion JSON Schema.

## Compatibility policy

- Patch releases may add validation for inputs that were unsafe, ambiguous, or previously documented as unsupported.
- New optional fields with safe defaults require a minor release. Existing v1 documents continue to parse.
- New required fields, field removals/renames, changed meanings, or weaker security defaults require a new schema version and an explicit migration command.
- Future schema versions fail closed on older binaries. There is no automatic downgrade or silent fallback.
- `rust-proxy fmt` emits a normalized validated document and preserves secret references. `rust-proxy preview` is the safe export: it redacts secret-reference metadata and includes the compiled route fingerprint.

## Typed Proxy Host compilation

Phase 15 provides a compiler from the strict seven-field Proxy Host object into this same schema-v1
model. It adds no TOML fields. Canonical lowercase ASCII domains are required; Unicode, trailing
dots, IP literals, and wildcards are rejected. Forward destinations accept canonical DNS names or
IP literals with explicit nonzero ports and only `http` or verified `https`.

Enabled objects add one deterministic route, upstream group, and endpoint. Group policy is copied
from an explicitly selected validated template, preserving egress, DNS, health, retry, circuit, and
resource limits. Access-policy references resolve to existing middleware IDs and fail when missing,
disabled, unauthorized, or semantically incompatible. Disabled objects remain in typed
control-plane state but add no route or upstream. Managed HTTPS selects an existing HTTPS listener
and certificate covering the domain; compilation neither orders nor claims issuance of a
certificate. Every result passes the normal semantic validator before it becomes a candidate.

Complete desired state may be compiled with explicit current and desired object sets. Current stored
identities reserve deterministic generated namespaces; only complete compiler-shaped
route/group/endpoint trios are removed from active input. Missing trios represent pending state.
Partial/tampered trios and manual collisions fail closed. Desired objects are sorted by owner/object
ID, every enabled object is rebuilt, disabled objects generate nothing, and semantic validation runs
once on the complete candidate. This library operation neither persists nor activates.

Library consumers may create a typed preview from a compiled candidate and active configuration.
Preview revalidates both inputs, returns generated resource IDs, canonical hash, route fingerprints,
and hot-reload/restart classification, plus a configuration clone where every secret reference is
replaced with `<redacted-secret-reference>`. Preview does not persist or activate anything. Private
administrative validation and preview endpoints expose this high-level result without persistence
or activation.

Library consumers may compare an optional current preview summary with a candidate summary. The
result is an ordered, bounded typed diff over the seven Proxy Host fields plus generated resources.
Creation uses explicit additions; updates use replacements; disabling removes generated resources.
Version, object, or owner mismatches fail closed. The diff contains opaque access-policy references,
never policy contents or raw configuration, and performs no persistence or activation.

Private typed endpoints include owner-scoped `GET /v1/proxy-hosts` and
`GET /v1/proxy-hosts/{id}`, plus `POST /v1/proxy-hosts/validate` and
`POST /v1/proxy-hosts/preview`. CLI equivalents are:

```text
rust-proxy proxy-host list --socket SOCKET
rust-proxy proxy-host get --socket SOCKET OBJECT_ID
rust-proxy proxy-host validate --socket SOCKET proxy-host.json
rust-proxy proxy-host preview --socket SOCKET proxy-host.json
```

Local peer ownership is `uid-<uid>`; new bearer tokens inherit their creator's owner. Current
endpoint preparation supports `automatic_https = "disabled"` with no access-policy reference and
requires exactly one HTTP listener and one all-HTTP upstream template in active configuration.
Managed HTTPS and access policies fail closed until their typed ownership metadata exists. These
restrictions apply to endpoints, not lower-level compiler contract.

Typed Proxy Host desired state has a separate internal schema-v1 JSON store. It is bounded to 4,096
objects and 2 MiB, uses private directory/file permissions, stable owner/object ordering, globally
unique domains, and object-local generations beginning at one. Create rejects existing identity or
domain; update/delete require exact generation. File replacement is durable and atomic within its
directory. Administration opens it at `<state_dir>/admin/proxy-hosts.json`; list/get are owner
scoped, stable, and require `read_proxy_hosts`. Validation/preview reject its claimed IDs/domains.
This store is not active configuration and current endpoints do not write it.

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

## Active behavior

The schema defines bounded upstream DNS, health, retry, circuit, drain, weighting, and algorithm policies. Multiple endpoints, DNS A/AAAA names, round-robin, smooth weighted round-robin, random, power-of-two selection, passive health, supervised active HTTP/TCP health checks, group-local circuit breakers, and bounded retries are active. DNS resolution caps concurrent work, answers, TTL, lookup time, and stale lifetime; rejects an entire mixed answer set when any address violates egress policy; and revalidates stored addresses immediately before connection. Retries require an idempotent method, exclude WebSocket and gRPC, buffer only a body with a known exact size within `replay_body_bytes`, retry only connection/header-timeout failures, and obey attempt and total-time budgets. Active probes run immediately, use threshold hysteresis, have deterministic interval jitter, share the bounded `limits.max_health_checks` semaphore, and stop during shutdown. Circuit breakers use a bounded rolling sample and a strict half-open concurrency budget. `max_in_flight` defaults to 1024 per upstream group, the schema caps the aggregate at 100000, and excess work receives 503 without a waiting queue; a slot remains held through the response body, WebSocket, or raw TCP connection. Beginning endpoint drain immediately excludes new selections; active guards then receive the bounded `drain_timeout_secs` window. Snapshot replacement invokes the same contract for removed or transport-changed endpoints. Upstream URLs require explicit ports.

ACME automation is active for explicit issuers and HTTP-01, DNS-01, or TLS-ALPN-01 certificate policies. The only DNS adapter is a compile-time Cloudflare adapter with an explicit zone ID and secret-reference token. Orders, DNS answers, challenge state, account state, renewal work, and certificate publication are bounded. There is no automatic challenge or CA fallback. Optional `acme.renewal_owner` names the one node allowed to order in an HA fleet; managed ACME startup with a nonzero fleet generation requires it. See [ACME operations](../operations/acme.md) and [high availability](../operations/high-availability.md).

Route middleware is active through a compiled fixed-stage pipeline. It includes IP policy, edge and principal rate limits, non-queuing route/client in-flight limits, CORS, Basic and ForwardAuth, redirects, maintenance, rewrites, typed header/security policies, static custom errors, and bounded streaming compression. `max_requests` bounds an in-flight route policy, `max_per_client` must not exceed it, and `status` is restricted to 429 or 503. The aggregate configured route capacity cannot exceed 100000. Permits span upstream waits, response streaming, and WebSocket lifetime; cancellation releases them. See [the middleware contract](middleware.md) and the validated `config/examples/phase7.toml` fixture.

Observability policy is restart-only. Structured access events can be disabled or sampled with `access_log_sample_per_million`; OpenMetrics is enabled by default only on the private administrative Unix socket. Optional OTLP traces use one explicit HTTP/protobuf endpoint, a 1..=1,000,000 sampling rate, a queue capped at 16,384 spans, a batch no larger than that queue, and a 1..=30 second export timeout. Plaintext OTLP is accepted only to an explicit loopback IP. Export authentication headers are not accepted in v1; place a mutually authenticated local collector or TLS-authenticated relay at the configured endpoint.

File and DNS providers can replace endpoints only in one declared upstream group. Providers default disabled; static endpoints remain startup/stale fallback. File documents contain only IDs, literal socket addresses, and weights. DNS providers use one configured A/AAAA hostname and fixed port/template. Every result passes full configuration/egress validation and normal atomic revision activation. See [service discovery operations](../operations/service-discovery.md).

Configuration never silently accepts an inactive policy. TCP routing uses the explicit model in [ADR 0027](../adr/0027-tcp-routing-schema.md); bounded TLS ClientHello capture follows [ADR 0016](../adr/0016-clienthello-parser.md), with no handwritten parser.

Configured egress denies override allows. Literal addresses are checked during validation. Configured DNS answers pass the same policy at refresh and immediately before connection. A refresh failure retains the last allowed set only through its configured stale deadline; startup fails if the initial lookup has no fully allowed answer set.

## Commands

```text
rust-proxy validate --config config/examples/minimal.toml
rust-proxy preview --config config/examples/tls.toml
rust-proxy fmt --config config/examples/minimal.toml
rust-proxy validate --config config/examples/tcp.toml
rust-proxy validate --config config/examples/phase7.toml
rust-proxy validate --config config/examples/phase11-file.toml
rust-proxy validate --config config/examples/phase11-dns.toml
rust-proxy fleet hash --config config/examples/minimal.toml
```

The preview output is deliberately not re-applicable because secret references are replaced. Formatting does not resolve or print secret values, but it preserves configured environment names and file paths and should be handled as operational configuration.

## Machine-readable schema

[`config/schema-v1.json`](../../config/schema-v1.json) describes syntax, types, common bounds, and unknown-field rejection for editor/tooling use. TOML-only representation details and cross-object constraints—duplicate binds, references, route overlaps, egress policy, certificate relationships, and phased feature gates—require the real offline validator.
