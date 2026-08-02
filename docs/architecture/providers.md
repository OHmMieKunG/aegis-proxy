# Provider architecture

Current providers can replace endpoint lists in one predeclared upstream pool:

- File: strict bounded TOML containing endpoint IDs, literal socket addresses, and weights.
- DNS: bounded A/AAAA answers for one configured hostname, port, scheme, and TLS template.

Base configuration retains authority over listeners, routes, transport, TLS, CIDR policy, health,
balancing, retry, and circuits. Provider output cannot create those objects or supply secrets. One
provider owns at most one pool; static endpoints remain startup and stale fallback. Every accepted
result runs through full configuration validation and atomic revision activation.

The top-level managed runtime owns exactly one provider reconciliation task in both startup modes.
File-managed mode continues to reload the configured TOML path before reconciliation. Typed mode
never reads that path after startup: it reconciles the exact active bound configuration and copies
the same immutable typed-object binding onto provider-derived revisions before transactional
activation. Provider-derived revisions record their typed base revision as bounded provenance, so
restart can recover the active last-known-good snapshot while resuming from its non-provider base.
Fetch, validation, candidate persistence/binding, CAS, or activation failure leaves the active
runtime unchanged. Cancellation is joined during normal runtime shutdown.

Before a reconciliation attempt can create or activate a candidate, the provider supervisor writes
durable intent through the administration service's single HMAC audit writer. Validation rejection,
candidate creation, activation success/failure, rollback, and no-change skip use the bounded
`system_provider:provider-coordinator` actor. Provider paths, source payloads, endpoints, and secret
references are never audit fields. Missing or failed audit storage prevents later candidate
activation; if terminal audit fails after an activation already completed, the active runtime is
not rolled back, audit readiness becomes false, and later provider mutation fails closed.

Typed Discovery Sources configure only the existing bounded file and DNS providers. They do not
grant ownership of Proxy Hosts or other typed objects, and provider documents remain unable to
create routes, listeners, policies, certificates, or secrets.
Proxy Host drafts are outside desired-state snapshots and candidate bindings; no provider API can
list, mutate, promote, compile, or activate them. Reconciliation continues from applied bound state
while an owner edits an inactive draft.

SRV, Docker, Kubernetes, Consul, approval policies, and multi-source conflict resolution are absent.
Phase 22 adds approved providers on the stable typed domain model after core NPMPlus-compatible
workflows. The proxy process must never
receive the Docker socket; privileged discovery requires isolated least-privilege design, ADR, and
threat review.

See [service discovery operations](../operations/service-discovery.md) and
[provider threat review](../security/provider-threat-review.md).
