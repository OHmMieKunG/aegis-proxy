# Provider architecture

Current providers can replace endpoint lists in one predeclared upstream pool:

- File: strict bounded TOML containing endpoint IDs, literal socket addresses, and weights.
- DNS: bounded A/AAAA answers for one configured hostname, port, scheme, and TLS template.

Base configuration retains authority over listeners, routes, transport, TLS, CIDR policy, health,
balancing, retry, and circuits. Provider output cannot create those objects or supply secrets. One
provider owns at most one pool; static endpoints remain startup and stale fallback. Every accepted
result runs through full configuration validation and atomic revision activation.

Current working-tree limitation: the provider coordinator is polled only by the TOML watcher, while
typed startup disables that watcher to keep the mounted base restart-only. When durable typed state
selects typed startup, file/DNS providers do not refresh and remain on static fallback. This is a
release blocker, not supported steady-state behavior.

SRV, Docker, Kubernetes, Consul, approval policies, and multi-source conflict resolution are absent.
Phase 18 adds approved providers on the stable Phase 15 domain model. The proxy process must never
receive the Docker socket; privileged discovery requires isolated least-privilege design, ADR, and
threat review.

See [service discovery operations](../operations/service-discovery.md) and
[provider threat review](../security/provider-threat-review.md).
