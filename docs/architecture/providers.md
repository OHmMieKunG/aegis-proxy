# Provider architecture

Current providers can replace endpoint lists in one predeclared upstream pool:

- File: strict bounded TOML containing endpoint IDs, literal socket addresses, and weights.
- DNS: bounded A/AAAA answers for one configured hostname, port, scheme, and TLS template.

Base configuration retains authority over listeners, routes, transport, TLS, CIDR policy, health,
balancing, retry, and circuits. Provider output cannot create those objects or supply secrets. One
provider owns at most one pool; static endpoints remain startup and stale fallback. Every accepted
result runs through full configuration validation and atomic revision activation.

SRV, Docker, Kubernetes, Consul, approval policies, and multi-source conflict resolution are absent.
Phase 18 adds approved providers after Phase 15 defines stable domain objects. The proxy process
must never receive the Docker socket; privileged discovery requires isolated least-privilege design,
ADR, and threat review.

See [service discovery operations](../operations/service-discovery.md) and
[provider threat review](../security/provider-threat-review.md).
