# ADR-0017: Provider-normalized discovery

Status: Accepted; DNS foundation in Phase 4, bounded providers in Phase 11 | Date: 2026-07-19

## Context
Static config is safe. Configured upstream hostnames still require bounded DNS resolution in Phase 4, while file/container/orchestrator metadata providers add a separate desired-state mutation surface in Phase 11.
## Constraints
DNS answers and provider records are untrusted. Neither may create public listeners, secrets, arbitrary routes, or destinations outside the configured egress policy.
## Options considered
1. Keep literal IPs only.
2. Infer SRV names and service/transport semantics from the HTTP URL host.
3. Add required SRV service, protocol, port-override, priority, and weight fields to schema v1 now.
4. Activate configured A/AAAA resolution in Phase 4 and add explicit SRV configuration only in a later schema version.
## Decision
Phase 4 resolves only explicitly configured upstream A/AAAA names. It applies answer-count, TTL, timeout, refresh, stale-state, and egress-policy bounds at refresh and immediately before connection. DNS cannot create listeners, routes, middleware, certificates, or secrets.

SRV is deferred until a schema version explicitly represents the service and protocol labels, SRV priority/weight interaction with application weights, port replacement, TLS SNI, and fallback behavior. Schema v1 contains none of those fields. Inferring them from a URL would be ambiguous and unsafe.

Phase 11 adds two provider kinds. A file provider reads a strict, bounded local TOML document containing only endpoint IDs, literal socket addresses, and weights. A DNS provider resolves one configured A/AAAA hostname at one configured port. Each provider may replace endpoints in exactly one declared upstream group; no two providers may own the same group. Providers default disabled. Static endpoints remain the stale/failed-source fallback.

Transport, TLS server name, custom CA reference, egress policy, health, balancing, routes, and listeners remain trusted base configuration. Provider output cannot alter them. Every combined result passes the normal configuration validator and Phase 5 revision/activation transaction before publication. Invalid results retain the active snapshot. Status exposes only stable provider ID/kind, state, source hash, freshness, and endpoint count.

The proxy process does not implement Docker discovery and never opens or mounts the Docker socket. An isolated read-only metadata helper remains a design-only option requiring separate approval, threat review, filtering contract, binary, and ADR. Kubernetes Gateway API and Consul remain deferred.
## Rationale
Transport name resolution is required to connect to a configured service and belongs with upstream pools. A/AAAA preserves the configured port and endpoint identity. SRV changes port and selection semantics, so it needs an explicit contract rather than inference. Provider discovery changes desired topology/configuration and requires Phase 5 revision safety first. Keeping these concepts distinct resolves the earlier phase ambiguity without weakening one strict validator/activation path.
## Consequences
Phase 4 DNS can change only the address set behind an already-approved endpoint identity. Phase 11 provider polling uses bounded refresh, file debounce, and stale deadlines. Source loss retains the last valid provider endpoints only until that deadline, then restores configured static endpoints. Provider startup initially serves validated static endpoints until the first provider result activates.
## Security implications
Every DNS answer and file endpoint is capped and rechecked by the configured denied/allowed CIDRs before activation and by existing upstream connection policy before connect; stale answers have a hard lifetime. File sources must be regular non-symlink files and are read with a hard byte cap. Metadata is untrusted, default exposure is false, provider documents cannot contain hostnames or policy, and the proxy never receives the Docker socket.
## Reliability implications
Provider refresh failure retains the last valid address set for a configured bounded stale interval, then restores static endpoints. Every accepted topology change uses immutable revisions, atomic snapshot publication, last-known-good rollback, and normal endpoint drain rules.
## Operational implications
Phase 4 status shows endpoint DNS source, last success, expiry/stale deadline, answer count, and health without raw error/cardinality labels. Phase 11 status additionally shows provider source hash and freshness through the private administrative interface. File replacement should use atomic rename; partial writes remain inactive until stable and valid.
## Migration implications
DNS endpoint fields and the bounded file/DNS provider contracts are schema-v1 additions. SRV fields require a future schema version and migration. Removing static fallback endpoints or changing provider namespace ownership is a configuration change activated through the normal revision transaction.
## Alternatives rejected
Literal-IP-only operation is too restrictive for production services. URL-based SRV inference cannot safely define service/protocol labels, port and TLS behavior, or the interaction between DNS and configured weights. Adding incomplete SRV fields to v1 would freeze an unverified contract. Treating configured DNS resolution as a provider confuses transport with desired-state authority. Direct label-to-runtime mutation and unrestricted registry plugins are rejected.
## Revisit conditions
DNS behavior cannot meet required TTL/failover semantics, provider polling cannot meet measured event-volume needs, or a concrete container/orchestrator provider need arrives with an isolated privilege and activation model.
