# ADR-0017: Provider-normalized discovery

Status: Amended; DNS foundation in Phase 4, providers in Phase 11 | Date: 2026-07-16

## Context
Static config is safe. Configured upstream hostnames still require bounded DNS resolution in Phase 4, while file/container/orchestrator metadata providers add a separate desired-state mutation surface in Phase 11.
## Constraints
DNS answers and provider records are untrusted. Neither may create public listeners, secrets, arbitrary routes, or destinations outside the configured egress policy.
## Options considered
Literal IPs only; configured A/AAAA/SRV resolution with static route ownership; file/Docker/Kubernetes providers from v1; a generic registry abstraction.
## Decision
Phase 4 may resolve only explicitly configured upstream DNS names and explicit SRV records. It applies answer-count, TTL, timeout, refresh, stale-state, and egress-policy bounds at refresh and immediately before connection. DNS cannot create listeners, routes, middleware, certificates, or secrets.

Phase 11 owns file-fed desired-state updates and isolated container/orchestrator provider helpers. All such updates normalize into the same candidate validation and activation path. There is no direct metadata-to-runtime mutation.
## Rationale
Transport name resolution is required to connect to a configured service and belongs with upstream pools. Provider discovery changes desired topology/configuration and requires Phase 5 revision safety first. Keeping these concepts distinct resolves the earlier phase ambiguity without weakening one strict validator/activation path.
## Consequences
Initial operators distribute route/config files. Phase 4 DNS can change only the address set behind an already-approved endpoint identity. Provider discovery remains deferred and later gains freshness/debounce/LKG semantics.
## Security implications
Every DNS answer is capped and rechecked against denied/allowed CIDRs on refresh and connect; stale answers have a hard lifetime. Metadata is untrusted, default exposure is false, and the proxy never receives the Docker socket.
## Reliability implications
DNS refresh failure may retain the last allowed address set only for a configured bounded stale interval, then makes the endpoint unavailable. Later provider loss follows separately documented LKG and drain rules.
## Operational implications
Phase 4 status shows endpoint DNS source, last success, expiry/stale deadline, answer count, and health without raw error/cardinality labels. Phase 11 status additionally shows provider source, hash, and freshness.
## Migration implications
DNS endpoint fields are schema-v1 contracts. Future provider namespaces and conflict rules become separately versioned configuration contracts.
## Alternatives rejected
Literal-IP-only operation is too restrictive for production services. Treating configured DNS resolution as a provider confuses transport with desired-state authority. Direct label-to-runtime mutation and unrestricted registry plugins are rejected.
## Revisit conditions
DNS behavior cannot meet required TTL/failover semantics, or a concrete provider need arrives with an isolated privilege and activation model.
