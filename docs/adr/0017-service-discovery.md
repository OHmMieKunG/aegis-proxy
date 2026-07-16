# ADR-0017: Provider-normalized discovery

Status: Accepted for Phase 11 | Date: 2026-07-16

## Context
Static config is safe; dynamic file/DNS/container metadata is operationally useful.
## Constraints
Providers cannot create public routes, secrets, or arbitrary destinations.
## Options considered
Static only; file/DNS; Docker/Kubernetes from v1; generic registry.
## Decision
Static first, file/DNS later, then isolated provider helpers only after review.
## Rationale
One strict validator/activation path avoids provider-specific policy bypass.
## Consequences
Initial operators distribute files; discovery has freshness/debounce limits.
## Security implications
Metadata is untrusted, default exposure false, no proxy Docker socket.
## Reliability implications
Provider loss retains bounded stale state then drains/removes endpoints.
## Operational implications
Status shows provider source, hash, and freshness.
## Migration implications
Provider namespaces and conflict rules become versioned config contracts.
## Alternatives rejected
Direct label-to-runtime mutation and unrestricted registry plugins.
## Revisit conditions
Concrete operator need with isolated privilege model.
