# ADR-0023: Single node before HA

Status: Accepted for Phase 12 | Date: 2026-07-16

## Context
Clustering affects config rollout, certificates, audit, rate limits, and ownership.
## Constraints
No embedded consensus/database in v1.
## Options considered
Single node; independent nodes behind external LB; embedded cluster.
## Decision
Ship one node first, then independent signed/content-hash nodes behind an external LB.
## Rationale
Keeps failure modes and recovery legible.
## Consequences
Rate/health state is node-local initially.
## Security implications
Fewer shared credentials and control ports; later nodes need identity and snapshot authenticity.
## Reliability implications
LB drain and LKG behavior are tested before HA claims.
## Operational implications
Certificate ownership is external/one-writer in HA.
## Migration implications
Fleet rollout is additive and canary-based.
## Alternatives rejected
Premature consensus and shared writable certificate files.
## Revisit conditions
External-LB model cannot meet contracted availability.
