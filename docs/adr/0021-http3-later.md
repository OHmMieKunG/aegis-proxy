# ADR-0021: HTTP/3 later

Status: Accepted for later evaluation | Date: 2026-07-16

## Context
QUIC adds UDP exposure, migration, amplification, 0-RTT, and deployment complexity.
## Constraints
No H3/UDP initial release; TCP TLS remains independent.
## Options considered
Quinn/H3 in v1; later gated feature; omit forever.
## Decision
Evaluate separately after core security/observability evidence; do not advertise Alt-Svc in v1.
## Rationale
H1/H2 meet initial product need.
## Consequences
No QUIC performance benefit initially.
## Security implications
Avoids UDP amplification/replay surface until reviewed.
## Reliability implications
Existing TCP service is unaffected by disabled H3.
## Operational implications
No UDP firewall/LB requirement in v1.
## Migration implications
H3 requires separate listener/feature and rollback switch.
## Alternatives rejected
Unreviewed QUIC implementation in the core release.
## Revisit conditions
Stable stack, user demand, deployable UDP path, and DoS review.
