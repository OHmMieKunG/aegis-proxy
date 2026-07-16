# ADR-0022: UDP later

Status: Accepted for later evaluation | Date: 2026-07-16

## Context
Connectionless proxying needs protocol-specific pseudo-session, timeout, spoof, and amplification rules.
## Constraints
No UDP initial release.
## Options considered
Generic UDP forwarding; named protocol adapters; omit.
## Decision
Defer until a named protocol and bounded semantics are approved.
## Rationale
Generic UDP is unsafe and underspecified.
## Consequences
Only TCP/L4 is supported initially.
## Security implications
No unreviewed reflection/amplification path.
## Reliability implications
No pseudo-session state to recover or cap in v1.
## Operational implications
No UDP listener or firewall exposure.
## Migration implications
New protocol gets an independent feature/ADR and tests.
## Alternatives rejected
Pass-through datagrams based only on client address.
## Revisit conditions
Concrete protocol and threat/resource model.
