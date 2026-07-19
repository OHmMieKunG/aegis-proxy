# ADR-0022: Generic UDP remains excluded after Phase 13 review

Status: Accepted — no-go without a named protocol | Date: 2026-07-19

## Context
Connectionless proxying needs protocol-specific pseudo-session, timeout, spoof, NAT rebinding, and
amplification rules. Phase 13 found no named initial-release protocol or customer requirement that
justifies this state and attack surface.
## Constraints
No UDP proxying in the initial release. DNS resolution used by the process is not a UDP proxy
feature. Client input must never select an arbitrary destination.
## Options considered
Generic UDP forwarding; configured destination forwarding with generic pseudo-sessions; named
protocol adapters; omit permanently.
## Decision
Reject generic UDP forwarding. Consider only a named protocol in a later isolated feature after its
protocol-specific bounded-session and anti-abuse design is approved.
## Rationale
Generic UDP is unsafe and underspecified: it risks open forwarding, reflection/amplification,
spoofed sources, ambiguous response routing, unbounded pseudo-sessions, and incorrect timeout/NAT
semantics.
## Consequences
Only TCP/L4 is supported initially. No UDP listener, route schema, runtime task, or dependency is
added.
## Security implications
No unreviewed reflection/amplification path. Any future design must use configured destinations,
revalidate destination policy, rate/size limit datagrams, and bound sessions globally and per peer.
## Reliability implications
No pseudo-session state to recover, drain, observe, or cap in v1.
## Operational implications
No UDP listener, firewall exposure, load-balancer affinity, or new metric cardinality in v1.
## Migration implications
Each named protocol gets an independent feature, schema version, ADR, compatibility policy,
disable/rollback path, and protocol-specific tests. It cannot silently widen an existing listener.
## Alternatives rejected
Pass-through datagrams based only on client address and generic configured-destination forwarding
were rejected. Permanent omission was rejected because a later named protocol may justify it.
## Revisit conditions
Concrete protocol/customer requirement; explicit response association and NAT behavior; bounded
five-tuple/session keys, idle and hard lifetimes, packet/byte rates, queues, memory and concurrency;
spoof/reflection/amplification tests; destination and rebinding policy; load-balancer model;
telemetry and drain behavior; fuzz/soak/external approval. See
`docs/research/udp-session-decision.md`.
