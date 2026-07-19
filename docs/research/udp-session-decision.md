# Bounded UDP session Phase 13 decision

Date: 2026-07-19 | Outcome: **NO-GO without a named protocol**

No initial-release route requires connectionless forwarding. A generic UDP proxy would introduce
open-forwarder, reflection, spoofing, response-association, NAT rebinding, state exhaustion, MTU,
and timeout ambiguity without protocol semantics to resolve them. UDP proxying therefore remains
absent; ordinary DNS resolver traffic does not change this decision.

## Rejected generic model

The proxy must not accept client-selected destinations or expose a catch-all datagram relay. Even a
configured-destination relay is insufficient without knowing whether a response is valid, how long
state remains authoritative, whether source-address changes are legal, and whether the protocol can
amplify small requests.

## Minimum later requirements

A named-protocol proposal must define and test all of these before implementation:

| Boundary | Required design |
|---|---|
| destination | validated configured targets only; CIDR/DNS policy at configuration, refresh and send time |
| session identity | explicit tuple/protocol key; collision and rebinding rules; no trust in payload-selected target |
| state budgets | global, listener, source-prefix and client session caps; bounded sharded map/queue |
| lifetime | short idle timeout plus hard maximum; deterministic expiry and bounded cleanup work |
| datagrams | maximum bytes, packets/second, bytes/second, bursts and in-flight sends; no IP reassembly in process |
| responses | protocol-valid association, source validation and bounded fan-out; no unsolicited reflection |
| abuse | spoof, reflection/amplification ratio, rebinding, floods, fragments, malformed input and eviction tests |
| operations | UDP-aware load-balancer affinity, drain, restart behavior, stable-label metrics and alerts |
| isolation | separate listener/feature/schema; off by default; disable without affecting HTTP/TCP |

## Required evidence

- named user and protocol requirement with supported versions;
- protocol threat model and amplification measurements;
- property/fuzz tests for session keys, parser and expiry;
- packet-loss, reorder, duplicate, NAT rebinding, timeout, fairness and budget integration tests;
- 24-hour-plus high-cardinality/resource soak and target-host/container confinement validation;
- independent protocol/security review with no unresolved critical/high findings.

## Decision

Generic UDP forwarding is permanently rejected. A named protocol can be reconsidered only through a
new ADR and isolated later phase after the minimum requirements above are measurable. No UDP proxy
listener, schema, runtime state, dependency, or firewall exposure enters the initial release.
