# ADR-0021: HTTP/3 remains deferred after Phase 13 review

Status: Accepted — no-go for the initial release | Date: 2026-07-19

## Context
QUIC adds UDP exposure, migration, amplification, 0-RTT, and deployment complexity. Phase 13
reviewed the current Quinn and Hyperium H3 projects without adding either dependency. Quinn is a
viable Tokio/Rustls QUIC transport, but the H3 project still describes itself as very experimental
and not yet an internal Hyper dependency.
## Constraints
No H3/UDP initial release; TCP TLS remains independent. A later implementation must fit the Rust
1.88 MSRV, remain separately disableable, use bounded state, and pass interoperability and abuse
testing on supported deployment targets.
## Options considered
Quinn/H3 in v1; a later isolated and gated feature; omit permanently.
## Decision
Do not implement or advertise H3/Alt-Svc in the initial release. Re-evaluate Quinn plus `h3` only
in an isolated non-release feature after the gates in the spike report are funded and testable.
## Rationale
H1/H2 meet the initial need. Adding a currently experimental H3 integration would enlarge the
pre-release protocol, UDP, operational, and dependency review surface without a demonstrated user
requirement.
## Consequences
No QUIC performance benefit initially. No Quinn/H3 code, dependency, listener, or configuration is
present, so an accidental H3 activation path does not exist.
## Security implications
Avoids UDP amplification, address-validation, migration, replay, connection-ID routing, and
flow-control surface until reviewed. A future design must default 0-RTT off and bound handshakes,
connections, streams, QPACK state, datagrams, queues, and per-peer work.
## Reliability implications
Existing TCP service is unaffected because H3 is absent rather than merely runtime-disabled.
## Operational implications
No UDP firewall, socket-buffer tuning, load-balancer affinity, or QUIC observability requirement in
v1. Later operators must be able to disable H3 without affecting TCP TLS.
## Migration implications
H3 requires a separate listener/feature, explicit configuration versioning, independent rollback
switch, and no automatic Alt-Svc advertisement before readiness.
## Alternatives rejected
Unreviewed Quinn/H3 in the core release was rejected. Permanent omission was rejected because the
transport may become justified after the ecosystem and product need mature.
## Revisit conditions
Named user demand; stable compatible Quinn/H3 versions; supported UDP load-balancer path; QUIC
interop runner plus browser/curl interoperability; loss, migration, NAT rebinding, retry/token,
amplification, 0-RTT, malformed input, fuzz, soak, and resource-abuse results; complete metrics and
runbooks; independent protocol/security approval. See `docs/research/http3-quic-spike.md`.
