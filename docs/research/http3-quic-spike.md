# HTTP/3 and QUIC Phase 13 spike

Date: 2026-07-19 | Outcome: **NO-GO for the initial release**

This is a dependency and design review, not an implementation or benchmark. No Quinn/H3 code,
feature, listener, configuration, or dependency was added.

## Evidence

- [Quinn](https://github.com/quinn-rs/quinn) is a pure-Rust async QUIC implementation with Tokio
  and Rustls support. Its current documentation reports stable Rust and Linux/macOS/Windows support
  and warns that high-rate endpoints may need privileged/system UDP-buffer tuning.
- [Hyperium H3](https://github.com/hyperium/h3) provides generic HTTP/3 client/server APIs and a
  Quinn adapter, but its current status explicitly remains "very experimental", warns that bugs and
  API changes remain possible, and describes Hyper integration as an eventual goal.
- The present proxy uses Hyper's HTTP/1.1 and HTTP/2 paths. There is no reviewed adapter that makes
  H3 inherit all existing routing, cancellation, middleware, header, body, audit, and drain
  invariants automatically.

These upstream facts show technical feasibility, not production suitability for this proxy.

## Compatibility assessment

| Area | Finding | Gate |
|---|---|---|
| runtime/TLS | Quinn can use Tokio and Rustls | compatible in principle; exact crypto/provider policy untested |
| MSRV | Quinn documents an MSRV below this project's 1.88 floor | compatible in principle; full resolved graph untested |
| Hyper integration | H3 is a separate experimental API, not current Hyper server transport | application adapter and invariant review required |
| deployment | QUIC needs UDP exposure, buffer tuning, firewall/LB support and connection-ID routing | unsupported in current container/host evidence |
| security | address validation, amplification, migration, 0-RTT and UDP state add new boundaries | no threat/test evidence yet |
| operations | H3 needs separate metrics, tracing, qlog-safe handling, draining and disable/rollback | not designed or tested |

## Required isolated experiment

A later ADR may authorize a non-release feature only when it includes:

1. fixed compatible Quinn/H3 versions and dependency/license/advisory review;
2. one separately bindable UDP listener with no effect on TCP TLS when disabled;
3. explicit address validation/retry policy and 0-RTT disabled by default;
4. global/per-peer bounds for handshakes, connections, streams, QPACK state, datagrams, queues,
   connection IDs, migration work, idle time and total lifetime;
5. request conversion preserving existing authority, forwarding-header, middleware, body/trailer,
   cancellation, upstream, and audit invariants;
6. QUIC interop runner plus independent curl/browser/server interoperability;
7. loss, reordering, PMTU, NAT rebinding, migration, retry-token, replay, amplification, malformed
   packet, connection-ID routing, graceful drain and TCP-independence tests;
8. long fuzz and 24-hour resource-abuse soak with memory/CPU/FD/packet-rate evidence;
9. bounded stable-label metrics, safe qlog controls, operator runbooks and target-host UDP tuning;
10. independent QUIC protocol and security review.

## Decision

H3 stays absent. Do not advertise `Alt-Svc`, open UDP, reserve a runtime feature, or add dependencies
in the initial release. Revisit only after a named product need and every gate above has an owner,
test environment, and acceptance threshold.
