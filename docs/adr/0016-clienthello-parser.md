# ADR-0016: TCP TLS ClientHello inspection

Status: Proposed for Phase 3 | Date: 2026-07-16

## Context
TLS passthrough needs bounded SNI/ALPN inspection without terminating TLS.
## Constraints
Forward exact bytes; reject malformed/oversized/slow handshakes; safe Rust.
## Options considered
Rustls acceptor API; maintained parser crate; handwritten parser.
## Decision
Phase 0/3 spike decides based on consumed-prefix preservation, RFC coverage, license, advisories, and fuzz history. No parser is copied or silently hand-written.
## Rationale
Passthrough parser ambiguity is release-blocking security risk.
## Consequences
TLS passthrough remains unavailable until the gate passes.
## Security implications
Bounded peek, SNI validation, fuzzing, and no arbitrary destination.
## Reliability implications
Timeout/parse failure closes only the affected flow.
## Operational implications
Passthrough is explicit listener/route configuration.
## Migration implications
Parser replacement requires corpus/interoperability regression tests.
## Alternatives rejected
Unbounded buffering and best-effort byte scanning.
## Revisit conditions
Required SNI behavior or parser vulnerability.
