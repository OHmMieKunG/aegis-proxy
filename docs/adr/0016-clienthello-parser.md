# ADR-0016: TCP TLS ClientHello inspection

Status: Accepted for Phase 4 | Date: 2026-07-16

## Context
TLS passthrough needs bounded SNI/ALPN inspection without terminating TLS. Inspection must not alter, reconstruct, or lose any client bytes.
## Constraints
Forward exact bytes; reject malformed, oversized, or slow handshakes; use safe Rust; add no second TLS parser unless necessary; never choose a destination from unvalidated client data.
## Options considered

1. Rustls `server::Acceptor`, with the caller retaining every raw byte supplied through its `Read` interface.
2. A maintained standalone ClientHello parser and a separate raw-prefix buffer.
3. A handwritten minimal parser.
## Decision
Use the Rustls 0.23 `server::Acceptor` already pinned by the project. Read no more than 16 KiB under the configured peek timeout, retain those bytes unchanged, and feed only a cursor over the retained bytes to the acceptor. Once Rustls yields `Accepted`, use its `client_hello()` SNI/ALPN view for route selection, connect only to the configured route's selected endpoint, write the complete retained prefix unchanged, and then copy both directions.

Missing SNI on an SNI-routed listener, malformed input, timeout, overflow, unknown SNI, or unavailable upstream closes only that flow. No plaintext/non-TLS fallback occurs on a TLS-passthrough listener.
## Rationale
Rustls already performs TLS record and ClientHello parsing used by the termination path. Capturing bytes outside the parser preserves the exact prefix without relying on a private Rustls buffer or writing a second parser. The reviewed 0.23.42 source exposes `Acceptor::read_tls`, `Acceptor::accept`, and `Accepted::client_hello`; it does not expose a raw-prefix recovery API, so caller-owned capture is required.
## Consequences
The implementation remains coupled to Rustls's public acceptor API. A 16 KiB limit can reject unusually large ClientHellos, including some extension-heavy clients; this is an explicit resource policy. Encrypted ClientHello can hide the inner name, so routing sees only information Rustls exposes from the outer ClientHello and no ECH support is claimed.
## Security implications
Peek size/time and concurrent connections are bounded. SNI is canonicalized under the same exact/wildcard policy as other routes. Raw input is never logged. The captured prefix is forwarded exactly once. Fuzzing, malformed-record tests, fragmented-record tests, and a byte-for-byte black-box test are mandatory. Handwritten byte scanning remains forbidden.
## Reliability implications
Timeout/parse failure closes only the affected flow. Prefix retention supports ClientHellos split across reads or TLS records. Upstream connection failure cannot rematch another route.
## Operational implications
Passthrough uses a distinct explicit listener and cannot share a bind with HTTP/HTTPS. Status and logs use stable listener/route/upstream IDs, never raw SNI as an unbounded label.
## Migration implications
Rustls upgrades must rerun the ClientHello corpus and exact-prefix tests. Parser replacement requires a new accepted ADR and interoperability regression campaign.
## Alternatives rejected
A second parser adds dependency and differential-parsing risk without a demonstrated need. A handwritten parser is rejected because TLS fragmentation and extension parsing are security-sensitive. Unbounded buffering and best-effort byte scanning are rejected.
## Revisit conditions
Rustls removes or materially changes the acceptor API; required clients exceed the documented bound; ECH routing becomes required; a parser vulnerability affects this path; or tests show prefix preservation/interoperability failure.
