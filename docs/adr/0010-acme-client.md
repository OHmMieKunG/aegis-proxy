# ADR-0010: ACME client

Status: Accepted for Phase 6 | Date: 2026-07-16

## Context
ACME needs HTTP-01, DNS-01, TLS-ALPN-01, renewal, and safe failure.
## Constraints
Local Pebble tests; no production credentials; one state owner in v1.
## Options considered
`instant-acme`; shelling out to Certbot; custom protocol client.
## Decision
Use a reviewed pure-Rust ACME client and typed challenge adapters; no shell.
## Rationale
Avoid subprocess injection and keep order/storage state in the proxy.
## Consequences
Provider coverage is intentionally small and maintained in project code.
## Security implications
Encrypted account keys, scoped DNS credentials, order locks, and challenge isolation.
## Reliability implications
Jitter/backoff and last-working-certificate retention.
## Operational implications
Explicit staging/production directories and expiry alerts.
## Migration implications
Account/order metadata is versioned; client replacement needs Pebble regression tests.
## Alternatives rejected
Certbot subprocesses and a hand-written ACME protocol.
## Revisit conditions
Library capability, advisory, provider, or compliance change.
