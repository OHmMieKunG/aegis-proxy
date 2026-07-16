# ADR-0010: ACME client

Status: Accepted and pinned for Phase 6 | Date: 2026-07-16

## Context
ACME needs HTTP-01, DNS-01, TLS-ALPN-01, renewal, account recovery, and safe failure. Current dependency capabilities were rechecked before Phase 6 implementation.
## Constraints
Local Pebble tests; no production credentials; one state owner in v1; Tokio/Hyper/Rustls/AWS-LC compatibility; account credentials must be encrypted before persistence; crate-specific types must not enter configuration or public API contracts.
## Options considered
`instant-acme 0.8.5`; higher-level `rustls-acme`; shelling out to Certbot/acme.sh; custom RFC 8555 client.
## Decision
Pin `instant-acme 0.8.5` behind `proxy-tls::acme::AcmeClient`, with default features disabled and only `aws-lc-rs` plus `hyper-rustls` enabled initially. Do not use its default HTTP transport: the 0.8.5 implementation collects response bodies without a byte limit. Supply an application-owned Hyper/Rustls transport with same-origin endpoint enforcement, bounded response bodies and headers, bounded connection reuse, and connect/request deadlines. Add its optional `time`/`x509-parser` ARI features only when the renewal scheduler consumes them. Challenge serving, DNS changes, storage, locking, scheduling, validation, and policy remain application-owned. TLS-ALPN-01 uses an in-memory, bounded, exact-SNI registry; certificates live for at most one hour and are selected only when the client offers `acme-tls/1`. No subprocess is permitted.
## Rationale
The crate is Apache-2.0, declares Rust 1.70 support, released 0.8.5 in 2026, and its official API supports all required challenge types, serializable account credentials, EAB, account-key rollover, revocation, profiles, concurrent orders, and optional ARI. It already uses the selected networking and crypto stack. The adapter limits replacement cost and prevents credential-rich errors/types from leaking outward.
## Consequences
Account keys are currently P-256 only. Provider coverage remains intentionally small and maintained in project code. Optional ARI dependencies are not paid for until used. The project owns more HTTP adapter code, including compatibility tests when Hyper or `instant-acme` changes. The project owns orchestration and must not confuse library protocol support with complete lifecycle safety.
## Security implications
Serialized `AccountCredentials` contains the private account key and must be size-bounded, age-encrypted, redacted, permission-restricted, and never logged. Every directory-derived endpoint must retain the configured scheme, host, and effective port; cross-origin and credentialed endpoints fail closed. CA responses are limited to 2 MiB under a 30-second total request deadline, with 10-second connects, 32 KiB protocol header buffers/lists, and at most two idle connections per origin. TLS-ALPN challenge certificates contain the RFC 8737 critical `acmeIdentifier` extension, one exact DNS SAN, a checked public-key match, and no fallback to a normal or wildcard certificate. Rustls 0.23.42 `CertifiedKey::from_der` rejects the required unknown critical extension during its key-match path, so this isolated path validates the RFC fields and SPKI itself, loads the signing key through the selected AWS-LC provider, then constructs `CertifiedKey`; normal certificates continue through the full WebPKI validation path. The initial Cloudflare DNS adapter is fixed to the official HTTPS v4 origin, one explicit zone ID and a size-bounded sensitive bearer token. It creates only exact TXT records with TTL 60, bounds responses at 64 KiB under a 15-second deadline, and uses exact name/content listing before creation and after an uncertain response so retries adopt one matching record instead of blindly duplicating it. More than one matching record fails closed for operator cleanup. Scoped DNS credentials, single-flight order locks, exact challenge isolation, validated CA responses, and retained working certificates remain mandatory. Dependency advisories require a release gate; `cargo-audit` is unavailable in the current environment.
## Reliability implications
Jitter/backoff, explicit CA classification, bounded concurrency, durable account storage, Pebble tests, and last-working-certificate retention are application responsibilities. Client failure cannot remove or replace active material.
## Operational implications
Explicit staging/production directories and expiry alerts. Custom roots are allowed only by explicit configuration, primarily for Pebble/private CAs; system trust remains the default.
## Migration implications
Account/order metadata is versioned outside the crate credential JSON. Client upgrade/replacement requires decrypt/restore, Pebble issuance/renewal/rollover, and rollback compatibility tests.
## Alternatives rejected
`rustls-acme` owns more listener/lifecycle policy than desired; subprocess clients add command, credential, and state coordination surfaces; a hand-written protocol client duplicates nonce/JWS/order correctness work.
## Revisit conditions
Unresolved advisory, maintenance decline, required non-P-256 account keys, incompatible MSRV/Rustls/Hyper, missing CA behavior, FIPS/compliance change, or repeated Pebble/public-CA interoperability defects.

## Provider API evidence
Cloudflare v4 create, exact-list-filter, and delete contracts were checked against the official API reference on 2026-07-16: `POST /zones/{zone_id}/dns_records`, `GET /zones/{zone_id}/dns_records` with `name.exact`, `content.exact`, `type`, and `match=all`, and `DELETE /zones/{zone_id}/dns_records/{dns_record_id}`.
