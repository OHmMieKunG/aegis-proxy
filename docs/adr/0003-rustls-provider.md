# ADR-0003: Rustls crypto provider

Status: Proposed for Phase 2 verification
Date: 2026-07-16

## Context

Rustls requires an explicit provider choice for TLS behavior, portability, and release policy.

## Constraints

TLS 1.2/1.3, safe defaults, Linux production, reproducible builds, no FIPS claim.

## Options considered

Rustls ring provider; Rustls aws-lc-rs provider; OpenSSL bindings.

## Decision

Keep provider selection explicit and verify `aws-lc-rs` versus `ring` in Phase 2; no accidental default provider.

## Rationale

The plan values Rustls; provider choice affects native build and license risk and must be evidence-based.

## Consequences

The lockfile and release targets must build the selected provider.

## Security implications

Provider advisories and crypto policy are release gates; no custom cryptography.

## Reliability implications

Provider build failures block the target artifact rather than silently falling back.

## Operational implications

Container/toolchain images must include required native build inputs if selected.

## Migration implications

Changing provider requires TLS interoperability and artifact review.

## Alternatives rejected

Native OpenSSL is not selected for v1 because it adds ABI/package surface.

## Revisit conditions

Required compliance profile, target portability failure, or material advisory.
