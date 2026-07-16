# ADR-0003: Rustls crypto provider

Status: Accepted
Date: 2026-07-16

## Context

Rustls requires an explicit provider choice for TLS behavior, portability, and release policy.

## Constraints

TLS 1.2/1.3, safe defaults, Linux production, reproducible builds, no FIPS claim.

## Options considered

Rustls ring provider; Rustls aws-lc-rs provider; OpenSSL bindings.

## Decision

Use Rustls with the `aws_lc_rs` provider selected through explicit Cargo features. Disable Rustls default features and enable only `aws_lc_rs`, `std`, and TLS 1.2 support. Do not claim FIPS validation and do not install a fallback provider.

## Rationale

The provider compiled and linked successfully in the Windows GNU workspace, the Linux release container, and the Linux test container. It supports the required Rustls TLS 1.2/1.3 policy. Ring remains a viable portability fallback, but carrying two runtime providers increases artifact and review surface without a demonstrated need.

## Consequences

The native AWS-LC build increases clean build time and requires CMake plus a C toolchain. Container build caches are used, and every supported release target must compile the provider.

## Security implications

Provider advisories and crypto policy are release gates; no custom cryptography, runtime provider choice, FIPS claim, or silent fallback exists.

## Reliability implications

Provider build failures block the target artifact rather than silently falling back. Windows MSVC remains unverified because the local environment lacks the MSVC linker; Linux builds pass.

## Operational implications

Container/toolchain images include CMake. Build-time and SBOM/native-code surface are documented and monitored.

## Migration implications

Changing provider requires a superseding ADR, TLS interoperability matrix, artifact/SBOM review, and full certificate-store restore test.

## Alternatives rejected

Ring was rejected for the current target because AWS-LC already passed both supported Linux build paths. Native OpenSSL remains rejected because it adds ABI/package surface.

## Revisit conditions

Required compliance profile, target portability failure, or material advisory.
