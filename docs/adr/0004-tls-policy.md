# ADR-0004: TLS policy

Status: Accepted
Date: 2026-07-16

## Context

Public termination and upstream TLS require predictable safe defaults.

## Constraints

TLS 1.2/1.3 only; TLS 1.3 preferred; no insecure verification escape hatch.

## Options considered

Rustls curated policy; library defaults; OpenSSL configuration.

## Decision

Define an explicit Rustls policy with configurable minimum version, ALPN, SNI selection, verified upstream roots, and typed CA bundles.

## Rationale

Library defaults can drift and do not express route/tenant certificate rules.

## Consequences

Legacy clients may fail; certificate/hostname validation is project-owned.

## Security implications

No downgrade or wrong-tenant certificate fallback; malformed material rejects activation.

## Reliability implications

Previous valid certificates remain available through renewal failure.

## Operational implications

TLS policy and expiry status are visible in config/status.

## Migration implications

Policy tightening is a documented breaking config change.

## Alternatives rejected

Implicit plaintext fallback and `insecure_skip_verify`.

## Revisit conditions

Verified regulatory or interoperability requirement.
