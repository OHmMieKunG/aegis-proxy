# ADR-0012: Administrative authentication

Status: Accepted for Phase 8 | Date: 2026-07-16

## Context
Private administration still needs explicit principal authentication.
## Constraints
No default credentials or plaintext remote admin.
## Options considered
Unix peer permissions; mTLS; hashed API tokens; OIDC sessions.
## Decision
Unix permissions first; mTLS and high-entropy hashed tokens for automation; OIDC only with the UI phase.
## Rationale
Local bootstrap is simple and remote access is explicit.
## Consequences
Token recovery is an operator ceremony; browser auth is deferred.
## Security implications
Constant-time verification, expiry/revocation, secure transport, no header-derived identity.
## Reliability implications
Lost credentials do not make the public data plane unavailable.
## Operational implications
Token plaintext is shown once; all actions are audited.
## Migration implications
Principal metadata is versioned and role changes are additive.
## Alternatives rejected
Basic admin passwords and query-string tokens.
## Revisit conditions
Multi-user browser administration is approved.
