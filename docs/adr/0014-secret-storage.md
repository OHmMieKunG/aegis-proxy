# ADR-0014: Secret references and envelopes

Status: Accepted for Phase 2/8 | Date: 2026-07-16

## Context
Keys, ACME credentials, tokens, and CA material must not be in config or logs.
## Constraints
Only `env://NAME` and absolute `file:///path` initially; bounded reads.
## Options considered
Environment/file refs; command providers; Vault-only; inline secrets.
## Decision
Use typed env/file references and age envelopes with externally injected identity.
## Rationale
Minimal local deployment surface without executing arbitrary provider code.
## Consequences
Secret identity availability is an explicit startup/activation dependency.
## Security implications
Permission checks, redaction, zeroization where practical, no shell/URL execution.
## Reliability implications
Missing required secret rejects the candidate and leaves active state.
## Operational implications
Credential rotation uses atomic generation replacement.
## Migration implications
New providers require ADR and threat review.
## Alternatives rejected
`exec://`, arbitrary URLs, scripts, and raw inline values.
## Revisit conditions
Managed KMS/HSM requirement with a bounded authenticated adapter.
