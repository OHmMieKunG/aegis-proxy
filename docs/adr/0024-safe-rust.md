# ADR-0024: No first-party unsafe Rust

Status: Accepted | Date: 2026-07-16

## Context
Proxy protocol/security code has high memory-safety impact.
## Constraints
Own crates use `#![forbid(unsafe_code)]`.
## Options considered
Safe Rust; isolated reviewed unsafe; broad native bindings.
## Decision
Use safe Rust; any exception needs a dedicated ADR, invariants, tests, fuzzing, and reviewer.
## Rationale
No current feature requires first-party unsafe code.
## Consequences
Some low-level integrations may be deferred or wrapped by audited dependencies.
## Security implications
Reduces memory-safety attack surface but does not replace protocol/security testing.
## Reliability implications
Fewer undefined-behavior failure modes.
## Operational implications
Native transitive unsafe is inventoried in dependency review.
## Migration implications
An unsafe exception must remain isolated and removable.
## Alternatives rejected
Unsafe shortcuts for performance or FFI convenience.
## Revisit conditions
Verified unavoidable safe-code limitation.
