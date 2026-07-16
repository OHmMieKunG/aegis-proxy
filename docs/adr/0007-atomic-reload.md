# ADR-0007: Atomic reload and probation

Status: Accepted
Date: 2026-07-16

## Context

Bad runtime changes must not replace a working configuration.

## Constraints

Prepare first; pointer and journal are durable; publication is non-failing.

## Options considered

Process restart; in-place mutation; journaled snapshot activation.

## Decision

Use immutable revision, activation-intent journal, active pointer, atomic snapshot publish, structural probation, and rollback.

## Rationale

It supports low-downtime changes and crash recovery without a database.

## Consequences

Filesystem fsync/rename behavior is tested on supported platforms.

## Security implications

Candidate validation and audit precede policy publication.

## Reliability implications

Incomplete probation selects the previous revision on restart.

## Operational implications

Activation status explains candidate, active, probation, and rollback states.

## Migration implications

Revision metadata is versioned and retained through rollback windows.

## Alternatives rejected

Blind file reload and restart-only deployment.

## Revisit conditions

Filesystem limits or multi-node coordination require a new control-plane protocol.
