# ADR-0008: File revision persistence

Status: Accepted
Date: 2026-07-16

## Context

V1 needs durable desired state, certificate metadata, audit, and rollback without relational state.

## Constraints

No database in initial release; atomic writes; one state-directory owner.

## Options considered

Versioned files; SQLite; PostgreSQL.

## Decision

Use immutable files, pointers, journals, fsync, retention, and append-only audit.

## Rationale

The state is small and file-shaped; backup/restore remains inspectable.

## Consequences

Querying and multi-writer coordination are intentionally limited.

## Security implications

Permissions and path containment are critical; SQL injection is absent in v1.

## Reliability implications

Crash injection verifies old-or-new state, never partial state.

## Operational implications

Operators can back up and inspect revisions with CLI tools.

## Migration implications

Schema transformations create new revisions.

## Alternatives rejected

DB dependency before demonstrated need.

## Revisit conditions

Measured state/query limits or clustered transactional requirements.
