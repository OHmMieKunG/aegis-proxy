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

Use immutable files, pointers, journals, fsync, retention, and append-only audit. Phase 5 keeps every revision for at least 30 days and the newest 70 revisions regardless of age. Active, immediate-previous, and activation-journal targets are never pruned. A hard 1,000-revision ceiling fails candidate creation if the age floor and protected targets prevent safe pruning.

Phase 15 adds an optional validated SHA-256 binding in revision metadata. High-level typed
candidates use it to link one canonical configuration revision to a separate strict immutable
desired-state snapshot. Low-level revisions omit it and preserve their existing representation.
Typed rollback never rewrites or directly activates the historical revision. It creates a new bound
forward revision and uses a separate private desired-state journal. Recovery selects previous or
target typed records from the durable active pointer before Admin starts.

## Rationale

The state is small and file-shaped; backup/restore remains inspectable.

## Consequences

Querying and multi-writer coordination are intentionally limited. V1 does not persist a success/rejection classification per revision, so the 70-revision recent window conservatively covers both outcomes instead of implementing separate 50-successful and 20-rejected buckets.
Typed snapshot retention is separately hard-bounded to 1,000 entries. The retained configuration
revision list is authoritative: Admin startup and typed snapshot creation validate the complete
bounded snapshot directory, then durably remove only snapshots whose revisions have already been
pruned. Invalid, tampered, symlinked, or retained-but-mismatched entries fail closed before any
deletion. Revision and snapshot stores remain separate file transactions, so interruption may leave
a harmless non-active orphan until the next reconciliation.
The rollback journal coordinates two file-backed transactions without introducing a database. An
unresolved journal blocks mutation rather than allowing typed desired state to diverge further.

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
