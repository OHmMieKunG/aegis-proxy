# ADR-0018: No database in the initial release

Status: Accepted | Date: 2026-07-16

## Context
V1 persistence is revisions, certificates, audit, and backups.
## Constraints
Single node; inspectable atomic files; no DB credential/HA burden.
## Options considered
Files; SQLite; PostgreSQL.
## Decision
Use versioned files and append-only audit; revisit SQLite/PostgreSQL only on evidence.
## Rationale
The state is small and file-shaped.
## Consequences
Complex relational queries and clustered transactions are deferred.
## Security implications
No SQL injection or DB network exposure; filesystem modes are critical.
## Reliability implications
Atomic rename/fsync and restore drills are required.
## Operational implications
Backup is simple, portable, and explicit.
## Migration implications
File schema migrations create new revisions.
## Alternatives rejected
Premature embedded/external database.
## Revisit conditions
Measured state limits or clustered control-plane requirement.
