# ADR-0025: Breaking configuration changes

Status: Accepted | Date: 2026-07-16

## Context
Strict config needs evolution without silent semantic drift.
## Constraints
Unknown/future fields fail; old active config must remain recoverable.
## Options considered
Silent coercion; in-place migration; versioned explicit migration.
## Decision
Use mandatory schema versions, offline pure migrations, new revision output, and explicit operator activation.
## Rationale
Operators see every behavior change and can roll back the binary/config pair.
## Consequences
Upgrades require a migration step and compatibility matrix.
## Security implications
No attacker-controlled unknown field is silently accepted.
## Reliability implications
Old revision remains until new candidate passes activation/probation.
## Operational implications
CLI reports field paths and migration diffs.
## Migration implications
N/N-1 support window is documented; irreversible semantics block old-binary rollback.
## Alternatives rejected
Automatic startup rewrite and permissive unknown fields.
## Revisit conditions
Schema tooling or fleet requirements materially change.
