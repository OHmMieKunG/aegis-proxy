# ADR-0006: Immutable runtime snapshots

Status: Accepted
Date: 2026-07-16

## Context

Requests must not observe partially changed routes, TLS, or middleware.

## Constraints

Data path reads immutable state; activation is serialized.

## Options considered

Immutable `Arc` snapshots; global read/write lock; mutable shared maps.

## Decision

Publish `Arc<RuntimeSnapshot>` atomically with `ArcSwap`.

## Rationale

Readers are simple and old streams can finish on their original snapshot.

## Consequences

Snapshots must stay bounded and old references are monitored.

## Security implications

No request can mutate policy; activation is the only publication path.

## Reliability implications

Reload failures leave the active snapshot untouched.

## Operational implications

Active revision/hash is observable.

## Migration implications

Future split control plane sends validated snapshots through a narrow interface.

## Alternatives rejected

Mutable maps and request-time config reads.

## Revisit conditions

Measured memory pressure or a stronger proven snapshot mechanism.
