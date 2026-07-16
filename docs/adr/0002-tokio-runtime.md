# ADR-0002: Tokio runtime

Status: Accepted
Date: 2026-07-16

## Context

Network I/O, timers, cancellation, signals, and bounded background work need one async runtime.

## Constraints

No blocking work on worker threads; no unbounded task spawning.

## Options considered

Tokio; async-std; manual polling.

## Decision

Use a multi-thread Tokio runtime with explicit task supervision and cancellation tokens.

## Rationale

Best fit for Hyper, Axum, Rustls, and ecosystem tooling.

## Consequences

Blocking filesystem, hashing, and password work needs bounded blocking pools.

## Security implications

Bounded tasks/queues prevent scheduler and memory abuse.

## Reliability implications

Critical tasks change readiness; restartable tasks use capped backoff.

## Operational implications

Thread count and shutdown deadline are observable configuration/runtime values.

## Migration implications

Runtime wiring is isolated in the binary supervisor.

## Alternatives rejected

Manual polling adds code and failure modes.

## Revisit conditions

Tokio cannot satisfy target platform or protocol requirements.
