# ADR-0026: Upstream selection and failure state

Status: Accepted for Phase 4 | Date: 2026-07-16

## Context
Multiple endpoints need deterministic weighted selection, health-aware exclusion, bounded passive feedback, active checks, draining, safe retries, and circuit isolation without putting mutable configuration on the request path.

## Constraints
Safe Rust; bounded state and tasks; no unhealthy/draining choice when healthy capacity exists; no unsafe body replay; no route rematch; endpoint transport policies must not share incompatible pools.

## Options considered

1. One immutable group definition with small shared per-endpoint atomics and bounded synchronized health samples.
2. A centralized actor receiving every selection/result through a bounded channel.
3. Stateless random selection with transport errors handled only per request.

## Decision
Compile each group into an `Arc<UpstreamPool>`. Immutable endpoint definitions and clients are paired with shared endpoint runtime handles containing availability state and active-request counters. Selection uses only eligible `Healthy` or `Starting` endpoints; `Draining` and `Unhealthy` endpoints receive no new work. Algorithms are round robin, smooth weighted round robin, random, and power-of-two choices.

Active and passive observations update a bounded hysteresis state machine. Circuit state is group-local with a bounded rolling sample and an atomic half-open permit budget. Request attempts acquire a guard that decrements active count on every exit. Runtime replacement reuses a handle only when endpoint ID and complete transport/security identity match; removed or changed handles drain.

Retries are a separate explicit attempt policy. Default automatic replay is limited to configured attempts/time and requests whose method is idempotent and whose body is proven replayable within its cap. No retry occurs after response bytes, for WebSocket/gRPC streaming, or merely because an `Idempotency-Key` exists. Until the replay implementation is active, validation permits only one attempt.

## Rationale
Request-path atomics avoid an actor/channel bottleneck while bounded synchronized windows keep complex transition logic inspectable. A guard makes active accounting cancellation-safe. Separating health, circuit, and retry state avoids treating one mechanism as an undocumented substitute for another.

## Consequences
Endpoint state is node-local and intentionally not HA-consistent. Smooth weighted selection requires small locked group state; lock scope contains arithmetic only and never I/O. Starting endpoints can receive traffic only under a documented bootstrap policy. Pool identity comparison becomes part of Phase 5 reload correctness.

## Security implications
Selection cannot add destinations; all endpoints originate from validated config/DNS and pass egress checks. Bounds apply to endpoints, DNS answers, samples, probes, attempts, and half-open work. Retry defaults prevent non-idempotent replay and amplification.

## Reliability implications
Hysteresis reduces oscillation. All-unavailable groups fail quickly with 503 and do not fall through to another route. Draining preserves existing work until its deadline. Health task failure affects readiness/status but not unrelated pools.

## Operational implications
Status exposes stable group/endpoint IDs, state, active count, transition reason class, and bounded timestamps. Raw DNS names/errors are not metric labels. Operators configure explicit thresholds and probe behavior.

## Migration implications
Adding algorithms or changing selection arithmetic can alter traffic distribution and requires an ADR/config compatibility note. Phase 5 must preserve or drain state using the complete endpoint identity rule.

## Alternatives rejected
A central actor adds queue pressure and makes selection dependent on task scheduling. Stateless selection cannot provide drain, health, or circuit guarantees. Unbounded event histories are rejected.

## Revisit conditions
Measured contention violates an approved benchmark envelope; a load-balancing algorithm needs richer shared state; or multi-node health coordination becomes an approved requirement.
