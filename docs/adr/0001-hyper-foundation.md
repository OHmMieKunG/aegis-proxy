# ADR-0001: Hyper proxy foundation

Status: Accepted
Date: 2026-07-16

## Context

The data plane needs direct HTTP framing, streaming, cancellation, H1/H2, and bounded resource control.

## Constraints

Safe Rust, Tokio runtime, no generic forward proxy, no copied upstream code.

## Options considered

Hyper; Pingora; an external proxy; custom sockets.

## Decision

Use Hyper with Tokio adapters. Keep the proxy policy in project code.

## Rationale

Focused protocol control and broad ecosystem fit; less framework surface for v1.

## Consequences

The project owns routing, pools, retries, limits, and protocol translation correctness.

## Security implications

Single framing interpretation, explicit header normalization, smuggling corpus and fuzz tests are mandatory.

## Reliability implications

Streaming/cancellation are explicit; connection lifecycle is supervised by the runtime.

## Operational implications

One binary, no external proxy dependency.

## Migration implications

Adapters isolate a future Pingora evaluation.

## Alternatives rejected

Pingora deferred until a benchmark/correctness spike; custom parser rejected.

## Revisit conditions

Measured inability to meet support/performance goals or safer proven Pingora fit.
