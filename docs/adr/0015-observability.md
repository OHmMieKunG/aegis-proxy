# ADR-0015: Structured telemetry

Status: Accepted for Phase 9 | Date: 2026-07-16

## Context
Operators need route/upstream/TLS/reload visibility without leaking data.
## Constraints
Bounded queues and labels; audit differs from best-effort telemetry.
## Options considered
`tracing` + Prometheus/OpenTelemetry; vendor SDK; log-only.
## Decision
Use structured tracing, bounded JSON logs, Prometheus/OpenMetrics, and optional OTLP.
## Rationale
Open standards integrate with existing Grafana/Loki/Prometheus/SIEM systems.
## Consequences
Cardinality budgets and redaction become code/test responsibilities.
## Security implications
No secrets, raw paths, IPs, or auth headers in labels/logs.
## Reliability implications
Exporter loss cannot block requests; durable audit mutation policy is separate.
## Operational implications
Health/readiness and failure counters are documented.
## Migration implications
Metric names remain stable within a major API line.
## Alternatives rejected
Unbounded per-request labels and bundled telemetry storage.
## Revisit conditions
A measured integration requires a different exporter.
