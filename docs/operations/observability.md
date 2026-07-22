# Observability operations

Current implementation emits structured JSON logs, bounded OpenMetrics, and optional OTLP/HTTP
protobuf traces. Telemetry is diagnostic and best effort. The HMAC-chained
administrative audit log remains the durable mutation record.

## Private endpoints

The administration Unix socket exposes unauthenticated `/live` and `/ready`
probes. `/health/details` and `/metrics` require the normal Unix-peer and RBAC
authentication boundary. No TCP metrics listener exists. Keep the socket under
its mode-`0700` parent and never bridge it to a wildcard or public address.

`rust-proxy metrics --socket /run/aegisproxy/admin.sock` retrieves OpenMetrics
using peer credentials. A local collector may execute that command into an
atomic, mode-`0600` textfile for a node-exporter textfile collector, or use a
reviewed Unix-domain-socket HTTP integration. Preserve file ownership and do
not attach request-derived labels. Failure to scrape must not affect traffic.

Import `deploy/observability/grafana-dashboard.json` and load
`deploy/observability/prometheus-rules.yaml` into an existing private monitoring
stack. Prometheus supplies its own bounded `up{job="aegisproxy"}` series. Test
each alert in staging by temporarily overriding its expression with `vector(1)`
or replaying synthetic series; do not perform failure drills on production.

## Cardinality budget

Configuration validation rejects a conservative estimate above 100,000 series.
The formula is:

```text
(listeners + route/listener pairs) * 170
+ endpoints * 17
+ rate-limit middleware * 3
+ listeners * 6
+ certificates * 4
+ 14 process-wide bounded outcomes
```

Only validated listener, route, upstream-group, endpoint, middleware,
certificate, and issuer IDs become identity labels. Outcome, protocol, and
status-class values are closed enums. Removed-object series are pruned during
reload after active guards drain. OpenMetrics output is capped at 16 MiB.

Forbidden labels and attributes include raw hostname, path, query string,
client IP, user agent, request ID, arbitrary header values, credentials, and
free-form error text. Request IDs remain JSON-log correlation fields only.

## JSON logs and Loki

Send stdout/stderr JSON through journald or a bounded file/log driver. Configure
the shipper with a finite disk buffer, TLS server verification, authenticated
egress, retry limits, and drop alerts. Loki labels should be limited to service,
environment, severity, and stable configured IDs. Parse other fields at query
time; never label request IDs or actor IDs.

Access events use `event_name="http.access"`. Trace spans use stable configured
IDs, method, and protocol only. Authorization, cookies, query strings, raw
headers, secret values, and client-selected host/path data are absent by
construction and covered by a canary integration test.

## OTLP traces

`observability.otlp_traces` is optional and restart-only. HTTPS is required
except for an explicit loopback IP endpoint. The queue is at most 16,384 spans,
batches cannot exceed the queue, export timeout is at most 30 seconds, and
sampling is parent-aware. W3C `traceparent`/`tracestate` is parsed; malformed
input is removed rather than forwarded. Export uses a worker-thread batch
processor, so a slow or unavailable collector does not delay proxy requests.

Use a private TLS collector with a certificate rooted in the bundled WebPKI
roots. This release has no OTLP bearer-secret configuration; place a mutually
reviewed local authenticated collector in the same trust boundary when the
backend requires additional authentication. Monitor collector loss externally
and `aegisproxy_telemetry_drops_total` where emitted.

## Triage

1. Check `/live`, `/ready`, then authenticated `/health/details`.
2. Check `up`, reload outcomes, audit readiness, and telemetry drops.
3. Split HTTP failures by stable route; split upstream attempts by configured
   group and endpoint.
4. Check certificate expiry and renewal outcomes.
5. Correlate JSON logs by request ID locally. Do not promote it to a metric or
   Loki label.
6. Verify the durable audit chain before trusting mutation history.

Metric and dashboard compatibility is stable only within the v1 major line.
Alert thresholds are starting points, not measured production SLOs.
