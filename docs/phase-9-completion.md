# Phase 9 completion: observability and audit logging

Date: 2026-07-18

## 1. Phase title

Phase 9: Observability and audit logging.

## 2. Original objectives

Provide production-oriented structured logs, bounded metrics, optional
OpenTelemetry tracing, private health semantics, example dashboards/alerts,
and SIEM guidance without weakening the durable administrative audit boundary
or creating request-controlled cardinality.

## 3. Implemented scope

- Strict `observability` TOML configuration with recursive unknown-field
  rejection, restart-only activation semantics, access-log sampling, an exact
  maximum-series estimate, and bounded optional OTLP settings.
- Structured JSON application logs and a separate `aegisproxy_access` target.
  Access events contain stable configured IDs, normalized request ID, method,
  protocol, status class, bytes, duration, and completion outcome. Bodies,
  queries, authorization, cookies, arbitrary headers, and user agents are not
  recorded.
- A typed `prometheus-client` registry exposed only as authenticated
  OpenMetrics on the private administrative Unix socket. CLI retrieval uses
  `rust-proxy metrics --socket <path>`.
- Bounded families for HTTP requests/active requests/bytes/latency,
  connections, upstream attempts/latency/active work/health/retries, TLS
  handshakes, rate-limit decisions, reload outcome/duration, certificate
  expiry/renewal, durable-audit readiness/outcomes, and telemetry drops.
- Labels originate only from validated listener, route, upstream, endpoint,
  middleware, certificate, and issuer IDs or closed outcome/protocol/status
  enums. Removed configured-object series are pruned. OpenMetrics output is
  capped at 16 MiB; configurations estimated above 100,000 series are rejected.
- Optional OTLP/HTTP protobuf traces using a compatible pinned OpenTelemetry
  set, Rustls WebPKI roots, parent-aware sampling, W3C trace-context extraction
  and canonical injection, a finite queue/batch, and bounded shutdown/export
  time. Export work runs outside the Tokio request workers.
- Minimal `/live` and `/ready` probes plus authenticated `/health/details` with
  active revision, control/audit readiness, and stable certificate validity
  windows. Existing versioned paths remain compatible.
- Nine Prometheus alert rules and nine passing `promtool` firing simulations,
  an eight-panel Grafana dashboard, cardinality/redaction guidance, private
  Prometheus integration guidance, Loki label policy, and SIEM/audit-chain
  export/recovery guidance.
- The Phase 8 HMAC-chained durable audit remains separate from best-effort
  telemetry. Audit append failure sets readiness false and mutations continue
  to fail closed while the data plane serves.

## 4. Deferred scope

- Bundled Prometheus, Loki, Grafana, OpenTelemetry Collector, or SIEM storage.
- A public or wildcard-bound metrics/health listener.
- Provider freshness metrics until providers exist in Phase 11.
- Portable process CPU/RSS/file-descriptor and Tokio scheduler metrics; no
  stable dependency-free cross-platform source was selected.
- Detailed circuit-state transitions, idle-pool connection counts, and every
  internal queue depth. Existing request outcomes, health, retries, capacity
  behavior, and bounded resource tests remain available.
- Browser dashboards/UI code, clustering, HTTP/3, UDP, and plugins.
- Long fuzz campaigns and release-candidate soak belong to Phase 13. No new
  untrusted parser was introduced by the OpenMetrics registry.

## 5. Architecture decisions

- ADR-0015 remains accepted: `tracing` JSON, `prometheus-client` OpenMetrics,
  optional OTLP, bounded labels/queues, and durable audit separation.
- OTLP uses HTTP/protobuf with Rustls roots rather than gRPC/native TLS. This
  reuses the HTTP/Rustls trust model and avoids a second transport/native stack.
- Observability policy is restart-only. A reload cannot silently retain old
  exporter behavior under a newly displayed configuration.
- The private Unix socket is the sole scrape/health-details boundary. Public
  data listeners never route administrative endpoints.
- No PLAN correction or new material ADR was required.

## 6. Files created

- `crates/proxy-core/src/telemetry.rs`
- `crates/rust-proxy/src/telemetry.rs`
- `deploy/observability/grafana-dashboard.json`
- `deploy/observability/prometheus-rules.yaml`
- `deploy/observability/prometheus-tests.yaml`
- `docs/operations/observability.md`
- `docs/operations/siem.md`
- `docs/phase-9-completion.md`

## 7. Files modified

- `Cargo.lock`
- `config/schema-v1.json`
- `config/schema/admin-openapi.yaml`
- `crates/proxy-admin/src/server.rs`
- `crates/proxy-config/src/{lib,redact,revision}.rs`
- `crates/proxy-core/{Cargo.toml,src/acme_manager.rs,src/lib.rs}`
- `crates/proxy-core/src/{middleware/access,middleware/rate,route,runtime,tcp}.rs`
- `crates/proxy-core/src/upstream/pool.rs`
- `crates/proxy-core/tests/grpc.rs`
- `crates/rust-proxy/{Cargo.toml,src/main.rs}`
- `crates/rust-proxy/tests/admin_cli.rs`
- `docs/{configuration-v1,dependencies,implementation-readiness-review}.md`
- `README.md`

## 8. Dependencies added

- `prometheus-client 0.25.0` with defaults disabled for typed OpenMetrics.
- `opentelemetry 0.32.0` (`trace`, defaults disabled).
- `opentelemetry_sdk 0.32.1` (`trace`, defaults disabled).
- `opentelemetry-otlp 0.32.0` with only HTTP protobuf, blocking Reqwest
  exporter, Rustls WebPKI roots, and trace features.
- `tracing-opentelemetry 0.33.0` with defaults disabled.

Purpose, features, licenses, native/unsafe surface, alternatives, and upgrade
policy are recorded in `docs/dependencies.md`. No Git dependency was added.

## 9. Configuration introduced

`observability` now supports `access_log`,
`access_log_sample_per_million`, `metrics`, and optional `otlp_traces` with an
explicit endpoint, samples per million, queue size, batch size, and export
timeout. Credentials, query strings, fragments, unbounded queues, and plaintext
non-loopback endpoints are rejected. Preview/redaction never resolves or emits
secret material. The default keeps JSON access logs and private metrics enabled
and leaves OTLP disabled.

## 10. Tests added

- Recursive unknown observability field and unsafe OTLP endpoint/limit tests.
- Maximum-configuration series calculation and ceiling rejection.
- Typed label allowlist, raw-value rejection, stale-series reconciliation,
  certificate/audit/upstream/reload family tests.
- Invalid inbound trace-context stripping and canonical propagation boundary.
- Black-box daemon/API/CLI test with query, authorization, cookie, user-agent,
  and arbitrary-header canaries. Logs, metrics, audit, and token state are
  scanned; a held-open OTLP sink cannot delay a second proxied request.
- Authenticated metrics and health route coverage in checked OpenAPI.
- Existing audit reopen/tamper/sequence-chain tests retained and passed.
- Dashboard JSON/query lint and exact alert-to-simulation coverage.
- `promtool` syntax check and firing simulations for all nine alerts.

## 11. Commands executed

Final environment: Ubuntu 26.04 WSL2, kernel
`7.1.3-microsoft-standard-WSL2`, Rust/Cargo 1.97.1.

- `RUSTUP_TOOLCHAIN=stable cargo fmt --all -- --check` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo check --workspace --all-targets` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --all-targets --all-features -- -D warnings` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo test --workspace --all-features` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo tree -e features --workspace | wc -l` —
  exit 0, 2,445 lines.
- `rust-proxy validate --config config/examples/minimal.toml` — exit 0,
  output `valid`.
- Python JSON/YAML/schema/OpenAPI/dashboard/query/alert coverage lint — exit 0.
- Debian `promtool 2.53.5` `check rules` — exit 0, nine rules found.
- Debian `promtool 2.53.5` `test rules` — exit 0, all simulations passed.
- `RUSTUP_TOOLCHAIN=stable cargo audit` — exit 101, command unavailable.
- `RUSTUP_TOOLCHAIN=stable cargo deny check` — exit 101, command unavailable.
- `command -v gitleaks` — exit 1, command unavailable.
- `RUSTUP_TOOLCHAIN=stable cargo fuzz --help` — exit 101, command unavailable.
- `docker version` — exit 1; Docker Desktop WSL integration is unavailable.

Targeted config, telemetry, core, admin, and CLI integration tests plus strict
Clippy were run after their associated logical units. Temporary downloaded
`promtool` package files were removed after validation.

## 12. Actual command results

The final workspace suite passed 243 tests and ignored two:

- `aegisproxy-admin`: 15 passed.
- `aegisproxy-config`: 57 passed.
- `aegisproxy-core`: 116 passed, one ignored manual release reload benchmark.
- gRPC integration: one passed.
- `aegisproxy-secrets`: six passed.
- `aegisproxy-tls`: 40 passed.
- Pebble integration: one ignored because its Compose fixture is absent.
- Admin CLI integration: one passed.
- Certificate CLI integration: two passed.
- Configuration CLI integration: five passed.
- All doc-test targets passed with zero failures.

Project code produced no compiler or Clippy warning. Cargo still reports the
existing future-incompatibility warning for transitive
`proc-macro-error2 v2.0.1`.

## 13. Security checks

- All own crates retain `#![forbid(unsafe_code)]`; Phase 9 adds no unsafe block.
- Strict Clippy with warnings denied passed.
- Canary values were absent from JSON logs, OpenMetrics, audit records, token
  state, and trace attributes by allowlisted span construction. Trace payloads
  never receive raw header, host, path, query, cookie, authorization, user-agent,
  or client-IP fields.
- Untrusted trace headers are removed before upstream forwarding; only validated
  canonical W3C context from the active span may be injected.
- Metric labels and series are derived from validated bounded configuration or
  closed enums. Raw attacker values fail to create series in unit/integration
  tests.
- Metrics and detailed health require private peer authentication and RBAC.
- Durable audit remains HMAC-chained and mutation-gating; telemetry failure does
  not weaken it.
- Advisory, automated license, and dedicated secret scanning did not run because
  `cargo-audit`, `cargo-deny`, and `gitleaks` are unavailable.
- No independent observability/security review has occurred.

## 14. Performance checks

No throughput, latency, or production-capacity claim is made. The held-open
OTLP sink test proves two proxy requests complete below the two-second test
bound while export is stalled. Registry encoding is bounded to 16 MiB and the
configuration series estimate to 100,000. No representative load/soak or
collector-throughput benchmark was run.

## 15. Known limitations

- OTLP success interoperability with a real collector was not exercised; the
  exporter compiled and slow/unavailable behavior was tested.
- OpenTelemetry SDK-internal queue/export drop counts are not bridged into the
  process OpenMetrics registry. Access-log sampling drops are counted; exporter
  failures retain bounded SDK behavior and structured diagnostics.
- Process CPU/RSS/FD/Tokio scheduler, detailed circuit transition, audit disk
  usage, and idle upstream pool metrics are not exported.
- `/health/details` reports local control/audit/revision/certificate status;
  provider freshness is absent because providers are Phase 11.
- Prometheus needs a reviewed local UDS-capable collector or atomic textfile
  bridge; no TCP scrape listener is provided.
- Dashboard thresholds are examples, not measured SLOs.
- Fuzz smoke, Pebble, container, advisory/license/secret scans were unavailable.

## 16. Residual risks

- **High until independent review:** HTTP telemetry/redaction and trace-context
  propagation need protocol/application-security review.
- **Medium:** absent advisory/license/secret tooling leaves supply-chain evidence
  incomplete.
- **Medium:** OTLP collector compatibility and authentication topology require a
  representative staging deployment.
- **Medium:** telemetry gaps above can delay diagnosis of scheduler, circuit, or
  disk-pressure incidents; alerts must combine host/runtime monitoring.
- **Medium:** operator alert thresholds and scrape bridge have not been validated
  against real workload/cardinality.
- **Low/medium:** transitive `proc-macro-error2` may fail a future compiler.

## 17. Acceptance-criteria checklist

- [x] No request canary appears in emitted logs, metrics, audit records, token
  state, or the allowlisted trace schema.
- [x] A slow OTLP exporter cannot delay proxy requests; queue, batch, and timeout
  are bounded.
- [x] Every required example alert fires in a checked `promtool` simulation.
- [x] Series count has a deterministic documented formula, validates below the
  100,000 ceiling, and rejects an estimated overflow.
- [x] Private metrics and authenticated health details have checked API routes.
- [x] Durable audit remains separate, chained, bounded, and fail-closed for
  mutation.

## 18. Exit-criteria checklist

- [x] Phase 9 code, contract tests, dashboard, alerts, and runbooks are complete.
- [x] Formatting, compilation, strict Clippy, unit/integration/doc tests, and
  available artifact lint pass.
- [x] Known limitations and unavailable checks are explicit.
- [ ] Operators validate dashboards, collector integration, scrape bridge, and
  runbooks in a representative staging failure drill. This is an external
  operational gate and no staging system was authorized.
- [ ] Independent observability/redaction and protocol review. This remains a
  release gate and is not claimed complete.

## 19. Commit list

- `33876fa feat(config): define bounded telemetry policy`
- `bb37258 feat(metrics): expose bounded OpenMetrics`
- `242d327 feat(metrics): instrument upstream security state`
- `6593b9d feat(tracing): export bounded OTLP spans`
- `7bdc5d8 feat(metrics): expose certificate audit health`
- `a6aaad6 feat(admin): expose health probe aliases`
- `f367aa1 docs(observability): add operator bundle`
- `0a0d83a test(tracing): isolate slow OTLP exporter`
- `db41a49 feat(metrics): report runtime health outcomes`
- `631d4e9 feat(admin): report detailed health state`
- The separate Phase 9 report commit follows this list.

## 20. Readiness for the next phase

Phase 9 local implementation and available validation are complete. Per user
direction, work stops here. Phase 10 remains optional and unapproved; no web UI
was started. This repository is not production-ready: external review, staging
drill, missing supply-chain/security checks, Phase 13 hardening, and Phase 14
release evidence remain required.
