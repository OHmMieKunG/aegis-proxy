# Repository documentation audit

> Historical evidence from 2026-07-22. For current behavior and readiness, use
> [`STATUS.md`](../../../STATUS.md) and the
> [Phase 0–16 readiness audit](../../reviews/repository-readiness-phase-0-16.md).

Audit date: 2026-07-22
Verified commit: `aadac76a1618bdf9926ec37705b657fe64cdd430`
Evidence priority: source, tests, manifests, schemas, persistence, deployment, tooling, then docs.

Status meanings: implemented, partial, experimental, absent, planned, deferred, historical. Paths
below are exact repository paths. Production `.rs` paths in the Tests column contain inline
`#[cfg(test)]` modules; `Missing` explicitly records absent focused evidence.
“Current documentation” records audit-start condition; documentation actions were applied by this
rebaseline, while feature work remains assigned to its roadmap phase.

## Protocols

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| HTTP/1.1 | Implemented | `crates/proxy-core/src/lib.rs` (`serve_http1_connection`) | `crates/proxy-core/src/lib.rs` (`supports_http1_keep_alive`) | Incomplete | Update | Current/14 |
| HTTP/2 | Implemented | `crates/proxy-core/src/lib.rs` (`serve_http2_connection`) | `crates/proxy-core/src/lib.rs` (`proxies_http2_selected_by_alpn`) | Incomplete | Update | Current/14 |
| HTTP/3 | Absent | no dependency/listener in `Cargo.toml` or `crates/` | Missing: feature absent | Accurate/scattered | Clarify | 20 |
| HTTPS termination | Implemented | `crates/proxy-tls/src/acceptor.rs` | `crates/proxy-core/src/lib.rs` (TLS matrix tests) | Incomplete | Update | Current/17 |
| TLS passthrough | Implemented | `crates/proxy-core/src/tcp.rs` | `crates/proxy-core/src/lib.rs` (ClientHello integration tests) | Incomplete | Update | Current/20 |
| Raw TCP | Implemented | `crates/proxy-core/src/tcp.rs` | `crates/proxy-core/src/lib.rs` (`proxies_plain_tcp_bidirectionally`) | Incomplete | Update | Current/16 |
| UDP proxying | Absent | no schema/runtime in `crates/` | Missing: feature absent | Accurate | Clarify | 20, named protocol only |
| WebSocket | Implemented | `crates/proxy-core/src/lib.rs` (`is_websocket_upgrade`) | `crates/proxy-core/src/lib.rs` (`tunnels_websocket_upgrade_bytes`) | Incomplete | Update | Current |
| Server-Sent Events | Partial | `crates/proxy-core/src/middleware/compression.rs` excludes `text/event-stream` | Missing focused SSE test | Absent | Clarify | 19 |
| gRPC | Implemented | `crates/proxy-core/src/lib.rs` (H2 streaming/trailers) | `crates/proxy-core/tests/grpc.rs` | Incomplete | Update | Current |
| gRPC-Web | Absent | no translation in `crates/proxy-core` | Missing: feature absent | Absent | Clarify | 20 |
| PROXY v1 | Absent | `docs/adr/0023-high-availability.md` records external-LB model | Missing: feature absent | Accurate | Clarify | 20 |
| PROXY v2 | Absent | `docs/adr/0023-high-availability.md` records external-LB model | Missing: feature absent | Accurate | Clarify | 20 |
| Upstream TLS | Implemented | `crates/proxy-tls/src/client.rs` | `crates/proxy-core/src/lib.rs` (custom-CA/wrong-name tests) | Incomplete | Update | Current |
| Client mTLS | Absent | no client verifier/schema in `crates/proxy-tls` or `crates/proxy-config` | Missing: feature absent | Absent | Clarify | 20 |

## Routing and balancing

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| Domain routing | Implemented | `crates/proxy-config/src/lib.rs` (`RouteConfig.hosts`); `crates/proxy-core/src/route.rs` (`RouteIndex`) | `crates/proxy-core/src/route.rs` | Accurate/dense | Update | Current |
| Path routing | Implemented | `crates/proxy-core/src/route.rs` exact/prefix index | `crates/proxy-core/src/route.rs` | Accurate | Update | Current |
| Method matching | Implemented | `crates/proxy-config/src/lib.rs` (`RouteConfig.methods`) | `crates/proxy-config/src/conflict.rs`; `crates/proxy-core/src/route.rs` | Incomplete | Update | Current |
| Header matching | Implemented | `crates/proxy-config/src/lib.rs` (`HeaderMatch`) | `crates/proxy-core/src/route.rs` | Incomplete | Update | Current |
| Query matching | Absent | query preserved only in `crates/proxy-core/src/route.rs` | Missing: feature absent | Accurate | Clarify | 19 |
| Route priority | Implemented | `crates/proxy-config/src/conflict.rs` | `crates/proxy-config/src/conflict.rs` | Accurate | Update | Current |
| Round robin | Implemented | `crates/proxy-config/src/lib.rs` (`BalancingAlgorithm::RoundRobin`) | `crates/proxy-core/src/upstream/pool.rs` | Accurate | Update | Current |
| Weighted round robin | Implemented | `crates/proxy-core/src/upstream/pool.rs` (`select_smooth`) | `crates/proxy-core/src/upstream/pool.rs` | Accurate | Update | Current |
| Random | Implemented | `crates/proxy-config/src/lib.rs` (`BalancingAlgorithm::Random`) | Missing focused distribution test | Incomplete | Clarify | Current/19 |
| Power of two | Implemented | `crates/proxy-config/src/lib.rs` (`PowerOfTwo`) | `crates/proxy-core/src/upstream/pool.rs` | Accurate | Update | Current |
| Least connections | Absent | no variant in `crates/proxy-config/src/lib.rs` | Missing: feature absent | Absent | Clarify | 19 |
| Sticky sessions | Absent | no affinity policy in `crates/proxy-config/src/lib.rs` | Missing: feature absent | Absent | Clarify | 20 |
| Backup upstreams | Absent | no endpoint tier in `crates/proxy-config/src/lib.rs` | Missing: feature absent | Absent | Clarify | 19 |
| Upstream draining | Implemented | `crates/proxy-core/src/upstream/pool.rs` (`DrainingEndpoint`) | `crates/proxy-core/src/upstream/pool.rs` | Accurate | Update | Current |

## Resilience

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| Active health | Implemented | `crates/proxy-core/src/upstream/health.rs`; supervisor in `crates/proxy-core/src/lib.rs` | `crates/proxy-core/src/upstream/health.rs`; `crates/proxy-core/src/lib.rs` | Accurate | Update | Current |
| Passive health | Implemented | `crates/proxy-core/src/upstream/health.rs` | `crates/proxy-core/src/upstream/health.rs` | Accurate | Update | Current |
| Retries/retry safety | Implemented | `crates/proxy-config/src/lib.rs` (`RetryConfig`); `crates/proxy-core/src/lib.rs` | `crates/proxy-core/src/lib.rs` | Accurate | Update | Current |
| Circuit breaker | Implemented | `crates/proxy-core/src/upstream/circuit.rs` | `crates/proxy-core/src/upstream/circuit.rs` | Accurate | Update | Current |
| Connection limits | Implemented | `crates/proxy-core/src/middleware/limit.rs`; `crates/proxy-core/src/upstream/pool.rs` | `crates/proxy-core/src/middleware/limit.rs`; `crates/proxy-core/src/upstream/pool.rs` | Incomplete | Update | Current |
| Request limits | Implemented | `crates/proxy-config/src/lib.rs` (`LimitsConfig`); `crates/proxy-core/src/lib.rs` | `crates/proxy-core/src/lib.rs` | Incomplete | Update | Current |
| Graceful shutdown | Implemented | `crates/rust-proxy/src/main.rs`; `crates/proxy-core/src/runtime.rs` | `crates/rust-proxy/tests/signal_cli.rs`; `crates/proxy-core/src/upstream/pool.rs` | Accurate | Update | Current |
| Graceful reload | Implemented | `crates/proxy-core/src/runtime.rs`; `crates/rust-proxy/src/main.rs` | `crates/proxy-core/src/lib.rs` (`managed_file_reload_is_atomic_and_rejects_invalid_change`) | Accurate | Update | Current |
| Last-known-good | Implemented | `crates/proxy-config/src/revision.rs`; `crates/rust-proxy/src/main.rs` | `crates/proxy-config/src/revision.rs`; `crates/rust-proxy/tests/config_cli.rs` | Accurate | Update | Current |
| Rollback | Implemented | `crates/proxy-config/src/revision.rs` | `crates/proxy-config/src/revision.rs`; `crates/rust-proxy/tests/admin_cli.rs` | Accurate | Update | Current |

## TLS and certificates

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| Static certificates | Implemented | `crates/proxy-tls/src/generation.rs`; `crates/rust-proxy/src/main.rs` | `crates/proxy-tls/src/generation.rs`; `crates/rust-proxy/tests/cert_cli.rs` | Accurate | Update | Current |
| Automatic certificates | Implemented, explicit policy | `crates/proxy-core/src/acme_manager.rs` | `crates/proxy-core/src/acme_manager.rs`; `crates/proxy-tls/tests/pebble.rs` (ignored by default) | Incomplete versus automatic HTTPS | Clarify | 17 |
| ACME HTTP-01 | Implemented | `crates/proxy-tls/src/acme/challenge.rs` | same path; `crates/proxy-tls/tests/pebble.rs` (ignored by default) | Accurate | Update | Current/17 |
| ACME DNS-01 | Implemented for Cloudflare | `crates/proxy-tls/src/acme/dns_provider.rs` | same path; `crates/proxy-tls/tests/pebble.rs` (ignored by default) | Accurate | Clarify limit | Current/17 |
| ACME TLS-ALPN-01 | Implemented | `crates/proxy-tls/src/acme/challenge.rs` | same path; `crates/proxy-tls/tests/pebble.rs` (ignored by default) | Accurate | Update | Current/17 |
| Wildcard certificates | Implemented through DNS-01 | `crates/proxy-tls/src/acme/order.rs` | `crates/proxy-tls/src/acme/order.rs` | Accurate | Update | Current |
| Renewal scheduling | Implemented | `crates/proxy-tls/src/acme/scheduler.rs`; `crates/proxy-core/src/acme_manager.rs` | `crates/proxy-tls/src/acme/scheduler.rs`; `crates/proxy-core/src/acme_manager.rs` | Accurate | Update | Current |
| Renewal history | Absent | status only in `crates/proxy-core/src/acme_manager.rs` | Missing: feature absent | Absent | Clarify | 17 |
| Certificate storage | Implemented | `crates/proxy-tls/src/generation.rs` | `crates/proxy-tls/src/generation.rs` | Accurate | Update | Current |
| Secret encryption | Implemented | `crates/proxy-secrets/src/envelope.rs` | `crates/proxy-secrets/src/envelope.rs` | Accurate | Update | Current |
| Private-key protection | Partial | `crates/proxy-tls/src/generation.rs`; `crates/proxy-secrets/src/envelope.rs` | `crates/proxy-tls/src/generation.rs`; `crates/proxy-secrets/src/envelope.rs` | Incomplete | Clarify | 15/17 |
| Certificate export | Absent by design | metadata-only API in `crates/proxy-admin/src/server.rs` | `crates/proxy-config/src/redact.rs`; `crates/rust-proxy/tests/cert_cli.rs` | Incomplete | Clarify | 15 |

## Security and policy

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| Forwarded trust/trusted proxies | Implemented | `crates/proxy-core/src/middleware/normalize.rs` | same path; `crates/proxy-core/src/lib.rs` | Accurate | Split guide | Current |
| Domain-fronting protection | Implemented | `crates/proxy-core/src/route.rs` | `crates/proxy-core/src/lib.rs` (`rejects_authority_that_differs_from_sni`) | Incomplete | Update | Current |
| Smuggling defenses | Implemented at parsed boundary | `crates/proxy-core/src/lib.rs` (framing/header checks) | same path; `fuzz/fuzz_targets/header_processing.rs` | Incomplete | Update | Current |
| Header/body limits | Implemented | `crates/proxy-config/src/lib.rs` (`LimitsConfig`); `crates/proxy-core/src/lib.rs` | `crates/proxy-core/src/lib.rs` | Incomplete | Update | Current |
| IP allow/deny | Implemented | `crates/proxy-core/src/middleware/ip.rs` (`IpPolicy`) | `crates/proxy-core/src/middleware/ip.rs` | Accurate | Update | Current |
| Rate limiting | Implemented, node-local | `crates/proxy-core/src/middleware/rate.rs` | `crates/proxy-core/src/middleware/rate.rs` | Accurate | Update | Current |
| Basic auth | Implemented | `crates/proxy-core/src/middleware/auth.rs` | same path; `crates/proxy-core/src/lib.rs` | Accurate | Update | Current |
| OIDC/OAuth2 | Absent natively | ForwardAuth only in `crates/proxy-core/src/middleware/auth.rs` | Missing: native feature absent | Incomplete | Clarify | 19 |
| ForwardAuth | Implemented | `crates/proxy-core/src/middleware/auth.rs` | same path; `crates/proxy-core/src/lib.rs` | Accurate | Update | Current |
| API-token scopes | Absent | role only in `crates/proxy-admin/src/rbac.rs` | Missing: feature absent | Incomplete | Clarify | 15 |
| RBAC | Implemented, fixed | `crates/proxy-admin/src/rbac.rs` | `crates/proxy-admin/src/rbac.rs` | Accurate | Update | Current/15 |
| Audit logging | Implemented | `crates/proxy-admin/src/audit.rs` | `crates/proxy-admin/src/audit.rs` | Accurate | Update | Current |
| Secret redaction | Implemented | `crates/proxy-secrets/src/lib.rs` (`SecretBytes`); `crates/proxy-config/src/redact.rs` | `crates/proxy-secrets/src/lib.rs`; `crates/proxy-config/src/redact.rs` | Accurate | Update | Current |
| Secret rotation | Partial | component replace/revoke in `crates/proxy-admin/src/auth.rs` and `crates/proxy-tls/src/generation.rs` | `crates/proxy-admin/src/auth.rs`; `crates/proxy-tls/src/generation.rs` | Incomplete | Clarify | 15/17 |

## Control plane

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| Typed admin API | Implemented low-level | `crates/proxy-admin/src/server.rs`; `config/schema/admin-openapi.yaml` | `crates/proxy-admin/src/server.rs`; `crates/rust-proxy/tests/admin_cli.rs` | Incomplete | Clarify | 15 |
| Config/semantic validation | Implemented | `crates/proxy-config/src/lib.rs` (`load_bytes`, `validate`) | same path; `crates/rust-proxy/tests/config_cli.rs` | Accurate | Update | Current |
| Candidate preview | Implemented | `crates/proxy-admin/src/server.rs` (`/v1/config/preview`) | same path; `crates/rust-proxy/tests/config_cli.rs` | Incomplete | Update | Current/15 |
| Field-level diff | Absent | fingerprints/class only in `crates/proxy-admin/src/server.rs` | Missing: feature absent | Contradictory Rustdoc | Correct | 15 |
| Revision creation/activation | Implemented | `crates/proxy-config/src/revision.rs`; `crates/proxy-core/src/runtime.rs` | `crates/proxy-config/src/revision.rs`; `crates/proxy-core/src/runtime.rs` | Accurate | Update | Current |
| Optimistic concurrency | Implemented | `crates/proxy-admin/src/server.rs` (exact `If-Match`) | same path; `crates/rust-proxy/tests/admin_cli.rs` | Accurate | Update | Current |
| Rollback | Implemented | `crates/proxy-config/src/revision.rs` | same path; `crates/rust-proxy/tests/admin_cli.rs` | Accurate | Update | Current |
| Backup | Implemented | `crates/proxy-admin/src/backup.rs` | `crates/proxy-admin/src/backup.rs` | Accurate | Update | Current |
| Restore | Partial | `crates/proxy-admin/src/backup.rs` validates but does not extract/activate | Missing clean extraction/activation test | Easy to overread | Clarify | 21 |
| Restore validation | Implemented | `crates/proxy-admin/src/backup.rs`; `crates/proxy-admin/src/server.rs` | `crates/proxy-admin/src/backup.rs`; `crates/proxy-admin/src/server.rs` | Accurate | Update | Current |
| Runtime status/node drain | Implemented | `crates/proxy-admin/src/server.rs` | same path; `crates/rust-proxy/tests/ha_chaos.rs`; `crates/rust-proxy/tests/signal_cli.rs` | Incomplete | Update | Current |
| Fleet coordination | Partial | `crates/rust-proxy/src/fleet.rs`; external LB | `crates/rust-proxy/tests/ha_chaos.rs` | Accurate | Clarify no cluster | 21 |

## Dynamic infrastructure

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| File provider | Implemented | `crates/proxy-config/src/provider/file.rs` | same path; `crates/proxy-core/src/provider.rs` | Accurate | Update | Current/18 |
| DNS/SRV provider | Partial | A/AAAA only in `crates/proxy-config/src/provider/dns.rs` | same path; `crates/proxy-core/src/upstream/dns.rs` | Incomplete | Clarify | 18 |
| Docker/Kubernetes/Consul | Absent | no integrations in `crates/` | Missing: features absent | Accurate | Clarify | 18 / deferred Consul |
| Reconciliation | Implemented | `crates/proxy-core/src/provider.rs` (`ProviderCoordinator`) | `crates/proxy-core/src/provider.rs` | Accurate | Update | Current |
| Provider health | Implemented | `crates/proxy-core/src/provider.rs`; `crates/proxy-core/src/telemetry.rs` | both evidence paths; `crates/proxy-admin/src/server.rs` | Accurate | Update | Current |
| Conflict resolution | Partial | one provider per pool in `crates/proxy-config/src/lib.rs` | `crates/proxy-config/src/lib.rs` | Incomplete | Clarify | 18 |
| Approval policies | Absent | no object/workflow in `crates/proxy-config` or `crates/proxy-admin` | Missing: feature absent | Absent | Create roadmap | 18 |
| Stale cleanup | Implemented for current providers | static fallback in `crates/proxy-core/src/provider.rs` | `crates/proxy-core/src/provider.rs` | Accurate | Update | Current |

## User experience

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| Web GUI/first-run/admin creation | Absent | no UI workspace/assets/routes in repository | Missing: feature absent | Contradictory old direction | Correct | 16 |
| Proxy Host/Stream Host CRUD | Absent | low-level TOML only in `crates/proxy-admin/src/server.rs` | Missing: feature absent | Absent | Define API first | 15–16 |
| Certificate/access-policy GUI | Absent | backend metadata only in `crates/proxy-admin/src/server.rs` | Missing: feature absent | Absent | Plan | 16 |
| User/role GUI | Absent | fixed roles/token API in `crates/proxy-admin/src/rbac.rs` and `crates/proxy-admin/src/auth.rs` | Missing: feature absent | Absent | Plan | 15–16 |
| Dashboard/logs/health/revisions/rollback/backups/settings GUI | Absent | backend routes only in `crates/proxy-admin/src/server.rs` | Missing: feature absent | Absent | Plan | 16 |
| Human-readable errors | Partial | stable API codes/field errors in `crates/proxy-admin/src/server.rs` | `crates/proxy-admin/src/server.rs` | Incomplete | Document/extend | 15–16 |
| Progressive disclosure | Absent | no GUI/domain workflow in repository | Missing: feature absent | Absent | Acceptance gate | 16 |
| Responsive/accessibility | Absent | no UI in repository | Missing: feature absent | Absent | Acceptance gate | 16 |

## Observability and delivery

| Capability | Status | Evidence | Tests | Current documentation | Required action | Roadmap phase |
|---|---|---|---|---|---|---|
| Structured logs/metrics/tracing/OTel | Implemented | `crates/proxy-core/src/telemetry.rs`; `crates/rust-proxy/src/telemetry.rs` | `crates/proxy-core/src/telemetry.rs`; `crates/rust-proxy/src/telemetry.rs` | Accurate/incomplete | Update | Current |
| Request correlation/audit | Implemented | `crates/proxy-core/src/middleware/normalize.rs`; `crates/proxy-admin/src/audit.rs` | `crates/proxy-core/src/middleware/normalize.rs`; `crates/proxy-admin/src/audit.rs` | Accurate | Update | Current |
| Benchmarks | Experimental | `docs/benchmarks/reload-2026-07-16.md` | `crates/proxy-core/src/runtime.rs` (ignored benchmark) | Incomplete | Index/clarify | 21 |
| Fuzzing | Harness implemented; campaign incomplete | eight files under `fuzz/fuzz_targets/` | dated smoke only in `fuzz/README.md`; long campaign missing | Accurate | Clarify | 21 |
| Integration tests | Implemented | `crates/proxy-core/tests/`; `crates/rust-proxy/tests/`; `crates/proxy-tls/tests/` | `crates/proxy-core/tests/`; `crates/rust-proxy/tests/`; `crates/proxy-tls/tests/`; 268 current passes | Scattered | Create guide | Current/21 |
| End-to-end tests | Partial | `docs/history/validation/elysium-validation-2026-07-19.md` | Missing maintained automated suite | Incomplete | Archive/clarify | 21 |
| UI tests | Absent | no UI in repository | Missing: feature absent | Absent | Plan | 16 |
| Release workflow/SBOM/signing | Absent | `.github` absent; no release tooling | Missing: feature absent | Incomplete | Clarify | 21 |
| Container scanning | Absent | no workflow/current scan in repository | Missing: feature absent | Historical gap | Clarify | 21 |
| Multi-architecture images | Absent | `Dockerfile`; no build matrix | Missing: feature absent | Absent | Clarify | 21 |
| Upgrade/migration | Partial | `crates/proxy-config/src/lib.rs` schema policy; no migration command | `crates/proxy-config/src/revision.rs` only | Incomplete | Add guide | 15/21 |

## Documentation findings

- `PLAN.md` greenfield/no-UI claims contradicted code and approved direction; archived and replaced.
- Phase reports and dated evidence were moved under `docs/history/` with notices.
- README formerly linked stale readiness review; `STATUS.md` now owns current state.
- Local link scans found zero broken relative Markdown targets before and after moves.
- No repository-owned AGENTS, status, changelog, contribution guide, docs index, CI, or Markdown
  tooling existed.
- User concept guides remain deferred until stable Phase 15 objects prevent fictional documentation.
