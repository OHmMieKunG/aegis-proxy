# Phase 1: Minimal secure HTTP reverse proxy

## 1. Phase title

Minimal secure HTTP reverse proxy.

## 2. Original objectives

Proxy HTTP/1.1 and WebSocket traffic with streaming, cancellation, backpressure, safe framing, explicit resource budgets, deterministic failure behavior, and graceful shutdown.

## 3. Implemented scope

- HTTP/1.1 listener and pooled Hyper upstream client.
- Exact listener/host/path/method/header route matching with deterministic priority.
- Streaming request and response bodies with Hyper backpressure.
- Request-body limit for declared and chunked bodies.
- Header byte/count limits and request-header timeout.
- Upstream response-header timeout with 504 mapping; connect/protocol failures map to 502.
- WebSocket upgrade tunnelling with bidirectional copy, cancellation, and tracked shutdown.
- HTTP/1.1 downstream keep-alive and upstream connection reuse.
- Graceful listener stop, accepted-request drain, upgrade-task drain, and hard drain deadline.
- Client cancellation propagation to a pending upstream request.
- Hop-by-hop and `Connection`-nominated header removal.
- Untrusted forwarding and request-ID header removal.
- CONNECT, absolute-form, missing Host, malformed upgrade, and ambiguous framing rejection.
- Static literal-IP upstream policy. Link-local, multicast, and unspecified destinations are forbidden; private/loopback destinations require an explicit CIDR.
- Strict startup validation occurs before any listener bind.
- Non-root container, loopback-published Compose example, and hardened systemd unit.

## 4. Deferred scope

HTTP/2, gRPC, TLS, HSTS/SNI, multi-endpoint balancing, health checks, dynamic snapshots/reload, middleware execution, DNS, admin API, metrics, and access/audit logs remain in later phases. Forwarding-header reconstruction for explicitly trusted proxies remains deferred; Phase 1 always strips these headers.

## 5. Architecture decisions

Hyper remains the sole HTTP framing source. Parsed requests are reconstructed; raw inbound framing is never forwarded. DNS endpoints are rejected until a resolver can enforce policy on every answer and connection. Upgrade tasks use Tokio's existing task tracker rather than a new supervisor abstraction.

## 6. Files created

- `.dockerignore`
- `Dockerfile`
- `compose.yaml`
- `deploy/container.toml`
- `deploy/systemd/aegisproxy.service`

## 7. Files modified

- `crates/proxy-core/src/lib.rs`
- `crates/proxy-config/src/lib.rs`
- `config/examples/minimal.toml`

## 8. Dependencies added

No new direct dependencies beyond the Phase 0 workspace set. Existing Hyper, Hyper-util, Tokio, Tokio-util, HTTP-body-util, Tracing, and typed configuration crates cover Phase 1.

## 9. Configuration introduced

Phase 1 validates listener conflicts, limits, static endpoints, endpoint IDs, algorithms, literal IPs, explicit private CIDRs, route references, and startup state. Both checked-in TOML examples validate through the real CLI.

## 10. Tests added

The proxy-core suite contains 14 tests covering route predicates, unsafe request targets, HTTP forwarding, Host authority reconstruction, graceful drain, no-new-acceptance behavior, WebSocket tunnelling, response timeout, upload streaming, download streaming, H1 keep-alive, body limits, CL+TE ambiguity, slow headers, invalid startup, and client cancellation. The configuration suite contains four tests covering strict fields, duplicate binds, resource bounds, and egress policy.

## 11. Commands executed

- `cargo fmt --all -- --check` — passed.
- `cargo check --workspace --all-targets` — passed on the GNU Windows toolchain.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed.
- `cargo test --workspace --all-features` — passed: 18 workspace tests.
- `rust-proxy validate --config config/examples/minimal.toml` — passed.
- `rust-proxy validate --config deploy/container.toml` — passed.
- `docker compose config` — passed.
- `docker compose build proxy` — passed; latest Linux release image built.
- `docker compose run --rm --no-deps proxy validate --config /etc/aegisproxy/config.toml` — passed.
- `docker build --target test .` — passed on latest source: 18 Linux workspace tests.
- Ten-cycle Linux proxy-core smoke soak — passed: 130 test executions, zero failures.
- `cargo audit --version` and `cargo deny --version` — unavailable; neither cargo subcommand is installed. No audit success is claimed.

## 12. Actual command results

All format, compile, lint, local test, Linux test, image build, Compose schema, and configuration validation commands above exited 0. The first Linux test run exposed three listener-readiness races in test code; commit `e09b4e4` fixed them with a bounded readiness retry. The latest Docker test-stage run passed all 18 tests. The Windows GNU linker still emits a non-fatal `.drectve` warning caused by the local linker shim; Linux builds are clean.

## 13. Security checks

An internal request-reconstruction review found and fixed two defects before exit: CL+TE reached the service and was forwarded, and non-default upstream ports were absent from Host. Regression tests cover both. This is not an independent security review. No public admin listener, Docker socket, plaintext secret, production credential, or external CA was used.

## 14. Performance checks

Only a bounded ten-cycle Linux protocol smoke soak was run. It is a stability check, not a benchmark, throughput claim, latency target, or capacity envelope. Formal reproducible performance work remains assigned to later phases.

## 15. Known limitations

- Static HTTP upstreams must use literal IP addresses.
- One endpoint is selected per group; Phase 4 adds balancing and health state.
- HTTP/1.1 only; HTTP/2 and TLS begin in Phase 2.
- No generated request ID, access log, metrics, or trusted-proxy reconstruction yet.
- Route hostname canonicalization and conflict analysis are incomplete until Phase 3.
- The code remains in one source module; splitting follows only when Phase 2/3 responsibilities require it.

## 16. Residual risks

HTTP parser/translation correctness still requires external protocol review and a larger smuggling corpus. Current per-listener connection limits are global rather than per-client. There is no DNS path, so DNS rebinding is avoided rather than solved. The runtime image uses resolved upstream base digests during the recorded build, but Dockerfile tags are not yet pinned; release pinning is Phase 14.

## 17. Acceptance-criteria checklist

- [x] Black-box request streaming occurs before client completion.
- [x] Black-box response streaming occurs before upstream completion.
- [x] Header, body, timeout, and connection limits reject or drain deterministically in covered cases.
- [x] Cancellation propagates upstream.
- [x] No new listener acceptance is preferred after drain cancellation.
- [x] Accepted requests finish or reach the configured drain deadline.
- [x] Invalid startup validation occurs before listener bind.
- [x] WebSocket upgrade and bidirectional bytes pass.
- [x] H1 keep-alive and upstream reuse pass.
- [x] Linux workspace integration tests pass.
- [x] Bounded Linux smoke soak passes.

## 18. Exit-criteria checklist

- [x] Internal protocol/security review of request reconstruction completed.
- [x] Review findings fixed with regression tests.
- [x] Linux integration baseline passes.
- [x] Linux smoke-soak baseline passes.
- [x] Deployment manifests validate and the release image builds.
- [x] Deferred H2/TLS/multi-route work remains outside Phase 1 implementation.

## 19. Commit list

- `0798254` — bounded HTTP forwarding.
- `9831939` — request resource limits.
- `39cbc99` — static egress policy and graceful drain.
- `1fa44e7` — tracked WebSocket tunnels.
- `3f88bb8` — hardened development manifests.
- `9362c94` — HTTP header timeouts.
- `d4fbdca` — explicit ambiguous-framing rejection.
- `8610b38` — streaming, keep-alive, and startup tests.
- `e09b4e4` — cross-platform listener readiness fix.
- `c6a4a17` — cancellation propagation test.
- `81976f0` — container compilation cache.
- `b377d89` — upstream authority-port fix.
- `1f6e32e` — no-new-acceptance drain test.
- `95ab293` — reproducible Linux workspace test stage.

## 20. Readiness for the next phase

Phase 1 mandatory exit criteria are met. Phase 2 may add Rustls TLS termination and HTTP/2 without weakening the Phase 1 HTTP boundary. The project is not production-ready.
