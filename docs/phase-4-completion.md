# Phase 4: Load balancing and health checks

## 1. Phase title

Load balancing, health checks, bounded DNS, TCP proxying, and TLS passthrough.

## 2. Original objectives

Implement static and bounded DNS endpoint sets, deterministic load balancing, active/passive health, circuit breaking, safe retries, connection reuse, endpoint draining, raw TCP proxying, and bounded SNI-based TLS passthrough.

## 3. Implemented scope

- Round-robin, smooth weighted round-robin, deterministic pseudo-random, and power-of-two selection.
- Per-endpoint active counters and health-aware exclusion with healthy-before-starting bootstrap behavior.
- Bounded passive failure windows, recovery cooldowns, and separate active/passive hysteresis counters.
- Supervised HTTP/TCP active checks with immediate first probe, deterministic jitter, global concurrency cap, deadlines, and cancellation.
- Group-local bounded rolling circuit breaker with strict half-open permits and stale-result epochs.
- Bounded retries for configured attempts/time and exact-known replayable bodies; only safe idempotent methods; no WebSocket/gRPC replay; connect/header-timeout failures only.
- Hickory A/AAAA resolution with bounded answers, lookups, TTLs, stale lifetime, concurrency, and shutdown work.
- Full-set egress validation at startup/refresh and immediate pre-connect revalidation. Mixed allowed/forbidden DNS answers fail closed.
- Pinned custom Hyper resolver: a connector can use only the configured endpoint host and validated addresses.
- Raw TCP listeners with configured-only `tcp://` endpoints, bounded dial/idle/lifetime, backpressure, half-close behavior, and graceful drain.
- TLS passthrough with Rustls `server::Acceptor`, 16 KiB ClientHello bound, handshake deadline, exact/wildcard/default SNI selection, and byte-for-byte prefix preservation.
- Pool drain handles: beginning drain immediately excludes the endpoint and waits for active guards only to the configured deadline.
- Immediate public-listener socket release when graceful drain begins.

## 4. Deferred scope

- SRV discovery requires a later versioned schema because v1 cannot express service/protocol/priority/weight/port/TLS semantics.
- Live removed-endpoint idle-client eviction and drain integration are Phase 5 snapshot responsibilities. The pool contract is implemented and tested in Phase 4.
- Provider discovery remains Phase 11. Kubernetes, Consul, Docker metadata, UDP, HTTP/3, PROXY protocol, ALPN routing, and ECH routing remain deferred.
- Upstream status API DTOs are deferred until the Phase 5 runtime snapshot gives the Phase 8 administrative API a coherent state source; no speculative public DTO was added.

## 5. Architecture decisions

- ADR-0026 defines shared endpoint runtime handles, health state, attempt guards, circuit state, and Phase 4/5 drain ownership.
- ADR-0016 uses Rustls ClientHello parsing with caller-owned raw capture; handwritten TLS parsing remains forbidden.
- ADR-0027 uses `tcp` for one explicit default route, `tls_passthrough` for SNI routes, and `tcp://` for raw destinations.
- ADR-0017 limits Phase 4 DNS to A/AAAA and defers SRV until an explicit schema exists.
- HTTP-family and TCP-family listeners, routes, and endpoint groups cannot mix.
- Client input selects only among validated configured routes; SNI never becomes a destination hostname or port.

## 6. Files created

- `crates/proxy-core/src/upstream/{circuit,dns,health,pool}.rs`
- `crates/proxy-core/src/tcp.rs`
- `config/examples/tcp.toml`
- `docs/adr/0026-upstream-failure-state.md`
- `docs/adr/0027-tcp-routing-schema.md`

## 7. Files modified

- `PLAN.md`
- `Cargo.lock`
- `crates/proxy-config/src/lib.rs`
- `crates/proxy-core/{Cargo.toml,src/lib.rs,src/route.rs,src/upstream/mod.rs}`
- `crates/proxy-core/tests/grpc.rs`
- `crates/proxy-tls/src/generation.rs`
- `crates/rust-proxy/tests/config_cli.rs`
- `config/schema-v1.json`
- `docs/{configuration-v1.md,dependencies.md}`

The planned upstream directory split was used because health, DNS, balancing, and circuit state are independently testable. Retry execution remains near HTTP request forwarding because body ownership and response-byte boundaries are protocol-local.

## 8. Dependencies added

- `hickory-resolver 0.26.1`, default features disabled; `system-config` and `tokio` only, for TTL-aware bounded A/AAAA resolution.
- `tower-service 0.3` for the custom Hyper DNS resolver service contract.
- `ipnet 2` directly in proxy-core for validated egress policy types.
- Tokio `io-util` feature for bounded raw TCP relay.

`docs/dependencies.md` records purpose, features, license, native/unsafe exposure, alternatives, and upgrade policy. No Git dependency was added.

## 9. Configuration introduced

- Upstream algorithm, endpoint weights, active/passive health, retry, circuit-breaker, DNS, egress, and drain policies.
- `limits.max_health_checks`, `limits.max_dns_lookups`, and raw TCP connect/idle/lifetime bounds.
- `tcp` and `tls_passthrough` listener protocols plus explicit `tcp://host:port` endpoints.
- Strict cross-family validation, explicit ports, TCP-health requirement for TCP pools, and rejection of unsupported raw-TCP retry/TLS-client options.

## 10. Tests added

- Distribution and selection tests for all four algorithms, unavailable/starting/draining states, and active-guard accounting.
- Active/passive threshold, recovery, bounded-window, and state-isolation tests.
- Circuit rolling-window, open, half-open, stampede, and stale-result behavior.
- Real weighted request distribution, failover, active HTTP/TCP health, retry safety, and circuit request-count tests.
- DNS answer cap, mixed-answer rebinding rejection, stale expiry, pinned-host connector, and policy revalidation tests.
- Plain TCP bidirectional forwarding and shutdown drain.
- Fragmented ClientHello, byte-for-byte prefix preservation, exact/wildcard/default SNI precedence, unknown SNI, malformed/oversized/slow ClientHello, and no-upstream-dial failure behavior.
- Shipped TCP configuration validation and JSON Schema coverage.

## 11. Commands executed

- `cargo fmt --all -- --check` — passed.
- `cargo check --workspace --all-targets` — passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed.
- `cargo test --workspace --all-features` — passed after fixing the deterministic Windows TLS restart-path failure it exposed.
- Twenty serial `cargo test -q -p aegisproxy-core --all-features` iterations — passed.
- Focused config, pool, circuit, health, DNS, TCP, TLS-passthrough, gRPC, CLI-corpus, and TLS-generation regressions — passed.
- `config/schema-v1.json` through PowerShell `ConvertFrom-Json` — passed.
- `cargo tree -e features -p hickory-resolver --depth 1` — inspected; only intended direct features were selected.
- `cargo audit` and `cargo deny check` — attempted; both tools are unavailable, so no success is claimed.

## 12. Actual command results

The final workspace suite passed 112 tests: 27 configuration, 64 proxy-core, one gRPC, five secret, 12 TLS, one certificate CLI, and two configuration CLI tests. Documentation test binaries passed. The 20-iteration serial core/gRPC functional soak passed 1,300 tests with zero failures in 123.7 seconds.

Strict workspace Clippy and formatting exited zero. Windows GNU emitted the known linker `.drectve` warning, and Cargo retained the known future-incompatibility notice for transitive `proc-macro-error2 2.0.1`; neither was hidden or claimed resolved.

The first final workspace attempt exposed a deterministic Windows canonical-path bug in TLS generation restart. Commit `8c36a24` normalizes only internally generated verbatim drive references. The isolated regression and full workspace suite then passed.

## 13. Security checks

- DNS answers are bounded, full-set validated, stale-limited, pinned, and revalidated immediately before connection.
- Link-local, multicast, unspecified, metadata, loopback, and private destinations remain governed by explicit egress policy; denies override allows.
- No request field, Host, SNI, or query value can create an arbitrary upstream destination.
- Unsafe/unbounded body replay is not performed. gRPC, WebSocket, POST, and unknown-size bodies are attempted once under covered defaults.
- ClientHello parsing is bounded by size, time, and concurrency; malformed or unknown SNI closes only that flow.
- Captured TLS bytes are neither logged nor reconstructed and are forwarded exactly once.
- TCP and HTTP transport families cannot be accidentally mixed.
- Draining is terminal for health observations and excludes new work immediately.

No independent protocol/security review has been completed. Dependency advisory and license-policy tools remain unavailable locally.

## 14. Performance checks

The 20-iteration run is a functional stability soak, not a throughput benchmark. No RPS, latency, CPU, memory, allocation, TLS-handshake, or connection-scale claim is made. Reproducible performance methodology and named-hardware acceptance remain later work.

## 15. Known limitations

- Phase 5 must integrate live endpoint removal, reuse only identical runtime handles, evict idle clients, and enforce active drain deadlines across snapshot replacement.
- DNS SRV, dynamic providers, service-registry metadata, and cross-node health are absent.
- TLS passthrough supports SNI only; no ALPN predicates, ECH inner-name routing, PROXY protocol, or mixed HTTP/TCP bind.
- A 16 KiB ClientHello policy may reject extension-heavy clients; this is explicit and documented.
- Health/status state is not yet exposed through an administrative API.
- The Windows GNU linker warning and transitive future-incompatibility warning remain.

## 16. Residual risks

DNS and HTTP/TLS interoperability need independent review. Health oscillation and retry amplification require production-representative failure testing. Hyper idle-client eviction during live snapshot replacement is not proven until Phase 5. ClientHello compatibility needs a broader external corpus and fuzzing. Supply-chain checks are incomplete without `cargo-audit` and `cargo-deny`.

## 17. Acceptance-criteria checklist

- [x] Healthy endpoints are preferred; unavailable and draining endpoints are never selected.
- [x] All-unavailable groups fail without route fallback.
- [x] Active and passive thresholds transition exactly under unit/integration tests.
- [x] Weighted and health-aware selection matches deterministic covered behavior.
- [x] Unsafe/unbuffered/non-idempotent and gRPC/WebSocket requests are not replayed.
- [x] Retry attempt and wall-clock budgets are bounded.
- [x] Circuit half-open concurrency is bounded and stale results cannot close a new epoch.
- [x] DNS answers, lookup work, TTL, stale use, and egress policy are bounded and tested.
- [x] Plain TCP and SNI TLS passthrough pass black-box forwarding/failure/drain tests.
- [x] Beginning endpoint drain excludes new work and waits only to the configured deadline.
- [x] Twenty serial core/gRPC suite iterations pass without failure.
- [ ] Live endpoint-removal idle eviction and active drain across snapshot replacement; assigned to Phase 5 by the corrected phase boundary.

## 18. Exit-criteria checklist

- [x] Mandatory Phase 4 pool, health, retry, circuit, DNS, TCP, and TLS-passthrough behavior is implemented.
- [x] Configuration cannot silently accept an unsupported Phase 4 policy.
- [x] Failure/recovery functional soak passed with bounded amplification assertions in covered tests.
- [x] Full workspace tests, formatting, check, and strict Clippy pass.
- [ ] Independent DNS/HTTP/TLS protocol and security review is complete; required before production release, not before Phase 5 implementation.

Phase 5 may begin. Production readiness is not claimed.

## 19. Commit list

- `52e40c3` — define upstream failure boundaries.
- `17c7abd` — bound upstream policies.
- `1be763f` — add health-aware balancing.
- `37ad075` — supervise active health checks.
- `9ec2edc` — add bounded circuit breaker.
- `7453632` — add bounded safe retries.
- `8f51a25` — defer SRV to explicit schema.
- `2526fda` — add bounded DNS resolution.
- `19c93d9` — define TCP routing schema.
- `6a851a4` — add bounded TCP passthrough.
- `6e7585e` — close listener before drain.
- `2285c1a` — coordinate endpoint draining.
- `35df7dd` — align drain acceptance phases.
- `8c36a24` — normalize Windows file references.

## 20. Readiness for the next phase

The data plane now has immutable route/pool state, bounded endpoint resolution, health/circuit/retry behavior, TCP/SNI transport support, active-work guards, and an explicit drain contract. Phase 5 can build transactional revision persistence and atomic runtime snapshots, reusing identical endpoint handles while draining changed/removed handles. It must prove crash recovery, failed-candidate isolation, long-stream continuity, idle-client eviction, and last-known-good rollback. The project is not production-ready.
