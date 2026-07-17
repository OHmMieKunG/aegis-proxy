# Phase 7 completion: middleware and authentication

Date: 2026-07-17

## 1. Phase title

Phase 7: Middleware and authentication.

## 2. Original objectives

Implement the fixed middleware pipeline and approved v1 middleware: forwarding/request-ID normalization, redirect and rewrite, typed request/response/security headers, request/body/time/in-flight limits, CORS, Basic authentication, ForwardAuth/Authentik, trusted-client IP policy, edge and principal rate limits, bounded retry/circuit integration, maintenance/custom errors, streaming compression, and access events.

## 3. Implemented scope

- Compiled middleware stages independent of configuration list order, with duplicate/incompatible-stage rejection before activation.
- Trusted forwarding-chain and request-ID normalization. Untrusted forwarding identity is removed; generated and accepted IDs are bounded.
- Fixed redirects; segment-aware path rewrites that never rematch; typed request/response mutation; HSTS/CSP validation.
- Deny-first IP policy, bounded client-IP/principal token buckets, route/client and upstream-group in-flight semaphores, no waiting queues, and limiter reuse across equivalent reloads.
- Declared body-size rejection before terminal/auth middleware. Existing Phase 1/4 connection, header, upstream, retry, and drain deadlines remain the timeout core.
- Strict exact-origin CORS with preflight before authentication and scoped actual-response headers.
- TLS-only Basic authentication with secret-referenced Argon2id PHC hashes, validated cost parameters, generic denials, bounded blocking work, and deadlines.
- TLS-only fail-closed ForwardAuth using a configured upstream group, strict request/response header allowlists, bounded response/deadline, required principal, safe redirects, and client identity-header stripping.
- Static public/authenticated maintenance policy and bounded static custom pages for selected upstream or internal 5xx failures, with no interpolation or route rematch.
- Streaming gzip/Brotli negotiation with exact content-type policy, conservative protocol/sensitivity exclusions, and bounded encoder concurrency.
- Final structured access events with stable listener/route IDs, normalized request ID, method, status, bytes, duration, completion, and body-error state. Raw path, query, host, client IP, user agent, headers, cookies, authorization, and principal are not recorded.
- Validated `config/examples/phase7.toml`, updated companion JSON Schema, middleware contract/interaction matrix, and Authentik guide.

The Phase 4 retry and circuit implementation was reused rather than duplicated into a speculative `middleware/retry.rs`. The planned generic `error.rs` is represented by the narrower `custom_error.rs` module.

## 4. Deferred scope

- Native route OIDC and browser sessions.
- Arbitrary middleware ordering or runtime middleware plugins.
- Cache/store plugins and a general response-buffering middleware. V1 buffers only explicitly bounded retry/auth work.
- Prometheus, OpenTelemetry export, bounded asynchronous log delivery, rotation, and SIEM integration (Phase 9).
- Web UI (Phase 10), service discovery (Phase 11), clustering (Phase 12), and HTTP/3/UDP evaluation (Phase 13 or later).

## 5. Architecture decisions

- Retained the approved one-process Hyper/Tokio model and fixed compiled stage order from `PLAN.md`; no new ADR was required.
- Security identity is computed once at the forwarding boundary and reused by IP, rate, in-flight, auth, audit, and upstream header construction.
- Limits reject immediately instead of queueing. Permits live through streamed response/WebSocket/TCP lifetime as applicable.
- Authentication supports one route policy: Basic or ForwardAuth. ForwardAuth is the v1 Authentik/OIDC integration boundary; native OIDC stays deferred.
- Response finalization is centralized: custom error, response/security/CORS mutation, then compression. It never rematches.
- Access events wrap the final response body so status/byte/duration accounting observes cancellations and errors.

## 6. Files created

- `crates/proxy-core/src/middleware/{access,auth,compression,cors,custom_error,headers,ip,limit,maintenance,mod,normalize,rate,redirect,rewrite}.rs`
- `config/examples/phase7.toml`
- `docs/guides/authentik-forward-auth.md`
- `docs/middleware.md`
- `docs/phase-7-completion.md`

## 7. Files modified

- `Cargo.lock`
- `config/schema-v1.json`
- `crates/proxy-config/src/{lib,revision}.rs`
- `crates/proxy-core/Cargo.toml`
- `crates/proxy-core/src/{lib,route,runtime}.rs`
- `crates/proxy-core/src/upstream/pool.rs`
- `crates/rust-proxy/tests/config_cli.rs`
- `docs/{configuration-v1,dependencies}.md`

## 8. Dependencies added

- `argon2 0.5.3`: bounded Argon2id Basic-auth verification; minimal `alloc,password-hash` features.
- `async-compression 0.4.42`: streaming gzip/Brotli; minimal `tokio,gzip,brotli` features.
- `base64 0.22`: strict Basic credential decoding; `alloc` only.
- `getrandom 0.3`: operating-system request-ID entropy; failure is explicit.
- `zeroize 1`: owned authentication secret-buffer cleanup.
- `futures-util 0.3` moved from dev-only to runtime for fallible streaming body adapters.
- `tokio-util` enabled its `io` feature for streaming compression adapters.

Purposes, licenses, native/unsafe surface, alternatives, and upgrade policy are recorded in `docs/dependencies.md`. No Git dependency was added.

## 9. Configuration introduced

`MiddlewareConfig` now supports `security_headers`, `rate_limit` (`client_ip` or `principal`), `in_flight_limit`, `ip_policy`, `cors`, `basic_auth`, `forward_auth`, `rewrite`, `header_mutation`, `maintenance`, `custom_error`, `compression`, and `redirect`. Upstream groups gained bounded `max_in_flight` (default 1024). Cross-route validation enforces terminal-action exclusivity, one policy per stage, HTTPS authentication/HSTS rules, principal-rate authentication, protected-header rejection, reference validity, and aggregate capacity limits.

The shipped Phase 7 example uses secret references and placeholder local endpoints/certificate paths. It is a validation fixture, not deployment-ready configuration.

## 10. Tests added

- Strict schema and cross-stage validation for every Phase 7 middleware variant.
- Unit tests for normalization, redirects, rewrite canonicalization, header protection, IP precedence, rate-key bounds/reload reuse, in-flight lifetime/reload reuse, auth cost/header/redirect rules, CORS, maintenance, custom errors, compression negotiation/exclusions, and access-body preservation.
- Black-box tests for trusted/untrusted forwarding, redirects without upstream dial, CORS preflight versus auth, Basic principal replacement, ForwardAuth allow/deny/timeout/spoof behavior, rate ordering, route/upstream in-flight body lifetime, rewrite without rematch, maintenance, internal/upstream custom errors, compression, and early body limits.
- The CLI valid/invalid corpus now validates `config/examples/phase7.toml`.

The reviewed mapping from interactions to concrete tests is in `docs/middleware.md`.

## 11. Commands executed

Final gate on 2026-07-17:

- `cargo fmt --all -- --check` — exit 0.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` — exit 0.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets --all-features -- -D warnings` — exit 0.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace --all-features` — exit 0.
- `cargo tree -e features --workspace` — exit 0; 2,215 lines reviewed/output generated.
- `cargo +stable-x86_64-pc-windows-gnu test -p rust-proxy --test config_cli shipped_valid_and_invalid_corpus_has_expected_result` — exit 0.
- PowerShell `ConvertFrom-Json` parse of `config/schema-v1.json` — exit 0.
- `cargo audit` — exit 1: `cargo-audit` is not installed (`no such command`).
- `cargo deny check` — exit 1: `cargo-deny` is not installed (`no such command`).

Targeted unit and black-box tests were run after the associated logical changes. One targeted access test attempt timed out after 305.8 seconds during the Windows GNU build with no compiler output; a compile check then passed and the same targeted test was rerun successfully (1 passed). No passing result is claimed for the timed-out attempt.

## 12. Actual command results

The final full workspace suite passed:

- `aegisproxy-config`: 52 passed.
- `aegisproxy-core`: 115 passed, 1 ignored manual release-mode reload benchmark.
- gRPC integration: 1 passed.
- `aegisproxy-secrets`: 6 passed.
- `aegisproxy-tls`: 40 passed.
- Pebble integration: 1 ignored because `tests/pebble/compose.yml` is not present.
- Certificate CLI integration: 2 passed.
- Configuration CLI integration: 4 passed.
- All doc-test suites passed with zero failures.

The GNU linker emitted its existing `corrupt .drectve at end of def file` warning. Cargo also reported the existing future-incompatibility warning for transitive `proc-macro-error2 v2.0.1`. Neither warning caused a failed check; both remain tracked risks.

## 13. Security checks

- Strict Clippy with warnings denied passed for workspace source.
- Workspace crates retain `#![forbid(unsafe_code)]`; Phase 7 adds no project unsafe block.
- Pairwise regression tests verify forwarding spoof resistance, protected-header handling, auth fail-closed behavior, TLS-only auth, body-limit ordering, no route rematch, bounded limiter state, retry safety, and compression exclusions.
- Access events intentionally omit high-risk and high-cardinality request fields.
- `cargo-audit` and `cargo-deny` were unavailable, so advisory/license policy did not pass locally. CI or a prepared release environment must run them.
- No independent application-security, protocol, or Authentik interoperability review has occurred.

## 14. Performance checks

No new throughput or latency claim is made. Unit tests verify bounded key stores, semaphore release, stream lifetime, and compression concurrency. The final full suite completed in 68.3 seconds on the current Windows GNU development environment. A reproducible release-mode middleware/compression/auth benchmark was not run; it remains required before production assessment.

## 15. Known limitations

- Access events use the process tracing subscriber; Phase 9 must provide bounded asynchronous delivery, rotation/export guidance, metrics, and traces.
- WebSocket access accounting covers the HTTP upgrade response, not tunnel-byte totals.
- ForwardAuth compatibility must be verified against the deployed Authentik version and topology.
- Compression is deliberately skipped for unknown-size and sensitive/protocol-specific responses; operators cannot force unsafe cases.
- Custom maintenance/error content is static and cannot interpolate request data.
- No general buffering middleware exists; this is intentional v1 scope.
- Linux container/systemd behavior and Authentik interoperability were not exercised in this Windows phase gate.

## 16. Residual risks

- **High until independent review:** authentication header contracts and ForwardAuth outage/domain-routing blast radius.
- **Medium:** compression CPU/latency behavior under hostile negotiation; concurrency is bounded but not benchmarked.
- **Medium:** synchronous subscriber/exporter configuration can still affect request latency until Phase 9 isolation.
- **Medium:** absent local advisory/license tools leave dependency policy incompletely verified.
- **Low/medium:** GNU linker warning and transitive future-incompatibility may become build blockers after toolchain upgrades.
- **Low:** route/middleware interaction regressions remain possible as new stages are added; the fixed-stage validator and matrix must be extended with every future variant.

## 17. Acceptance-criteria checklist

- [x] Configuration cannot express arbitrary middleware order; runtime compiles fixed stages.
- [x] Duplicate and incompatible stage combinations fail validation.
- [x] ForwardAuth response headers cannot overwrite hop-by-hop, framing, forwarding, routing, TLS, cookie-response, or other protected fields.
- [x] Basic and ForwardAuth denial/redirect/timeout behavior is documented and regression-tested.
- [x] Client-IP and principal rate-key stores have configured maximums and bounded eviction behavior.
- [x] Route/client and upstream in-flight work is bounded and held through streamed work.
- [x] Pairwise security interactions listed in the phase plan have unit or black-box regression evidence.
- [x] A combined shipped example passes the real offline CLI validator.
- [x] Formatting, compilation, strict Clippy, and full workspace tests pass.
- [ ] Dependency advisory and license commands pass locally; tools are unavailable.
- [ ] Independent security and Authentik interoperability review; required before production use.

## 18. Exit-criteria checklist

- [x] Fixed stage matrix reviewed against implementation.
- [x] Shipped Phase 7 example validates through the binary CLI test.
- [x] Implemented combinations have black-box/regression tests mapped in `docs/middleware.md`.
- [x] Mandatory Phase 7 functionality is implemented or explicitly tied to the already-active Phase 1/4 timeout/retry core.
- [x] Deferred features remain deferred.
- [x] No unresolved compiler, Clippy, unit, integration, or documentation-test failure.
- [x] Phase 8 has not started.

## 19. Commit list

1. `5e2105c` `fix(proxy): normalize trusted forwarding`
2. `d89fa81` `feat(proxy): propagate trusted request IDs`
3. `83fda95` `feat(middleware): add redirects and headers`
4. `42fd165` `feat(middleware): enforce route IP policy`
5. `83590af` `fix(test): avoid revision path collisions`
6. `5de8036` `feat(middleware): add bounded edge limits`
7. `d5f6c18` `feat(middleware): enforce strict CORS`
8. `83f4f3a` `feat(middleware): add bounded Basic auth`
9. `39f5a5a` `fix(proxy): reject large bodies before middleware`
10. `1bc16ee` `feat(middleware): add typed path rewrites`
11. `256e0c0` `feat(middleware): add typed header mutation`
12. `505faa5` `feat(auth): add fail-closed ForwardAuth`
13. `0ef3508` `feat(middleware): add static maintenance`
14. `c95d538` `feat(middleware): add static upstream errors`
15. `22171cc` `feat(middleware): rate-limit principals`
16. `f64d58d` `feat(middleware): stream response compression`
17. `2c19f84` `feat(upstream): bound in-flight work`
18. `1d702c0` `feat(middleware): bound in-flight requests`
19. `ed40579` `fix(middleware): customize proxy failures`
20. `228ed70` `feat(logging): add bounded access events`
21. `2fecafd` `test(config): add phase 7 example`
22. `94f0ec4` `docs(middleware): publish phase 7 contract`

The separate phase-report commit is appended after this file is committed.

## 20. Readiness for the next phase

Phase 7 mandatory implementation and local compiler/test gates are complete. The repository is ready to begin Phase 8 administrative API/CLI work, subject to the recorded unavailable dependency-policy tools and later independent reviews. Per operator instruction, Phase 8 is not started in this work session.
