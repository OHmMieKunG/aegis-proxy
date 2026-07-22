# Production Rust Reverse Proxy — Implementation Plan

> Historical document
>
> This plan was superseded on 2026-07-22 after phases 0–13. It remains unchanged below for decision traceability. See [`STATUS.md`](../../../STATUS.md) and [`PLAN.md`](../../../PLAN.md).

Status: architecture plan only; no implementation exists yet
Research date: 2026-07-15 (Asia/Bangkok)
Working binary name: `rust-proxy` (rename before Phase 1 if desired)

## 1. Executive summary

Build a security-first reverse-proxy platform as one Rust process and one deployable binary. The first production release will use declarative, strictly validated TOML configuration and a local CLI/API; it will not include a web UI, arbitrary runtime plugins, a database, clustering, UDP proxying, or HTTP/3. This keeps the first release small enough to audit while still delivering HTTP/1.1, HTTP/2, WebSocket, gRPC, TCP/TLS passthrough, TLS termination, ACME, health-aware load balancing, safe hot reloads, core middleware, metrics, tracing, and hardened deployment.

The design adopts concepts, not code:

- From NPMPlus: operator-friendly workflows, certificate visibility, per-route policy, access lists, auditability, and a future management UI.
- From Caddy: canonical typed configuration, preflight validation, atomic activation, last-known-good rollback, automatic certificate lifecycle, safe failure during CA outages, and a single-binary operational model.
- From Traefik: the explicit listener/router/middleware/service/provider vocabulary, namespaced discovery, continuous configuration updates, TCP/TLS routing, and observable per-route/per-upstream state.

The selected data-plane foundation is Tokio + Hyper + Rustls, not Pingora. Hyper gives direct control over HTTP protocol boundaries, streaming, cancellation, Tower interoperability, and Rustls integration. Pingora remains a benchmark-backed revisit option because its Rustls integration is described as experimental, it is Linux-first, and adopting it would commit the project to a larger proxy framework before requirements are validated.

Security is expressed as measurable controls and test obligations, never as a claim that the product is vulnerability-free. Invalid or ambiguous configuration is rejected. Failed live activation leaves the current snapshot serving. Certificate renewal never deletes a working certificate before a replacement is verified and activated. The administrative endpoint is not public by default.

## 2. Current repository assessment

The application workspace at `C:\KMITL-CE\LAB\NPM Rust` was inspected before this plan was written and rechecked after drafting.

| Area | Verified state | Consequence |
|---|---|---|
| Files | Initial inspection found zero items. Final recheck found `PLAN.md` plus empty `.git` and `.agents` directories that appeared during the managed session; no source/project files exist. | This is a greenfield design; no existing code can be reused. The origin of the empty managed-session directories is not assumed. |
| Git | The final empty `.git` placeholder is not a valid repository; `git status` still reports “not a git repository.” | Phase 0 must initialize version control and repository policy. |
| Rust | No `Cargo.toml`, source, toolchain file, or lockfile | Toolchain/MSRV and workspace layout are new decisions. |
| Dependencies | None | Every dependency below is proposed, not already installed. |
| Configuration/docs | None | `PLAN.md` is the first repository artifact. |
| CI/CD | No `.github`, workflows, release scripts, or scanners | Phase 0 must establish all CI and release controls. |
| Deployment | No Dockerfile, Compose, systemd, Kubernetes, or packaging files | Deployment artifacts are phased and must not be claimed as implemented. |
| Database/migrations | None | The MVP deliberately starts without a database. |
| API/auth | None | All trust boundaries are new and require implementation plus review. |
| Local environment | Windows/PowerShell; production target is Linux | Development must remain cross-platform where practical; low-port binding, capabilities, seccomp, and systemd are Linux-specific. |

Architecture map:

```text
Project type:       empty greenfield repository
Main entrypoints:   none
Backend structure:  none
Frontend structure: none
Persistence:        none
Security boundary:  none implemented
Build/test commands:none
Deploy/CI files:    none
Highest risk:       creating protocol, configuration, certificate, and admin trust boundaries correctly
```

No repository API, dependency, test result, benchmark, or implementation status is implied by this document. `PLAN.md` is the only authored deliverable in the workspace.

## 3. Goals

1. Proxy HTTP/1.1 and HTTP/2 correctly with streaming bodies, backpressure, cancellation, connection reuse, WebSocket upgrades, and gRPC trailers.
2. Terminate TLS with Rustls, route by SNI/host/path/header/method, and support explicit TCP TLS passthrough.
3. Provide static and DNS upstreams, deterministic weighted load balancing, active/passive health checks, draining, bounded retries, and graceful shutdown.
4. Automate ACME HTTP-01, DNS-01, and TLS-ALPN-01 with durable encrypted private-key/account storage and safe renewal failure behavior.
5. Make configuration strict, typed, reviewable, versioned, atomically activated, rollback-capable, and usable offline.
6. Keep administration private by default with Unix-socket access, explicit remote enablement, authentication, RBAC, optimistic concurrency, and audit logs.
7. Make all important state visible through structured logs, access/audit logs, Prometheus/OpenMetrics metrics, OpenTelemetry traces, and health endpoints.
8. Produce a minimal non-root container and a hardened systemd deployment, plus backup/restore and signed upgrade/rollback procedures.
9. Keep the workspace safe Rust. Any transitive unsafe/native code must be inventoried and reviewed rather than ignored.
10. Preserve a clear path to a separate UI, discovery providers, HTTP/3, and high availability only when their costs are justified.

## 4. Non-goals

The following are not first-release commitments:

- A general-purpose web server, PHP runtime, file browser, CDN, WAF, bot detector, or response cache.
- Arbitrary Nginx/Caddy/Traefik configuration compatibility.
- Source or binary compatibility with NPMPlus, Caddy, or Traefik.
- Runtime-loaded native plugins, embedded scripting, user-supplied shell hooks, or execution of configuration as code.
- A public-by-default administrative API or dashboard.
- Kubernetes ingress/controller behavior, Consul/etcd integration, or automatic exposure of containers.
- Multi-tenant SaaS control-plane isolation or billing.
- FIPS certification. A FIPS-capable dependency does not make this product certified.
- Guaranteed zero downtime for changes that require rebinding an existing address with incompatible listener settings.
- Guaranteed performance numbers before the benchmark environment and baselines are recorded.
- A claim of complete security or absence of vulnerabilities.

## 5. Assumptions

- Initial production target: modern 64-bit Linux (`x86_64` and `aarch64`) with kernel-supported nonblocking sockets.
- One trusted operator owns the initial configuration file and host. Multi-user browser administration arrives only with the UI phase.
- Ports 80/443 can be provided through systemd socket activation, rootless port forwarding, or `CAP_NET_BIND_SERVICE`; the process itself runs non-root.
- Configuration authors are trusted administrators, but configuration files, provider metadata, inbound traffic, DNS answers, upstream responses, and administrative clients are still treated as potentially malformed or compromised.
- The repository will use a dual `MIT OR Apache-2.0` project license unless legal review selects another permissive license. No AGPL source is copied.
- The first release is single-node. High availability uses multiple independent data-plane instances behind an external load balancer before any custom consensus system is considered.
- The system trust store is appropriate for upstream TLS unless a route supplies an explicit CA bundle.
- ACME DNS-01 initially supports a small, reviewed provider set (proposed: Cloudflare API and RFC 2136), not every DNS vendor.
- `Needs verification`: final crate versions, MSRV, feature flags, and transitive license/unsafe inventories must be locked during Phase 0 because dependency state changes over time.

## 6. Constraints

- Own workspace crates use `#![forbid(unsafe_code)]` and deny warnings in CI.
- Unknown configuration fields are errors. Deprecated fields are errors after their documented migration window.
- No inline plaintext secrets in normal configuration. Secret references are resolved through explicit providers.
- No arbitrary upstream URL can be derived from an inbound request; configured upstreams are the only egress targets.
- No direct Docker socket mount in the data-plane process.
- No silent fallback from an invalid startup configuration. `--resume-last-known-good` is explicit.
- Live activation is transactional at the structural commit point: validate and prepare first, durably record the revision/audit intent and active pointer, then perform the non-failing snapshot publication; otherwise retain the active snapshot.
- Queues, bodies, headers, connections, DNS answers, background work, rate-limit keys, metrics labels, and log buffers are bounded.
- Request and response bodies stream by default. Buffering is opt-in and size-limited.
- Security-sensitive defaults cannot be disabled by a generic “advanced config” text box.
- Feature work must land with the smallest runnable check that detects regression; protocol/security paths require integration or adversarial tests.

## 7. Comparative analysis: NPMPlus, Caddy, and Traefik

### 7.1 Research provenance

Official repositories were shallow-cloned and inspected at these snapshots:

| Project | Snapshot | License observed | Primary material |
|---|---|---|---|
| NPMPlus | `513f14bbfd8735d08eafc74c5b1b63eded688fa5` (`develop`, 2026-07-15) | AGPL-3.0-or-later fork with MIT-origin material | [repository](https://github.com/ZoeyVid/NPMPlus), `backend`, `frontend`, Nginx templates, Certbot integration, Dockerfile, Compose, workflows |
| Caddy | `873fac5fc094fe538d0c477509127bb321d51a32` (`master`, 2026-07-12) | Apache-2.0 | [repository](https://github.com/caddyserver/caddy), core config/admin lifecycle, HTTP/TLS modules, storage, CLI, workflows |
| Traefik | `4bc7630e9dc0b51fc308d9622c326ccc46cd030c` (`master`, 2026-07-15) | MIT | [repository](https://github.com/traefik/traefik), static/dynamic config, providers, routers, middleware, ACME store, dashboard, workflows |

Documentation is behavior/context evidence; source inspection confirms current structure. Conclusions labeled “inference” are independent engineering judgments, not upstream claims. No upstream source will be copied.

### 7.2 Feature and architecture comparison

| Area | NPMPlus | Caddy | Traefik | Independent conclusion |
|---|---|---|---|---|
| Primary product shape | Nginx-based proxy manager with Node/Express API, React UI, relational model/migrations, generated Nginx templates, Certbot, and a multi-component container | Single Go server platform with JSON-native config, Caddyfile adapter, admin API, modules, automatic HTTPS | Single Go application proxy with install/static config plus provider-fed routing/dynamic config, dashboard/API | Start as one Rust binary, but keep a typed router/service model and future UI boundary. |
| Configuration | UI/API writes database state that renders Nginx config; “advanced” and prerun escape hatches exist | Canonical JSON plus adapters; API loads validated config and rolls back failed reloads | Separate install and routing config; multiple providers merge namespaced objects and hot-reload | Use one strict TOML source of truth in v1, compiled into an immutable runtime snapshot. Add providers only after file behavior is solid. |
| HTTP proxy | Nginx HTTP/1/2/3, gRPC, WebSocket, compression, headers, access controls | Core HTTP/1.1/2/3 proxy, streaming, health checks, load balancing, retries | HTTP/1.1/2/3, WebSocket, gRPC, many middleware/load-balancer options | Deliver HTTP/1.1/2 first. Treat HTTP/3 as a separate transport project. |
| TCP/UDP | Nginx stream proxy, proxy protocol, TCP/UDP options | Core project focuses on HTTP; layer 4 normally requires an additional module | First-class HTTP, TCP, UDP routers/services and TLS passthrough | Implement bounded TCP/TLS passthrough in v1; defer UDP session tracking. |
| TLS/certificates | Certbot subprocess/plugins, custom/BYO cert UI, scheduled renewal, multiple CA settings, HTTP/DNS challenges, OCSP options | Integrated automated HTTPS, multi-issuer fallback, durable storage/locking, background renewal, local CA | ACME resolvers via lego, HTTP/DNS/TLS challenges, file-backed local ACME store, router references | Integrate ACME as a library; retain old certs on all failures; encrypt account/private keys; do not shell out. |
| Routing | Host/location forms rendered into Nginx; access lists per host/location; manual custom upstream blocks for load balancing | Ordered handler routes and flexible matchers; route blocks preserve literal order | Explicit entrypoints, routers, rules/priorities, middleware chains, and services | Adopt explicit listener → route → middleware chain → upstream group with conflict validation. |
| Discovery | Primarily static/manual configuration | Static plus DNS A/AAAA/SRV dynamic upstream modules; broader behavior through modules | Strong provider model: file, Docker, Kubernetes, ECS, Consul, KV, etc. | Static and DNS first; file provider second; Docker only through an isolated read-only discovery helper. |
| Management | Full HTTPS web UI, API/Swagger, users/permissions, OIDC, 2FA, audit model | Powerful local/remote admin API and CLI, but no built-in manager UI/RBAC workflow | Dashboard/API primarily shows runtime config/status; full routing config normally comes from providers | Start with files + CLI + local REST API. Build a separate UI only after API/RBAC/audit stabilize. |
| Observability | Nginx/error/access logs, optional rotation, GoAccess, CrowdSec/open-appsec integrations | Structured logs, access logs, Prometheus/OpenMetrics, OTLP metrics and tracing | Structured/access logs, many metric backends, tracing, dashboard, health ping | Native JSON logs, Prometheus/OpenMetrics, OTLP traces, explicit redaction/cardinality budgets; external log rotation. |
| Deployment assumption | Opinionated container, host network example, persistent `/data`, many compiled modules/tools, optional companion containers | Single binary/container/systemd; local admin on loopback; persistent data directory | Single binary/container/Kubernetes; provider credentials/socket access; dashboard optional | Prefer single minimal binary/container, bridge networking by default, admin Unix socket, explicit volumes. |
| Extension model | Custom Nginx snippets/modules/scripts and container rebuilds | Compile-time Go modules/custom builds | Providers plus Go/Yaegi/Wasm plugin mechanisms | No plugin ABI in v1. Compile-time Cargo features only for reviewed providers. |
| HA | SQLite-focused manager is effectively single-node | Shared storage modules can coordinate certificate work; application instances remain separate | OSS ACME file cannot be shared concurrently; external cert-manager recommended for HA | Single-node certificate writer first; independent replicas with external certificate distribution before clustering. |

### 7.3 Major strengths worth learning from

NPMPlus:

- It makes proxy hosts, certificates, access policy, audit history, and common authentication workflows approachable to operators.
- It persists desired state and regenerates/tests Nginx configuration before reload.
- It treats secure cookies, CSP, OIDC, 2FA, TLS policy, access lists, log privacy, and container capabilities as visible operational concerns.
- It demonstrates real demand for BYO certificates, wildcard/DNS issuance, per-location policy, proxy protocol, custom error behavior, and migration/backup guidance.

Caddy:

- Its [admin API](https://caddyserver.com/docs/api) blocks until a new configuration succeeds and retains the old config if loading fails.
- Its [automatic HTTPS lifecycle](https://caddyserver.com/docs/automatic-https) emphasizes background renewal, issuer/challenge fallback, durable storage, and continuing to serve through CA/OCSP failures.
- The core/module lifecycle loads, provisions, validates, starts, and later cleans up a full configuration, enabling transactional thinking.
- [Reverse proxy behavior](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) explicitly covers health checks, retry safety, streaming, connection reuse, and dynamic DNS tradeoffs.
- It keeps deployment simple: one binary, a local admin listener, and a persistent data directory.

Traefik:

- Its [provider model](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) separates discovery from normalized routing objects.
- Its router → middleware → service model makes request flow and ownership explicit.
- It treats HTTP, TCP, UDP, SNI passthrough, entrypoints, lifecycle, health checks, and observability as one coherent operational model.
- Dynamic configuration updates continuously without treating every route change as a process restart.
- Its [dashboard security guidance](https://doc.traefik.io/traefik/operations/dashboard/) explicitly warns against public unauthenticated administration.

### 7.4 Operational weaknesses and security-sensitive areas

These are engineering assessments of tradeoffs, not vulnerability findings.

| Project | Observed pressure point | Implication for this project |
|---|---|---|
| NPMPlus | One image combines patched Nginx/AWS-LC/modules, Node API, React assets, Certbot/Python plugins, templates, SQLite/other DB clients, shell scripts, and optional services. | Avoid a broad runtime image and subprocess-based certificate system. Fewer components reduce patch and failure surfaces. |
| NPMPlus | Raw advanced Nginx configuration and opt-in prerun scripts bypass typed policy; URI sanitization can be disabled. | Do not provide arbitrary text/script escape hatches. Add typed capabilities or require a fork. |
| NPMPlus | The reference Compose uses host networking and the UI may bind broadly unless operators opt into localhost binding. | Bridge networking and a local admin socket are defaults; host network is an explicit documented exception. |
| NPMPlus | Configuration is split across database rows, rendered files, environment variables, mounted paths, and runtime tools. | Keep one canonical desired-state file and a clear derived runtime snapshot. |
| NPMPlus | SQLite is recommended and migration back is not automatic. | Start without a DB; make every on-disk format versioned and backup/restore tested before migrations. |
| Caddy | The native JSON config is powerful but verbose; adapters and modules can make effective behavior non-obvious. | Publish one strict human format and a redacted compiled preview. No adapter ecosystem initially. |
| Caddy | Its admin API can replace live config and is therefore a critical control-plane capability. | Default to a permissioned Unix socket; remote admin requires explicit TLS/auth/RBAC. |
| Caddy | Third-party modules require custom builds and expand supply-chain/review scope. | No runtime/plugin marketplace. Reviewed compile-time features only. |
| Caddy | Core does not provide an NPM-style multi-user management UI and audit workflow. | Build management as a separate later layer, not into the data-plane request path. |
| Traefik | Provider and middleware breadth creates a large configuration surface and provider-merge complexity. | Start with file/static/DNS providers and a small middleware set; add only measured needs. |
| Traefik | The current Docker provider source defaults `ExposedByDefault` to true, while hardened examples explicitly set it false. | Any discovery provider is deny-by-default and requires an enable label plus constraints. |
| Traefik | Docker discovery commonly needs Docker API access; compromise can expand toward daemon control. | Never mount the Docker socket in the proxy. Use an isolated least-privilege socket proxy/helper if approved. |
| Traefik | ACME local file storage cannot safely be shared across OSS instances. | Single writer in v1; HA uses external certificate management or an explicit leader design later. |
| Traefik | Label-based configuration can scatter policy across application manifests and make review/rollback harder. | Normalize provider data into a previewable candidate and require activation policy. |

## 8. Features to adopt conceptually

1. Immutable, versioned runtime snapshots with transactional activation and old-snapshot draining.
2. Explicit listeners, routes, middleware chains, upstream groups, certificate policies, and discovery providers.
3. A canonical typed config plus `validate`, `preview`, `diff`, `activate`, `rollback`, and redacted export operations.
4. Automatic certificate management with multiple configured issuers, explicit staging/production endpoints, safe retry/backoff, and last-working-certificate retention.
5. Per-route access control and middleware chains, but with compiler-enforced ordering.
6. Active and passive health, weighted balancing, connection pooling, bounded retries, and draining.
7. Static and DNS A/AAAA upstreams first, then file-fed dynamic upstreams; explicit SRV configuration is deferred until a later schema version defines its port, weight, priority, and TLS semantics.
8. Private-by-default administrative interfaces, audit records, OIDC/Authentik compatibility, and future operator UI.
9. Prometheus/OpenMetrics, OpenTelemetry, structured logs, access logs, certificate/reload metrics, and explicit redaction.
10. Single binary, non-root execution, minimal image, explicit persistent state, backup/restore, and signed releases.

## 9. Features to simplify, avoid, or defer

| Feature | v1 treatment | Revisit condition |
|---|---|---|
| Web UI | Defer; files + CLI + local API first | API, RBAC, CSRF/session model, and audit have passed external review. |
| Database | Avoid in v1 | Searchable multi-user UI state or cluster coordination demonstrably exceeds file-store needs. |
| PostgreSQL | Avoid | Multi-node control plane and transactional shared state are approved requirements. |
| SQLite | Defer | A UI needs users/sessions/preferences beyond config and audit files. |
| Runtime plugins/Wasm/scripts | Avoid | At least three externally developed extensions cannot be met by compile-time features and a sandbox threat model is approved. |
| Docker discovery | Later, isolated helper only | Static/DNS/file discovery is insufficient and a restricted Docker API proxy is deployed. |
| Kubernetes | Later | A Gateway API/controller product is explicitly funded and tested independently. |
| Consul/etcd | Avoid initially | A production operator requires it and ownership/consistency semantics are specified. |
| HTTP/3/QUIC | Separate evaluation | Quinn + HTTP/3 stack passes interop, fuzz, migration, observability, and resource-abuse gates. |
| UDP proxy | Defer | Named protocols require it and bounded pseudo-session semantics are designed. |
| Query matching | Defer | A real route cannot use path/header/method matching; canonicalization and logging rules are approved. |
| Regex routes/rewrites | Defer from MVP | Exact/prefix matchers are insufficient; use only linear-time Rust `regex` with complexity limits. |
| Response cache | Out of scope | A separate RFC-compliant cache design, privacy model, invalidation policy, and disk budget exist. |
| WAF/bot ML | Integrate externally | Dedicated WAF/bot service is selected; proxy only supplies forward-auth/mirror/log hooks. |
| Arbitrary DNS providers | Small built-in set | A provider has maintainers, tests, scoped credentials, and a reviewed API client. |
| Automatic OCSP fetching/stapling | Defer | CA ecosystem need is demonstrated and a maintained Rust implementation passes fail-open/fail-closed review. |
| On-demand TLS for unknown hostnames | Avoid in v1 | An allow/authorize endpoint, abuse limits, domain ownership controls, and rate-limit protections are designed. |
| ECH, post-quantum-only TLS, mTLS identity mesh | Defer | Client compatibility, library maturity, and concrete deployment requirements justify them. |

## 10. Proposed product scope

### 10.1 MVP through Phase 5

- HTTP/1.1 and HTTP/2 downstream/upstream; HTTP/2 negotiated by ALPN and explicit h2c upstream only.
- Streaming request/response bodies, trailers, backpressure, cancellation, pooled upstream connections.
- WebSocket tunneling and transparent gRPC over HTTP/2.
- HTTP and HTTPS listeners; BYO certificates; SNI, host, path exact/prefix, header exact/presence, and method matching.
- Static upstreams, round-robin/weighted round-robin/power-of-two choices, active/passive health, draining.
- TCP proxy and bounded ClientHello SNI peek for TLS passthrough; no generic CONNECT/open proxy.
- Strict TOML configuration, offline lint/preview, live atomic route snapshot reload, last-known-good revisions.
- Core access logs, health/readiness/liveness, Prometheus metrics, and graceful shutdown.

### 10.2 Production v1 through Phase 9

- ACME HTTP-01, DNS-01 (reviewed providers), TLS-ALPN-01; wildcard certificates; multiple configured CAs; staging; encrypted managed key/account storage; expiry alerts.
- Redirect, rewrite, request/response headers, request limits/timeouts, IP policy, rate/in-flight limits, Basic auth, forward auth (including Authentik), CORS, security headers, maintenance/custom errors, retries, circuit breaking, bounded buffering, compression, and request IDs.
- Local REST admin API and CLI with candidate validation, preview, activation, rollback, audit, backup/restore, token/mTLS auth, and roles.
- OpenTelemetry tracing, security/admin audit logs, route/upstream/TLS/rate/reload metrics, dashboards/runbooks.
- Docker Compose, systemd, rootless/minimal container, SBOM, signed releases, provenance, and upgrade/rollback tests.

### 10.3 Later releases

- Separate web UI and native admin OIDC/Authentik login.
- File provider then isolated Docker discovery; Kubernetes Gateway API only as a separately scoped product.
- Multi-instance deployment patterns and optional split control/data planes.
- HTTP/3 evaluation/implementation; UDP only if justified.

### 10.4 Capability-to-phase mapping

| Capability | Phase |
|---|---|
| HTTP/1.1, WebSocket, streaming, cancellation, backpressure, connection pooling, graceful shutdown | 1 |
| HTTP/2, gRPC, TLS termination, BYO certs, secure upstream TLS | 2 |
| SNI/host/path/header/method routes, typed config/conflict checks | 3 |
| Weighted balancing, active/passive health, draining, TCP/TLS passthrough | 4 |
| Hot reload, revisions, rollback, last-known-good | 5 |
| ACME HTTP/DNS/TLS-ALPN, wildcard/multi-CA/renewal/encrypted storage | 6 |
| All v1 middleware and forward-auth/Authentik | 7 |
| CLI, admin API, RBAC, tokens, audit, backup/restore | 8 |
| Full observability, alerts, dashboards, SIEM guidance | 9 |
| Optional web UI and native admin OIDC | 10 |
| File/DNS refinement and isolated Docker discovery | 11 |
| HA deployment and certificate coordination patterns | 12 |
| Fuzzing, resource abuse, HTTP/3/UDP gated evaluations, external review | 13 |
| Release hardening, signed artifacts, migration/rollback production proof | 14 |

## 11. Proposed Rust technology stack

Versions are intentionally not guessed here. Phase 0 pins exact versions/features in `Cargo.lock`, records MSRV, runs license/advisory checks, and captures a dependency review. Status below means active at the research snapshot, not a perpetual guarantee.

### 11.1 Selected major dependencies

| Crate/family | Purpose | Status/license at research | Alternatives | Selection rationale | Main risk/control |
|---|---|---|---|---|---|
| Tokio | Async runtime, sockets, timers, signals, bounded channels, task supervision | Active Tokio project; MIT; documented LTS lines | async-std, smol, Pingora runtime | Dominant ecosystem fit with Hyper, Axum, Rustls, Hickory, and instant-acme | Runtime stalls from blocking work; isolate blocking FS/crypto, instrument task latency, pin LTS-compatible version. |
| Hyper + `hyper-util` + `http-body-util` | HTTP/1.1 and HTTP/2 server/client primitives, pooling, streaming bodies | Active; Hyper is MIT and explicitly low-level | Pingora, h2 custom, reqwest server misuse | Direct protocol/body control with no second HTTP stack; production ecosystem | Low-level integration burden; use conformance tests, centralized hop-by-hop handling, fixed builder limits. |
| Rustls + `tokio-rustls` + `hyper-rustls` | Downstream/upstream TLS and ALPN | Active; Apache-2.0/MIT/ISC; TLS 1.2/1.3 | OpenSSL, BoringSSL, native-tls | Safe defaults, no obsolete protocol support, Rust ecosystem integration | Crypto provider includes reviewed native/unsafe internals; inventory and pin. No “FIPS” claim. |
| `aws-lc-rs` Rustls provider | Cryptographic primitives | Maintained with Rustls ecosystem; permissive | `ring` provider | Rustls recommends it for complete feature set/performance; matches future PQ capability path | Native build/reproducibility/unsafe surface; build-stage toolchain only, review advisories and supported targets. |
| Tower + `tower-http` (selected layers only) | Service abstraction and reusable timeout/trace/sensitive-header layers | Active; MIT | Custom middleware trait | Shared model across Hyper/Axum; avoids custom plumbing | Generic stacks can obscure order; compile middleware into a fixed explicit sequence and snapshot-test it. |
| Axum | Administrative REST API and health endpoints | Active Tokio project; MIT; own crate forbids unsafe | Actix Web, raw Hyper | Thin Hyper/Tower layer, predictable extractors/errors, no separate runtime | Must not share public data-plane routes or defaults; separate listener, limits, auth, error type. |
| Serde + `toml` | Typed config, persisted metadata, API payloads | Mature/active; generally MIT/Apache-2.0 | YAML, JSON-only, Figment | TOML is human-readable without YAML's implicit typing/alias complexity; Serde supports strict structs | `deny_unknown_fields` must be applied recursively; test duplicate keys and parser limits. |
| `arc-swap` | Atomic `Arc<RuntimeSnapshot>` publication | Established; Apache-2.0/MIT | `RwLock<Arc<_>>` | Lock-free read path and one atomic activation point | Snapshot pinning by long streams; keep snapshots compact, expose age/count, optional stream lifetime. |
| Hickory resolver | DNS A/AAAA resolution with TTLs and async support; library SRV support remains available for a later explicit schema | Active Rust DNS project; Apache-2.0/MIT | system resolver, trust-dns legacy name | Needed for health-aware DNS discovery and revalidation | DNS poisoning/rebinding; explicit resolvers optional, validate every resolved IP against egress policy, cap answers/TTL. |
| `instant-acme` | Async RFC 8555 ACME protocol, accounts/orders/ARI/profiles/EAB | Active; Apache-2.0; production use stated by project | rustls-acme, external Certbot/acme.sh, custom protocol | Pure Rust, Tokio/Rustls/Hyper alignment, caller retains challenge/lifecycle control | Smaller maintainer base and only P-256 account keys currently; isolate adapter, test with Pebble, retain import/export escape path. |
| `age` | Standard encrypted file format for certificate/account private material | Active Rust implementation; MIT/Apache-2.0 | custom AEAD envelope, OS keyring, Vault-only | Avoids inventing nonce/envelope cryptography; supports multiple recipients and offline recovery | Decryption identity is secret-zero; require external read-only secret injection and separate backup. Disable unused SSH/plugin features. |
| `secrecy` + `zeroize` | Reduce accidental secret display/copies and clear owned buffers on drop | Established security crates; permissive licenses | Manual wrapper/drop | Safer APIs for tokens, passwords, decrypted key bytes | Cannot guarantee removal from all allocator copies/core dumps; also disable dumps, avoid cloning, lock down process. |
| `rustls-native-certs` + PEM parser | System CA roots and explicit per-upstream CA bundles | Active Rustls ecosystem; permissive | `webpki-roots` only | Supports enterprise/system trust and route-specific roots | Host store varies; fail activation on load errors and report certificate sources. Containers install pinned CA package. |
| `idna`, `ipnet` | Host canonicalization and CIDR validation | Established; permissive | Hand parsing | Standards-aware host and network policy handling | IDNA policy surprises; store/display Unicode separately, route only on canonical A-label. |
| `clap` | CLI parsing/help/completions | Active; MIT/Apache-2.0 | `std::env` | Many subcommands and stable error/help behavior justify it | CLI surface drift; golden help tests and semver policy. |
| `tracing`, `tracing-subscriber`, `tracing-opentelemetry` | Structured spans/events, JSON logs, OTLP bridge | Active Tokio/OTel ecosystem; permissive | `log`, custom events | Async-aware instrumentation and one event model | Accidental sensitive fields/cardinality; typed redacted fields and allowlists only. |
| OpenTelemetry Rust + OTLP exporter | Vendor-neutral traces (and optional metrics export later) | Active; Apache-2.0 | vendor SDKs | Standard collector integration | API churn/export backpressure; isolate exporter, bounded batch, never block request path. |
| `prometheus-client` | Prometheus/OpenMetrics encoding and metric families | Maintained Prometheus client; Apache-2.0/MIT | `metrics` facade/exporter, custom text | Explicit label types and direct scrape endpoint | Cardinality/memory; enum/ID labels only, no raw host/path/client values. |
| `argon2`, `subtle` | Password/API-token hashing and constant-time comparisons | RustCrypto ecosystem; permissive | bcrypt/scrypt, direct equality | Modern password hashing and explicit constant-time verification | CPU/memory DoS; cap auth attempts, fixed reviewed parameters, run hashing in bounded blocking pool. |
| `sha2`, `rand_core`/OS RNG | Config/content hashes, audit chain, identifiers/nonces | RustCrypto ecosystem; permissive | stdlib (no crypto hash), custom RNG | Standard primitives rather than custom crypto | Do not reuse non-secret hashes as MACs; audit chain uses HMAC with separate key if tamper evidence enabled. |
| `thiserror` | Typed internal errors without string matching | Active; MIT/Apache-2.0 | manual `Error` impls | Small boilerplate reduction with stable error taxonomy | Do not serialize internal causes to clients; map centrally. |

### 11.2 Conditional/deferred dependencies

| Dependency | Decision |
|---|---|
| Pingora | Do not select now. Its official repository advertises HTTP/1/2, gRPC/WebSocket, graceful reload, and load balancing, but Rustls is experimental, Linux is tier 1, Windows preliminary, and it brings a full proxy framework. Revisit only after a Phase 0 spike compares correctness effort and reproducible benchmarks against Hyper. |
| Quinn + `h3` | Evaluation only in Phase 13. Quinn supplies QUIC, not a complete production HTTP/3 proxy. Require version compatibility, interop, migration, qlog/metrics, retry/address-validation, UDP buffer, and abuse testing. |
| SQLx | Not in v1. If Phase 10 approves SQLite, prefer SQLx over SeaORM for explicit queries/migrations and smaller abstraction. Re-evaluate compile-time/offline metadata and native SQLite packaging. |
| SeaORM | Reject initially; object-relational abstraction has no value without a complex domain DB. |
| SQLite | No runtime dependency in v1. Consider for users/sessions/UI preferences only. Configuration/certificates remain portable files. |
| PostgreSQL | Defer to a clustered control plane. Do not require an external DB for a single proxy. |
| `notify` | Skip initially. Periodic content-hash polling plus SIGHUP is simpler and catches atomic replacements. Add native watchers only if polling is measurably insufficient. |
| TLS ClientHello parser | No crate is selected yet. Phase 0 must verify whether a supported Rustls acceptor API can inspect SNI/ALPN while retaining the exact consumed prefix for passthrough; otherwise compare maintained safe parsers for RFC coverage, license, advisories and fuzz history. A new handwritten parser requires its own ADR and expert review. |
| `regex` | Not in MVP route matching. If added, use Rust's linear-time engine, reject oversized patterns, and forbid backreferences/lookaround assumptions. |
| `async-compression` | Add only in Phase 7 for selected streaming encoders; disable unused algorithms/features. |
| `governor` | Candidate for Phase 7 rate limiting after keyed-state eviction and clock/test behavior are reviewed. Do not commit before that spike. |
| `openidconnect` | Candidate for native admin OIDC in Phase 10. ForwardAuth covers Authentik/application SSO in v1 with less session complexity. |
| Tonic | Dev/test dependency for gRPC fixtures; not required to transparently proxy gRPC. Consider runtime use only for gRPC health checking. |

### 11.3 Dependency policy

- Commit `Cargo.lock`; pin CI actions and container bases by immutable digest.
- Default-deny Git dependencies; crates.io only unless an exception ADR records commit, owner, license, and removal plan.
- Minimal Cargo features; `cargo tree -e features` reviewed each release.
- `cargo audit` and `cargo deny check advisories bans licenses sources` on every PR and daily schedule.
- Record direct-dependency owner, purpose, last review date, license, unsafe/native build surface, and replacement path in `docs/dependencies.md`.
- Automated update PRs run full CI and soak/security subsets before merge; no unattended production update.
- Generate SBOM from the release artifact and compare it to the lockfile.
- Project license allowlist starts with `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `ISC`, `BSD-2-Clause`, `BSD-3-Clause`, `Unicode-3.0`, and other explicitly reviewed runtime necessities; GPL/AGPL runtime dependencies require legal/security ADR approval.

## 12. Architecture overview

### 12.1 Process model

The v1 system is one process with strongly separated listeners and modules, not microservices:

```text
                         immutable Arc<RuntimeSnapshot>
                                     |
Internet -> listeners -> protocol -> router -> middleware -> upstream pools -> services
               |          |           |           |               |
          conn limits   Rustls/     route IDs   bounded work   health/drain/DNS
                        Hyper

Local Unix socket -> Axum admin -> auth/RBAC -> candidate compiler -> activator
                                            |          |               |
                                           audit   config/cert store   atomic swap

Background supervisor -> ACME, renewal, health checks, DNS refresh, metrics export,
                         revision retention, audit flush, shutdown coordination
```

The data-plane fast path reads immutable state. It cannot mutate desired configuration, certificate records, users, or audit logs. The control plane cannot install a partially compiled configuration; it submits candidates to the single activator. Administrative and observability listeners use separate address/limit/auth policies from public listeners.

### 12.2 Runtime snapshot

`RuntimeSnapshot` contains only fully validated, runtime-ready structures:

- schema/revision/hash and activation timestamp;
- canonical listener table and certificate resolver views;
- compiled HTTP and TCP route indexes;
- fixed middleware pipelines;
- upstream-group definitions and handles to pool/health state;
- trusted-proxy and egress policy sets;
- metric-safe route/upstream IDs;
- no unresolved secret references and no plaintext configuration export.

Each request/stream obtains an `Arc` to the active snapshot. Reload publishes a new `Arc` atomically. Existing requests complete against the old snapshot; new requests use the new one. Shared upstream pool/health handles are reused only when their identity and transport policy are unchanged.

### 12.3 Privilege boundaries

- Prefer systemd socket activation so the process never needs low-port capability.
- Otherwise grant only `CAP_NET_BIND_SERVICE`, then drop it after listener bind where supported.
- Public listeners do not route to admin/metrics handlers.
- Admin defaults to `/run/rust-proxy/admin.sock` mode `0660`, owned by a dedicated group.
- State directory is `0700`; secret and private-key material is `0600`; certificate/public metadata may be `0644` only when needed.
- The process runs as a dedicated UID/GID with no shell, no Docker group, no write access outside state/runtime directories, and no host root filesystem mount.
- Data-plane egress is restricted by network policy/firewall in addition to in-process CIDR policy.

### 12.4 Required architecture-area traceability

| Required area | Concrete design location |
|---|---|
| Workspace and crate layout | Section 37 and Phase 0. |
| Proxy data plane | Sections 12.1, 14, 16 and 28.3. |
| Administrative control plane | Sections 15, 17.5, 22 and 25. |
| Configuration model | Section 17.1–17.2. |
| Configuration validation | Section 17.3–17.4. |
| Dynamic configuration reload | Sections 17.5 and Phase 5. |
| Routing engine | Sections 19 and `proxy-core::route` below. |
| Middleware pipeline | Section 20 and Phase 7. |
| TLS subsystem | Sections 14.4, 18.1 and ADR-002. |
| ACME subsystem | Sections 18.2–18.4 and Phase 6. |
| Certificate storage | Sections 18.3–18.4 and 21. |
| Upstream manager | Sections 14.4, 14.7 and Phase 4. |
| Health-check subsystem | Sections 14.7, 28 and Phase 4. |
| Service-discovery subsystem | Sections 9–10, 19.3 and Phase 11. |
| Authentication and authorization | Sections 20, 25 and Threat controls. |
| Secret storage | Sections 17.3, 18.3, 21 and 25.3. |
| Persistence layer | Sections 21, 34 and ADR-003/004. |
| Audit logging | Sections 21.3, 27.1 and 29.1. |
| Observability | Section 29 and Phase 9. |
| CLI | Section 23 and Phase 8. |
| Administrative API | Section 22 and ADR-006. |
| Optional web UI | Section 24, Phase 10 and ADR-008. |
| Background task lifecycle | Sections 28.1 and Phase-specific supervisors. |
| Graceful startup and shutdown | Section 28.1 and Phases 1/5. |
| Upgrade and migration | Section 35 and Phase 14. |
| Backup and restore | Sections 34, 39 and Phase 8. |
| Plugin or extension strategy | Sections 9, 37 and ADR-009. |
| Multi-instance and high-availability strategy | Sections 36 and Phase 12. |
| Failure isolation | Sections 12.3, 13 and 28.2. |
| Resource limits | Sections 14, 28.3 and deployment manifests in Phase 1. |

## 13. Component responsibilities

The following names are the actual crates/modules proposed in Section 37; they are not additional workspace crates.

| Crate/module | Responsibility | Failure behavior | Resource boundary |
|---|---|---|---|
| `proxy-config` | TOML schema, migrations, canonicalization, validation, route-conflict analysis, compiled preview | Candidate rejected; active runtime untouched | Config bytes, object counts, strings, and validation work capped |
| `proxy-secrets` | Parse secret refs, read allowed providers, wrap/zeroize, age encrypt/decrypt | Missing/invalid required secret blocks candidate/startup | Max secret size; no directory traversal; provider allowlist |
| `proxy-core::types` | Shared IDs, errors, time/duration/size types, cancellation and redaction contracts inside the data-plane crate | Typed errors; no independent I/O | No global mutable state |
| `proxy-core::runtime`/`listener` | Listener lifecycle, runtime snapshot activation/draining, connection acceptance | Critical failure changes readiness and asks the binary supervisor to drain/exit | Bounded listeners, connections, channels and grace periods |
| `proxy-core::http` | HTTP/1.1/2 server/client, hop-by-hop handling, body streaming, WebSocket/gRPC behavior | Protocol error closes affected stream/connection; no process-wide fallback | Per-listener connection/header/body/time limits |
| `proxy-core::route` | Canonical host/SNI/path/header/method matching and deterministic priority | No match returns configured 404/421; ambiguity cannot activate | Immutable indexed tables; matcher complexity capped |
| `proxy-core::middleware` | Fixed-stage policy compiler and v1 middleware implementations | Fail closed for auth/policy; fail safely for optional transforms | Body buffers, limiter keys, auth calls, compression work bounded |
| `proxy-core::upstream` | DNS/static targets, pools, TLS transport, load balancing, active/passive health, retries, draining | Unavailable group returns 503; old connections drain | Max endpoints, idle/active connections, health tasks, DNS answers |
| `proxy-core::tcp` | TCP forwarding, optional PROXY protocol, bounded TLS ClientHello SNI inspection/passthrough | Unknown/invalid flow closed; no arbitrary destination | Connection count, peek bytes/time, idle/lifetime limits |
| `proxy-tls::{acceptor,selector,store}` | Rustls policy, SNI selection, BYO import, upstream trust and atomic encrypted generations | Existing valid cert remains; invalid new material rejected | Handshake concurrency/time, cert count/size |
| `proxy-tls::acme` | Accounts/orders/challenges/renewal/backoff/issuer selection and single-writer locks | Keep working cert; alert/retry; never replace with invalid/expired-new material | Concurrent orders, per-CA rate, retry schedule, DNS propagation deadline |
| `proxy-config::revision` | Atomic config revisions, probation journal, active pointer and retention | Mutation fails before runtime publication when durability cannot be guaranteed | Disk watermarks, retention counts, fsync monitoring |
| `proxy-admin::{api,auth,rbac,status}` | Axum REST API, auth/RBAC, concurrency control, redacted responses, health endpoints | Authorization/audit fail closed for mutation; data plane continues | Separate body/connection/rate/time limits |
| `proxy-admin::{audit,backup}` | Durable audit append and consistent encrypted backup/restore validation | Security mutations fail if audit intent cannot persist; backup failure has no active-state effect | Disk watermarks, archive/record caps, fsync/export timeouts |
| `rust-proxy::telemetry` | Structured/access events, Prometheus/OpenMetrics, OTLP export, redaction/cardinality | Drop non-audit telemetry under pressure and increment counters | Bounded queues/batches/labels; exporter timeouts |
| `rust-proxy` | Main binary, CLI, config/bootstrap wiring, exit codes | Clear nonzero failure; no secret-rich panic output | One Tokio runtime; explicit thread counts |

Background tasks are registered with the supervisor as `critical` (listener acceptors, activator, certificate resolver integrity) or `restartable` (DNS refresh, health probes, OTLP exporter). Restartable tasks have capped exponential backoff and a restart budget; exhausting it changes readiness and requires operator action.

## 14. Data-plane design

### 14.1 Listener and connection acceptance

1. Each listener has an independent semaphore. When full, TCP accepts are briefly paused or immediately closed according to policy; no unbounded accepted-socket queue is created in userspace.
2. Optional PROXY protocol is `off` by default. If enabled, a configured version and trusted peer CIDR list are mandatory; untrusted or missing headers in `required` mode are rejected before HTTP/TLS parsing.
3. TLS handshakes have concurrency and wall-clock limits. Only TLS 1.2/1.3 are available; v1 default is TLS 1.3 + compatible modern TLS 1.2, configurable to TLS 1.3 minimum.
4. ALPN selects `h2` or `http/1.1`. Cleartext downstream h2c is disabled by default and allowed only on an explicit listener.
5. Hyper connection builders receive explicit header count/buffer size, keep-alive, HTTP/2 stream/window/frame, and timer settings. Defaults are documented and tested rather than inherited invisibly.
6. Per-connection metadata records the immediate peer, trusted client IP result, TLS/SNI/ALPN, listener ID, connection ID, and cancellation token.

### 14.2 HTTP request normalization and smuggling boundary

- Treat Hyper's parsed request as the only message framing. Never forward raw downstream framing bytes.
- Reject conflicting/multiple `Content-Length`, `Content-Length` with transfer coding, invalid transfer-coding chains, obsolete line folding, invalid header names/values, bare CR/LF, oversized request targets, and invalid HTTP/2 connection-specific headers. Raw corpus tests prove the exact behavior.
- Permit HTTP/1.1 `Transfer-Encoding: chunked` only as parsed framing; upstream framing is regenerated by Hyper.
- Remove hop-by-hop headers and headers named by `Connection` before forwarding. `TE` is preserved only as `trailers` where protocol-valid.
- Reject absolute-form targets unless the listener explicitly supports a future forward-proxy mode (none in v1). Reject `CONNECT`; this product is not an open proxy.
- Require one valid HTTP/1.1 Host/HTTP/2 authority and reject Host/authority disagreement. Canonicalize IDNA to an A-label, case, trailing dot and port under one documented policy before matching.
- After route selection, rebuild upstream Host/`:authority` from the canonical routed client authority by default, or from a route's dedicated fixed `upstream_host`; never forward the original byte form or derive authority from a general header template. Upstream TLS SNI remains a separately validated endpoint setting.
- Remove inbound `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, and request-ID headers unless the immediate peer is configured as trusted. Rebuild forwarded values from trusted chain plus the actual peer. Parsing is right-to-left and stops at the first untrusted hop.
- Strip client-supplied internal auth/result headers before Basic/ForwardAuth/OIDC middleware can add trusted values.

### 14.3 Body streaming, cancellation, and backpressure

- Forward Hyper body frames directly; never call `collect()` on the normal path.
- A counting body wrapper enforces streamed byte limits after HTTP transfer framing is removed but before any content decoding (inbound content decoding is not provided), even when `Content-Length` is absent or false.
- Buffering middleware uses a per-request allocation budget and a process-wide semaphore; overflow returns 413/502 without spilling plaintext to disk in v1.
- Downstream disconnect drops the upstream future/body and cancels WebSocket/TCP copies. Upstream cancellation is best-effort at protocol boundaries: reset HTTP/2 streams; close/release HTTP/1 connections that cannot be safely reused.
- Hyper/Tokio polling supplies transport backpressure. Any transform uses bounded channels with capacity documented in config defaults.
- Expect/continue is forwarded only after route and early policy acceptance; rejected requests do not invite large body upload.

### 14.4 Upstream connection management

- Pool key includes scheme, endpoint, SNI, ALPN/HTTP versions, CA identity, client certificate identity, proxy protocol, and relevant socket policy; incompatible security contexts never share connections.
- Default upstream TLS verifies chain, hostname, validity, and configured trust. No production `insecure_skip_verify` option exists.
- Per-upstream limits cover dial concurrency, total/idle connections, idle lifetime, request concurrency, response-header timeout, and maximum response headers.
- DNS names resolve through the upstream group's resolver policy. Every answer is capped, canonicalized, and checked against `allowed_cidrs`/`denied_cidrs` at every refresh and connect; link-local, multicast, unspecified, and configured cloud metadata ranges are denied unless explicitly approved.
- Happy Eyeballs behavior and IPv4/IPv6 preference are explicit and tested.
- Connection reuse is disabled after framing/protocol errors, `Connection: close`, failed body completion, or cancellation that leaves unread bytes.

### 14.5 WebSocket and gRPC

- WebSocket support validates HTTP/1.1 upgrade tokens, receives both upgrades, then runs bounded `copy_bidirectional` with idle/max-lifetime/shutdown cancellation. It does not interpret frames.
- HTTP/2 extended CONNECT WebSocket support is deferred until interoperability is proven.
- gRPC is proxied as HTTP/2 without decoding messages. Preserve `content-type`, `te: trailers`, status, trailers, deadlines, and cancellation. Do not retry a stream after any request bytes are sent unless a future explicit gRPC policy proves safety.
- Integration fixtures use Tonic to verify unary, streaming, large messages within limits, deadlines, cancellation, and trailers.

### 14.6 TCP and TLS passthrough

- A TCP route always maps a configured listener/SNI predicate to a configured upstream group; clients cannot choose a host/port.
- TLS passthrough peeks a bounded ClientHello (proposed maximum 16 KiB with a short timeout), parses only enough for SNI/ALPN, then forwards all bytes unchanged.
- Exact and leftmost-wildcard SNI routes are supported; one explicit catch-all may exist. Ambiguity is a configuration error.
- Non-TLS TCP routing is listener/catch-all based. TLS termination for arbitrary TCP protocols is deferred unless a protocol requires it.
- Bidirectional copies have idle, maximum lifetime, byte accounting, connection limits, cancellation, and drain semantics.
- UDP is excluded because connectionless pseudo-session state, amplification, spoofing, NAT rebinding, and per-protocol timeout behavior need a separate design.

### 14.7 Load balancing, health, retry, and drain

- Algorithms in v1: round robin, smooth weighted round robin, random, and power-of-two choices using active request count. Consistent hashing/sticky cookies wait for a concrete use case.
- Active HTTP health checks use configured method/path/Host/expected status with no redirects by default; TCP checks use connect success; optional gRPC health checks are later within Phase 4 if Tonic cost is accepted.
- State machine: `Starting` → `Healthy`; consecutive failure threshold → `Unhealthy`; consecutive success threshold → `Healthy`; `Draining` receives no new work but preserves existing connections until deadline.
- Passive health counts classified connect errors, timeouts, resets, and configured status classes in a rolling bounded window. Client cancellation and policy rejection are not upstream failures.
- Health transitions use hysteresis and jitter; probes are bounded and never share user credentials.
- Retries occur only within a total attempt/time budget. Connection failures before request bytes may retry. After sending bytes, default retries are limited to idempotent methods and replayable bodies; POST/PATCH never retry merely because an `Idempotency-Key` exists unless route policy and bounded buffering explicitly authorize it.
- Circuit breaker is per upstream group, driven by a bounded rolling error/latency sample. Open state fails quickly; a small half-open probe budget tests recovery. Health and breaker states are visible and independently reasoned.

## 15. Control-plane design

The control plane is an Axum application on a separate listener. It exposes desired-state operations, not mutable internal objects.

Core rules:

- Unix socket only by default. TCP binding is explicit and refuses wildcard/public addresses unless TLS plus an admin authentication policy are configured.
- Every mutating request carries `If-Match: "<active-revision>"`; stale clients receive `409 Conflict` with the current revision.
- API payloads have a small default limit (proposed 1 MiB), strict JSON fields, request deadline, rate/in-flight limits, and uniform redacted errors.
- Candidate validation is pure until secret/resource preparation. Validation cannot activate.
- Only the activator owns the activation mutex and publishes snapshots.
- Every authorization decision and mutation attempt emits an audit record. If durable audit cannot be written, mutation fails closed while read-only status remains available.
- Admin API never returns private keys, resolved secrets, raw authorization/cookie headers, or decrypted backups.
- Debug/pprof-style endpoints are not compiled/exposed by default.

Logical separation is sufficient for v1, but the crate boundaries allow `proxy-admin` to become a separate process later if threat analysis or workload isolation warrants it.

## 16. Request lifecycle

The fixed lifecycle is:

1. Accept connection under listener limit.
2. Parse trusted PROXY protocol if configured.
3. Complete bounded TLS/ALPN or bounded TCP ClientHello peek.
4. Parse HTTP with strict protocol limits.
5. Establish immutable request context: IDs, immediate peer, trusted client IP, listener, SNI, canonical authority.
6. Run outer access/security audit span.
7. Enforce syntax/header/body-declaration limits and trusted-forwarded normalization.
8. Match one route deterministically; return 404 (no host route) or 421 (SNI/authority mismatch where policy requires) without falling through to an internal service.
9. Execute the compiled middleware stages in Section 20.
10. Select a healthy, non-draining upstream under circuit/concurrency policy.
11. Establish/reuse a transport with the exact upstream TLS/pool key.
12. Stream request and response, propagating cancellation and trailers.
13. Classify outcome for passive health/breaker, release counters, and write one redacted access event.
14. On shutdown, stop accepting, mark readiness false, drain until deadlines, then cancel remaining work.

No error path rematches another route. Custom errors transform only eligible upstream/proxy responses and never mask admin/auth/policy failures unless explicitly defined.

## 17. Configuration model and lifecycle

### 17.1 Canonical format

Use one TOML document with `schema_version = 1`. JSON is an API representation only; YAML is not accepted in v1. All maps with security impact use named IDs matching `^[a-z][a-z0-9_-]{0,62}$`.

Representative configuration (illustrative schema, not implemented):

```toml
schema_version = 1

[runtime]
state_dir = "/var/lib/rust-proxy"
shutdown_grace = "30s"
config_poll_interval = "1s"

[limits]
max_connections = 20000
max_connections_per_ip = 200
max_header_bytes = "32KiB"
max_headers = 100
max_request_body = "32MiB"
request_header_timeout = "10s"
request_body_idle_timeout = "30s"
response_header_timeout = "30s"
idle_connection_timeout = "120s"

[[listeners]]
id = "web"
bind = "0.0.0.0:80"
protocol = "http"

[[listeners]]
id = "websecure"
bind = "0.0.0.0:443"
protocol = "https"
certificate_policy = "public-web"
http_versions = ["http1", "http2"]

[trusted_proxies]
cidrs = ["10.20.0.0/16"]
header_mode = "forwarded"
trusted_hops = 1

[secrets]
state_encryption_recipients_file = "/etc/rust-proxy/state-recipients.txt"
state_decryption_identity = "file:///run/secrets/state-age-identity"

[[certificate_policies]]
id = "public-web"
domains = ["example.com", "www.example.com"]
source = "acme"
issuer = "letsencrypt-production"
challenge = "http-01"

[[acme_issuers]]
id = "letsencrypt-production"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
account_email = "ops@example.com"

[[upstream_groups]]
id = "app"
algorithm = "smooth_weighted_round_robin"
allowed_cidrs = ["10.30.0.0/16"]

[[upstream_groups.endpoints]]
id = "app-a"
url = "https://10.30.0.10:8443"
weight = 2
server_name = "app.internal.example"
ca_bundle = "file:///etc/rust-proxy/internal-ca.pem"

[[upstream_groups.endpoints]]
id = "app-b"
url = "https://10.30.0.11:8443"
weight = 1
server_name = "app.internal.example"
ca_bundle = "file:///etc/rust-proxy/internal-ca.pem"

[upstream_groups.health]
kind = "http"
path = "/readyz"
interval = "10s"
timeout = "2s"
unhealthy_threshold = 3
healthy_threshold = 2

[middlewares.edge-limit]
type = "rate_limit"
scope = "client_ip"
rate = 20
burst = 40

[middlewares.security]
type = "security_headers"
hsts_max_age = "5m"
hsts_include_subdomains = false
hsts_preload = false
content_security_policy = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"

[[routes]]
id = "app-api"
listeners = ["websecure"]
hosts = ["example.com"]
path_prefixes = ["/api/"]
methods = ["GET", "HEAD", "POST"]
headers = [{ name = "x-api-version", value = "1" }]
priority = 100
middlewares = ["edge-limit", "security"]
upstream_group = "app"

[admin]
unix_socket = "/run/rust-proxy/admin.sock"
allowed_uids = [1001]

[observability]
log_format = "json"
access_log = true
metrics_bind = "127.0.0.1:9100"
tracing = false
```

### 17.2 Strict parsing and limits

- Reject unknown fields at every struct level, duplicate TOML keys, duplicate IDs, invalid Unicode/control characters, overlong strings, excessive object counts, non-finite numbers, and out-of-range durations/sizes.
- Read at most a configured config byte limit (proposed 4 MiB) before parse.
- Canonicalize durations, byte sizes, CIDRs, hostnames, paths, methods, and header names into typed values. Never keep security decisions as free-form strings.
- Secret refs support only `env://NAME` and absolute `file:///path` in v1. `exec://`, relative paths, URLs, and shell expansion are forbidden.
- Offline lint checks secret syntax without resolving. `--resolve-secrets` additionally verifies existence, type, permissions, and maximum size without printing values.

### 17.3 Validation pipeline

1. Read bounded bytes and hash exact input.
2. Parse schema header only; reject unsupported future versions.
3. Apply a deterministic, explicit migration to an in-memory candidate only when `config migrate` is invoked. Startup does not rewrite files.
4. Deserialize strict typed structs.
5. Canonicalize names/addresses/hosts/paths/headers.
6. Validate scalar ranges and safe default resolution.
7. Resolve references and detect cycles.
8. Validate port/listener conflicts, TLS/listener compatibility, ACME challenge reachability assumptions, certificate domain coverage, and upstream transport policy.
9. Compute matcher intersections, duplicate routes, ambiguous priorities, catch-all exposure, and SNI/Host conflicts.
10. Compile middleware order and reject invalid combinations.
11. Validate upstream IP/DNS egress policy, duplicate endpoints, empty groups, retry/body replay compatibility, and health thresholds.
12. Resolve required secrets into guarded values only for preparation/activation.
13. Produce a redacted canonical preview, warnings, activation class (`hot`, `warm`, `restart_required`), and candidate hash.

Warnings never silently downgrade errors. Examples of warnings: HSTS preload implications, public admin bind refused unless explicitly acknowledged, route without TLS, very high limits, use of public DNS upstream, or certificate expiring soon. Security invariants remain errors.

### 17.4 Conflict and port rules

- Duplicate canonical matchers are errors regardless of declaration order.
- Routes with intersecting host/path/method/header predicates are allowed only when computed specificity or explicit `priority` makes one unambiguous. Equal-priority intersections are errors.
- An exact host outranks a leftmost wildcard, which outranks a listener catch-all. Exact path outranks prefix; longer prefix outranks shorter. Method/header constraints add specificity but do not override a higher explicit priority.
- Declaration order is never a tie-breaker.
- At most one HTTP catch-all and one TCP catch-all per listener.
- TCP and HTTP cannot bind the same address/port in one process. HTTP/3 later also reserves UDP on its HTTPS port.
- A listener address/protocol change that cannot be staged without rebinding is `restart_required`, not falsely advertised as hot.

### 17.5 Activation and reload

1. Serialize activations through one mutex and check `If-Match`/base revision.
2. Validate/compile candidate with no mutation.
3. Stage secrets, Rustls configs, route tables, middleware, pools, health tasks, and newly bindable listeners.
4. Run structural readiness checks: listeners bound, task startup acknowledged, certificate/key pairs match, required secret providers readable, pool policy build succeeds.
5. Write immutable revision/metadata and a probation journal containing candidate + previous IDs to temporary paths; `fsync` and rename them; append and `fsync` the audit intent.
6. Atomically replace and sync the active revision pointer, retaining the previous ID. If this fails, tear down staged resources and leave the runtime untouched.
7. Publish the prepared snapshot with the non-failing `ArcSwap` store while still holding the activation coordinator, then mark the journal `probation`.
8. Hold old resources through a short structural probation. A candidate-created critical task/synthetic readiness failure atomically restores the previous pointer and snapshot and marks the candidate failed. Ordinary upstream unhealthiness does not trigger policy rollback. If rollback cannot be persisted, immediately serve the old in-memory snapshot, make administration unready, reject further mutations, and rely on the prewritten incomplete-probation journal to select the previous revision at restart.
9. After probation succeeds, mark the journal committed; mark old endpoints/listeners draining and stop them after references finish or deadline.
10. Append and flush success/failure audit outcome and expose status/metrics. A crash before `committed` causes startup recovery to validate journal/pointer and choose the previous revision rather than guessing.

File reload uses content-hash polling plus SIGHUP/admin activation. An invalid changed file records a rejected candidate and leaves the active snapshot untouched. Startup with an invalid configured file exits nonzero. An operator may explicitly start with `--resume-last-known-good`; this action is logged loudly and does not overwrite the bad file.

## 18. Certificate lifecycle

### 18.1 Sources and selection

- `acme`: managed account/order/challenges/renewal.
- `imported`: BYO PEM chain/key copied into encrypted managed storage after pair, hostname, validity, algorithm, and chain parsing checks.
- `external_files`: explicit read-only certificate/key refs for integrations that rotate atomically; unencrypted private-key paths require a high-severity warning and opt-in because encryption at rest is outside this process.
- Certificate selection uses canonical SNI exact match, then leftmost wildcard. No SNI uses an explicitly configured default certificate; otherwise handshake fails without revealing another tenant certificate.

### 18.2 ACME issuance

- `instant-acme` is wrapped behind an internal `AcmeClient` adapter so crate changes do not leak into route/config types.
- Each issuer has explicit directory URL, staging/production label, account, EAB refs, profile, preferred key algorithm, challenge allowlist, request limits, and retry policy.
- Never infer “production” from a URL or silently switch a configured production order to staging. Staging is an operator-selected issuer used for tests.
- HTTP-01 owns only `/.well-known/acme-challenge/<token>` on the configured listener and precedes user redirects/routes for active tokens. Tokens are random, bounded, time-limited, and exact-match.
- TLS-ALPN-01 installs an ephemeral `acme-tls/1` certificate for the exact SNI and active authorization only. ALPN/handshake paths are isolated from normal certificate selection.
- DNS-01 uses typed provider modules with scoped secret refs. The provider writes one exact TXT record, waits through bounded authoritative/recursive propagation checks, completes validation, and attempts cleanup. Cleanup failure alerts but does not erase order evidence.
- Wildcards require DNS-01. Provider credentials should be limited to `_acme-challenge` records/zones where vendor capabilities permit.
- Orders for identical domain sets/issuer/account are single-flight. Global/per-CA concurrent order limits and jitter reduce thundering herds and rate-limit risk.

### 18.3 Storage encryption

- Public certificate chains and non-secret metadata may remain plaintext for inspection.
- Private keys, ACME account credentials, EAB HMAC values cached in state, and recovery material are age-encrypted to one or more configured X25519 recipients.
- Decryption identity arrives through a root-owned, service-group-readable file with restrictive mode, a systemd credential, a container secret, or a later KMS adapter. It is never stored beside encrypted state or exported in backups by default.
- Decrypted bytes live only in `Secret`/zeroizing buffers until converted to Rustls signing keys. Core dumps are disabled in deployment guidance; logs/debug output cannot format secret wrappers.
- Encryption at rest does not mean keys are absent from process memory: Rustls signing-key objects and allocator/library copies may not be zeroized. Minimize copies/lifetime, disable dumps/swap where operationally appropriate, isolate the process, and treat a process-memory compromise as certificate-key compromise.
- Rotation encrypts all material to old + new recipients, verifies restore with the new identity, then removes the old recipient in a later explicit step.

### 18.4 Renewal and failure behavior

1. Parse every stored certificate at startup and continuously expose `not_before`, `not_after`, names, issuer, and status.
2. Prefer ACME Renewal Information when available; otherwise schedule before expiry using a documented lifetime fraction/window plus per-certificate jitter.
3. Acquire a per-certificate durable process lock; in v1 only one process owns the state directory.
4. Order/solve/finalize into a new temporary record. Validate chain, key match, domains, validity window, algorithms, and successful Rustls load.
5. Encrypt and atomically persist the new generation/key/account metadata and sync its directory; retain current and previous records.
6. Atomically replace `current.json` with a pointer containing new + previous generation IDs, then publish the already validated resolver through a non-failing snapshot store. If pointer replacement fails, do not publish. A crash before the pointer keeps the old generation; a crash after it loads the verified new generation on restart.
7. Retain the previous generation through a rollback window; garbage collection never deletes either ID referenced by the current pointer.
8. On any failure, continue serving the current certificate—even when near expiry—while retrying with capped exponential backoff and alert escalation. Never replace a valid certificate with a staging, malformed, not-yet-valid, unrelated, or shorter-unexpected certificate.
9. Alert at configurable thresholds (default proposal: 30, 14, 7, 3, and 1 day) and on repeated renewal failure.

Multiple CAs are an ordered, explicit policy. Fallback is attempted only for classified issuer/challenge failures and respects per-CA account/rate state. OCSP stapling remains deferred; short-lived certificates and expiry monitoring are preferred until a maintained implementation and CA need justify it.

## 19. Routing model

### 19.1 HTTP predicates

Supported v1 predicates:

- listener ID;
- canonical exact host or one-label wildcard (`*.example.com`), with optional explicit catch-all;
- exact path or segment-aware prefix;
- method set;
- exact/presence header predicates with canonical header names and bounded values;
- optional TLS-required/SNI-host-consistency policy.

Query matching and regex are deferred. Before routing, validate every percent escape, decode only RFC unreserved characters, uppercase preserved escapes, and reject NUL/control bytes, literal backslash, encoded slash/backslash, and `.`/`..` segments including encoded forms. Route and forward the same canonical path by default so an upstream cannot reinterpret a different path and bypass route authentication; never double-decode. An incompatible raw-path mode is deferred to a separate security decision. Path prefix matching is segment-aware so `/api` does not accidentally match `/apiv2`.

### 19.2 Precedence

Sort by explicit numeric priority descending, then host specificity, path specificity/length, method/header specificity. Validation rejects any remaining intersection. A route ID is stable and unique; metrics/logs use the ID, not raw requested host/path.

TLS SNI and HTTP authority are independently validated. By default, a TLS route requires authority to be covered by the selected SNI route/certificate policy; mismatches return 421 or fail handshake where possible. Explicit domain-fronting behavior is out of scope.

### 19.3 Actions

One route has exactly one terminal action:

- proxy to an upstream group;
- redirect;
- static maintenance response;
- deny with fixed status.

Custom errors are response middleware, not an alternate router. A route cannot proxy to a target derived from headers/path/query. Rewrites affect only the upstream request after route/auth decisions; they do not rematch.

### 19.4 Service discovery merge

Every provider outputs namespaced `DiscoveredEndpoint` records into a normalized candidate. Static config owns listeners/routes/security policy. Discovery may add/remove endpoints only inside an explicitly linked upstream group; it cannot create a public route, middleware, certificate policy, admin setting, or secret reference. Provider loss obeys configured stale TTL, then drains/removes endpoints and alerts—never exposes an unrelated service.

## 20. Middleware model and ordering

### 20.1 Fixed stages

Middleware order is compiled, not interpreted from arbitrary list order:

1. Outer request span and access-log guard.
2. Request ID and trusted client/forwarded-header normalization.
3. Header/request-target and declared body-size limits.
4. ACME HTTP-01 internal challenge intercept with dedicated global limits (exact system route only, unaffected by user-route auth/IP policy); TLS-ALPN-01 is handled before HTTP in the TLS acceptor and never enters this pipeline.
5. User-route IP allow/deny and pre-auth in-flight/edge rate limit.
6. Redirect or public maintenance terminal action.
7. CORS preflight validation/short-circuit.
8. Basic/ForwardAuth (native OIDC later).
9. Principal-aware rate limit.
10. URL rewrite and request-header mutation.
11. Timeout/buffering/retry/circuit/upstream proxy core.
12. Custom upstream/proxy error page.
13. Response/header security, CORS actual-response headers, and cache-control.
14. Compression.
15. Final byte/status accounting, passive health classification, trace/access event.

Response effects unwind in the declared response-stage order, not simply reverse request order. The compiler rejects any user chain that attempts to move a type outside its allowed stage.

### 20.2 Middleware rules and interactions

| Middleware | Stage and rules | Required interactions/security checks |
|---|---|---|
| Request ID propagation | Stage 2. Accept inbound ID only from trusted peers and only if it matches a bounded format; otherwise generate cryptographically random ID. | Set one internal/request/upstream header; response echo optional. Never use raw ID as metric label or file path. |
| Access logging | Outer stage 1, finalized at 15 so it observes rejects, auth failures, upstream attempts, bytes, and cancellation. | Headers/query/body absent by default; sensitive fields always redact. Logging failure never blocks data traffic, but drop counter/alert is mandatory. |
| IP allowlist/denylist | Stage 5 using trusted client IP, not arbitrary `X-Forwarded-For`. Deny takes precedence. | Invalid/missing trusted chain falls back to immediate peer. CIDR sets immutable; return 403 without revealing rule. |
| Rate limiting | Edge limiter at stage 5; optional authenticated-principal limiter at 9. Token bucket with monotonic clock, bounded key store, idle eviction. | Key source must be trusted. Exhaustion returns 429 + bounded `Retry-After`; local-only semantics documented; metrics use limiter ID only. |
| In-flight limit | Stage 5 per listener/route/client and stage 11 per upstream. | Release on cancellation/panic-safe guard. 503 or 429 policy explicit; no waiting queue unless bounded with timeout. |
| Request-size limits | Header/declared length at stage 3; streaming counter at stage 11. | Reject oversized `Content-Length` before auth/upstream. Unknown length remains streamed and bounded; do not decompress inbound bodies. |
| Timeout policies | Header/handshake before routing; auth timeout at stage 8; overall/upstream dial/response/body-idle at 11. | Distinguish 408, 504, and client cancel; zero/unlimited values rejected except explicitly safe stream lifetime fields. |
| Redirects | Terminal stage 6 after IP/edge limits, before auth by default. Target is typed fixed/relative template with host allowlist. | CRLF impossible through typed URI; preserve/drop query explicitly; method status (301/302/303/307/308) validated. Protected redirects require a separate authenticated route. |
| Maintenance pages | Terminal stage 6 for public maintenance; an authenticated variant compiles after stage 8. | Fixed embedded or bounded read-only file content; no path derived from request; `Retry-After`, cache policy, and status explicit. |
| CORS | Preflight at stage 7; actual response headers at 13. Exact origin/scheme/host/port allowlist; `Vary: Origin`. | Wildcard origin with credentials is invalid. Preflight bypasses auth by default but validates requested method/headers; optional authenticated preflight is explicit. |
| Basic authentication | Stage 8. Store Argon2id hash + username mapping via secret refs; TLS route required. | Constant-time verification, bounded hash pool/rate limits, `WWW-Authenticate`, no plaintext password/logging. Strip inbound identity headers first. |
| Forward authentication | Stage 8 before rewrite, sends method/original canonical URL and allowlisted headers to configured auth upstream. | Short timeout/body/header caps, verified TLS, no client body by default, fail closed on error, allowlisted returned identity headers only. Strip spoofed copies. Validate redirects. |
| Authentik integration | Use ForwardAuth contract in v1 with a documented recipe and explicit returned-header allowlist. | Authentik endpoint is a configured upstream with TLS/egress policy; trust no arbitrary `X-authentik-*` from clients. Native OIDC is not implied. |
| OIDC integration | Proxied applications use ForwardAuth in v1. Native browser OIDC for admin/UI is Phase 10. | Authorization Code + PKCE, exact issuer/audience/nonce/state, key rotation, secure HttpOnly SameSite cookies, CSRF, logout/session expiry. No implicit trust of email/group claims. |
| URL rewrite | Stage 10 after route/auth; supports typed path prefix strip/add and exact replacement. No regex in MVP. | Does not rematch, change scheme/authority, or introduce `..`/CRLF. Preserve original path in internal context, not client-controlled header. |
| Header manipulation | Request stage 10; response stage 13. Typed set/add/remove allowlists. | Cannot directly set hop-by-hop, framing, `Host`, authority, forwarded, request-ID, auth-result, or TLS identity headers; dedicated typed options own them. Reject CR/LF. |
| Security headers | Response stage 13. Set/override policy explicit per header. | Do not blindly overwrite application CSP/HSTS without configured precedence. Apply `X-Content-Type-Options`, frame policy, referrer policy, permissions policy as selected. |
| HSTS | Response stage 13 only for HTTPS. | HTTP use is invalid. `includeSubDomains`/`preload` require explicit acknowledgement because rollback is slow; never infer preload submission. |
| CSP | Response stage 13 with a validated bounded string/template; report-only supported separately. | No nonce generation in v1 unless HTML mutation exists (it does not). Warn that a proxy CSP can break apps; prefer app-owned CSP. Reject CR/LF. |
| Cache-control policy | Response stage 13, typed set/remove for configured status/content types. | No response cache. Avoid caching auth/error/sensitive responses by safe default; preserve upstream unless explicit override. |
| Custom error pages | Stage 12 for selected proxy errors/status classes only. | Bounded static content or fixed internal service; recursion impossible; never replace admin/auth/policy errors unless explicit; preserve request ID, avoid leaking upstream cause. |
| Compression | Stage 14 after final response headers. Stream gzip/Brotli for allowed types/sizes; set `Vary`; remove/recompute length. | Skip already encoded, range, WebSocket, gRPC, SSE by default, no-transform, tiny, and secret-bearing/authenticated responses unless explicitly approved to reduce BREACH risk. CPU concurrency capped. |
| Buffering controls | Stage 11, off by default. Bounded request/response memory only. | Required for replay/inspection only; reject sizes over route/process budget. No unencrypted temp files. Disables streaming latency and must emit metrics. |
| Retry policy | Stage 11 around upstream attempt only, not auth/middleware. Total deadline/attempt budget. | See Section 14.7; never duplicate unsafe or partially sent requests by default. Record attempt count; exclude intentional hedging in v1. |
| Circuit breaker | Stage 11 before endpoint selection/attempt. Per-group closed/open/half-open state. | Bounded rolling stats, minimum sample size, cooldown/jitter, small probe budget. Does not replace active health; 503 response distinct in metrics. |

Middleware configuration references named definitions, but each route gets a compiled concrete chain. Definitions are immutable per snapshot; sharing does not create mutable cross-route state except explicitly scoped limiter/breaker stores.

## 21. Persistence model

### 21.1 No database in v1

Desired state and operational state are naturally file-shaped. A database would add migrations, credentials, backups, failure modes, and HA expectations without solving an approved requirement. Use Serde plus atomic filesystem operations.

Proposed state layout:

```text
/etc/rust-proxy/
  proxy.toml                         # operator-owned desired state, read-only to process
/var/lib/rust-proxy/
  config/
    active.json                      # revision ID/hash pointer, atomic replace
    revisions/<sequence>-<hash>.toml # immutable canonical config
    metadata/<revision>.json         # author/source/time/warnings/activation result
  certs/<certificate-id>/
    current.json                     # active generation pointer
    generations/<id>/cert.pem        # public chain
    generations/<id>/key.age         # encrypted private key
    generations/<id>/metadata.json
  acme/<issuer-id>/account.age
  audit/admin-YYYY-MM-DD.jsonl
  backups/                           # optional local staging only; not sole backup
/run/rust-proxy/
  admin.sock
  readiness
```

### 21.2 Atomicity and durability

- Write in the destination directory using exclusive create, verify bytes/hash, flush file, rename, then sync directory where the platform supports it.
- Never update immutable revisions/generations in place.
- Active pointers contain schema version, sequence, hash, and target. On startup, verify target hash before use.
- One process lock protects a state directory. Failure to acquire exits; it never guesses multi-writer safety.
- Disk low/high watermarks expose alerts. Certificate renewal/config mutation stops before exhausting reserved state space; traffic continues from memory/current files.
- Revision retention default proposal: last 50 successful, last 20 rejected, and at least 30 days; never delete the active or immediate previous revision.

### 21.3 Audit storage

Admin/security audit is append-only JSONL with sequence, UTC timestamp, actor type/ID, source peer, action, resource IDs, old/new revision hashes, authorization result, outcome, request ID, and redacted error code. Each record includes previous hash and HMAC using a dedicated externally injected audit key. This detects local modification but does not protect against an attacker who owns both process and key; production guidance forwards records promptly to append-protected SIEM/object storage.

Audit records carry a non-secret key ID. Rotation writes a chain-transition record authenticated by old and new keys before the old key is retired. If the old key is unavailable after an incident, starting a new chain is an explicit break-glass action with an externally recorded gap; continuity is never fabricated.

Access logs are not stored in this state directory by default. They go to stdout/journald/container logging. Internal log rotation is avoided; operators configure journald retention, Docker logging driver, or external `logrotate` with copy/truncate behavior tested.

## 22. Administrative API design

Version prefix: `/v1`. Content type: JSON. Errors use one envelope:

```json
{
  "error": {
    "code": "config.route_conflict",
    "message": "route app-api conflicts with app-catchall at equal priority",
    "details": [{"path": "routes[3].priority", "reason": "ambiguous overlap"}],
    "request_id": "01..."
  }
}
```

No stack trace, filesystem internals, secret value, upstream response body, or raw database/library error is returned.

| Method/path | Role | Behavior |
|---|---|---|
| `GET /v1/live` | unauthenticated only on private health listener | Event loop/process alive; no dependency details. |
| `GET /v1/ready` | private health listener | 200 only with active snapshot, required listeners/tasks ready, and not draining; otherwise 503 reason codes. |
| `GET /v1/status` | viewer | Version, uptime, active revision, reload/cert/task summary; redacted. |
| `GET /v1/config/active` | viewer | Canonical redacted active config + ETag. |
| `POST /v1/config/validate` | operator | Strict validation and warnings; no persistence/activation. |
| `POST /v1/config/preview` | operator | Redacted normalized objects, route order, middleware order, diff, activation class. |
| `POST /v1/config/candidates` | operator | Persist immutable candidate against base revision; returns ID/hash. |
| `POST /v1/config/candidates/{id}/activate` | admin | Requires `If-Match`; audited transactional activation. |
| `GET /v1/config/revisions` | viewer | Paginated redacted metadata. |
| `GET /v1/config/revisions/{id}` | viewer | Redacted revision and activation outcome. |
| `POST /v1/config/revisions/{id}/rollback` | admin | Validates old schema/migrates in memory, creates a new forward revision, activates transactionally. |
| `GET /v1/routes` | viewer | Effective route/status summary; no secrets. |
| `GET /v1/upstreams` | viewer | Endpoint health/drain/breaker summary; DNS addresses only if role/policy permits. |
| `GET /v1/certificates` | viewer | Names, source, issuer, expiry, renewal status; never private material. |
| `POST /v1/certificates/{id}/renew` | operator | Deduplicated renewal request with rate/authorization checks. |
| `POST /v1/backups` | admin | Creates encrypted manifest/archive staging record; never includes age identity. |
| `POST /v1/restore/validate` | admin | Offline-like validation of encrypted backup and compatibility; no mutation. |
| `GET /v1/audit` | auditor/admin | Paginated audit metadata; authorization events cannot be filtered away by caller. |

Config upload endpoints accept TOML bytes only when content type is explicit; JSON API object support waits until schema-generation parity is proven. OpenAPI is generated/checked from API types or maintained with contract tests; it is not publicly served by default.

## 23. CLI design

One binary provides offline and online operations:

```text
rust-proxy run --config /etc/rust-proxy/proxy.toml
rust-proxy run --check --config proxy.toml  # dry-run full startup preparation; binds nothing
rust-proxy config validate --file proxy.toml [--resolve-secrets]
rust-proxy config preview --file proxy.toml [--against REV]
rust-proxy config fmt --check|--write
rust-proxy config migrate --from FILE --to FILE
rust-proxy config activate --file proxy.toml --expect REV
rust-proxy config revisions
rust-proxy config rollback REV --expect CURRENT
rust-proxy cert list|inspect ID|renew ID|import ...
rust-proxy secret recipient generate       # explicit local ceremony; never logs identity
rust-proxy token create --role operator     # returns plaintext once; stores/prints hash workflow
rust-proxy backup create --output FILE
rust-proxy backup verify FILE
rust-proxy restore validate FILE
rust-proxy health --socket /run/rust-proxy/admin.sock
rust-proxy completion bash|zsh|fish|powershell
rust-proxy version --verbose
```

Offline commands never contact the running daemon unless `--resolve-secrets`/online action is explicit. Online commands default to the Unix socket. Exit codes are stable: `0` success, `2` usage, `3` invalid config, `4` conflict/stale revision, `5` authorization, `6` unavailable, `7` partial operational warning. JSON output is opt-in and versioned. Human output redacts secrets and is safe to paste into tickets.

## 24. Web UI strategy

No UI in v1. Phase 10 requires explicit approval after the administrative API, audit, RBAC, and backup/rollback workflows have production evidence.

If approved:

- Build a separate TypeScript frontend project consuming `/v1`; it has no direct data-plane or state-directory access.
- Serve it on the private admin origin through a same-origin gateway, not through arbitrary public routes. Default remains disabled.
- Prefer generated API types from checked OpenAPI; no duplicate handwritten contract.
- Use OIDC Authorization Code + PKCE with Authentik-compatible discovery. Session cookies are `Secure`, `HttpOnly`, scoped to admin path/host, short-lived, rotated, and `SameSite=Lax` or stricter where flow permits.
- CSRF uses origin checks plus a session-bound token for all mutations. CSP forbids inline script/object/base URI and constrains connect/frame ancestors.
- Escape untrusted values, avoid dangerous HTML rendering, and test stored/reflected/DOM XSS. Route/config text is displayed as text, never injected markup.
- UI performs preview/diff and sends `If-Match`; it cannot bypass server validation or permissions.
- Multi-user management, recovery, WebAuthn/TOTP, and break-glass behavior require their own threat review; no default credentials.

## 25. Authentication and authorization

### 25.1 Administrative access

Authentication modes:

1. Unix socket filesystem permission plus optional allowed peer UID/GID (default local mode).
2. Mutual TLS with explicitly configured admin CA and certificate-to-principal mapping (recommended remote automation).
3. Random API tokens, displayed once, stored only as Argon2id hashes with token ID/role/expiry/last-used metadata; verification is constant-time after indexed ID lookup.
4. OIDC browser session only in Phase 10.

Remote TCP admin requires TLS and at least mTLS or token auth. Plain HTTP, wildcard public bind without explicit acknowledgement, query-string tokens, Basic admin passwords, and default credentials are forbidden.

Roles:

| Role | Permissions |
|---|---|
| `viewer` | Read redacted status/config/routes/upstreams/cert metadata. |
| `auditor` | Viewer plus audit read/export. |
| `operator` | Viewer plus validate/preview/candidate creation, drain/renew actions; cannot activate policy or manage identities. |
| `admin` | Activate/rollback, manage admin auth/RBAC, backup/restore operations, all operator actions. |

Permissions are checked server-side per route and resource. Deny is default. Role mapping from OIDC uses exact issuer + client ID + allowlisted claim values; email domain alone is never authorization. Break-glass access is a separately stored short-lived recovery token or local root/admin-group procedure, always audited.

### 25.2 Data-plane authentication

- Basic auth: Argon2id hashes through secret refs, TLS-only, rate-limited.
- ForwardAuth: generic contract for Authentik, oauth2-proxy, Authelia, and similar services; fail closed and allowlist headers.
- Native route OIDC: deferred. It duplicates session, refresh, logout, claim, CSRF, and cookie logic that a dedicated identity proxy already handles.
- API-key/JWT validation is not bundled under “OIDC”; add only with explicit issuer/audience/key-rotation requirements.

### 25.3 Bootstrap and secret management

- There is no built-in `admin@example.com` or generated password printed to ordinary logs.
- Local initial administration uses state/socket ownership. Token generation is an explicit CLI action that prints a secret once to the terminal and emits only token ID/hash metadata to storage/audit.
- Secrets are referenced, never committed. Environment refs are acceptable for simple containers but file/systemd credentials are preferred because environment values may leak through process inspection/crash tooling.
- Secret file checks cover absolute path, no symlink escape where configured, owner/mode, regular-file type, maximum size, and atomic rotation semantics.

## 26. Threat model

### 26.1 Scope, assets, actors, and trust boundaries

Protected assets are listener availability, routing policy, upstream credentials, certificate private keys, ACME account keys, administrative identities/tokens, audit integrity, configuration history, and the confidentiality/integrity of proxied traffic. Adversaries include anonymous internet clients, hostile tenants or upstreams, a compromised discovery source, a stolen operator credential, a malicious dependency/build input, and a local user with less privilege than the service. A fully compromised host kernel is outside the application's prevention boundary; deployment controls must reduce blast radius and enable detection and recovery.

Trust boundaries are: public client to listener; proxy to upstream; proxy to DNS/discovery; proxy to ACME CA/DNS provider; local or remote administrator to control plane; control plane to immutable runtime snapshot; process to state/secret files; container to host; and CI to release artifact. Configuration, discovery metadata, DNS answers, certificate responses, forwarded headers, logs, and backups are untrusted until validated for their use.

Security objectives are measurable controls and tests, not a claim of being vulnerability-free:

- Only explicitly configured routes and upstream destinations can receive traffic.
- Administrative mutations require authenticated, authorized, auditable principals and optimistic concurrency.
- Parser ambiguity is rejected at the edge; hop-by-hop semantics are normalized once.
- Resource use is bounded per listener, route, connection, request, background queue, and process.
- A failed reload or renewal preserves the last-known-good configuration or still-valid certificate.
- Secrets are absent from normal logs, redacted exports, diagnostics, and build artifacts.

### 26.2 Threat-to-control matrix

| Threat | Preventive controls | Detection and required verification |
|---|---|---|
| Untrusted inbound HTTP traffic; malformed HTTP messages | Hyper parser; strict URI/method/header validation; bounded start line, headers, count, body, and trailers; reject ambiguous syntax before routing. | Malformed corpus, differential parser tests, fuzz targets, rejection counters without reflected payloads. |
| Request smuggling; HTTP desynchronization | One framing interpretation; reject conflicting/multiple `Content-Length`, invalid transfer encoding, forbidden H2 connection headers, ambiguous whitespace, and H1 upgrade anomalies; reconstruct upstream request instead of forwarding raw bytes. | Smuggling corpus across H1-to-H1, H1-to-H2, H2-to-H1; expert protocol review before release. |
| Header injection; CRLF injection; log injection | Typed header APIs only; reject control bytes; canonical structured log fields; escape terminal/newline content; never concatenate raw headers into protocol or log lines. | Property tests and log-sink assertions for CR/LF/control characters. |
| Host-header attacks; open-proxy misuse | Require an explicit listener and route match; normalize authority/Host consistency; no catch-all proxy target; unmatched requests receive a fixed response. | Tests for absolute-form requests, duplicate Host, unknown hosts, IP authorities, CONNECT, and wildcard precedence. |
| SSRF | Upstreams are configured objects, not client-supplied URLs; canonical scheme/authority; optional egress CIDR allowlist; forbid userinfo and link-local/metadata/loopback/private destinations unless explicitly allowed per upstream. | Config lint plus runtime destination policy after every DNS resolution; metadata endpoint test suite. |
| DNS rebinding; DNS poisoning | Use the selected Hickory resolver with capped answers and bounded record TTL; validate every resolved address against destination policy and pin each connection to its validated result; never reuse validation after an answer changes. DNSSEC is not claimed unless an explicitly configured validating path is proven end to end. | Resolver simulation with answer changes, mixed public/private answers, TTL expiry, NXDOMAIN and poison/failure metrics. |
| Path traversal and path-based policy bypass | Canonicalize once as Section 19.1, reject encoded separators/backslashes/dot segments, and forward the same canonical path used for policy; proxy core does not map URL paths to local files; maintenance/error files are pre-opened from a configured root with canonical containment and no user-derived path. | Traversal/routing corpus including double encoding, encoded separators/dots, Unicode, mixed slash forms and filesystem symlinks. |
| TLS downgrade; weak TLS configuration | Rustls; TLS 1.3 and 1.2 by explicit policy, 1.0/1.1 unavailable; no opportunistic plaintext fallback; safe curated suites/groups; HSTS opt-in only after domain readiness. | TLS scanner in integration/release environment; config validation rejects unsupported versions/combinations. |
| Certificate theft; ACME account compromise | Encrypted key envelopes at rest; identity supplied separately; restrictive modes; no key API/export by default; separate ACME account and certificate identities where operationally useful; rotate/revoke runbook. | Secret scanning, permission checks, access audit, restore drill, incident exercise. |
| Secret leakage | Secret references; `secrecy`/zeroization where effective; debug implementations redact; panic/crash/log/export filters; never place secrets in metrics labels or CLI arguments when avoidable. | Canary-secret tests search logs, API responses, backups, diagnostics, and core-dump policy. |
| Authentication bypass; authorization bypass | Fail-closed auth chain; exact issuer/audience; server-side RBAC per operation; mTLS mapping; expired/revoked token rejection; no identity from untrusted headers. | Full authorization matrix and negative tests for every admin endpoint and data-plane auth mode. |
| Session fixation; CSRF; administrative XSS | UI deferred; if enabled, rotate session on login/privilege change, secure cookies, origin plus CSRF token checks, strict CSP, output encoding, no unsafe HTML. | Browser integration tests and independent UI security review before Phase 10 exit. |
| SQL injection | No database in v1. Any later SQL layer must use compile-time/parameterized queries and least-privileged schema roles. | Revisit threat model and add injection tests before introducing SQL. |
| Command injection | Runtime never invokes a shell; no raw hook/script feature; subprocesses are avoided. Packaging scripts use fixed commands and treated arguments. | CI grep/policy review for process execution and shell construction. |
| Configuration injection | Strict typed schema, unknown-field rejection, no templating/eval/includes in v1, bounded strings, canonical IDs, semantic validation, signed/authorized activation. | Parser fuzzing, malicious config corpus, diff/preview, audit of source hash and actor. |
| Sensitive headers in logs | Denylist plus explicit opt-in allowlist; redact Authorization, Cookie, Set-Cookie, proxy auth, API keys, and configured names; query logging off by default. | Golden log tests with canary values and SIEM export tests. |
| Abuse of forwarded headers; incorrect client-IP attribution | Strip inbound forwarding headers from untrusted peers; explicit trusted-proxy CIDRs and hop policy; rebuild standardized `Forwarded` and selected `X-Forwarded-*`; PROXY protocol off by default and listener-scoped. | Multi-hop/spoof tests for IPv4/IPv6, PROXY protocol and direct bypass paths. |
| Rate-limit bypass | Key source is authenticated identity or trusted effective IP; canonicalize IPv4/IPv6; bounded local token buckets; document that per-node limits are not global in v1. | Distributed-node limitation documented; spoof, reconnect and key-cardinality tests. |
| Denial of service; Slowloris; large-body attacks | Header/read/write/idle/total timeouts; body limits before and during streaming; minimum data-rate option; connection/listener/route concurrency caps; bounded queues and buffers. | Slow client/upstream, oversized chunked body and queue saturation tests; reason-specific counters. |
| Compression bombs | Request decompression not provided in v1; response compression only for eligible bounded metadata and streaming output, never decompress upstream content; disable for secret-bearing responses where compression side channels matter. | Highly compressible payload tests and CPU/memory profiling. |
| Connection, file-descriptor, memory, or CPU exhaustion | Global and scoped semaphores; pooled-connection caps/idle expiry; budgeted buffers; route regex absent in v1; OS `LimitNOFILE`, cgroup memory/CPU/PIDs; overload shedding. | Soak and exhaustion tests prove rejection and recovery without unbounded growth. |
| ReDoS | Exact/prefix matchers only in v1; later regex must use Rust's linear-time `regex` crate, length limits and compile-at-activation. | Adversarial pattern/input tests before regex is enabled. |
| Dependency supply-chain compromise | Minimal pinned lockfile; `cargo-deny`, `cargo-audit`, provenance review, controlled update PRs, two-person release, SBOM, signed artifacts; forbid unknown Git dependencies in release. | CI policy gates, review of advisories/exceptions, verification instructions for signatures/provenance. |
| Malicious container metadata; Docker socket exposure | No Docker provider in v1; later provider is a separate least-privileged helper using a filtered socket proxy/API and validates labels as untrusted config; proxy never mounts Docker socket. | Hostile-label/provider integration tests and deployment policy scan. |
| Unsafe defaults; privilege escalation | Admin socket local, no implicit routes/providers, deny unmatched traffic, non-root process, drop capabilities after bind, immutable config/state boundaries. | Default-config tests and container/systemd security analysis. |
| Container escape impact | Minimal image, read-only root, no shell where practical, non-root UID, no privileged mode, no Docker socket, minimal capabilities, seccomp/AppArmor/SELinux guidance, dedicated writable mounts. | Trivy/Grype and deployment-manifest policy checks; host assumed separately hardened. |
| Administrative API exposure | Unix socket default; remote bind requires explicit TLS/auth configuration and warning; separate listener/limits; no data-plane route can reach admin service internally. | Port/bind tests, external scan, startup audit event with redacted bind/auth mode. |
| Insecure backups | Encrypted archive; certificate keys remain encrypted; backup key kept separately; manifest/checksum/schema version; restrictive destination permissions. | `backup verify`, restore drill and canary-secret handling checks. |
| Rollback attacks | Rollback is an authorized new revision, never silent; minimum supported schema; artifact signature verification; audit links old/new hashes and actor. | Stale revision and downgrade tests; alerts on rollback action. |
| Configuration race conditions | Single serialized activation coordinator; compare-and-swap expected revision; immutable snapshot; atomic state writes; cancellation-safe prepare/commit. | Parallel activation/reload/property tests and crash-injection at every state transition. |
| Certificate renewal race conditions | Per-certificate lock; staged issuance and parse/key/domain verification; atomic encrypted replacement; runtime snapshot swap; retain prior valid material; distributed ownership required before HA ACME. | Concurrent renewal simulation, crash injection, malformed/incorrect certificate and CA outage tests. |

Residual risks are recorded in Section 40. Expert security review is mandatory for protocol normalization, TLS passthrough, ACME/DNS credential handling, ForwardAuth header trust, remote administration, UI session handling, and any future Docker/Kubernetes discovery.

## 27. Security controls

### 27.1 Application controls

- `#![forbid(unsafe_code)]` in first-party crates. An exception requires an ADR, isolated wrapper, reviewer with unsafe expertise, Miri where applicable, fuzz tests, and a documented reason no safe alternative works. Transitive unsafe is tracked by dependency policy.
- Reject unknown config keys and unsupported schema versions; do not silently coerce, skip, or fall back.
- Normalize a request exactly once and pass typed values between stages. Strip hop-by-hop headers named both statically and by the `Connection` header.
- Outbound TLS verifies name and chain against an explicit system/bundled/private trust choice. There is no `insecure_skip_verify` release option.
- Administrative and secret comparisons use constant-time primitives after non-secret identifier lookup. Token material has at least 256 random bits and bounded expiry.
- Error responses expose stable codes and request IDs, not internal paths, configuration content, upstream bodies, or parser details.
- Audit records are append-only at the application boundary, hash-chained/HMAC-protected, flushed on security mutations, and shipped off-host for stronger tamper evidence.

### 27.2 Build and release controls

- Commit `Cargo.lock`; pin toolchain and container base by digest; require reviewed lockfile changes.
- Build in isolated CI with minimal credentials, protected environments, short-lived OIDC credentials where supported, and no untrusted PR access to signing secrets.
- Generate CycloneDX or SPDX SBOM, vulnerability scan it and the final image, sign artifact/image/checksums with Cosign, and publish SLSA-compatible provenance where the CI platform permits.
- Release source, compiler version, features, target, and dependency lock are recorded. A second rebuild compares artifacts where deterministic output is supported; documented nondeterminism blocks a reproducibility claim, not necessarily a release.

### 27.3 Host and container controls

- Dedicated UID/GID; state `0700`, secret files `0600`, admin socket `0660` with a dedicated admin group; no shared application UID.
- Prefer systemd socket activation or rootless port forwarding. If direct low-port bind is required, grant only `CAP_NET_BIND_SERVICE` to the binary/unit and use `NoNewPrivileges`; do not retain root.
- Read-only root filesystem, writable mounts only for state/audit if local, tmpfs for `/tmp`, dropped capabilities, bounded PIDs, memory and CPU, seccomp default profile plus AppArmor/SELinux confinement.
- Data-plane and control-plane have separate sockets, concurrency budgets, authorization, and eventually process privileges if the threat model or operational evidence justifies a split.

### 27.4 Operational controls

- Document key/token/account rotation, certificate revocation, compromised-config rollback, backup loss, admin lockout, dependency advisory, and denial-of-service runbooks.
- Security updates use controlled PRs, all gates, canary deployment, and rollback. No unattended dependency update reaches production.
- A release-blocking security review checklist maps each threat above to code, test, deployment control, owner, and residual risk.

## 28. Reliability and failure handling

### 28.1 Startup, tasks, and shutdown

Startup order is: parse static bootstrap; acquire single-instance lock; check state permissions; decrypt/validate required certificates; build candidate snapshot; bind admin then data listeners; mark ready; start supervised background tasks. A required failure before readiness exits non-zero without partially serving. Optional provider failure leaves its last validated contribution active and marks degraded only if one exists; otherwise its routes do not exist.

Every background task has an owner, cancellation token, restart policy, bounded work queue, heartbeat/status, and shutdown deadline. Programming panics in critical tasks trigger readiness failure and controlled process termination; blindly restarting corrupt or invariant-breaking tasks is forbidden. Non-critical exporters may restart with capped exponential backoff and jitter.

Shutdown sequence is: readiness false; stop accepting admin mutations and new data connections; cancel discovery/renewal scheduling; drain HTTP requests, streams, TCP connections and upstream pools to configured deadlines; flush audit/log telemetry to a bounded deadline; persist status; exit. Long-lived WebSockets/TCP streams receive a separately configured drain deadline. A second signal forces exit.

### 28.2 Failure matrix

| Failure | Required behavior |
|---|---|
| Invalid startup config | Exit non-zero with redacted field-path errors; do not listen. |
| Invalid runtime candidate | Reject candidate; active revision is unchanged; audit failure reason/code. |
| Activation listener bind failure | Abort before commit, close prepared resources, preserve active listeners/snapshot. |
| Crash between candidate write and activation | Journal/revision state identifies uncommitted candidate; restart selects only last committed known-good revision. |
| Upstream connect/TLS failure | Mark passive result, try another healthy endpoint only when retry policy/body replay safety permits; otherwise return stable 502/504. |
| Health checker failure | It may change endpoint health using hysteresis, never mutate route config; last probe details are bounded/redacted. |
| DNS/provider outage | Keep endpoints until configurable stale deadline; mark stale; after deadline fail closed for that provider, never invent an address. |
| ACME issuance/renewal failure | Keep and serve current valid certificate; retry with bounded backoff respecting CA guidance; alert by remaining lifetime; never replace with invalid material. |
| Certificate expired with no replacement | Fail TLS handshake for that name or use an explicitly configured non-expired fallback; never silently serve a wrong-name certificate. |
| State disk full/read-only | Reject mutations/issuance requiring durable commit; continue data plane from memory where safe; readiness policy distinguishes data service from administrative durability. |
| Audit sink unavailable | Local durable queue is bounded. Security mutations fail closed when required durable audit cannot be written; read-only and data traffic continue. |
| Metrics/tracing exporter unavailable | Drop/export with bounded queue and counters; never block proxy traffic. |
| Log sink slow | Bounded non-blocking queue; access log sampling/drop policy is explicit, but security audit is separate and durable. |
| Admin overload/attack | Separate small pool/limits; data-plane budgets remain available. |
| Worker panic/invariant breach | Mark unready, capture redacted diagnostic, drain/restart process under supervisor; do not continue in unknown state. |

### 28.3 Resource budgets

Every value has a global default and optional listener/route override within operator-set maxima:

| Resource | Enforcement |
|---|---|
| Connections | Global/listener/IP semaphores, accept backoff, OS backlog. |
| Concurrent requests/streams | Global/route/upstream semaphores; immediate 503 or bounded queue. |
| Queues | Fixed capacity and maximum wait; no unbounded channels. |
| Headers/body/buffers | Count and byte caps; streaming fixed-size chunks; replay buffer disabled unless bounded retry policy needs it. |
| Time | Handshake, header, body idle, total request, upstream connect/response, keepalive and drain deadlines. |
| Pools | Per-origin connection/idle caps and maximum age; evict on endpoint removal/drain. |
| Background work | Separate semaphores for DNS, health probes, ACME and exports. |
| File descriptors/disk | Startup budget check, systemd/container limits, audit/cert/state retention alerts. |

Defaults are selected and documented during Phase 1 using tests and operational review; they are not hidden library defaults. Exceeding a limit produces a typed reason, bounded response, metric, and structured log at an appropriate sampled level.

## 29. Observability

### 29.1 Logs and audit

- `tracing` JSON logs to stdout/stderr by default: timestamp, level, stable event name, request ID, route ID, listener ID, upstream ID, outcome, duration, byte counts, protocol and TLS metadata. No raw body, authorization, cookies, secret/query values, or high-cardinality user agents by default.
- Access logs are a separate target with configurable sampling and redacted allowlisted headers. Request IDs accept an inbound value only from trusted proxies and only if syntax/length is valid; otherwise generate a random ID and forward it.
- Security audit uses a separate append-only file/sink: actor, auth method, action, object, before/after revision hashes, outcome, source address where trustworthy, request ID and HMAC-chain metadata. It never contains secret values.
- The application does not implement log-file rotation. Containers use the runtime log driver; systemd uses journald retention; bare metal uses journald or logrotate with reopen signaling. Audit retention/export is explicitly configured and disk usage alerted.

### 29.2 Metrics

Prometheus/OpenMetrics is exposed only on the admin listener or a separately authenticated/internal listener. Initial metric families include:

- Requests, active requests/connections/streams, bytes and latency histograms by bounded listener/route/protocol/status-class labels.
- Upstream attempts, active connections, connect/response latency, health state/transitions, retries and circuit state by configured upstream/endpoint ID.
- TLS handshakes/failures by protocol/reason class; certificate expiry timestamp and renewal outcome by certificate ID/issuer, never domain label by default.
- Rate-limit decisions, queue depth/rejections, timeout/limit reasons, access-log drops and telemetry export drops.
- Active config revision info, activation duration/outcome, rollback count, provider freshness, ACME schedule/outcome, background-task health.
- Process/runtime CPU, memory, file descriptors and Tokio task/scheduler signals where stable instrumentation exists.

Configured IDs are bounded in count. Never label by raw host/path/client IP/request ID/user/token/DNS answer. Histograms have reviewed buckets. Removed revisions/endpoint series expire. A metrics-cardinality test loads the maximum supported config and asserts a calculated series ceiling.

### 29.3 Tracing and health

- OpenTelemetry export is optional and asynchronous with bounded batches. W3C `traceparent`/`tracestate` are accepted only after validation; sampling is parent-aware with a local cap. Authorization and route match attributes are low-cardinality and redacted.
- `/live` means event loop/process supervision is functioning; it does not check dependencies.
- `/ready` means listeners and an active valid snapshot exist and required local state is usable. Optional provider/exporter/upstream failures are reported as components but do not automatically make all routes unready.
- `/health/details` is authenticated and returns redacted component status, active/candidate revision, certificate windows, provider freshness, and task heartbeat. Public data listeners do not expose these endpoints by default.

Ship example dashboards and alerts for latency/error rates, no healthy upstreams, rejection/overload, certificate windows/renewal failures, provider staleness, activation failure, audit sink/disk pressure and process restart. Prometheus scrapes the private metrics endpoint; Grafana consumes Prometheus; Loki/agents consume structured stdout/journald; SIEM guidance maps audit JSON through TLS-authenticated collectors. Examples are integrations, not bundled infrastructure.

## 30. Performance strategy

Correctness, bounded memory and predictable overload behavior take priority over peak request counts. No throughput or latency promise is made until measured on a named release, target and workload.

Benchmark profiles are versioned under `bench/`:

1. Plain H1 keepalive with small fixed response.
2. TLS H1/H2, including handshake/resumption and H2 multiplexing.
3. Streaming upload/download with bounded memory assertions.
4. WebSocket concurrency and bidirectional traffic.
5. gRPC unary and streaming.
6. Route tables at 10, 1,000 and supported-maximum rules; certificate lookup at equivalent SNI counts.
7. Weighted balancing with healthy/unhealthy transitions and retry-safe failures.
8. Reload of minimum, representative and maximum supported configuration while traffic continues.
9. Slow client/upstream, upstream outage, overload and sustained soak.

The reproducible environment records CPU model/count, RAM, kernel, NIC/network namespace topology, Rust toolchain, features, build flags, TLS mode, upstream program, payloads, connections, warm-up, run time and raw results. Use a dedicated host, fixed CPU governor where possible, no internet dependency, at least five measured runs, latency p50/p90/p99/p99.9, throughput, errors, CPU, RSS/allocator, FDs and network bytes. Criterion is for microbenchmarks; a pinned `wrk2`/`h2load`/`ghz` or purpose-built load harness covers protocols; exact tool versions are locked.

Phase 1 establishes a baseline and support envelope rather than advertising it. Subsequent PRs fail the performance gate when median throughput or p99 latency regresses more than 5% in two repeated controlled comparisons, or peak RSS/FD count grows more than 10%, unless the PR documents evidence and obtains performance-owner approval. Soak acceptance is no crash, deadlock, unbounded monotonic resource growth, or unexplained error; quantitative release SLOs are a Phase 14 product decision based on target hardware and workloads.

## 31. Testing strategy

### 31.1 Test layers

| Layer | Required coverage |
|---|---|
| Unit | Route normalization/precedence/conflicts; header and hop-by-hop handling; trusted forwarding; each middleware order/interaction; strict parsing and cross-field validation; certificate/SNI selection; weighted/load-balancing invariants; rate limiting/time; authn/RBAC; secret/log redaction; typed errors and retry decision. |
| Property-based | Matcher determinism and order independence where promised; config round-trip without secrets; weighted selection distributions within statistical bounds; limits never exceed budget; normalization idempotence; no unauthorized RBAC operation. Use `proptest`. |
| Integration | H1/H2, WebSocket, unary/streaming gRPC, TLS termination/SNI, TCP/TLS passthrough; local Pebble ACME HTTP-01/DNS-01/TLS-ALPN-01 and renewal; custom cert import; upstream/health transitions; graceful reload/shutdown; large bounded upload, streaming download, slow endpoints; retry/idempotency/timeouts/circuit behavior; ForwardAuth; activation rollback. |
| Security | Parser/smuggling corpus; CRLF/header/Host/forwarded tests; SSRF/rebinding/path traversal; auth bypass/RBAC matrix; UI CSRF/XSS when applicable; secret canaries; malformed TLS; resource exhaustion; dependency/container/static scans; unsafe review. |
| Fuzz | Config parser/validator, URI/authority/forwarded normalization, H1 edge translation adapters, certificate import/selection metadata, PROXY protocol when enabled. Seed with regressions; sanitize findings before committing corpus. |
| Performance | All Section 30 profiles, maximum supported configuration, overload/recovery, 24-hour pre-release soak initially and longer before declared production tiers. |
| Upgrade/recovery | Schema N-1 to N, unsupported version rejection, interrupted activation/renewal/backup, binary rollback, backup verification and clean-host restore. |

Test servers bind ephemeral loopback ports and use deterministic clocks/RNG wrappers where behavior depends on time/random choice. Tests must not use public ACME, public DNS, Docker socket, or internet services. Protocol tests run both same-protocol and translation paths. Integration suites assert response correctness, cancellation, backpressure and resource cleanup, not only status codes.

### 31.2 Security and correctness tooling

- `cargo test --workspace --all-features` plus minimal/default feature combinations.
- `cargo nextest` may improve CI scheduling, but is optional until suite size justifies another tool.
- `cargo-fuzz` nightly smoke runs and scheduled longer campaigns; crashing inputs become regression tests.
- `proptest` for invariants; Loom only for a demonstrated small concurrency primitive, not broad speculative modeling.
- Miri on first-party unsafe-free core/config tests where dependencies permit; incompatibilities are documented, not ignored globally.
- Clippy warnings denied, rustfmt check, rustdoc tests and API docs warnings.
- No coverage percentage is treated as proof. Coverage reports identify untested security branches; every security control must have a named test or deployment validation.

### 31.3 Test acceptance

- Tests are hermetic and repeatable; flaky tests are quarantined only with owner, issue and expiry, never silently retried to green.
- Every fixed security/correctness defect adds a regression test and, where relevant, a fuzz seed.
- Critical parsers and authorization decisions exercise success, rejection and boundary values.
- Graceful reload test maintains traffic and asserts zero accepted-request loss attributable to activation; failed activation preserves exact active revision/hash.
- Resource tests assert configured hard limits and post-load recovery within a documented observation window.

## 32. CI/CD design

### 32.1 Workflows

| Workflow | Trigger and gates |
|---|---|
| `ci.yml` | PR/push: pinned toolchain, formatting, Clippy `-D warnings`, docs, unit/property tests, workspace feature matrix, integration subset, config examples validate. |
| `security.yml` | PR plus schedule: `cargo-audit`, `cargo-deny` advisories/licenses/bans/sources, secret scan, CodeQL Rust analysis, fuzz smoke, policy checks, dependency diff. |
| `integration.yml` | PR labels/main/nightly: Linux protocol matrix, Pebble ACME, reload/shutdown, rootless container/systemd harness where available. |
| `fuzz.yml` | Nightly/manual: per-target bounded campaigns, corpus/artifact retention, issue creation without exposing secrets. |
| `perf.yml` | Trusted main/manual on dedicated runner: pinned profiles, compare baseline, store raw result and environment manifest; never run untrusted code on persistent privileged runner. |
| `container.yml` | Build minimal image, run as non-root/read-only tests, Trivy and Grype scan, Syft SBOM, Compose smoke and health checks. |
| `release.yml` | Protected signed tag: full gates, semver check, cross-platform/architecture build, checksums/SBOM, image manifest, Cosign signatures and provenance, release notes; manual approval. |
| `upgrade.yml` | Main/release: configuration migration fixtures, state/backup N-1 restore, binary upgrade/rollback and candidate crash injection. |

Required targets are Linux x86_64 and aarch64 for production. macOS and Windows builds are best-effort developer/CLI compatibility until listener, privilege and filesystem semantics have dedicated support; production support claims remain Linux-only. Cross-compiled artifacts require native/emulated smoke tests before release.

### 32.2 Tool decisions

| Tool | Decision and purpose |
|---|---|
| `cargo-audit` | Use for RustSec advisories; time-bounded, justified exceptions only. |
| `cargo-deny` | Use for license compatibility, duplicate/high-risk crates, advisories and non-registry/Git source policy. |
| `cargo-semver-checks` | Run once public crate/API stability exists; before then it is informative because the product API is CLI/config/admin API. |
| `cargo-fuzz` | Use for parser/normalization inputs on nightly Rust in isolated jobs. |
| `proptest` | Use in ordinary tests for stated invariants. |
| Miri | Scheduled targeted run; record unsupported dependencies/paths and never describe partial execution as full proof. |
| CodeQL | Enable Rust analysis as defense in depth; compiler/Clippy/fuzz/manual review remain primary. |
| Trivy | Gate OS/package/image/IaC findings by reviewed policy. |
| Syft | Generate SPDX or CycloneDX SBOM for binaries/images. |
| Grype | Scan SBOM/image as a second database/view; deduplicate but do not hide disagreements. |
| Cosign | Keyless signing/provenance in CI where identity controls are adequate; document offline/keyed alternative. |

Secret scanning uses a maintained scanner such as Gitleaks plus platform scanning. License allowlist initially accepts MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode and compatible notice licenses; copyleft or unclear licenses require legal review. NPMPlus's AGPL-3.0-or-later code is research-only and is not linked, copied, or vendored. Dependency exceptions name owner, rationale, compensating control and expiry.

Release notes list security changes, config schema/migration actions, behavioral changes, known issues, checksums/signature verification and rollback procedure. Release jobs never automatically deploy production; deployment promotion verifies the immutable signed digest.

## 33. Deployment architecture

### 33.1 Hardened reference deployment

```text
Internet
   |
[optional L4 load balancer: health checks + source preservation]
   |
80/443/TCP ----> rust-proxy (non-root, read-only root, private admin socket)
                       |-- outbound TLS --> allowlisted application networks
                       |-- DNS/ACME HTTPS --> constrained egress
                       |-- /var/lib/rust-proxy (revisions + encrypted certs)
                       |-- /run/rust-proxy/admin.sock (0660 proxy-admin)
                       `-- stdout/access + append-only audit --> collectors/SIEM

Operator/automation --> SSH/local CLI or authenticated private mTLS admin listener
Prometheus -----------> private metrics endpoint
Backup agent ---------> read-consistent backup command --> encrypted off-host store
```

Data-plane ports may be public; administrative, metrics, debug and health-details endpoints are private. Application upstream networks accept traffic only from proxy nodes/security groups. Egress policy allows configured upstreams, resolvers, selected ACME CAs and DNS APIs; a dynamic destination cannot bypass the application's address policy.

### 33.2 Docker Compose and rootless containers

- Publish `80:8080` and `443:8443` through rootless Podman/Docker where its networking performance/source-IP behavior is acceptable; otherwise grant only `CAP_NET_BIND_SERVICE` and bind 80/443. Never use `privileged`, `network_mode: host` by default, or mount `/var/run/docker.sock`.
- Run a fixed non-root UID/GID, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, PIDs/memory/CPU/FD limits, tmpfs `/tmp`, and only `/var/lib/rust-proxy` writable. Mount config and secret identity read-only from separate sources.
- Bridge mode gives network isolation and explicit publishing but may alter apparent client IP and add NAT; configure only the bridge/gateway as trusted if it inserts forwarding metadata. Host mode simplifies ports/source address and can improve some workloads, but expands network visibility and port-collision blast radius; it requires explicit approval and admin still binds only Unix/private address.
- Compose healthcheck uses the CLI against the Unix socket. A container restart policy handles process failure, not invalid configuration loops; deployment validates the candidate before replacement.

### 33.3 systemd and bare-metal Linux

- Install a signed/checksummed binary and a dedicated system user. Use systemd credentials for the age identity/DNS tokens where available.
- Unit hardening includes `User=`, `Group=`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` only if required, `CapabilityBoundingSet=`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernel*`, `ProtectControlGroups=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes` if compatible, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallArchitectures=native`, and explicit `ReadWritePaths=/var/lib/rust-proxy /run/rust-proxy`.
- Prefer systemd socket activation only after Phase 1 proves graceful listener ownership and upgrade semantics. Otherwise the binary binds before dropping its sole capability.
- Bare-metal files follow Section 21 ownership/modes. Journald handles application/access logs; audit is forwarded and retained separately.

### 33.4 Kubernetes (later/optional)

Kubernetes is not a Phase 1–9 deployment target. When added, use a Deployment/DaemonSet only after choosing source-IP and load-balancer behavior; restricted Pod Security, non-root UID, read-only root, dropped capabilities, seccomp `RuntimeDefault`, NetworkPolicy, projected secrets, persistent state only if node ownership is defined, and separate readiness/liveness. Native Ingress/Gateway API discovery belongs to Phase 11; until then, mount an immutable validated config. Do not claim HA ACME by sharing a writable volume.

### 33.5 Persistence, upgrade, limits, and certificates

- Persist revisions, active pointer, encrypted certificate/account envelopes, audit spool and backup metadata. Ephemeral metrics/access logs are exported, not backed up as application state.
- Deployment order is backup/verify, offline config migration/validation, start candidate on test ports or canary node, readiness/traffic probe, then load-balancer promotion. Rollback uses the prior signed binary plus a compatible revision; never overwrite the prior artifact during upgrade.
- Shared certificate storage is avoided initially. Each independent node may issue distinct certificates only if challenge routing, CA rate limits and ownership are designed; the recommended HA model uses an external certificate controller/vault and distributes encrypted/imported leaf material. Network filesystems with concurrent writers are unsupported.
- Resource values are deployment inputs derived from the tested support envelope. Memory limit must exceed configured maximum connections/buffers plus measured baseline; FD limit covers listeners, downstreams, upstream pools, state/audit files and safety margin. Startup warns/fails when a configured theoretical maximum cannot fit the OS limit.

## 34. Backup and recovery

The backup format is versioned, encrypted and self-describing. It contains committed configuration revisions, active revision pointer, encrypted certificate/ACME envelopes, token metadata/hashes, retained local audit segments plus audit-chain checkpoint, schema/version manifest and checksums. Off-host audit storage remains the authoritative long-retention record. The archive excludes the age decryption identity by default; that identity and backup recovery key are escrowed separately under organizational policy. Plaintext keys are never materialized in the archive.

`backup create` obtains a consistent read lock/snapshot without stopping traffic, writes to a new file, fsyncs, verifies manifest/checksums and atomically renames. `backup verify` authenticates/decrypts into protected temporary memory/storage, checks every referenced object and reports only metadata. Retention is daily/weekly/monthly policy outside the proxy, with encrypted off-host/off-account copies and immutable retention where available.

Restore is never an in-place blind extract:

1. Install a compatible signed binary on a clean host.
2. Provide recovery identity through a protected channel.
3. Run `restore validate` for archive authentication, schema, paths, modes, certificate/key match and config semantics.
4. Restore into a new state directory; validate and bind test listeners without public traffic.
5. Atomically switch the service state pointer/start unit, verify readiness and representative routes, then promote traffic.
6. Audit the restore and rotate credentials if compromise motivated recovery.

Phase 8 proposes initial service objectives for operator approval: configuration/audit metadata RPO 15 minutes when backup automation is enabled, certificate/config recovery RTO 60 minutes on a prepared host. They are not guaranteed until Phase 14 drills demonstrate them on the production topology. Quarterly restore drills measure actual RPO/RTO and include lost node, corrupt latest backup, unavailable KMS/identity, expired certificate and binary rollback cases.

## 35. Upgrade and migration strategy

- `schema_version` is mandatory. Readers support current `N` and, during a documented window, `N-1`; older/newer versions fail with a migration command, never auto-mutating at daemon startup.
- Migrations are pure, deterministic transformations producing a new file/revision and human-readable diff. The original and secrets remain untouched. Each step has fixtures, idempotence check where applicable and a reverse/rollback statement; some semantic upgrades may require explicit operator input.
- State-format changes write new versioned objects and switch a pointer only after fsync/verification. Destructive garbage collection waits through a rollback window.
- Administrative API uses `/v1`, additive compatibility within a release line, explicit deprecation and contract tests. CLI JSON has its own output schema version.
- Upgrade compatibility matrix records binary version, config/state versions, feature flags and rollback boundary. The new binary validates current state/config before service replacement.
- Release rollback restores the prior signed binary and compatible last-known-good revision. A configuration created with irreversible new semantics cannot be fed silently to an old binary; `rollback-check` must confirm compatibility or direct the operator to a pre-upgrade backup.

## 36. High-availability strategy

Single-node reliability comes first. Phase 12 adds multi-instance operation without embedding a general distributed database.

### 36.1 Initial multi-node model

- An external L4 load balancer sends 80/443 traffic to independently healthy nodes and drains a node before restart. It preserves source address directly or via explicitly trusted PROXY protocol v2.
- CI/automation validates one declarative revision, then distributes the exact content hash to nodes with staged canary/rolling activation. Each node retains its own last-known-good copy. Fleet status detects drift; quorum is not used to reinterpret configuration.
- Health, rate limits, passive circuit state and pools remain node-local. Operators must size load balancer behavior accordingly. Global rate limiting requires a later external service and explicit availability/privacy trade-off.
- Audit records include node ID and are shipped to a central append-only/SIEM destination. Metrics aggregate by controlled node/route labels.

### 36.2 Certificates and ACME in HA

Supported strategies, in preference order:

1. External certificate manager/vault issues and distributes encrypted material; nodes only load assigned certificates.
2. One explicitly elected/operated certificate controller owns ACME account/order state and publishes versioned encrypted bundles; proxy nodes never all renew.
3. Independent node certificates only where DNS/HTTP challenges, renewal jitter, CA limits and load balancer routing have been proven.

Shared mutable filesystem/SQLite certificate state and simultaneous ACME renewal are unsupported. TLS-ALPN-01 behind an L4 balancer needs deterministic challenge routing to the owner; otherwise use DNS-01 or centralized termination.

### 36.3 Split-plane revisit

If remote fleet coordination, tenant isolation or availability requirements exceed declarative rollout, split control and data plane behind authenticated mTLS with signed snapshots and monotonic versions. The data plane must continue from LKG during control-plane loss. This is a new ADR/security review, not a hidden evolution of the v1 admin API.

## 37. Repository and crate structure

The workspace starts with a few cohesive crates, not one crate per concept:

```text
.
|-- Cargo.toml                    # workspace, shared lint/profile policy
|-- Cargo.lock
|-- rust-toolchain.toml
|-- deny.toml
|-- PLAN.md
|-- README.md
|-- SECURITY.md
|-- LICENSE
|-- crates/
|   |-- proxy-core/               # runtime snapshot, HTTP/TCP proxy, routing, upstreams
|   |   |-- Cargo.toml
|   |   |-- src/{lib,types,runtime,listener,http,tcp,route,upstream,limits,error}.rs
|   |   `-- src/middleware/{mod,access,auth,headers,limit,rewrite}.rs
|   |-- proxy-config/             # serde schema, validation, revision/migration
|   |   |-- Cargo.toml
|   |   `-- src/{lib,schema,validate,conflict,revision,migrate,redact}.rs
|   |-- proxy-secrets/            # secret refs/sources, redaction wrappers, age envelopes
|   |   |-- Cargo.toml
|   |   `-- src/{lib,reference,source,envelope,redact}.rs
|   |-- proxy-tls/                # rustls selection, encrypted store, ACME
|   |   |-- Cargo.toml
|   |   `-- src/{lib,acceptor,selector,store,acme,renewal}.rs
|   |-- proxy-admin/              # Axum API, RBAC, audit, backup/restore
|   |   |-- Cargo.toml
|   |   `-- src/{lib,api,auth,rbac,audit,backup,status}.rs
|   `-- rust-proxy/               # binary, CLI, lifecycle/wiring only
|       |-- Cargo.toml
|       `-- src/{main,cli,bootstrap,supervisor,telemetry}.rs
|-- config/
|   |-- schema/                   # generated JSON Schema/OpenAPI artifacts
|   `-- examples/                 # minimal, TLS, gRPC, TCP, auth examples
|-- tests/
|   |-- integration/              # black-box harness and protocol scenarios
|   |-- security-corpus/          # reviewed non-secret malformed inputs
|   |-- upgrade-fixtures/
|   `-- support/                  # local upstream, DNS and auth test services
|-- fuzz/fuzz_targets/
|-- bench/{README.md,profiles,results-schema}/
|-- deploy/
|   |-- compose/{compose.yaml,proxy.toml}
|   |-- systemd/rust-proxy.service
|   |-- container/{Dockerfile,seccomp.json}
|   `-- kubernetes/README.md       # later; no unsupported manifest claim
|-- docs/
|   |-- architecture.md
|   |-- configuration.md
|   |-- operations/{acme,backup,upgrade,incident-response}.md
|   |-- security/{threat-model,hardening}.md
|   `-- adr/                       # extracted accepted decision records
`-- .github/workflows/{ci,security,integration,fuzz,perf,container,release,upgrade}.yml
```

Allowed dependency direction is `rust-proxy -> admin/tls/core/config/secrets`; `admin -> config + secrets` plus narrow runtime command/status interfaces; `tls -> secrets` and validated TLS DTOs; `config -> secrets` only for the opaque `SecretRef` type; `core -> config` only through a compiled runtime snapshot. `proxy-secrets` depends on no application crate. Config has no network or process dependency. Core does not know Axum or storage formats. Cross-cutting types remain in the owning crate until demonstrated duplication justifies a small shared crate.

The binary crate performs dependency injection and lifecycle only. Each phase below names expected paths; names may change only through an updated ADR and PLAN rather than silently changing component boundaries.

## 38. Phased implementation roadmap

Work is sequential unless a phase explicitly identifies a parallel documentation/test task. A phase is not complete while its acceptance or exit criteria are waived; any exception becomes a dated risk with an owner.

### Phase 0: Repository assessment and architecture decisions

- **Objectives:** Bootstrap a reviewable Rust workspace; validate the risky library/protocol assumptions; turn this plan into accepted ADRs and a traceability matrix.
- **Exact deliverables/files:** Root `Cargo.toml`, lock/toolchain/lint/license policy, Section 37 crate skeletons, README/SECURITY; `docs/architecture.md`, `docs/adr/0001..0011`, dependency license/maintenance inventory; small throwaway-or-testbed Hyper streaming/cancellation, Rustls/ClientHello passthrough, and Axum-Unix-socket spikes under `tests/spikes/` only where documentation cannot answer compatibility.
- **Dependencies:** Current official crate docs/source, stable Rust with MSRV 1.88, Linux CI runners; no production service dependency. MSRV 1.88 supersedes the Phase 0 implementation's original 1.85 selection under ADR-0028 because locked Hickory DNS and certificate dependencies require it.
- **Security controls:** `forbid(unsafe_code)`, approved licenses/sources, threat-model review, no copied upstream code, no secrets or public listeners in spikes.
- **Tests:** Workspace build/lint/doc smoke; stream/backpressure/cancellation and Rustls handshake spike assertions; dependency-policy CI.
- **Acceptance criteria:** All ADR fields are approved; chosen versions resolve under one MSRV; every direct dependency has owner/purpose/license/risk; spikes demonstrate streaming without whole-body buffering and admin Unix-socket feasibility.
- **Known risks:** Library API churn and hidden platform limitations. **Exit:** architecture/security maintainers accept decisions and unresolved blockers are assigned. **Deferred:** usable proxy, UI, ACME, providers.

### Phase 1: Minimal secure HTTP reverse proxy

- **Objectives:** Proxy HTTP/1.1 and WebSocket end to end with streaming, cancellation, backpressure, safe framing and graceful shutdown; establish explicit resource budgets.
- **Exact deliverables/files:** `proxy-core/{runtime,listener,http,upstream,limits,error}.rs`, binary bootstrap/supervisor/CLI `run`, a deliberately small single-listener/single-upstream bootstrap config, integration upstream harness, systemd/container developer manifests.
- **Dependencies:** Tokio, Hyper/hyper-util/http/http-body-util, tower-service where useful, ArcSwap, tracing, thiserror; Phase 0.
- **Security controls:** Loopback upstream example, deny unmatched host, header normalization/hop-by-hop stripping, trusted-forwarding off, SSRF destination policy, size/count/time/concurrency limits, no CONNECT/open proxy.
- **Tests:** H1 keepalive, WebSocket upgrade/bidirectional close/cancellation, streaming upload/download, cancellation, slowloris, oversized headers/body, conflicting framing/smuggling corpus, upstream timeout/failure, signal drain and resource cleanup.
- **Acceptance criteria:** A black-box test proxies streaming bodies without buffering beyond configured chunks; all stated limits reject deterministically; no new requests after drain begins; accepted requests finish or hit declared drain deadline; invalid startup never listens.
- **Known risks:** Protocol edge ambiguity and Hyper adapter misuse. **Exit:** protocol/security review of request reconstruction and passing Linux integration/soak baseline. **Deferred:** H2, TLS, multi-route/middleware, retries.

### Phase 2: TLS termination and certificate loading

- **Objectives:** Add HTTP/2 over ALPN, secure TLS termination, SNI certificate selection and BYO encrypted certificate lifecycle.
- **Exact deliverables/files:** `proxy-tls/{acceptor,selector,store}.rs`, `proxy-secrets/{reference,source,envelope,redact}.rs`; TLS config DTO/validation; `cert import/list/inspect`; test CA/fixtures; TLS and gRPC/H2 integration scenarios; operations key-recovery doc.
- **Dependencies:** Rustls, tokio-rustls, rustls-pemfile, explicit WebPKI/native root strategy, age/secrecy/zeroize as justified; Phase 1.
- **Security controls:** TLS 1.2/1.3 curated defaults, exact/wildcard SNI rules, no wrong-name fallback, encrypted keys/mode checks, outbound TLS verification, secret redaction.
- **Tests:** H1/H2 ALPN, certificate/key/name/expiry validation, exact/wildcard precedence, malformed TLS/cert files, encrypted store restart/recovery, gRPC unary/streaming, TLS scanner job.
- **Acceptance criteria:** Supported TLS matrix passes; plaintext never replaces failed TLS; private-key canary is absent from logs/API; certificate swap is atomic and existing connections continue.
- **Known risks:** Secret identity availability and crypto-provider packaging. **Exit:** TLS/secret-storage expert review and restore drill. **Deferred:** ACME, OCSP stapling pending Rustls/provider evaluation, H3.

### Phase 3: Routing engine and typed configuration

- **Objectives:** Implement schema v1, deterministic host/path/header/method matching, listener/TCP/SNI models and full offline validation.
- **Exact deliverables/files:** `proxy-config/{schema,validate,conflict,redact}.rs`, compiled route index in `proxy-core/route.rs`; `config validate/preview/fmt`; JSON Schema and examples/docs; TCP listener/passthrough module if isolated cleanly.
- **Dependencies:** Serde, TOML parser, schemars only if generated schema quality is verified, ArcSwap, and the Phase 0 ClientHello-parser decision; Phases 1–2.
- **Security controls:** Unknown-field rejection, bounded strings/collections, duplicate/conflict/port/upstream/secret/certificate/order validation, explicit default route, no regex/query match, no implicit provider.
- **TCP schema decision:** Per ADR-0027, `tcp` listeners accept one explicit default route; `tls_passthrough` listeners accept canonical exact/single-label wildcard SNI hosts plus an optional explicit default. Both use only configured `tcp://host:port` endpoints. HTTP-family and TCP-family listeners/routes/upstream transports cannot be mixed.
- **Tests:** Unit/property conflict and precedence matrix; Host/authority/IDNA policy, path segment/prefix boundaries, headers/methods, SNI/TCP passthrough, unknown/invalid example corpus and redacted export.
- **Acceptance criteria:** Same validated input always compiles to the same route order/hash; every ambiguous equal-precedence overlap is rejected or has explicit priority; all shipped examples validate; invalid listener/certificate references identify exact field paths.
- **Known risks:** Conflict analysis complexity and HTTP/TCP listener coexistence. **Exit:** schema freeze for v1 preview and documented compatibility policy. **Deferred:** query/regex, UDP, dynamic providers.

### Phase 4: Load balancing and health checks

- **Objectives:** Static/DNS endpoint sets, round-robin and weighted selection, connection reuse/draining, active/passive health, safe retries and circuit breaking.
- **Exact deliverables/files:** `proxy-core/upstream/{pool,balance,health,retry,circuit,dns}.rs` (split directory when warranted), health task supervisor, upstream status API DTOs, health/load test harness.
- **Dependencies:** Phase 3 and Hickory for bounded TTL-aware A/AAAA resolution; the system resolver remains an explicitly documented fallback mode only if its refresh semantics meet the deployment requirement. SRV requires a later versioned schema and is not a Phase 4 exit criterion.
- **Security controls:** Address revalidation after DNS, egress policy, bounded pools/checks/queues, hysteresis, idempotent-method default retry, opt-in replay only within body cap, no retry after response bytes.
- **Tests:** Weighted distribution/property tests, zero/one/all unhealthy, active/passive thresholds/recovery, DNS rebind/stale/NXDOMAIN, pool draining, gRPC streaming non-retry, cancellation and circuit half-open stampede control.
- **Acceptance criteria:** Selection never chooses a draining/unavailable endpoint when a healthy one exists; beginning drain immediately excludes new work and waits for active guards only to the configured deadline; thresholds transition exactly as configured; unsafe request is attempted once by default. Live endpoint removal, idle-client eviction, and deadline behavior across snapshot replacement are integrated and accepted in Phase 5 because Phase 4 has no activation mechanism.
- **Known risks:** Health oscillation and retry amplification. **Exit:** failure-injection/soak proves recovery and bounded amplification. **Deferred:** global health/rate state, Consul/Kubernetes.

### Phase 5: Dynamic reload and last-known-good rollback

- **Objectives:** Versioned candidate workflow, immutable snapshot swap, file polling/SIGHUP reload, atomic rollback and crash recovery.
- **Exact deliverables/files:** `proxy-config/revision.rs`, activation coordinator/runtime snapshot, offline `config revisions`, file/SIGHUP activation, state journal/layout, upgrade/crash fixtures. Authenticated `config activate/rollback` and `/v1/config*` consume this activation model in Phase 8; an offline command must not switch a live pointer without prepared runtime publication and durable audit.
- **Dependencies:** ArcSwap, fs2 or narrowly scoped file-lock primitive if standard locking is insufficient; Phases 3–4.
- **Security controls:** Serialized compare-and-swap activation, source hash/audit, prepare-before-commit, path/mode validation, maximum revisions/retention, no silent fallback.
- **Tests:** Concurrent stale writers, invalid candidate, listener/secret/cert preparation failure, repeated same hash, crash injection before/after fsync/rename/pointer switch, in-flight long stream across reload, removed/transport-changed endpoint idle-client eviction and active-work drain deadline, automatic rollback where post-activation probe fails.
- **Acceptance criteria:** Failed candidate leaves byte-identical active revision/hash; restart after each injected crash selects either old or fully committed new state, never partial; removed/transport-changed endpoints receive no new work, close idle clients, and drain active work only to the configured deadline; activation meets benchmarked reload budget without accepted-request loss.
- **Known risks:** OS/filesystem atomicity and listener changes. **Exit:** documented supported filesystems plus successful crash/reload campaign. **Deferred:** authenticated mutation CLI/API to Phase 8; multi-node rollout and signed fleet snapshots.

### Phase 6: ACME certificate automation

- **Objectives:** Automated issuance/renewal via HTTP-01, DNS-01 and safely gated TLS-ALPN-01; multiple CA directories/accounts; wildcard and failure-safe storage.
- **Exact deliverables/files:** `proxy-tls/acme/{client,challenge,scheduler,account,dns_provider}.rs`, CLI renew/status and an internal status model, Pebble and DNS test provider, ACME/rotation/revocation runbooks. Authenticated administrative ACME endpoints consume that model in Phase 8, when the private transport, authentication, RBAC, mutation audit, and request limits exist; Phase 6 must not expose an ACME-specific ad hoc API.
- **Dependencies:** `instant-acme` if Phase 0/current audit confirms required challenge/profile support; otherwise a minimal compatible client decision ADR. DNS providers are compile-time feature adapters with secret refs.
- **Security controls:** Per-certificate lock, encrypted account/key material, domain/identifier allowlist, nonce/order validation by library, staged key/cert match, renewal jitter/backoff, CA rate awareness, challenge route isolation/cleanup, least-privileged DNS token.
- **Tests:** Pebble issuance/renewal/failure for all enabled challenges, wildcard DNS-01, alternate/staging CA, account rollover, challenge collision, concurrent renewal/crash, wrong-name/key/chain rejection, working-certificate preservation.
- **Acceptance criteria:** Renewal scheduler alerts at documented windows; every simulated issuance/storage/reload failure continues serving prior valid material; stale challenge data is removed; wildcard cannot select HTTP-01; no production CA in CI.
- **Known risks:** DNS API breadth, CA behavior and encrypted-key availability. **Exit:** expert ACME/key review and multi-cycle accelerated renewal soak. **Deferred:** large provider catalog, HA issuer, OCSP until justified.

### Phase 7: Middleware and authentication

- **Objectives:** Implement the fixed pipeline and approved middleware: redirect/rewrite, headers/security policies, request limits/timeouts, compression, CORS, Basic/ForwardAuth, IP policy, local rate limit, retry/circuit control, maintenance/errors and logging.
- **Exact deliverables/files:** `proxy-core/middleware/{mod,normalize,access,redirect,rewrite,headers,cors,auth,ip,limit,rate,retry,compression,error}.rs`; config variants/order validator; Authentik/ForwardAuth integration guide.
- **Dependencies:** Tower-style services only where streaming/error types remain manageable; Argon2, constant-time primitive; Phases 4–6.
- **Security controls:** Fixed stages, allowlisted ForwardAuth request/response headers, fail closed, TLS-only Basic, trusted client IP, bounded rate keys/cache, safe redirect/rewrite targets, HSTS/CSP opt-in validation, compression exclusions.
- **Tests:** Each requested middleware unit tests plus pairwise security interactions; Authentik success/deny/timeout/spoof; CORS preflight vs auth; limit before body/auth; redirect before proxy; retry-body safety; custom error escaping; rate-key bypass.
- **Acceptance criteria:** Config cannot express an invalid order; no auth response header can overwrite hop-by-hop/routing/TLS fields; denial/timeout behavior matches documented matrix; memory stays bounded at maximum rate-limit keys.
- **Known risks:** Interaction explosion and auth outage blast radius. **Exit:** matrix reviewed and all combinations shipped in examples pass black-box tests. **Deferred:** native route OIDC, cache/store plugins, arbitrary middleware.

### Phase 8: Administrative API and CLI

- **Objectives:** Complete local REST API/CLI, RBAC, tokens/mTLS, audit, backup/restore and safe remote automation.
- **Exact deliverables/files:** `proxy-admin/{api,auth,rbac,audit,backup,status}.rs`, OpenAPI, CLI commands in Sections 22–23, Unix socket transport, optional private mTLS listener, operational docs.
- **Dependencies:** Axum, tower-http only selected modules, Argon2, HMAC/hash primitives, OpenAPI generator only if it cannot diverge; Phase 5 state model.
- **Security controls:** Local default bind, deny-by-default RBAC, request/body/rate limits, CAS/`If-Match`, token one-time display/hash/expiry, durable audit gate for mutations, backup encryption, stable redacted errors.
- **Tests:** Endpoint contract/golden OpenAPI, authn modes, complete role-action matrix, stale revision, token revoke/expiry, remote plaintext/public-bind rejection, audit failure, backup tamper/path traversal and clean-host restore.
- **Acceptance criteria:** Every mutation has authorization, audit and concurrency tests; unauthenticated remote request cannot read health details/config; backup/restore drill meets proposed targets or records measured gap; CLI stable exit codes match docs.
- **Known risks:** Admin credential recovery and audit disk pressure. **Exit:** independent admin API/RBAC review. **Deferred:** browser sessions/UI, multi-tenant roles, gRPC admin.

### Phase 9: Observability and audit logging

- **Objectives:** Production logs, metrics, OpenTelemetry, health semantics, dashboards/alerts and SIEM guidance with cardinality/redaction controls.
- **Exact deliverables/files:** instrumentation throughout crates; metrics/trace exporters in binary/admin; dashboard/alert examples; Loki/Prometheus/Grafana/SIEM docs; observability contract tests.
- **Dependencies:** tracing/tracing-subscriber, metrics exporter or `prometheus-client`, OpenTelemetry crates pinned as a compatible set; Phases 4–8.
- **Security controls:** Private endpoints, bounded async exporters, sensitive field denylist/allowlist, label budget, audit separation/HMAC chain, no body/query default.
- **Tests:** Canary-secret log/trace/metric scan, maximum-config cardinality calculation, exporter outage/slow sink, audit tamper/gap, request-ID trust, dashboard query lint and health semantics.
- **Acceptance criteria:** No canary appears in any exported signal; exporter loss cannot delay proxy requests; required alerts fire in failure simulations; series count is within calculated/documented ceiling.
- **Known risks:** Telemetry crate churn and accidental cardinality. **Exit:** operators validate dashboards/runbooks against a staging failure drill. **Deferred:** bundled collectors/storage.

### Phase 10: Web UI, if approved

- **Objectives:** Decide whether operational evidence warrants a UI; if yes, provide a separate accessible frontend without weakening API safety.
- **Exact deliverables/files:** Decision ADR; separate `ui/` workspace, locked JS dependencies, generated client, private-origin packaging, OIDC/Authentik session gateway, CSP/CSRF configuration, browser tests.
- **Dependencies:** Stable `/v1`/OpenAPI, Phase 8 RBAC and Phase 9 audit; explicit product/security approval.
- **Security controls:** Authorization Code + PKCE, exact redirect origins, secure rotated cookies, CSRF+Origin, strict CSP/output encoding, dependency/SBOM scans, no secrets in browser storage, no direct public default.
- **Tests:** OIDC login/logout/expiry/fixation, every role view/action, CSRF, stored/reflected/DOM XSS, clickjacking/CSP, stale revision/diff, accessibility and API failure states.
- **Acceptance criteria:** Independent application-security review has no unresolved critical/high finding; UI cannot perform/read beyond direct API role; disabling/removing UI leaves full CLI/API operation.
- **Known risks:** Large new attack/dependency surface. **Exit:** explicit ship decision after review. **Deferred:** UI by default, UI plugin marketplace. If not approved, publish the no-UI ADR and close phase.

### Phase 11: Service discovery

- **Objectives:** Add file and DNS dynamic providers first; evaluate an isolated Docker metadata helper; specify Kubernetes Gateway API later.
- **Exact deliverables/files:** `proxy-config/provider/{file,dns}.rs`, provider coordinator/status, namespace/conflict rules, isolated `proxy-discovery-docker` design/spike only after approval, provider docs/fixtures.
- **Dependencies:** Phase 5 atomic activation and Phase 4 DNS/health; Docker/Kubernetes clients only in separate compile-time features/binaries after license/security review.
- **Security controls:** Providers can only populate declared namespaces/templates, default exposure false, labels untrusted/strict, debounce+bounds+stale policy, destination validation, Docker socket never mounted into proxy and helper gets read-only filtered API.
- **Tests:** Partial writes, rename/watch storms, duplicate/conflict across providers, stale/delete/recovery, malicious labels/metadata, socket-proxy denial, rebind/private address and provider rollback.
- **Acceptance criteria:** Invalid provider update cannot change active snapshot; provider status identifies source hash/freshness; no object is exposed without explicit enable/allowlisted network/template; proxy process has no Docker socket access.
- **Known risks:** Event storms, metadata privilege and eventual consistency. **Exit:** provider threat review/failure soak. **Deferred:** Consul unless demanded with clear benefit; Kubernetes implementation follows separate ADR.

### Phase 12: High availability and clustering

- **Objectives:** Support externally load-balanced nodes, content-addressed fleet rollout/drift detection and a safe certificate-ownership strategy.
- **Exact deliverables/files:** fleet deployment/runbook, node status/revision export, canary/rolling automation examples, LB health/drain integration, certificate-controller ADR/prototype if required, HA chaos suite.
- **Dependencies:** Phases 5, 6, 8, 9 and real multi-node requirements.
- **Security controls:** mTLS/signature for distributed snapshots, monotonic revision policy, node identity, off-host audit, explicit trusted LB/PROXY peers, no shared mutable state, split-plane privilege review.
- **Tests:** Node loss/network partition/control-plane outage, mixed revisions/drift, rolling rollback, LB drain, duplicate ACME prevention, cert distribution/key compromise, central audit/export outage.
- **Acceptance criteria:** Data nodes continue LKG through controller loss; rollout detects every divergent hash; one node can drain/restart without failed accepted requests beyond LB policy; renewal has exactly one owner.
- **Known risks:** Distributed race/operational complexity. **Exit:** production-topology chaos and recovery drill. **Deferred:** embedded consensus/database and global rate limiter unless separately justified.

### Phase 13: Security hardening, fuzzing, external review, and deferred-transport decisions

- **Objectives:** Close the threat/control/test traceability, extend fuzz/soak, harden packaging, obtain independent review, and record evidence-based go/no-go ADRs for HTTP/3/QUIC and UDP without enabling them in the first release.
- **Exact deliverables/files:** final threat model/control matrix, pentest scope/results/remediation, unsafe/dependency review, hardened seccomp/AppArmor examples, incident runbooks, fuzz corpus and release-candidate evidence bundle; Quinn/H3 compatibility/interoperability/resource-abuse spike report and a separate bounded-UDP-session requirements decision.
- **Dependencies:** Feature-complete release candidate; qualified external protocol/application/container reviewers.
- **Security controls:** All Section 27 controls and exception expiry; two-person remediation verification; public vulnerability disclosure process/security contact.
- **Tests:** Long fuzz campaigns, smuggling/desync corpus, auth/SSRF/DoS/malformed TLS, 24-hour-plus soak, container/host escape-impact review, backup/rollback/compromise tabletop; if transport spikes proceed, QUIC interop/migration/amplification/0-RTT/resource tests and UDP spoof/NAT-rebinding/timeout/budget tests in an isolated non-release feature.
- **Acceptance criteria:** No unresolved critical/high review finding; medium findings have owner/deadline/compensating control; all named threats map to evidence; fuzz targets have documented run time/corpus and no known crash.
- **Known risks:** Late architectural findings and transport experiments distracting from release. **Exit:** security owner signs release recommendation with residual risks, and H3/UDP each has an explicit later-phase ADR outcome. **Deferred:** H3/UDP implementation and any optional feature that missed review are disabled/excluded.

### Phase 14: Production release preparation

- **Objectives:** Produce verifiable artifacts, operating evidence, support envelope, migration/rollback docs and a controlled canary/general release.
- **Exact deliverables/files:** signed binaries/images/checksums/SBOM/provenance, final manuals/examples, compatibility/support matrix, release notes, SLO/support decision, on-call/incident/backup/upgrade runbooks, benchmark/soak results, release checklist.
- **Dependencies:** All mandatory earlier exits, protected release infrastructure and staging topology representative of production.
- **Security controls:** Signed immutable promotion, two-person release approval, short-lived CI identity, scanner/advisory gates, non-root/read-only deployment validation, secret-free artifacts.
- **Tests:** Full CI/security/protocol/performance/upgrade/rollback/restore suite on exact artifacts; multi-arch smoke; canary traffic and forced rollback; certificate renewal and upstream outage drill.
- **Acceptance criteria:** Every Section 39 release criterion has linked evidence; operator unfamiliar with implementation completes install, validate, backup, upgrade and rollback runbook; canary meets approved SLO/error budget through observation window.
- **Known risks:** Environment-specific networking and operational readiness. **Exit:** product, engineering, security and operations owners approve general availability scope. **Deferred:** every non-GA feature remains absent or disabled and documented, not “experimental on” by default.

## 39. Acceptance criteria

### 39.1 MVP acceptance (Phases 0–9)

The first supported release candidate must meet all of the following with linked CI or drill evidence:

1. Linux x86_64 and aarch64 artifacts start non-root with read-only root filesystem and only documented state/run mounts writable.
2. H1/H2, WebSocket, gRPC, TCP passthrough and TLS termination pass black-box happy, cancellation, timeout and failure tests. UDP and H3 are absent/disabled.
3. Every accepted request matches an explicit route and configured upstream; unknown hosts/SNI and disallowed destinations fail closed.
4. Strict schema rejects every unknown key, conflicting route/listener, invalid secret/certificate/upstream, and invalid middleware order in the maintained invalid fixture set.
5. Runtime activation is atomic: all injected pre-commit failures retain the prior hash, in-flight streams complete under the old snapshot, and crash points recover only a committed revision.
6. ACME HTTP-01/DNS-01 and gated TLS-ALPN-01 pass local-CA issuance/renewal/failure tests; prior valid certificate remains served after every simulated renewal failure.
7. Retry tests prove non-idempotent/unbuffered requests are not replayed by default and no retry occurs after response bytes are sent.
8. Forwarded/client-IP spoof corpus cannot influence effective client identity from an untrusted peer; upstream receives only rebuilt forwarding fields.
9. Every admin endpoint appears in the RBAC matrix; negative tests demonstrate deny-by-default; every mutation produces a durable redacted audit record or fails closed.
10. Secret canaries placed in every supported secret source do not appear in application/access/audit logs, metrics, traces, diagnostics, config export, API errors, backup metadata or release artifacts.
11. Header/body/concurrency/queue/time limits are verified at boundary values; overload tests show bounded RSS/FDs and recovery after load stops.
12. `/live`, `/ready`, detailed health and metrics exhibit documented behavior during upstream, provider, audit, disk and exporter failures.
13. A clean-host backup restore, binary/config upgrade and rollback complete using published instructions; measured RPO/RTO and any gap are recorded.
14. Required CI gates are green on the exact signed release artifact; SBOM, checksums, signatures/provenance and verification instructions are published.
15. There are no unresolved critical/high findings from the Phase 13 review; residual risks and supported envelope are in release notes.

### 39.2 Capability acceptance beyond MVP

- A web UI is accepted only under Phase 10's explicit ship gate; its absence does not block MVP.
- File/DNS discovery is accepted only when an invalid/stale update cannot replace LKG. Docker discovery additionally proves the proxy has no Docker socket and default exposure is false.
- HA is accepted only after exact-hash rollout/drift, node drain, control-plane outage and single-owner certificate renewal drills on the target topology.
- H3/QUIC is accepted only after its ADR is revisited, Quinn/H3 stack interoperability and DoS behavior are tested, UDP deployment is secured, and an operator can disable it without affecting TCP TLS.
- Any stated performance tier names exact hardware, build, config and workload plus raw reproducible results; otherwise performance remains unclaimed.

## 40. Risk register

Severity describes impact if realized; likelihood is the pre-mitigation planning estimate and must be recalibrated from implementation evidence.

| ID | Risk | Severity | Likelihood | Mitigation/trigger | Owner category |
|---|---|---:|---:|---|---|
| R1 | HTTP parsing/translation ambiguity enables smuggling/desync | Critical | Medium | Strict reconstruction, corpus/differential/fuzz tests, protocol expert review; block release on unresolved ambiguity. | Data-plane + Security |
| R2 | Certificate/ACME key disclosure | Critical | Low–Medium | Encrypted envelopes, separate identity, modes, no export/logging, rotation/revocation drills. | TLS + Security/Ops |
| R3 | Reload race causes partial/incorrect policy | High | Medium | Immutable snapshots, serialized CAS activation, crash injection and LKG journal. | Config/Runtime |
| R4 | Retry duplicates a state-changing request | High | Medium | Idempotent default, bounded explicit replay opt-in, attempt/response-byte state machine tests. | Data-plane |
| R5 | Forwarded-header trust misattributes attacker IP | High | Medium | Explicit peers/hops, strip/rebuild, direct-bypass/multi-hop tests and deployment docs. | Security/Ops |
| R6 | DNS/provider data routes to internal/metadata services | Critical | Medium | Destination policy on each answer/connection, explicit private exceptions, no client URL, rebind tests. | Upstream/Discovery |
| R7 | DoS exhausts memory/FD/CPU | High | High | Layered limits, bounded queues/pools, cgroups/systemd, overload/soak tests and capacity docs. | Runtime/Performance/Ops |
| R8 | Dependency or build-chain compromise | Critical | Low–Medium | Minimal/pinned dependencies, audit/deny/scans, protected CI, SBOM/signature/provenance, controlled updates. | Build/Security |
| R9 | ACME outage/race expires certificates | High | Medium | Early jittered renewal, prior cert retention, per-cert lock/HA owner, expiry alerts and outage drills. | TLS/Ops |
| R10 | Filesystem encryption identity is unavailable or co-located | High | Medium | External injection/escrow, startup readiness behavior, documented backup/restore and rotation. | Security/Ops |
| R11 | Admin API accidentally becomes public | Critical | Low–Medium | Unix socket default, explicit secure remote gate, separate listener, deployment scans/tests. | Control-plane/Ops |
| R12 | Audit disk/sink outage blocks operations or loses evidence | High | Medium | Separate bounded durable spool, disk alerts/retention, mutation fail-closed policy, off-host ship. | Audit/Ops |
| R13 | Dynamic discovery exposes workloads unexpectedly | High | Medium | Deferred, namespaces/templates, explicit enable, default exposure false, isolated Docker helper. | Discovery/Security |
| R14 | UI introduces session/CSRF/XSS/supply-chain flaws | High | Medium | UI optional/deferred, separate origin/client, strict controls and independent review. | UI/Security |
| R15 | HA creates split-brain configuration or duplicate renewal | High | Medium | Content hash rollout/drift, external LB, one renewal owner, no shared writable DB/filesystem. | Distributed/Ops |
| R16 | Rust/protocol crate API churn delays delivery | Medium | High | Pin versions, Phase 0 spikes, narrow adapters, scheduled updates; revisit foundations only on evidence. | Architecture |
| R17 | Config schema becomes too complex for safe operation | High | Medium | Small v1 grammar, strict examples/linter/preview, no templates/plugins, usability tests. | Config/Product |
| R18 | Performance target conflicts with safety limits | Medium–High | Medium | Benchmark methodology, explicit support envelope, never remove bounds without review; profile before redesign. | Performance/Security |
| R19 | Backup is present but unrestorable | High | Medium | Authenticated versioned archive, clean-host quarterly drills, measured RPO/RTO, separate key escrow. | Ops |
| R20 | Scope growth prevents a secure first release | High | High | Mandatory/deferred scope map, phase exits, explicit approval for UI/H3/UDP/cluster/providers/plugins. | Product/Tech lead |

## 41. Decision log

These are proposed ADRs to be ratified in Phase 0. Each becomes a file under `docs/adr/`; a changed decision supersedes rather than rewrites history.

### ADR-001: Hyper rather than Pingora for the initial proxy foundation

- **Context:** The proxy needs transparent ownership of H1/H2 semantics, streaming, cancellation, Rustls and custom policy. Pingora offers a mature proxy framework, but its Rustls support and portability need project-specific validation and it introduces a larger opinionated surface.
- **Options:** Hyper/hyper-util directly; Pingora; build protocol handling from sockets; bind to an external proxy.
- **Decision:** Use Tokio + Hyper with narrow internal adapters. Keep a Phase 0 Pingora benchmark/feature spike only if current APIs materially change this assessment.
- **Rationale:** Hyper is a focused protocol foundation, works directly with Rustls/Tower ecosystem and lets the project enforce its normalization, retry and limit state machines without inheriting unused framework features.
- **Consequences:** More connection-pool, health, retry and proxy correctness code belongs to this project; implementation must not access raw parser internals casually.
- **Security implications:** Smaller selected surface but greater responsibility for smuggling/desync and resource controls; expert review and differential/fuzz tests are release gates.
- **Revisit conditions:** Measured inability to meet support/performance objectives, unacceptable maintenance burden, or Pingora demonstrates stable Rustls/required protocol/target support with a safer total design.

### ADR-002: Rustls rather than native OpenSSL/BoringSSL bindings

- **Context:** TLS must be memory-safe by default, operationally predictable and support modern H1/H2 plus certificate selection.
- **Options:** Rustls; OpenSSL bindings; BoringSSL/AWS-LC bindings directly; OS-native TLS.
- **Decision:** Rustls with a deliberately selected crypto provider and explicit root-store policy.
- **Rationale:** Rust API integration, modern protocol policy and reduced C ABI/packaging burden fit the minimal Linux service. Direct provider choice remains visible rather than assumed.
- **Consequences:** Legacy cipher/client interoperability is intentionally limited; OCSP and special enterprise features need verification; crypto provider affects artifact/license posture.
- **Security implications:** TLS 1.0/1.1 and unsafe fallback remain unavailable; key storage/ACME safety still belong to the application.
- **Revisit conditions:** Required regulated crypto/FIPS profile, unsupported must-have TLS capability, or material upstream maintenance/security change.

### ADR-003: Declarative files as source of truth rather than database-authored configuration

- **Context:** Operators need review, validation, versioning and rollback without introducing a stateful control service.
- **Options:** Strict TOML files; embedded database; PostgreSQL-backed control plane; provider-only API objects.
- **Decision:** Strict versioned TOML plus content-addressed immutable revision files and administrative candidate API.
- **Rationale:** Human review/GitOps/offline linting are simple, failure behavior is inspectable and one node needs no database.
- **Consequences:** Multi-writer editing is CAS-based, not relational; secrets are external refs; very large fleet coordination comes later.
- **Security implications:** Unknown fields/injection are rejected and no SQL surface exists; filesystem ownership, rollback authorization and Git secret hygiene are critical.
- **Revisit conditions:** Proven requirements for multi-tenant querying, high-rate concurrent control-plane writes or policy relationships that cannot be safely represented/validated.

### ADR-004: Neither SQLite nor PostgreSQL in v1

- **Context:** Some audit/token/revision metadata needs durability, but not relational transactions across independent services.
- **Options:** Versioned filesystem; embedded SQLite; external PostgreSQL.
- **Decision:** Use atomic filesystem objects and append-only audit. If persistence requirements grow, evaluate SQLite for single-node first; PostgreSQL only with an actual multi-node control-plane design.
- **Rationale:** Avoid migrations, backup/HA/credential/connection burden before it solves a demonstrated need.
- **Consequences:** Implement careful fsync/rename/locking and retention; filtering audit at scale is delegated to SIEM.
- **Security implications:** Removes SQL injection and DB network exposure; local file tamper/permissions and crash consistency require dedicated tests.
- **Revisit conditions:** File-state benchmarks/support limits fail, token/audit query volume is unmanageable, or transactional multi-entity writes become required.

### ADR-005: One binary/process with logical plane separation

- **Context:** Data and administration need privilege/failure isolation, but a mandatory distributed control plane would make v1 deployment and recovery much harder.
- **Options:** Monolithic binary/process; two local processes; remote control/data services.
- **Decision:** One binary/process, separate listeners, modules, budgets and authorization; keep narrow interfaces that permit a later split.
- **Rationale:** Atomic in-memory snapshot activation and simple deployment outweigh premature IPC/distributed failure modes.
- **Consequences:** A process crash affects both planes; supervisor restarts and LKG startup are essential. Admin load must never consume data budgets.
- **Security implications:** No network IPC secret initially, but one memory address space contains keys and proxy traffic metadata. OS/process split may later reduce blast radius.
- **Revisit conditions:** Multi-tenant control plane, independent scaling, unacceptable shared-process blast radius, or HA controller requirements.

### ADR-006: REST/JSON administration rather than gRPC

- **Context:** Local CLI, automation and a possible browser UI need a stable, inspectable mutation API; data plane already supports gRPC traffic but does not need gRPC control.
- **Options:** REST/JSON/OpenAPI; gRPC/protobuf; custom Unix protocol; direct file-only operations.
- **Decision:** Versioned REST/JSON over Unix socket by default and private mTLS TCP when explicitly enabled.
- **Rationale:** Straightforward browser/tool integration and human-debuggable contracts; no second IDL/build stack.
- **Consequences:** Streaming control operations use bounded status/polling or SSE only if justified; OpenAPI must stay in contract tests.
- **Security implications:** Body/content-type limits, CSRF for future browser use and exact auth/RBAC remain mandatory; remote plaintext is forbidden.
- **Revisit conditions:** High-volume bidirectional fleet control, generated multi-language agents, or REST semantics demonstrably impede reliability.

### ADR-007: Static configuration first, provider-normalized dynamic configuration later

- **Context:** Discovery is useful but brings untrusted event sources, churn, conflicts and privileged metadata APIs.
- **Options:** Static only forever; providers from first release; staged provider model normalized into the same schema.
- **Decision:** Static v1; file/DNS providers Phase 11; isolated Docker/Kubernetes/registry providers only after need and threat review.
- **Rationale:** Stabilize one validation/activation model before adding event sources. Providers cannot bypass compiled schema/policy.
- **Consequences:** Early operators generate/distribute files; later provider updates have debounce, namespace, freshness and LKG semantics.
- **Security implications:** No default Docker socket or auto-exposure; all provider metadata is untrusted and destination-checked.
- **Revisit conditions:** A target deployment cannot operate safely without discovery, accompanied by a concrete source and privilege model.

### ADR-008: No built-in web UI in v1; separate frontend if approved

- **Context:** UI improves accessibility but adds JavaScript supply chain, browser sessions, CSRF/XSS and release work before core correctness is proven.
- **Options:** Built-in bundled UI; separate frontend; API/CLI only.
- **Decision:** API/CLI only through Phase 9; separate frontend/gateway in Phase 10 only with product/security approval.
- **Rationale:** Keeps MVP achievable and administration scriptable while preserving a clean API seam.
- **Consequences:** Less friendly initial onboarding; docs/examples and CLI ergonomics carry more weight.
- **Security implications:** Avoids browser attack surface initially; future UI cannot be granted implicit internal trust.
- **Revisit conditions:** Stable API/RBAC/audit, demonstrated user need, staffed frontend/security ownership.

### ADR-009: Compile-time features and stable internal interfaces, not runtime plugins

- **Context:** Operators may want DNS providers/middleware, but dynamic native/Wasm plugins create ABI, sandbox, signing and policy complexity.
- **Options:** Native dynamic plugins; Wasm plugins; subprocess extensions; compile-time features; no extensions.
- **Decision:** No general plugin system. Use reviewed compile-time features/adapters and external standard-protocol services such as ForwardAuth/OTLP.
- **Rationale:** The smallest auditable dependency and execution surface meets initial needs.
- **Consequences:** New in-process integrations require a release/build; feature combinations are tested and SBOM-visible.
- **Security implications:** No arbitrary third-party code/config execution in the proxy process. External services get narrow authenticated network contracts.
- **Revisit conditions:** Multiple proven extensions cannot be served by standards/compile features and a sandbox/signing/update threat model is funded.

### ADR-010: Single-node first rather than immediate clustering

- **Context:** Clustering affects configuration consensus, certificate ownership, audit and rate limiting, while most proxy correctness is node-local.
- **Options:** Embedded consensus from start; external database/controller; independent nodes with declarative rollout; single node only.
- **Decision:** Deliver one reliable node first, then externally load-balanced identical nodes/content-hash rollout in Phase 12.
- **Rationale:** Avoid premature consensus and retain operationally legible failure modes.
- **Consequences:** v1 local rate/health state is not globally consistent; operators use external automation/LB for early redundancy.
- **Security implications:** Fewer remote control ports and shared credentials; later snapshot authenticity, node identity and single renewal ownership need a new review.
- **Revisit conditions:** Contracted availability cannot be met by external LB/independent nodes or coordinated writes become a hard requirement.

### ADR-011: HTTP/3/QUIC later, independently gated

- **Context:** H3 may improve specific networks but adds UDP exposure, QUIC tuning, different DoS characteristics, deployment/LB complexity and a younger Rust integration stack.
- **Options:** Quinn plus an H3 crate in MVP; another proxy foundation with H3; later feature; omit indefinitely.
- **Decision:** Ship H1/H2 first. Evaluate Quinn/H3 after Phase 9 as a separate listener/feature and security/performance ADR.
- **Rationale:** H3 is not required for the first functional production proxy and should not delay core TLS/config/ACME correctness.
- **Consequences:** No initial QUIC/0-RTT; Alt-Svc is not advertised. TCP service is unaffected if later H3 is disabled.
- **Security implications:** Avoids UDP amplification/state and 0-RTT replay initially. Later evaluation must address address validation, rate limits, migration, keying, LB and replay-safe methods.
- **Revisit conditions:** Stable compatible Quinn/H3 stack, target-user demand, deployable UDP path and completed protocol/DoS review.

## 42. Open questions

These do not block writing the plan; Phase 0 owners must resolve blocking items before their dependent phase:

1. Product name, executable prefix, license and public repository/release policy.
2. Supported Linux distributions/glibc versus musl targets, MSRV and support lifetime.
3. Expected maximum listeners/routes/endpoints/certificates/connections and target hardware for the initial support envelope.
4. Whether private/RFC1918 upstreams are the common case, and the exact initial SSRF egress policy/bootstrap ergonomics.
5. System trust store, bundled WebPKI roots, and private-CA provisioning defaults for upstream TLS.
6. Required ACME DNS providers and whether each can use narrowly scoped credentials; whether TLS-ALPN-01 is operationally required.
7. Whether certificate private-key encryption identity comes from systemd credentials, Kubernetes secret, file, HSM/KMS envelope service, or a supported subset.
8. Required behavior when the audit durable sink is unavailable: all security mutations fail closed is proposed; confirm which emergency operations remain possible and audited later.
9. Whether remote administration is required in MVP or Unix socket/SSH automation suffices.
10. Exact TCP TLS passthrough/termination use cases and whether mixed HTTP/TCP on one address requires SNI preread complexity.
11. Required PROXY protocol versions and trusted load balancer topology.
12. Whether query matching/regex, OCSP stapling, native route OIDC, UDP, caching or Consul has a concrete first customer; all are currently deferred.
13. Backup key escrow, retention, target RPO/RTO and off-host store ownership.
14. Performance/SLO acceptance on named hardware and representative payload/upstream latency distributions.
15. Who fills owner roles for architecture, data plane, TLS/security, operations, release and product scope.

## 43. Definition of done

### 43.1 Plan deliverable

This `PLAN.md` is done when it has been reviewed end to end; current-repository claims match inspection; upstream claims are attributable to official source/docs; every requested capability is MVP, phased or explicitly deferred; dependencies and ADRs are internally consistent; every security-sensitive feature has controls/tests; every phase has deliverables, dependencies, controls, tests, measurable acceptance, risks, exit and deferred work; and no source code from NPMPlus, Caddy or Traefik has been copied.

### 43.2 Production product

The production release is done only when:

- Mandatory Phases 0–9, 13 and 14 meet their exit criteria; optional phases are clearly excluded or meet their own exits.
- The exact release commit/artifacts pass Section 39 and produce signed checksums, SBOM and provenance with user-verifiable instructions.
- Configuration, certificate, upstream, authentication, resource-exhaustion, reload, backup, upgrade and rollback failure behaviors are demonstrated, documented and monitored.
- Operators can install, validate, activate, inspect, back up, restore, upgrade, roll back, renew/revoke certificates, drain and diagnose using published runbooks without implementation knowledge.
- Known limitations, residual risks, performance support envelope, compatibility matrix and security contact/disclosure process are published.
- No default route, public administration, arbitrary forwarding trust, plaintext secret logging, raw hook, insecure upstream TLS, direct Docker socket, root runtime or silent config fallback is present.

### 43.3 Research sources and independent-design note

Research was performed against the pinned repository snapshots in Section 7.1 and official public documentation, including NPMPlus's [repository and documentation](https://github.com/ZoeyVid/NPMPlus), Caddy's [architecture](https://caddyserver.com/docs/architecture), [configuration API](https://caddyserver.com/docs/api), [automatic HTTPS](https://caddyserver.com/docs/automatic-https), [reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy), and [metrics](https://caddyserver.com/docs/metrics), plus Traefik's [configuration overview](https://doc.traefik.io/traefik/getting-started/configuration-overview/), [providers](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/), [ACME resolver](https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/), and [dashboard security guidance](https://doc.traefik.io/traefik/operations/dashboard/). Dependency selection must be revalidated against current official crate repositories, advisories and licenses when Phase 0 pins versions.

The comparisons derive requirements from observable behavior, documentation, public interfaces and high-level source organization. They do not authorize copying upstream implementation, configuration templates, UI assets, tests or text. Clean implementation uses this independently reasoned design, normal protocol specifications, selected library APIs and project-authored tests.
