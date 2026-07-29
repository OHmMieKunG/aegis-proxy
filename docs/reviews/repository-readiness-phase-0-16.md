# Repository readiness audit: Phases 0–16

Date: 2026-07-29
Audited state: current working tree based on `ec8de76`; not an immutable candidate
Benchmark: basic [NPMPlus](https://github.com/ZoeyVid/NPMplus) operator workflow
Scope: HTTP Proxy Host MVP; automatic HTTPS is Phase 17
Production decision: **NO-GO**

## Decision

The Rust proxy, private CLI/API, and typed control plane are suitable for controlled local or
staging tests. The embedded GUI is source-build testable. This audit fixed the two packaging gaps
that prevented a clean image from containing that GUI and prevented the loopback-only browser/OIDC
boundary from working in bridge networking.

The image and evaluation stack now build and become healthy on Docker Desktop's Linux engine. A
pinned Playwright container on the same host network completed the real Keycloak authorization-code
exchange, one-use setup with session/CSRF rotation, UI validate/preview/create/schema-2 activation,
and Host-header traffic. That run found and closed callback-parameter, ETag, activation-route,
secret-permission, realm-import, and container-startup defects.

Controlled-test GO is still withheld. Current startup reconciliation restores the GUI-created
Proxy Host over the mounted restart-time TOML base, and rebuilt Compose traffic passes before and
after a proxy restart. Source audit found a separate P0: typed startup disables the only file/DNS
provider reconciliation task, so provider-backed groups remain on static fallback and provider
status cannot advance. The GUI also has no Proxy Host edit/disable/delete controls, and the full
failure campaign has not run. Docker Desktop did not expose Linux host-network loopback to
Windows/WSL, so native-host browser usability still requires the documented Linux Docker host.

Production remains NO-GO because independent application-security/usability review, long
fuzz/soak, recovery drills, supply-chain scanning, reproducible multi-architecture artifacts,
SBOM, signing, provenance, and supported deployment evidence remain open.

## Findings

### Closed by this audit

1. **P0 — release image omitted the GUI.** The prior Dockerfile never built `ui/dist` and built
   `rust-proxy` without `web-ui`. The image could not serve browser administration. The Dockerfile
   now performs `npm ci`, generated-client drift comparison, typecheck, Vite build, and
   `cargo build --features web-ui`; only the Rust binary enters the runtime image.
2. **P0 — bridge networking made loopback administration unreachable.** The existing
   `compose.yaml` exposes only proxy traffic and cannot publish AegisProxy's intentionally
   loopback-only `127.0.0.1:9090` listener from a bridge container. `compose.evaluation.yaml` adds
   an explicit Linux host-network workflow with proxy traffic on `127.0.0.1:8080`, browser
   administration on `localhost:9090`, Keycloak HTTPS on `localhost:9443`, and the sample upstream
   on `127.0.0.1:9000`.
3. **P0 — no reproducible local OIDC fixture.** The evaluation stack now pins Keycloak, Nginx, and
   OpenSSL images by version and digest, imports an exact Aegis client/callback/groups mapper,
   generates a localhost CA/certificate into a named volume, and supplies the CA through the
   existing OIDC `ca_bundle` secret reference. Keycloak's supported container realm import and PEM
   TLS interfaces are used as documented in its
   [container](https://www.keycloak.org/server/containers),
   [realm import](https://www.keycloak.org/server/importExport), and
   [TLS](https://www.keycloak.org/server/enabletls) guidance.
4. **P1 — operator documentation was stale.** The README still listed GUI and native OIDC as
   absent, and `PLAN.md` still named Phase 15 as immediate. Both now describe the Phase 16
   candidate and point to the evaluation workflow.
5. **P0 — GUI activation was not restored by normal container restart.** Current startup now
   recompiles durable typed objects over the mounted TOML base, resumes or creates an exact bound
   revision, and fails closed on invalid reconciliation. Focused reconciliation, real-daemon, and
   rebuilt Compose restart regressions pass.

### Open

1. **P0 — provider reconciliation is disabled by typed startup.** The managed runtime starts
   `ProviderCoordinator` reconciliation only inside the TOML file-watcher task. Typed startup
   deliberately disables that watcher so the mounted base is restart-only, but currently starts no
   replacement provider task. Manual configured providers and typed Discovery Sources therefore
   remain on static fallback after typed startup. Restore provider reconciliation without restoring
   TOML hot reload or bypassing typed revision binding.
2. **P1 — real-system coverage is only a happy-path smoke.** `deploy/evaluation/smoke.mjs` proves
   the built binary, real Keycloak exchange, secure-cookie/CSRF rotation, typed activation, and
   traffic together. Stale revision, role denial, IdP outage, logout, post-restart session loss,
   XSS, edit/delete, and forward rollback are not yet covered.
3. **P1 — a high frontend advisory remains unresolved.** `npm audit --audit-level=high` exits 1
   with two high findings for React Router's RSC/server-mode CSRF advisory. This project is a static
   SPA and does not enable RSC, but non-applicability has not been independently accepted.
4. **P1 — production evidence is incomplete.** `cargo audit`, `cargo deny`, container scanners,
   independent application-security/usability review, long fuzz/soak, artifact, recovery, and
   deployment gates are absent or unavailable.
5. **P2 — Proxy Host edit/disable/delete is API-only, and secondary workflows remain
   expert-oriented.** The GUI wizard creates and activates but does not edit or delete existing
   Proxy Hosts. Stream Hosts, Certificates, Access
   Policies, and Users use typed raw-JSON forms. This does not block the selected seven-field HTTP
   Proxy Host creation path, but it does not meet the full selected lifecycle acceptance.

The provider-loop result is an unresolved runtime-critical readiness finding.

## Capability matrix

| Phase | Capability | Implementation | Current evidence | Readiness |
|---:|---|---|---|---|
| 0 | Architecture, workspace, strict schema baseline | Implemented | Current manifests/schema plus historical phase report | Currently tested |
| 1 | HTTP/1.1 proxy, streaming, bounds, shutdown | Implemented | Workspace unit/integration suite | Currently tested |
| 2 | TLS termination, upstream TLS, certificate storage | Implemented | TLS/core tests; Pebble excluded | Currently tested; production-gated |
| 3 | Typed routing, canonical targets, conflicts | Implemented | Config corpus and route/security tests | Currently tested |
| 4 | Balancing, health, retry, circuit, drain | Implemented | Core pool/health/failure tests | Currently tested |
| 5 | Immutable revisions, activation, recovery, rollback | Implemented | Revision/runtime crash-recovery tests | Currently tested; manual drill gated |
| 6 | ACME HTTP-01, DNS-01, TLS-ALPN-01 | Implemented | Unit tests; Pebble test intentionally ignored | Manually testable; production-gated |
| 7 | Fixed middleware/authentication stages | Implemented | Middleware and bypass tests | Currently tested |
| 8 | Private Unix API/CLI, RBAC, audit, backup validation | Implemented | Admin/CLI integration suite | Currently tested |
| 9 | Logs, OpenMetrics, tracing, alert fixtures | Implemented | Telemetry and admin status tests | Currently tested; topology-gated |
| 10 | Historical no-UI decision | Superseded by ADR-0029/0030 | ADR trace | Intentionally superseded |
| 11 | File and DNS A/AAAA discovery | Implemented | Provider validation/failure tests; typed-startup source audit found reconciliation is not started | Runtime regression; controlled-test blocker |
| 12 | External-load-balancer fleet checks | Implemented without clustering | HA chaos/fleet tests | Currently tested; production topology gated |
| 13 | Hardening examples and fuzz targets | Implemented as candidate material | Fuzz manifest builds; no current campaign/container enforcement | Production-gated |
| 14 | Behavior-preserving modularization | Implemented | Current full suite; historical contract comparison | Currently tested |
| 15 | Typed objects, ownership, candidate activation, forward rollback | Implemented | 106 Admin tests plus CLI integration | Currently tested; independent review gated |
| 16 | Loopback OIDC sessions, embedded GUI, typed startup reconciliation | Working-tree candidate | Rust OIDC/startup tests, clean UI build, five mocked tests, real Keycloak and restart smoke | Runtime tested; provider/failure campaign blocked |

## HTTP Proxy Host MVP matrix

| Operator capability | State |
|---|---|
| Clean checkout builds UI and embeds it in one Rust runtime binary | Implemented; local and container release builds pass |
| Start one documented evaluation Compose stack | Passed on Docker Desktop Linux engine; native Linux host remains required for browser access |
| Open GUI at `http://localhost:9090` | Passed from a host-network browser container; Docker Desktop did not expose it to Windows/WSL |
| Authenticate with evaluation Keycloak over HTTPS | Passed real authorization-code exchange |
| Issue and redeem one-use setup token | Passed with session-cookie and CSRF rotation |
| Create/validate/preview/activate seven-field HTTP Proxy Host | Passed through the real GUI and schema-2 endpoint |
| Edit, disable/delete, and forward rollback | API support exists; GUI controls and real lifecycle coverage are absent |
| Forward traffic by Host header | Passed before and after proxy restart |
| Preserve desired/active Proxy Host state across proxy restart | Passed: startup reconciles durable typed state and traffic remains available |
| Stale revision, unauthorized role, IdP outage, logout, restart/session loss | Unit/mock coverage is partial; real-system campaign blocked |
| CSP/cache headers, storage non-disclosure, XSS rendering | Unit/mock coverage passes; independent browser review gated |
| Automatic HTTPS | Intentionally deferred to Phase 17 |
| Traefik-style providers | Intentionally deferred to Phase 18 |

## Correctness, security, persistence, and parity

- HTTP framing terminates at parsed Hyper messages; current tests cover ambiguous framing,
  authority/SNI mismatch, normalized paths, protected forwarding headers, and request bounds.
- Typed Proxy Hosts compile through the existing validated configuration, immutable candidate,
  explicit activation, and forward-rollback path. Errors and rewrites do not rematch.
- Upstream destinations originate in validated configuration/typed objects and retain explicit
  loopback egress policy in the evaluation template.
- OIDC client secret and CA are file secret references. Session/OIDC tokens remain server-side;
  setup tokens are one-use hash-only in memory; browser storage tests pass.
- Desired objects, candidates, revisions, audit records, identity bindings, and the active Proxy
  Host survived the exercised restart. Provider-backed endpoint refresh remains broken in typed
  startup because no reconciliation task is started.
- The UI calls the typed `/v1` control plane; no UI-only mutation path, password login, public
  listener, Docker socket, or Node production runtime was added.
- API/UI parity is sufficient for the HTTP Proxy Host MVP. Other typed resources are present but
  use raw JSON and should be treated as expert workflows.

## Verification executed on 2026-07-29

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets` | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed |
| `cargo test --workspace --all-features` | Passed: 362 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | Passed; no doctests defined |
| `cargo tree -e features` | Passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | Passed |
| `cargo build --locked --release --bin rust-proxy --features web-ui` | Passed with generated production UI embedded |
| Shipped configuration corpus | Passed inside `config_cli`: 7 valid accepted, 3 invalid rejected |
| Admin OpenAPI parsing/private-route coverage | Passed in the Admin suite |
| Evaluation TOML | Passed `rust-proxy validate` |
| Evaluation Compose/realm static policy | Passed PyYAML, JSON parser, pinned-image, host-network, and no-Docker-socket assertions |
| `docker compose -f compose.evaluation.yaml up --build --wait` | Passed on Docker Desktop 4.84.0 / Linux Engine 29.6.2 |
| Real Keycloak + Playwright smoke | Passed login, setup/session rotation, validate, preview, create, schema-2 activate, headers/storage checks, and Host-header traffic |
| Proxy container restart | Passed: rebuilt Compose traffic for `proxy.localhost` succeeded before and after restart |
| Repository Markdown relative-link targets | Passed: every target exists across 135 Markdown files |
| `npm ci` | Passed; npm 9.2 emitted the Redocly npm-engine warning |
| Typecheck and generated-client drift | Passed |
| Vite production build | Passed |
| Playwright Chromium/axe suite | Passed: 5 scenarios in the pinned Playwright container |
| `npm audit --audit-level=high` | Failed: 2 high React Router findings; no critical finding reported |

Cargo continues to warn that transitive `proc-macro-error2 2.0.1` contains code rejected by a
future Rust version.

Unavailable checks were reported exactly:

- `cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, and
  `cargo fuzz`: Cargo reports `no such command`.
- `markdownlint` and `lychee`: unavailable; a direct repository-wide relative-link check passed.
- `trivy`, `grype`, `syft`, and `cosign`: unavailable.
- Docker Desktop's Linux engine is available to the Linux client and ran the image, Compose, and
  restart checks. Desktop host networking did not expose loopback listeners to Windows/WSL, so
  Playwright ran in a pinned host-network container.
- Pebble, container scan, long fuzz/soak, independent review, SBOM, signing, and provenance were
  not run.

## Remediation roadmap

| Priority | Item | Owner | Dependencies | Acceptance check |
|---|---|---|---|---|
| P0 | Restore provider reconciliation under typed startup | Runtime + providers | Existing coordinator; restart-only TOML base; typed binding | Manual and typed file/DNS providers refresh after typed restart; invalid durable state still fails closed; TOML changes do not hot reload |
| P0 | Run failure campaign on the same immutable image | Control-plane + security | Passing provider/startup P0 | Stale revision, role denial, IdP outage, restart/session loss, logout, CSRF/session rotation, headers/storage/XSS all pass with no critical runtime finding |
| P1 | Resolve or formally disposition React Router advisory | Frontend + security | Advisory analysis; upgrade compatibility | `npm audit` has no unresolved applicable high/critical finding, or signed non-applicability with compensating tests |
| P1 | Run supply-chain/container gates | Release/security | Scanner-capable Linux runner | Current Rust/npm/image advisories, licenses, secrets, SBOM, and container scan reviewed with no unresolved critical/high |
| P1 | Independent application-security and usability review | External reviewers | Immutable candidate and real-system evidence | Phase 16 exit checklist has no unresolved critical/high finding |
| P2 | Replace raw-JSON secondary workflows with task forms | Product/frontend | User research; stable typed contracts | Unfamiliar operator completes named workflows without editing JSON |

Controlled-test GO requires both open P0 rows. Production GO additionally requires the repository's
Phase 13/15/16/21 review, fuzz/soak, recovery, supply-chain, artifact, deployment, and signoff
gates.

## Ponytail complexity appendix

Ranked separately from correctness and security:

1. `delete:` remove deprecated schema-1 Proxy Host activation/rollback aliases after the published
   compatibility window; use only schema-2 typed candidate routes. Estimated reduction: about 120
   production/test/OpenAPI lines and two legacy actions.
2. `stdlib:` replace five `fs2::FileExt` lock sites with Rust 1.89+
   [`std::fs::File::{try_lock, unlock}`](https://doc.rust-lang.org/stable/std/fs/struct.File.html);
   remove `fs2` from three manifests. Estimated reduction: one unique dependency and about 8 lines.
3. `native:` no justified cut; browser primitives already cover forms, confirmation, storage, and
   accessibility basics where they are simpler.
4. `yagni:` no justified cut; apparently optional domains are committed Phase 15 product contracts,
   not speculative abstractions.
5. `shrink:` no safe whole-repository rewrite outranks the two targeted removals above.

Net possible after compatibility expiry: approximately **128 lines and 1 unique dependency**.
