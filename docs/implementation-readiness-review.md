# Implementation Readiness Review

Date: 2026-07-18
Repository: `/home/pkumham/aegis-proxy`
Environment: WSL2 Linux 7.1.3, x86_64
Source of truth: `PLAN.md`

## Repository state

- Valid Rust workspace with six crates and one deployable `rust-proxy` binary.
- `PLAN.md` was read completely before this review was updated.
- The repository contains implementation and phase reports through Phase 7.
- The current checkout contains no tracked modifications.
- A separate nested clean clone exists at `aegis-proxy/` and is untracked by this repository. It is treated as pre-existing user work and will not be modified or committed.

## Git state

- Valid Git repository on branch `dev`, tracking `origin/dev`.
- HEAD at review start: `8b743bb docs(phase-7): record implementation results`.
- Existing history contains 138 commits. No history rewrite, reset, rebase, amend, push, or remote mutation is authorized or planned.
- The only uncommitted path at review start is the untracked nested repository `aegis-proxy/`.

## Existing implementation

- Strict typed TOML schema v1, recursive unknown-field rejection, deterministic validation, redacted preview, route conflicts, and invalid fixture coverage.
- HTTP/1.1, HTTP/2, WebSocket, gRPC, streaming, cancellation, bounded bodies/headers/connections, graceful shutdown, TCP proxying, and bounded TLS ClientHello passthrough.
- Rustls TLS termination and verified upstream TLS, encrypted certificate generations, exact/wildcard certificate selection, and certificate CLI operations.
- Static/DNS upstreams, egress/CIDR policy, load balancing, health state, bounded retries, circuit breaking, and draining.
- Immutable configuration revisions, durable activation journal, CAS pointer, `ArcSwap` publication, file/SIGHUP reload, rollback, crash recovery, retention, and explicit last-known-good startup.
- ACME account/order/challenge/renewal foundations with HTTP-01, Cloudflare DNS-01, TLS-ALPN-01, encrypted storage, bounded transport, and Pebble integration coverage.
- Fixed-stage middleware for forwarding/request IDs, IP policy, rate/in-flight limits, redirects, CORS, Basic and ForwardAuth, rewrites, typed headers, maintenance/custom errors, compression, and bounded access events.
- `proxy-admin` remains a marker crate; the Phase 8 private administrative API, RBAC, durable audit, tokens, and backup/restore are not implemented.

## Existing uncommitted changes

- `aegis-proxy/`: untracked nested clean Git clone at `master`/`bfb60ca`. It will remain untouched and unstaged.
- No tracked file has an unstaged or staged change at review start.

## Completed phases

- Phase 0: repository assessment and architecture decisions.
- Phase 1: minimal secure HTTP reverse proxy.
- Phase 2: TLS termination and certificate loading.
- Phase 3: routing engine and typed configuration.
- Phase 4: load balancing and health checks.
- Phase 5: dynamic reload and last-known-good rollback.
- Phase 6: ACME certificate automation.
- Phase 7: middleware and authentication.

Each phase has a committed completion report. Independent protocol/security reviews and unavailable supply-chain tools remain release gates; their absence is not represented as completed evidence.

## Partially completed phases

- Phase 8 has only its placeholder crate and plan-approved dependency markers. No administrative transport or mutation surface exists yet.
- Phase 9 access-event groundwork exists, but Prometheus/OpenMetrics, OpenTelemetry, private health semantics, exporter bounds, and observability contract tests remain unimplemented.
- Phases 13 and 14 have not started.

## Next incomplete phase

Phase 8: Administrative API and CLI.

## Blocking issues

None for local Phase 8 implementation.

## Non-blocking issues

- `rust-toolchain.toml` pins Rust 1.97.0, while installed stable is 1.97.1. Rustup cannot write its update metadata under the managed home-directory sandbox. Checks will use `RUSTUP_TOOLCHAIN=stable` and record the exact compiler.
- `cargo-audit` and `cargo-deny` are not installed.
- Docker is reachable through Docker Desktop, but container validation belongs to the appropriate phase and may require external daemon permission.
- Independent protocol, TLS, ACME, authentication, and administrative security reviews remain mandatory release gates.

## Plan contradictions

- The earlier Phase 5 conflict between unauthenticated activation commands and Phase 8 authenticated/audited mutation was already corrected in `PLAN.md` by commit `4b9aa06`.
- Phase 10 is optional and requires explicit approval. The current no-UI ADR satisfies the initial-release direction; no UI dependency or source will be added.
- Phase 11–12 capabilities are conditional on demonstrated requirements and their explicit gates. They are not prerequisites for the mandatory initial release.
- No new unresolved contradiction between the current repository and `PLAN.md` was found.

## Security concerns

- Phase 8 introduces the highest remaining local trust boundary: configuration mutation, rollback, tokens, authorization, audit durability, and backup parsing.
- The admin interface must default to a permission-restricted Unix socket and must not be reachable from public data listeners.
- Every mutation must enforce authentication, deny-by-default RBAC, `If-Match`, strict bounded input, and durable audit intent before state change.
- Backup validation must prevent path traversal, tampering, secret disclosure, and in-place blind extraction.
- The existing nested clone must not enter artifacts, scans, or commits.

## Dependency concerns

- Phase 8 should reuse existing Tokio, Serde, SHA-256, revision, secret, and runtime facilities.
- Axum is justified for the private REST boundary; only required features should be enabled.
- Token hashing should reuse the already present Argon2 implementation and bounded blocking policy.
- An HMAC crate may be needed for audit chaining; no OpenAPI generator should be added unless a maintained static contract plus tests proves insufficient.
- Advisory, license, and transitive unsafe checks remain unverified locally until their tools are available.

## License concerns

- Project license is `MIT OR Apache-2.0`; direct dependency licenses are inventoried in `docs/dependencies.md`.
- No Git dependency or copied NPMPlus/Caddy/Traefik source is present.
- New Phase 8 direct dependencies must be recorded with license, native/unsafe surface, alternative, and upgrade policy before their implementation commit.
- Automated license enforcement is unavailable locally because `cargo-deny` is not installed.

## Proposed implementation sequence

1. Establish Phase 8 admin DTO/error/RBAC contracts and complete role-action negative tests.
2. Add hash-only API-token records with bounded Argon2 verification and expiry/revocation behavior.
3. Add hash-chained durable audit intent/outcome storage and make mutations fail closed on audit failure.
4. Expose the minimum private Unix-socket REST API for status, validation, preview, candidates, activation, revisions, rollback, routes, upstreams, certificates, audit, and backup/restore validation.
5. Wire online CLI commands to the Unix socket with stable exit-code mapping and redacted output.
6. Add versioned bounded backup creation/verification and clean-directory restore validation without in-place extraction.
7. Publish the administrative contract/OpenAPI, operational guidance, dependency inventory, tests, and Phase 8 completion report.

## Initial acceptance criteria

- Unix socket is the only default administrative transport and is created with restrictive permissions.
- Every endpoint has an explicit permission and complete allow/deny test matrix.
- Every mutation requires a valid principal, permission, `If-Match`, bounded payload, and durable audit intent.
- Failed audit persistence, stale revisions, malformed input, and preparation failure leave the active runtime unchanged.
- Tokens are displayed only at creation, stored as hashes, expire/revoke correctly, and never appear in logs or responses after creation.
- Backup archives are authenticated/versioned/bounded, reject traversal and tampering, exclude recovery identities, and validate into a new target only.
- CLI exit codes and redacted error envelopes match the documented contract.
- Formatting, compilation, strict Clippy, tests, and available dependency checks pass.

## Expected files to change

- `crates/proxy-admin/Cargo.toml` and focused modules under `crates/proxy-admin/src/`.
- `crates/rust-proxy/{Cargo.toml,src/main.rs}` and focused CLI integration tests.
- Narrow public status/activation interfaces in `proxy-core` or `proxy-config` only where the existing boundary is insufficient.
- `Cargo.lock`, `docs/dependencies.md`, administrative/API/backup documentation, API contract artifact, and Phase 8 tests/report.

## Initial risk register

| Risk | Severity | Likelihood | Mitigation |
|---|---:|---:|---|
| Admin listener becomes public or shares data-plane routing | Critical | Low | Unix-only default, separate server, bind and reachability tests |
| Authentication or RBAC bypass | Critical | Medium | Deny-by-default action enum and exhaustive role matrix |
| Mutation occurs without durable audit | High | Medium | Persist/fsync intent before activation; injected sink-failure tests |
| Stale client overwrites active policy | High | Medium | Mandatory exact `If-Match` CAS and concurrency tests |
| Token secret leaks or hashing exhausts workers | Critical | Low-Medium | One-time display, hash-only records, redaction, rate/in-flight bounds, bounded blocking semaphore |
| Backup tampering or path traversal overwrites state | Critical | Medium | Versioned authenticated manifest, normalized allowlist paths, validate into new directory only |
| Admin work starves data plane | High | Medium | Separate connection/body/in-flight/time limits and bounded blocking work |
| New dependencies expand unsafe/license surface | High | Medium | Minimal features, inventory, lockfile review, audit/deny when available |

## Readiness decision

Ready to implement Phase 8 locally. No production system, external credential, public listener, remote mutation, or destructive action is required.
