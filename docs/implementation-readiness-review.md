# Implementation Readiness Review

Date: 2026-07-16
Repository: `C:\KMITL-CE\LAB\AegisProxy`
Source of truth: `PLAN.md`

## Repository state

- Greenfield Rust reverse-proxy repository.
- Only authored project artifact before this review: `PLAN.md`.
- No source, tests, configuration examples, CI, container, systemd, Kubernetes, or deployment files.
- Managed empty `.agents` directory exists; no project files were found there.

## Git state

- Valid Git repository on branch `main`.
- HEAD: `f6c1c32 docs(plan): define reverse proxy implementation roadmap`.
- Working tree clean before this review.
- No remote push or history rewrite is authorized or planned.

## Existing implementation

None. There are no Rust crates, binaries, APIs, listeners, persistence formats, or runtime behavior to preserve.

## Existing uncommitted changes

None at review start. This review is the first new change.

## Existing ADRs and phase reports

None. The ADR summaries in `PLAN.md` must become implementation ADR files during Phase 0. No phase is complete.

## Next incomplete phase

Phase 0: repository assessment and architecture decisions. The research/plan portion exists; workspace bootstrap, dependency lock, policy files, ADR files, and compatibility spikes remain.

## Blocking issues

None for local implementation. Exact crate versions, MSRV, Rustls crypto provider, ClientHello passthrough strategy, and license/unsafe inventories require Phase 0 verification before production claims.

## Non-blocking issues

- Windows is the development shell; production support is Linux-first.
- Public ACME, public DNS, production credentials, and external deployment are unavailable and must not be used.
- Optional tools such as `cargo-audit`, `cargo-deny`, fuzzing, container scanners, and Linux systemd tests may be unavailable locally; record exact results.

## Plan contradictions

No verified contradiction at readiness time. The plan explicitly defers database, UI, runtime plugins, clustering, UDP, and HTTP/3. Any compiler, crate, protocol, or license conflict must follow the correction policy in `PLAN.md` and receive a separate ADR/plan commit.

## Security concerns

- No implemented trust boundary exists yet; every listener, parser, configuration path, secret provider, and admin action is new security-sensitive code.
- The first implementation must reject ambiguous HTTP framing, untrusted forwarding headers, arbitrary upstream destinations, insecure upstream TLS, public admin binds, and plaintext secret logging.
- TLS ClientHello passthrough parsing is a release-blocking review item.
- No production or personal credentials may enter the repository or test fixtures.

## Dependency concerns

- Start with the plan-selected minimal set: Tokio, Hyper, Rustls, Axum, Serde/TOML, Tower where useful, tracing, ArcSwap, Hickory, and secret-storage crates only when the phase requires them.
- Pin the toolchain and commit `Cargo.lock`.
- Record purpose, version, features, license, native/unsafe surface, alternative, review date, and upgrade policy in `docs/dependencies.md`.
- Do not add a database, UI, plugin, Docker provider, HTTP/3, or UDP dependency in the initial-release phases.

## License concerns

- Project license is not yet finalized; Phase 0 must record the legal decision.
- Default runtime dependency policy is permissive reviewed licenses only.
- NPMPlus, Caddy, and Traefik are research references; no source, assets, tests, or templates are copied.

## Proposed implementation sequence

1. Commit this readiness review.
2. Bootstrap stable Rust workspace, lint/toolchain/license/dependency policy, and minimal crate skeletons.
3. Add ADR files for material Phase 0 choices and dependency inventory.
4. Implement Phase 1 HTTP/1.1 + WebSocket streaming proxy with bounded limits and graceful shutdown.
5. Implement Phase 2 Rustls/TLS/H2/gRPC/BYO certificate loading.
6. Implement Phase 3 strict TOML, deterministic routing, TCP/TLS passthrough after ClientHello decision.
7. Continue through the mandatory phases in `PLAN.md`, committing each logical unit and phase report.

## Initial acceptance criteria

- `cargo fmt --all -- --check`, `cargo check --workspace --all-targets`, Clippy with warnings denied, and workspace tests pass for every committed logical unit.
- Phase 1 forwards streaming HTTP/1.1/WebSocket traffic without unbounded buffering; malformed framing and oversized inputs fail closed.
- Client cancellation cancels or closes the upstream safely.
- Shutdown stops readiness, drains bounded work, and exits by deadline.
- Invalid configuration never starts public listeners.
- No secret, private key, credential, or real certificate is committed.

## Expected initial files

- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `README.md`, `SECURITY.md`, `LICENSE`.
- `crates/proxy-core`, `crates/proxy-config`, `crates/proxy-secrets`, `crates/proxy-tls`, `crates/proxy-admin`, `crates/rust-proxy`.
- `docs/adr/`, `docs/dependencies.md`, `docs/phase-0-completion.md`.
- Phase-specific unit/integration tests and local fixtures.

## Initial risk register

| Risk | Severity | Mitigation | Owner |
|---|---:|---|---|
| HTTP framing/translation bug | Critical | Hyper-only framing, corpus tests, fuzzing, protocol review | Data plane/security |
| Dependency/license/unsafe mismatch | High | Phase 0 inventory, lockfile, cargo-deny/audit, ADR exceptions | Architecture/security |
| ClientHello parser unsafe or incomplete | Critical | Rustls API spike, safe parser comparison, fuzz gate | TLS/security |
| Unbounded resource use | High | Limits before feature growth, bounded queues/semaphores, soak tests | Runtime/performance |
| Reload state corruption | High | Immutable revisions, activation journal, crash tests | Config/runtime |
| Scope growth | High | Mandatory/deferred map and phase exits | Technical lead |

## Readiness decision

Ready to begin Phase 0 bootstrap. No external authorization or production access is required for the planned local work.
