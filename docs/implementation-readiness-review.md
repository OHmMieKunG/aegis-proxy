# Implementation Readiness Review

Date: 2026-07-16
Repository: `C:\KMITL-CE\LAB\AegisProxy`
Source of truth: `PLAN.md`

## Repository state

- Rust workspace and single `rust-proxy` deployable binary are established.
- Phases 0 through 4 are complete and have committed phase reports.
- Phase 5 is partially implemented. The working tree was clean at this review.
- No production systems, credentials, DNS, certificate authorities, or remote Git state are in scope.

## Git state

- Valid Git repository on branch `main`.
- HEAD at review start: `a49035d docs(config): document reload recovery`.
- Existing history has not been rewritten and no commits have been pushed by this implementation work.

## Existing implementation

- Strict typed TOML configuration, deterministic HTTP/TCP routing, secret references, and offline validation/preview/diff.
- HTTP/1.1, HTTP/2, WebSocket, gRPC, TCP, TLS termination, TLS passthrough, graceful shutdown, and bounded protocol handling.
- Static/DNS upstreams, egress policy, load balancing, active/passive health, retry/circuit controls, and draining.
- Immutable SHA-256 configuration revisions, activation journal, compare-and-swap active pointer, crash recovery, and `ArcSwap` runtime snapshots.
- Managed file reload by content-hash polling and Unix SIGHUP; invalid reloads preserve the active runtime.
- Explicit last-known-good recovery and offline revision listing.

## Existing uncommitted changes

None at review start.

## Completed phases

- Phase 0: repository and architecture foundation.
- Phase 1: minimal secure HTTP reverse proxy.
- Phase 2: TLS termination, HTTP/2, gRPC, and certificate loading.
- Phase 3: routing engine, strict configuration, TCP/TLS passthrough.
- Phase 4: load balancing, DNS, health checks, retry, circuit breaking, and draining.

## Partially completed phases

Phase 5 has atomic revision persistence, snapshot publication, polling/SIGHUP reload, crash-point tests, explicit LKG recovery, revision listing, and lossless ordinary reload coverage. Remaining mandatory evidence is listed below.

## Next incomplete phase

Phase 5: dynamic reload and last-known-good rollback.

## Blocking issues

None for the next local implementation units.

## Non-blocking issues

- The local Windows GNU environment cannot compile or execute the Unix SIGHUP path; Linux CI must verify it.
- `cargo-audit` and `cargo-deny` are not installed locally.
- The Windows GNU linker emits a known `corrupt .drectve` warning, and Cargo reports a future-incompatibility warning for `proc-macro-error2 v2.0.1`.
- Intended Linux filesystem power-loss behavior still needs a dedicated crash campaign.

## Plan contradictions

- Phase 5 originally required authenticated mutation API/CLI behavior before Phase 8 supplied authentication and durable audit authorization. `PLAN.md` now defers authenticated activation and rollback interfaces to Phase 8; the correction is committed as `4b9aa06`.
- No unresolved architecture contradiction is known.

## Security concerns

- Offline state commands remain read-only; unsafe unauthenticated activation/rollback was intentionally not added.
- LKG recovery is explicit and never silently replaces an invalid startup configuration.
- Windows directory durability is weaker than the intended Linux local-filesystem contract and is not represented as power-loss safe.
- Reload must prove that active streams retain their pinned snapshot and that changed/removed endpoint state cannot receive new work.

## Dependency concerns

- Phase 5 direct dependencies are `arc-swap`, `fs2`, `serde_json`, and `sha2`; their purpose and risk are recorded in `docs/dependencies.md`.
- No database, plugin system, UI, clustering, UDP, or HTTP/3 dependency has been introduced.
- Advisory and license policy checks remain unexecuted locally until their tools are installed; workspace resolution and feature-tree checks remain available.

## License concerns

- Project and direct-dependency license policy is documented; no upstream project source has been copied.
- Automated license-policy validation remains pending because `cargo-deny` is unavailable locally.

## Proposed implementation sequence

1. Prove an in-flight streaming response completes across snapshot activation while new traffic uses the new revision.
2. Reuse unchanged upstream runtime state and prove changed/removed endpoint idle eviction plus bounded active drain.
3. Implement and test revision retention without deleting active or immediate-previous revisions.
4. Record a reproducible reload benchmark and accepted budget.
5. Run the Linux filesystem crash/reload campaign and SIGHUP validation when a Linux test environment is available.
6. Complete and commit the Phase 5 report, then proceed to Phase 6.

## Initial acceptance criteria

- Failed candidates preserve the exact active revision/hash and serving runtime.
- In-flight streams complete under the snapshot they acquired; new requests observe only a fully prepared snapshot.
- Changed/removed endpoints receive no new work, idle clients close, and active work drains only to its declared deadline.
- Crash recovery selects the old or fully committed new revision, never partial state.
- Retention is bounded and never removes active or immediate-previous recovery state.
- Formatting, strict Clippy, and all workspace tests pass after each logical change.

## Expected files to change

- `crates/proxy-core/src/{lib,runtime}.rs` and focused runtime/upstream tests.
- `crates/proxy-config/src/revision.rs` for retention policy if not already isolated there.
- `docs/benchmarks/` for reload methodology/results.
- `docs/config-reload.md`, relevant ADRs, and `docs/phase-5-completion.md`.

## Initial risk register

| Risk | Severity | Likelihood | Mitigation | Owner |
|---|---:|---:|---|---|
| Active stream is interrupted or rematched during reload | Critical | Medium | Snapshot pinning plus long-stream integration test | Runtime/protocol |
| Reused or retired endpoint state receives wrong-revision work | High | Medium | Full transport/security identity comparison and drain tests | Upstream/runtime |
| Power loss exposes partial revision state | High | Medium | Local-filesystem contract, fsync/rename, crash injection on Linux | Config/reliability |
| Revision retention removes recovery state | High | Low | Protect active and immediate previous revisions; bounded tests | Config/reliability |
| Reload latency or activation gap is unmeasured | Medium | Medium | Reproducible local benchmark and explicit acceptance budget | Performance/runtime |
| Missing local audit/license tools hides dependency risk | High | Medium | Record unavailable checks and require CI execution before release | Supply chain |

## Readiness decision

Ready to continue Phase 5. No external authorization or production access is required for the next local test and runtime changes.
