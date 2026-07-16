# Phase 5: Dynamic reload and last-known-good rollback

## 1. Phase title

Versioned configuration, atomic runtime activation, live file reload, and explicit last-known-good recovery.

## 2. Original objectives

Implement immutable configuration revisions, serialized compare-and-swap activation, prepare-before-publish snapshots, structural probation and rollback, file polling/SIGHUP reload, crash recovery, bounded retention, unchanged-upstream reuse, changed-endpoint drain behavior, and measurable lossless activation.

## 3. Implemented scope

- Canonical TOML revisions addressed by monotonic sequence plus SHA-256, with separate strict JSON metadata.
- Exclusive process/OS state-directory ownership, private paths, bounded reads, `create_new`, file sync, same-directory rename, and directory sync on Unix.
- Durable active/previous pointer and activation journal with intent, probation, committed, and rolled-back phases.
- Exact compare-and-swap activation and fail-closed administrative readiness after an unrecoverable durable rollback error.
- Prepared immutable `RuntimeSnapshot` values published through one `ArcSwap` operation.
- File-backed daemon startup that prepares and binds before committing state and accepting traffic.
- Content-hash polling and Unix SIGHUP activation through one validation/preparation path; repeated bytes are ignored.
- Explicit `--resume-last-known-good --state-dir` recovery; normal invalid startup never silently falls back.
- Read-only offline `config revisions`; unauthenticated offline activation/rollback is absent.
- Runtime reuse only for fully equal upstream group/transport/security policy. Changed groups receive fresh clients, DNS state, pool state, and health tasks.
- Removed/changed pools stop new selection, close idle Hyper clients, retain active HTTP/TCP work until the configured deadline, then cancel it.
- In-flight HTTP responses continue on their acquired endpoint state while new requests use only the fully published candidate.
- Automatic revision retention: minimum 30 days, newest 70, protected active/previous/journal targets, hard ceiling 1,000.

## 4. Deferred scope

- Authenticated activation/rollback CLI and `/v1/config*` remain Phase 8 work because authorization and durable audit must exist first.
- Multi-node rollout, signed fleet snapshots, and clustering remain Phase 12.
- XFS qualification and physical storage power-loss testing remain release-environment work.
- Audit-event persistence, metrics, and tracing for reload outcomes remain Phase 9; existing structured logs report outcomes without secret content.

## 5. Architecture decisions

- ADR-0006: immutable atomic runtime snapshots.
- ADR-0007: prepare, durable intent, publish, probation, commit, and restore ordering.
- ADR-0008: file revisions with 30-day/newest-70 retention and protected recovery targets.
- ADR-0026: unchanged complete group reuse; changed groups drain with idle eviction and deadline cancellation.
- `PLAN.md` was corrected in commit `4b9aa06`: unauthenticated Phase 5 mutation surfaces were incompatible with the Phase 8 authentication/audit boundary.

## 6. Files created

- `crates/proxy-config/src/revision.rs`
- `crates/proxy-core/src/runtime.rs`
- `docs/config-reload.md`
- `docs/benchmarks/reload-2026-07-16.md`
- `docs/testing/phase-5-crash-recovery.md`
- `docs/phase-5-completion.md`

## 7. Files modified

- `PLAN.md`, `Cargo.lock`
- `crates/proxy-config/{Cargo.toml,src/lib.rs}`
- `crates/proxy-core/{Cargo.toml,src/lib.rs,src/tcp.rs,src/upstream/mod.rs,src/upstream/pool.rs}`
- `crates/rust-proxy/{src/main.rs,tests/config_cli.rs}`
- `docs/{dependencies.md,implementation-readiness-review.md}`
- `docs/adr/{0008-file-revisions.md,0026-upstream-failure-state.md}`

## 8. Dependencies added

- `arc-swap`: atomic `Arc<RuntimeSnapshot>` publication.
- `fs2`: cross-platform exclusive state-directory file lock.
- `serde_json`: strict bounded revision pointer/journal/metadata serialization.
- `sha2`: configuration content and canonical revision hashing.

All are recorded in `docs/dependencies.md`. No database, native service, runtime plugin, UI, clustering, UDP, or HTTP/3 dependency was introduced.

## 9. Configuration introduced

- `runtime.state_dir`: durable local configuration-state root.
- `runtime.config_poll_secs`: bounded file polling interval; Unix SIGHUP bypasses the wait.
- Existing per-group `drain_timeout_secs` now governs live snapshot retirement as well as shutdown drain.
- No new plaintext secret or public administrative configuration was introduced.

## 10. Tests added

- Candidate round-trip, hash deduplication, tamper rejection, owner locking, and ID traversal rejection.
- Compare-and-swap conflict, incomplete intent/probation recovery, committed restart, rollback, and crash-boundary fixtures.
- Missing secret/certificate preparation failure retaining the active revision.
- Explicit LKG CLI requirements and read-only revision listing.
- Content-hash polling, repeated hash behavior, invalid live change, and Unix SIGHUP activation.
- Concurrent old/new successful traffic and an in-flight streamed response across activation.
- Complete unchanged upstream state reuse and changed pool replacement.
- Removed endpoint idle-client eviction, active guard drain, and deadline cancellation for HTTP bodies/TCP relays.
- Retention pruning with active and immediate-previous targets outside the newest-70 window.
- Ignored dependency-free release activation benchmark harness.

## 11. Commands executed

- `cargo fmt --all -- --check` — passed.
- `cargo check --workspace --all-targets` — passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed.
- `cargo test --workspace --all-features -- --test-threads=1` — passed.
- Focused revision, runtime coordinator, reload, drain, CLI, and recovery tests — passed after defects described below were fixed.
- Release benchmark command from `docs/benchmarks/reload-2026-07-16.md` — passed.
- Linux Docker SIGHUP test with a 60-second poll interval — passed in 0.21 seconds.
- ext4 revision campaign command from `docs/testing/phase-5-crash-recovery.md` — eight tests passed in 0.70 seconds.
- `cargo tree --locked -e features` — passed.
- `cargo audit --version` — exit 101, command unavailable.
- `cargo deny --version` — exit 101, command unavailable.

## 12. Actual command results

The final serial workspace suite passed 128 tests: 35 configuration, 70 proxy-core, one gRPC, five secrets, 12 TLS, one certificate CLI, and four configuration CLI tests. One manual benchmark test was ignored by the normal suite and passed when explicitly run in release mode. Documentation tests passed.

Strict workspace Clippy, formatting, check, and feature-tree resolution exited zero. The Windows GNU linker still emits its known `.drectve` warning. Cargo still reports future incompatibility in transitive `proc-macro-error2 2.0.1`.

Failed runs were not hidden:

- An initial exact test filter matched zero tests; the corrected filter ran the intended test.
- The strengthened idle-eviction fixture initially failed because it did not answer reused requests; fixing the fixture then exposed a real retained-startup-snapshot bug.
- Drain integration initially kept the coordinator's old `Arc` until activation returned; dropping it before bounded drain waiting fixed idle eviction.
- Stable Rust rejected `#[cfg]` directly on expression statements; block-scoped conditional statements fixed compilation.
- Two ext4 container setup commands failed before tests because the login shell reset/expanded `PATH`; the explicit container `PATH` command passed.

## 13. Security checks

- Unknown, oversized, malformed, hash-mismatched, or missing revision state fails closed.
- Candidate preparation resolves required certificate/secret material before durable pointer publication; failure preserves the active snapshot/hash.
- Revision IDs cannot traverse paths; source labels and state files are bounded.
- Offline state mutation is intentionally absent until authentication, authorization, and durable audit exist.
- LKG recovery is explicit and verifies pointer, journal, metadata, hash, schema, and semantic configuration.
- Replaced endpoint destinations receive no new work. Idle clients close; active work ends normally or at its configured deadline.
- No secret values, raw configuration, private keys, or sensitive headers were added to logs or metadata.

No independent security/protocol review has occurred. Advisory and automated license-policy checks remain unavailable locally.

## 14. Performance checks

The release-mode 25-sample minimal activation benchmark recorded p50 41.513 ms, p90 46.935 ms, p99 48.101 ms, and maximum 48.228 ms on the documented Ryzen 9 5900HS Windows GNU environment. The local development guard of p99 100 ms / maximum 150 ms passed. This excludes polling, parsing, candidate creation, traffic, TLS, and Linux directory-fsync cost and is not a production SLO.

The managed reload integration test observed only complete old/new successful responses and preserved an old streamed response. It is correctness evidence, not a throughput or zero-loss capacity benchmark.

## 15. Known limitations

- Physical power-cut/controller fault injection on the exact production ext4 stack remains unexecuted.
- XFS, NFS, SMB, overlay state storage, distributed filesystems, and concurrent writers are unsupported.
- Listener binds/protocols, resource limits, state directory, and TLS handshake concurrency remain restart-only.
- Activation waits for all changed endpoints to drain concurrently up to each configured deadline; very long configured deadlines delay the mutation response but not new-snapshot traffic.
- The local benchmark uses a minimal route-only configuration; maximum-schema and sustained-traffic reload benchmarks remain.
- Authenticated mutation, audit records, metrics, and reload status API are deferred to their approved phases.

## 16. Residual risks

- Filesystem semantics vary by kernel, mount options, virtualized storage, caches, and controllers; deployment qualification is mandatory.
- A process crash after metadata deletion but before old revision-file deletion can leave an unreferenced immutable file; it cannot become active but cleanup tooling should be added before long-lived production use.
- Hyper/Rustls behavior across additional clients and long-lived HTTP/2/gRPC streams needs independent interoperability review.
- Dependency advisories/licenses have not been re-evaluated by `cargo-audit`/`cargo-deny` in this environment.
- The transitive future-incompatibility and Windows GNU linker warnings remain.

## 17. Acceptance-criteria checklist

- [x] Failed candidate leaves the active revision/hash and runtime unchanged.
- [x] Startup after injected intent/probation/commit states selects prior or fully committed state, never partial state.
- [x] Every request uses one prepared snapshot-derived state set; no error rematch exists.
- [x] In-flight long response completes under old endpoint state while new traffic uses the candidate.
- [x] Unchanged complete upstream group policy reuses pool/client/DNS state.
- [x] Removed/changed endpoints receive no new work and close idle clients.
- [x] Active HTTP/TCP work drains only to the configured deadline, then receives cancellation.
- [x] Automatic structural-probation failure restores in-memory and durable prior state.
- [x] Retention is bounded and protects active/immediate-previous/journal revisions.
- [x] Local activation budget passed and correctness traffic observed no activation-attributable response loss.

## 18. Exit-criteria checklist

- [x] Immutable revisions, journal, pointer, activation coordinator, snapshot swap, polling, SIGHUP, rollback, and LKG are implemented.
- [x] Supported storage contract is documented; logical crash/reopen campaign passed on local ext4.
- [x] Invalid startup and reload behavior is explicit with no silent fallback.
- [x] Full workspace formatting, check, strict Clippy, tests, Linux SIGHUP, ext4 recovery, and release benchmark evidence are recorded.
- [x] Authenticated mutation was deferred rather than exposed unsafely.
- [ ] Independent security/protocol review and physical deployment-storage fault test; required before production release, not before Phase 6 implementation.

Phase 5 is complete. Production readiness is not claimed.

## 19. Commit list

- `2e56f96` — persist immutable revisions.
- `1d860ed` — journal atomic activation.
- `8bcd120` — prepare immutable snapshots.
- `bdebc4c` — pin snapshot-derived request state.
- `6f29917` — coordinate atomic activation.
- `f333594` — reload managed configuration files.
- `5f439a4` — add explicit LKG recovery.
- `08e9f21` — poll configuration content hashes.
- `5921b45` — cover activation crash points.
- `daaf68c` — require explicit LKG state.
- `3eafca5` — list offline revisions.
- `e2c09d7` — assert lossless reload.
- `4b9aa06` — align configuration mutation phase boundaries.
- `e646445` — reload on SIGHUP.
- `a49035d` — document reload recovery.
- `26bbc9f` — refresh implementation readiness.
- `b68104e` — preserve streams across reload.
- `7c681f7` — reuse unchanged upstream state.
- `198c317` — retain bounded revision history.
- `119b2de` — add and run atomic reload benchmark.
- `93d9788` — exercise Unix SIGHUP reload.
- `bb5fe71` — enforce endpoint drain deadlines and release retired resources.
- `e5a83b3` — reject missing activation secrets.
- `1aa5b59` — record ext4 recovery evidence.
- `ec772b4` — enforce the TCP reload drain deadline.

## 20. Readiness for the next phase

Phase 6 may begin with one durable single-writer revision model, atomic runtime publication, explicit rollback/LKG semantics, live reload triggers, and proven certificate-preparation failure isolation. ACME work must preserve the currently serving certificate on every issuance, storage, validation, or reload failure; use explicit directory classification; retain encrypted account/certificate generations; and run only against local Pebble in tests. The project is not production-ready.
