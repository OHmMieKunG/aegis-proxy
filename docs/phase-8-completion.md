# Phase 8 completion: administrative API and CLI

Date: 2026-07-18

## 1. Phase title

Phase 8: Administrative API and CLI.

## 2. Original objectives

Complete the private local REST API and CLI, fixed RBAC, API-token lifecycle,
durable mutation audit, configuration compare-and-swap workflows, encrypted
backup validation, and safe automation on top of the Phase 5 revision model.

## 3. Implemented scope

- Axum HTTP/1 API on a Unix socket only. The parent directory is mode `0700`,
  the socket is mode `0660`, stale-socket replacement is guarded, and cleanup
  verifies the original inode and device.
- Mandatory Unix peer credentials with an optional UID allowlist. A bearer
  token is additional authentication and cannot bypass peer authorization.
- Fixed deny-by-default roles for viewer, operator, certificate manager, token
  manager, backup operator, and administrator actions.
- Hash-only API tokens with 256-bit random secrets, one-time plaintext display,
  bounded Argon2id verification, expiry, revocation, and private atomic storage.
- Bounded bodies, request deadlines, global in-flight limits, authentication
  work limits, and bounded per-principal token buckets.
- Health, active configuration, revision, route, upstream, certificate, audit,
  and token status resources. Responses expose stable IDs and public metadata,
  not configuration secret references or private material.
- Candidate validation, preview, creation, activation, and forward rollback.
  Every mutation requires an exact strong `If-Match` value and a durable audit
  intent before state change.
- Append-only HMAC-SHA256 chained audit records with bounded record/file counts,
  strict reopening validation, fsync, and fail-closed mutation behavior after a
  persistence failure.
- Encrypted age-X25519 backup creation and in-memory restore validation using a
  strict, checksummed, bounded manifest. Symlinks, special files, traversal,
  duplicate paths, tampering, and replacement of an existing archive fail.
- Certificate renewal requests, backup creation, restore validation, and token
  management through the same authorization, CAS, and audit boundary.
- A bounded Hyper Unix-socket CLI client with stable operational exit codes.
- Checked OpenAPI 3 contract plus administration and backup/recovery runbooks.
- Admin task failure is isolated from the data-plane serving task.

## 4. Deferred scope

- The optional private TCP/mTLS administrative listener. V1 exposes no TCP
  admin listener at all, so remote plaintext and public binding are impossible
  to configure. Adding remote administration requires an ADR and mTLS design.
- Automated archive extraction or in-place restore. Restore validation is safe;
  operators perform an explicit staged recovery. No unverified RTO is claimed.
- Live per-endpoint health/circuit counters in the upstream response. The API
  currently reports validated configured endpoints and stable group IDs.
- Browser sessions, web UI, multi-tenant roles, and gRPC administration.
- Independent API/RBAC and clean-host recovery review; these remain release
  gates, not implementation claims.

## 5. Architecture decisions

- ADR-0011 through ADR-0014 remain authoritative: Unix-only local default,
  peer credentials plus optional tokens, fixed RBAC, and chained durable audit.
- The existing Hyper/Tokio/Rustls one-process architecture is unchanged.
- Mutation audit uses intent-before-effect and result-after-effect records.
- Rollback creates a new forward revision rather than moving history backward.
- The API consumes narrow managed-control handles; the core does not depend on
  Axum or API storage formats.
- No new material architecture decision or PLAN correction was required.

## 6. Files created

- `config/schema/admin-openapi.yaml`
- `crates/proxy-admin/src/{audit,auth,backup,rbac,server}.rs`
- `crates/rust-proxy/src/admin_client.rs`
- `crates/rust-proxy/tests/admin_cli.rs`
- `docs/operations/{admin,backup}.md`
- `docs/phase-8-completion.md`

## 7. Files modified

- `Cargo.lock`
- `config/schema-v1.json`
- `crates/proxy-admin/{Cargo.toml,src/lib.rs}`
- `crates/proxy-config/src/{lib,redact,revision}.rs`
- `crates/proxy-core/src/{lib,runtime}.rs`
- `crates/rust-proxy/{Cargo.toml,src/main.rs}`
- `crates/rust-proxy/tests/config_cli.rs`
- `docs/{dependencies,implementation-readiness-review}.md`

## 8. Dependencies added

- `axum 0.8.9`: typed private HTTP routing and bounded JSON/query extraction;
  defaults disabled, features `http1,json,query,tokio` only.
- Existing approved `argon2`, `base64`, `getrandom`, `hmac`, `sha2`, `zeroize`,
  `age`, Hyper, Tokio, and Serde dependencies were reused at new crate
  boundaries. No Git dependency was added.

Purpose, features, license, native/unsafe exposure, alternatives, and upgrade
policy are recorded in `docs/dependencies.md`.

## 9. Configuration introduced

`admin` supports an absolute Unix socket, optional allowed UIDs, audit-key secret
reference, body and in-flight bounds, authentication-work bounds, request
deadline, and per-principal rate/burst limits. Defaults remain private and
bounded. Unknown fields are rejected recursively; an explicit regression test
proves that `admin.tcp_bind = "0.0.0.0:9090"` is rejected.

## 10. Tests added

- Complete fixed role/action matrix and deny-default behavior.
- Token randomness, hash-only persistence, redaction, expiry, revocation,
  unknown-token work, and bounded Argon2 behavior.
- Audit append/reopen, injection rejection, tamper detection, and persistence
  failure behavior.
- Backup encryption, manifest validation, tamper, traversal, symlink, size, and
  no-replacement behavior.
- Unix-socket modes/lifecycle, peer authentication, malformed authorization,
  request preconditions, pagination, error envelopes, OpenAPI route coverage,
  and bounded rate limiting.
- Forward-revision rollback and exact CAS activation behavior.
- Black-box CLI/API flow covering concurrent same-CAS activation, token role
  denial, audit records, revocation, and plaintext-token absence.
- Strict remote-listener configuration rejection.

## 11. Commands executed

Final gate on Ubuntu 26.04 WSL2, custom kernel 7.1.3, Rust/Cargo 1.97.1:

- `RUSTUP_TOOLCHAIN=stable cargo fmt --all -- --check` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo check --workspace --all-targets` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --all-targets --all-features -- -D warnings` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo test --workspace --all-features` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo tree -e features --workspace` — exit 0;
  2,183 output lines.
- Python/PyYAML parse and route assertion for `admin-openapi.yaml` — exit 0;
  20 paths parsed.
- `RUSTUP_TOOLCHAIN=stable cargo audit` — exit 101: command unavailable.
- `RUSTUP_TOOLCHAIN=stable cargo deny check` — exit 101: command unavailable.
- `command -v gitleaks` — exit 1: command unavailable.

Targeted unit, integration, CLI, manual Unix-socket, and strict Clippy checks
were also run after their associated changes.

## 12. Actual command results

The final workspace suite passed 240 tests and ignored 2:

- `aegisproxy-admin`: 15 passed.
- `aegisproxy-config`: 55 passed.
- `aegisproxy-core`: 115 passed, 1 ignored manual release reload benchmark.
- gRPC integration: 1 passed.
- `aegisproxy-secrets`: 6 passed.
- `aegisproxy-tls`: 40 passed.
- Pebble integration: 1 ignored because its Compose fixture is absent.
- Admin CLI integration: 1 passed.
- Certificate CLI integration: 2 passed.
- Configuration CLI integration: 5 passed.
- All documentation test suites passed with zero failures.

Cargo retains the existing future-incompatibility warning for transitive
`proc-macro-error2 v2.0.1`. No compiler or Clippy warning from project code was
accepted.

## 13. Security checks

- Strict Clippy with warnings denied passed.
- Workspace crates retain `#![forbid(unsafe_code)]`; Phase 8 adds no project
  unsafe block.
- API mutation tests cover authentication, authorization, exact CAS, durable
  audit intent, stable redaction, and bounded request resources.
- Token canaries are absent from persisted token and audit files.
- OpenAPI has no public bind or private-key field and covers every API route.
- Backup tests reject tampering, traversal, symlinks, special files, duplicate
  paths, oversized inputs, wrong identities, and destination replacement.
- `cargo-audit`, `cargo-deny`, and `gitleaks` are unavailable; advisory, license,
  and dedicated secret-scan gates therefore did not pass locally.
- No independent application-security/RBAC review has occurred.

## 14. Performance checks

No throughput, latency, RTO, or production-capacity claim is made. Resource
tests prove immediate bounded rejection, bounded key stores, bounded Argon2
concurrency, and response-size caps. The final workspace test command completed
in about 37 seconds including compilation and execution. A reproducible API
load benchmark and measured clean-host recovery drill remain required.

## 15. Known limitations

- Administration is local Unix-socket only; remote automation needs an operator
  transport such as SSH forwarding until an approved private mTLS listener
  exists.
- Restore validates an archive but deliberately does not extract or replace
  state. The staged manual recovery procedure has no measured RTO.
- Upstream status does not yet expose live endpoint health/circuit transitions.
- Audit-key rotation and off-host audit shipping require an operator runbook and
  Phase 9 SIEM integration.
- OpenAPI is checked from source but is not served by the daemon.
- Pebble, dependency advisory/license, and dedicated secret scanners were not
  available in this local gate.

## 16. Residual risks

- **High until independent review:** administrative authorization/action mapping,
  recovery paths, and audit fail-closed behavior need external review.
- **Medium:** local UID identity semantics depend on deployment namespace and
  socket ownership configuration.
- **Medium:** audit disk exhaustion intentionally disables mutations; alerting
  and off-host retention arrive in Phase 9.
- **Medium:** staged manual restore can extend outage time or invite operator
  error; no automated extractor is accepted without a separate safe design.
- **Medium:** absent advisory/license/secret tools leave supply-chain evidence
  incomplete.
- **Low/medium:** transitive `proc-macro-error2` may fail a future compiler.

## 17. Acceptance-criteria checklist

- [x] Every implemented mutation has authorization, durable audit, and exact
  concurrency/precondition tests.
- [x] API-token one-time display, hashing, expiry, revocation, and role denial
  are tested.
- [x] Remote plaintext/public bind is absent from the schema and explicitly
  rejected; unauthenticated remote access therefore has no listening surface.
- [x] Backup tamper, traversal, symlink, bounds, encryption, and validation are
  tested.
- [x] The clean-host restore/RTO gap is explicitly recorded instead of claimed.
- [x] CLI operational exit codes are documented and black-box tested.
- [x] Formatting, compilation, strict Clippy, and workspace tests pass.
- [ ] Dependency advisory/license and dedicated secret scans pass locally;
  required tools are unavailable.
- [ ] Independent admin API/RBAC and recovery review; required before release.

## 18. Exit-criteria checklist

- [x] Mandatory local API/CLI, token, RBAC, audit, CAS, backup, and restore
  validation functionality is implemented.
- [x] Private-by-default is stronger than required: no TCP admin surface exists.
- [x] Deferred browser/UI and remote mTLS scope remains deferred.
- [x] No unresolved compiler, Clippy, unit, integration, or doc-test failure.
- [x] Phase 9 has not been implemented early.
- [ ] Independent API/RBAC review; this external release gate remains open.

## 19. Commit list

1. `b32f482` `feat(admin): enforce fixed RBAC matrix`
2. `051380b` `feat(admin): add hash-only API tokens`
3. `da10373` `feat(audit): persist authenticated admin records`
4. `dd7d11b` `feat(admin): persist API token metadata`
5. `fa46dff` `feat(config): define bounded admin policy`
6. `d31803b` `feat(backup): validate encrypted state archives`
7. `a46f444` `feat(runtime): expose managed control handles`
8. `4793e07` `fix(test): secure managed identity fixture`
9. `d3f8054` `feat(admin): serve private Unix API`
10. `7a1f6ee` `security(admin): bound principal rate limits`
11. `ee92ba8` `feat(config): create forward rollback revisions`
12. `ccf23e0` `feat(admin): expose redacted status resources`
13. `1faa221` `feat(admin): activate audited config revisions`
14. `8869cd9` `feat(admin): manage audited API tokens`
15. `b214802` `fix(backup): never replace existing archives`
16. `8bee526` `feat(admin): audit certificate and recovery actions`
17. `ff37e64` `fix(admin): standardize redacted error envelopes`
18. `1ff9fcb` `docs(api): publish checked private OpenAPI`
19. `f038d95` `feat(cli): manage private administration workflows`
20. `c35e3f8` `test(admin): verify CAS RBAC token audit flow`
21. `8fbf25d` `docs(backup): define recovery validation flow`
22. `2369a54` `feat(admin): report certificate expiry status`
23. `8d6c657` `test(admin): reject remote listener config`

The separate phase-report commit is appended after this file is committed.

## 20. Readiness for the next phase

Phase 8 mandatory local implementation and compiler/test gates are complete.
The repository is ready for Phase 9 observability work. Independent admin/RBAC
review, measured recovery, and unavailable supply-chain tools remain release
gates; they do not block local Phase 9 implementation.
