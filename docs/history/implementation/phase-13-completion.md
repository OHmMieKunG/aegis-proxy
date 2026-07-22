# Phase 13: Security hardening, fuzzing, external review, and deferred transports

> Historical document — records phase evidence at completion time. See [`STATUS.md`](../../../STATUS.md) for current verification.

Status: **local implementation complete; external acceptance and exit gates blocked**

## 1. Phase title

Security hardening, fuzzing, independent-review preparation, and explicit HTTP/3/QUIC and UDP
decisions.

## 2. Original objectives

- Close named threat/control/test traceability.
- Extend fuzz and soak evidence around security-sensitive parsers and resource boundaries.
- Review unsafe/dependency/license exposure and harden Linux packaging.
- Prepare and obtain independent HTTP/TLS/application/container security review.
- Record evidence-based HTTP/3/QUIC and bounded UDP go/no-go outcomes without enabling either.

## 3. Implemented scope

- Added a complete threat-to-control verification matrix for every PLAN threat, with local,
  deferred, external-gate, evidence and residual-risk status.
- Added an independent penetration-test scope, severity/remediation contract, two-person retest
  rule, external signoff sheet, private vulnerability reporting process, and immutable candidate
  evidence bundle.
- Added eight bounded, safe fuzz entry points and one reviewed seed for each. Ran two 500-case ASan
  smoke campaigns per target during implementation; no crash artifact remains.
- Verified the real locked dependency MSRV, corrected it from Rust 1.85 to 1.88 through ADR-0028,
  and tested the full workspace with Rust 1.88.
- Removed direct unmaintained `rustls-pemfile`, preserved strict PEM section behavior through
  Rustls' underlying parser, and added a focused mixed-section regression test.
- Made first-party path dependencies exact, established Cargo Deny policy, reviewed the root-data
  license, documented native/transitive unsafe exposure, and added a dated advisory exception.
- Added optional default-deny seccomp, AppArmor, and Compose hardening examples with target-host
  validation requirements.
- Added security incident response, a local compromise/backup/rollback tabletop, and an executable
  24-hour soak evidence plan.
- Reviewed current Quinn/H3 primary-source status and recorded H3 as absent/no-go for v1. Rejected
  generic UDP and documented the minimum requirements for a later named-protocol proposal.

## 4. Deferred scope

- HTTP/3/QUIC and UDP implementation remain absent. No dependency, configuration, listener,
  firewall exposure, Alt-Svc advertisement, feature flag, or runtime state was added.
- Long fuzz, representative 24-hour soak, Docker/container runtime scan, Pebble ACME campaign,
  live AppArmor enforcement, independent penetration test, reviewer retests, and security-owner
  signoff remain external release gates.
- SBOM, provenance, artifact signatures, multi-architecture image validation, canary and release
  promotion belong to Phase 14 and were not started.

## 5. Architecture decisions

- ADR-0028 raises and verifies the MSRV at Rust 1.88 because the locked Hickory, ICU, rcgen and time
  graph cannot compile on 1.85. Broad dependency downgrade and loss of TTL-aware Hickory behavior
  were rejected.
- ADR-0021 records H3/QUIC no-go for the initial release after Quinn/H3 compatibility and maturity
  review. H3 must remain separately disableable and pass interop/resource/security gates later.
- ADR-0022 permanently rejects generic UDP forwarding. Only a named protocol with bounded,
  protocol-specific session and anti-abuse semantics may be reconsidered.
- No unsafe Rust was introduced; no dedicated unsafe ADR was needed.

## 6. Files created

- Fuzz package: `fuzz/Cargo.toml`, lockfile, README, ignore rules, eight targets, and eight seed files.
- Safe fuzz hooks: `crates/proxy-core/src/fuzzing.rs` and
  `crates/proxy-tls/src/fuzzing.rs`.
- ADR: `docs/adr/0028-raise-msrv-to-rust-1-88.md`.
- Security evidence: dependency/unsafe review, threat matrix, pentest scope/status, external signoff,
  release-candidate evidence, and tabletop under `docs/security/`.
- Research: `docs/research/http3-quic-spike.md` and
  `docs/research/udp-session-decision.md`.
- Operations/testing: `docs/operations/incident-response.md` and
  `docs/testing/phase-13-soak-plan.md`.
- Deployment: seccomp, AppArmor, Compose override, and validation README under `deploy/security/`.
- This report: `docs/phase-13-completion.md`.

## 7. Files modified

- Workspace/dependencies: root and crate Cargo manifests, both lockfiles, `deny.toml`,
  `docs/dependencies.md`, and `PLAN.md`.
- Security/disclosure: `SECURITY.md`.
- Fuzz exposure and strict PEM parser: proxy core/TLS library, generation, store, configuration,
  headers, TCP, and binary main source files.
- Deferred decisions: ADR-0021 and ADR-0022.

The pre-existing untracked nested `aegis-proxy/` directory was not read, modified, staged, or
committed.

## 8. Dependencies added

- `libfuzzer-sys` is fuzz-workspace-only and excluded from the release workspace/binary.
- No release runtime dependency was added.
- Direct `rustls-pemfile` was removed. Existing `rustls-pki-types` provides the strict PEM reader.
- Repo-local cargo-fuzz 0.13.2, cargo-audit 0.22.2, and cargo-deny 0.20.2 were installed under
  ignored `target/tools`; they are not shipped dependencies.

## 9. Configuration introduced

No application TOML schema or runtime feature was introduced. The root workspace `rust-version`
is now 1.88. `deny.toml` permits reviewed CDLA-Permissive-2.0 root data and carries one dated
RUSTSEC-2026-0173 exception. The optional Compose override enables no-new-privileges, seccomp and
AppArmor for the existing proxy service.

## 10. Tests added

- Fuzz targets: configuration parser, route conflict, host canonicalization, path normalization,
  header processing, forwarded headers, bounded ClientHello and certificate metadata.
- Reviewed corpora include strict/duplicate TOML, canonicalization/header chains, truncated
  ClientHello and valid bounded certificate metadata.
- TLS regression rejects mixed recognized PEM sections after parser replacement.
- Existing suites supplied smuggling/framing, auth/RBAC, SSRF/rebinding, DoS/resource-limit,
  malformed/slow TLS, activation/race/rollback, certificate, backup/audit and HA evidence.
- A local single-maintainer compromise tabletop was performed and documented. It does not count as
  an independent or live restore exercise.

## 11. Commands executed

Planning/dependency investigation included:

```text
RUSTUP_TOOLCHAIN=1.85.0 cargo check --workspace --all-targets
RUSTUP_TOOLCHAIN=1.88.0 cargo check --workspace --all-targets
target/tools/bin/cargo-audit audit
target/tools/bin/cargo-deny -L error check
cargo tree -e features
cargo report future-incompatibilities --id 1
```

Final Rust and fuzz gates:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --manifest-path fuzz/Cargo.toml --all-targets
RUSTUP_TOOLCHAIN=nightly target/tools/bin/cargo-fuzz run <each-target> <temporary-corpus> -- -runs=500 -max_len=<bound> -timeout=5
rust-proxy validate --config config/examples/minimal.toml
rust-proxy preview --config config/examples/minimal.toml
```

Packaging/source checks:

```text
python3 -m json.tool deploy/security/seccomp.json
python3 (PyYAML/static Compose and seccomp policy assertions)
apparmor_parser -Q -T -W deploy/security/aegisproxy.apparmor
docker compose -f compose.yaml -f deploy/security/compose-hardening.override.yaml config
rg (first-party unsafe, Git source, and bounded secret patterns)
sha256sum (lockfiles, profiles, and fuzz seeds)
```

## 12. Actual command results

- Format, stable all-target check, all-target/all-feature Clippy with denied warnings: passed.
- Workspace all-feature tests: 267 passed, 0 failed, 2 ignored. The ignored tests are the manual
  release reload benchmark and Docker-backed Pebble integration; neither is claimed passed.
- Rust 1.88 all-target MSRV check: passed. Rust 1.85 check failed with locked dependencies requiring
  Rust 1.86/1.88; ADR-0028 corrected the plan and declared MSRV.
- Fuzz package check: passed. Eight ASan targets × 500 cases: passed, no crash artifact. This is
  smoke only, not the mandatory long campaign.
- Minimal configuration validation/preview: passed without activation; preview remained redacted.
- Cargo Audit scanned 405 dependencies: no vulnerability, one allowed unmaintained warning.
- Cargo Deny advisories/bans/licenses/sources: passed after fixing initial policy failures.
- Feature-tree generation: passed, 2,439 lines.
- First-party unsafe syntax and Git dependency scans: no finding. Secret pattern scan found only one
  intentional private-key marker assertion in a test.
- Seccomp JSON/static assertions, Compose YAML structure, and AppArmor query compile: passed.
- Docker Compose failed because the WSL Docker stub reports Docker unavailable in this distro.
- AppArmor query emitted a missing kernel-interface/cache warning; profile load/runtime was not run.
- 24-hour soak, 24 worker-hour fuzz, independent pentest and owner signoff: not run/unavailable.

## 13. Security checks

- Every named PLAN threat maps to a control, local evidence/deferred absence, status and residual.
- No locally known critical/high finding remains; this is not an independent-review result.
- Local medium findings (MSRV, direct PEM parser, exact dependency/license policy) were fixed and
  regression-gated. The low transitive unmaintained macro has owner, mitigation, residual risk and
  expiry 2026-10-19.
- All owned crate roots forbid unsafe code; source scan found no first-party unsafe construct.
- No Git dependency, public admin listener, Docker socket, arbitrary plugin, shell secret provider,
  H3, UDP proxy, database, web UI, plaintext key, credential, or secret was introduced.
- Optional confinement reduces Linux impact but is not a portable guarantee until exercised on the
  exact release image, kernel, libc and configuration.

## 14. Performance checks

No throughput/latency claim or new benchmark was produced. Fuzz peak RSS was approximately 70–71
MiB in the displayed smoke runs, but that is not a proxy performance measurement. The required
24-hour soak and manual release reload benchmark remain unexecuted release evidence.

## 15. Known limitations

- External reviewers and security owner are unassigned/unsigned.
- Docker/container build/runtime/scan and Pebble cannot run in this WSL distro.
- AppArmor was syntax-queried only, not loaded or enforced.
- Fuzz evidence is 4,000 cases per final smoke across targets, not 24 worker-hours.
- No representative 24-hour soak, live restore drill, independent TLS scanner, protocol
  differential test, host escape-impact test, SBOM, provenance, signing or multi-arch evidence.
- Cargo Geiger, Gitleaks, Syft, Trivy, Grype, CycloneDX/SBOM tooling and Cosign are unavailable.
- Stable Cargo reports a future incompatibility in transitive `proc-macro-error2`; nightly 1.99
  also warns about a future atomic-method rename that cannot be used at the 1.88 MSRV.

## 16. Residual risks

- Independent protocol/application/TLS/container review may find late critical/high defects.
- Parser/security corpus coverage and resource behavior are not established by short fuzz smoke.
- Target container/kernel/libc may need a smaller or different confinement allowlist; weakening to
  unconfined would invalidate evidence.
- Transitive native AWS-LC/FFI and unsafe dependency defects remain possible despite safe owned code.
- Build-time unmaintained macro response may lag until the age/i18n dependency chain removes it.
- Operational restore, LB, certificate, audit, telemetry and saturation behavior may differ on
  representative hosts and during a continuous 24-hour run.

## 17. Acceptance-criteria checklist

- [ ] No unresolved critical/high finding from independent review: review not performed.
- [ ] External medium findings have owner/deadline/compensating control: no external findings exist
  because the engagement has not occurred.
- [x] Every named threat maps to implementation/deferred control, evidence, status and residual.
- [x] Eight fuzz targets document input bounds, sanitizer/toolchain, seed corpus hashes and smoke
  runtime; no known crash artifact exists.
- [ ] Required long fuzz campaign completed: only bounded smoke ran.
- [ ] Required representative 24-hour-plus soak completed: plan exists; run absent.
- [ ] Container/host escape-impact and Pebble campaigns completed: Docker unavailable.
- [x] Local backup/rollback/compromise tabletop documented with explicit gaps.

## 18. Exit-criteria checklist

- [x] Local implementation, documentation and available validation are complete.
- [x] H3/QUIC has explicit initial-release no-go ADR and later gates.
- [x] Generic UDP is explicitly rejected; named-protocol later requirements are documented.
- [x] HTTP/3/UDP remain absent from release code/configuration/dependencies/listeners.
- [ ] Qualified independent reviewers complete/retest the candidate.
- [ ] Security owner signs release recommendation with residual risks.
- [ ] Long fuzz, soak and target-host/container evidence satisfy their gates.

Phase 13 cannot honestly be marked fully accepted or exited. The remaining work requires elapsed
test time, representative external infrastructure, qualified independent people, and explicit
signatures; it cannot be manufactured by repository changes.

## 19. Commit list

- `fec2b52` — `test(security): add bounded fuzz targets`
- `7668f98` — `docs(adr): raise msrv to rust 1.88`
- `f48a91b` — `fix(deps): satisfy security policy gates`
- `8a2864d` — `docs(security): finalize dependency review scope`
- `5ebc5b9` — `chore(rust): satisfy stable clippy`
- `2d07db8` — `docs(security): add external review package`
- `ad29b48` — `security(deploy): add confinement and incident drills`
- `a2f1044` — `docs(adr): defer h3 and udp after review`
- `a3a005d` — `docs(test): define release-candidate soak gate`
- `dff7393` — `docs(security): record release-candidate evidence`

This report is committed separately after the list above.

## 20. Readiness for the next phase

**Not ready for Phase 14 and release remains NO-GO.** Do not begin production release preparation
until independent review/signoff, long fuzz, 24-hour soak, Docker/container/Pebble target-host
evidence, and all resulting remediation gates close. Per user instruction, work stops after this
Phase 13 report and does not start Phase 14.
