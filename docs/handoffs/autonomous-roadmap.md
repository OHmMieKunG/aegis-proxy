# Autonomous roadmap handoff

Updated: 2026-07-27

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `788b5a2`
- Current phase: Phase 15, in progress
- Completed unit: coordinated typed Proxy Host snapshot retention
- Implementation commit: `788b5a2`
- Documentation commit: this handoff's documentation commit
- Remote target: `origin/work/autonomous-roadmap`
- Expected working tree after documentation commit: clean

## Validation status

Format, all-target/all-feature workspace check, Clippy with denied warnings, 302 workspace tests,
doc tests, Rustdoc, feature tree, fuzz-manifest check, targeted revision/object-store/Admin CLI
tests, repository documentation links, added-line secret review, and `git diff --check` passed. Two
intentional ignored tests remain:
manual reload benchmark and Docker-backed Pebble integration.

## Completed retention boundary

The configuration revision store is authoritative. Admin startup and each typed candidate/forward
revision binding reconcile the bounded snapshot directory against retained revision metadata.
Every entry is validated before any removal; matching retained snapshots remain and only valid
orphan snapshots are durably removed. Tampered, malformed, symlinked, or mismatched retained state
fails closed. Separate file transactions may leave a harmless non-active orphan until restart or
the next binding.

## Remaining Phase 15 work

Access-policy/certificate ownership; remaining domain objects and contracts;
migration/compatibility tests; transport module split; full authorization/security review.

## Exact next task

Define the typed Access Policy ownership and sharing metadata required to compile protected Proxy
Hosts without exposing policy contents or credentials. Reuse existing policy configuration and
authorization paths; add strict contract, ownership, missing/disabled/incompatible reference, and
secret-redaction tests before exposing mutations.

## Known risks

- Activation is intentionally global and Admin-only until candidate ownership/approval metadata
  supports safe narrower authority.
- Access-policy and managed-HTTPS endpoint preparation fails closed until typed ownership metadata
  exists.
- Local Unix peer identity maps to stable `uid-<uid>`; user/session identity remains Phase 15/16.
- Transitive `proc-macro-error2 2.0.1` has a pre-existing future-incompatibility warning.
- Product remains production NO-GO pending later phases and independent review.
- Phase 15 transport modules exceed approximate size guidance; split after contracts stabilize and
  before Phase 15 exit.

## Unavailable tooling

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, `cargo fuzz`,
`markdownlint`, and `lychee` are unavailable in this environment. Python/PyYAML validated OpenAPI;
dated evidence is not substituted for current execution.
