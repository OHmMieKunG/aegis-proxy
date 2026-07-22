# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `b7a053b`
- Current phase: Phase 15, in progress
- Completed unit: crash-safe typed Proxy Host forward rollback
- Implementation commits: `69a5fe3`, `b7a053b`
- Documentation commit: this handoff's documentation commit
- Remote target: `origin/work/autonomous-roadmap`
- Expected working tree after documentation commit: clean

## Validation status

Format, all-target/all-feature workspace check, Clippy with denied warnings, 299 workspace tests,
doc tests, Rustdoc, feature tree, fuzz-manifest check, targeted revision/object-store/Admin CLI
tests, repository documentation links, added-line secret review, and `git diff --check` passed. Two
intentional ignored tests remain:
manual reload benchmark and Docker-backed Pebble integration.

## Completed rollback boundary

Admin-only typed rollback loads a retained bound historical object snapshot, compiles it against
current manual configuration, creates a new bound forward revision, journals previous and target
desired state, and activates only through the existing coordinator. Failure restores previous
objects. Indeterminate activation retains the journal; startup reconciles against the durable active
revision before Admin starts. Unresolved recovery blocks all mutation.

## Remaining Phase 15 work

Coordinated snapshot retention; access-policy/certificate ownership;
remaining domain objects and contracts; migration/compatibility tests; transport module split;
full authorization/security review.

## Exact next task

Coordinate typed snapshot retention with configuration revision pruning. Preserve the active,
previous, journal target, and every retained bound revision; remove only snapshots whose revisions
were durably pruned. Add cap, restart, tamper, and rollback-target retention tests.

## Known risks

- Typed snapshot retention is hard-bounded but not coordinated with configuration revision pruning;
  creation fails closed at 1,000 snapshot files.
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
