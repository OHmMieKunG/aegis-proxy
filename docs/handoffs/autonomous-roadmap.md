# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `9381542`
- Current phase: Phase 15, in progress
- Completed unit: immutable typed Proxy Host candidate desired-state binding
- Implementation commit: `80a7f27`
- Documentation commit: `9381542`
- Remote: `origin/work/autonomous-roadmap` through `9381542`
- Working tree before this handoff: clean

## Validation status

Format, all-target/all-feature workspace check, Clippy with denied warnings, 297 workspace tests,
doc tests, Rustdoc, feature tree, fuzz-manifest check, targeted revision/object-store/Admin CLI
tests, repository documentation links, added-line secret review, and `git diff --check` passed. Two
intentional ignored tests remain:
manual reload benchmark and Docker-backed Pebble integration.

## Completed binding boundary

Typed create/update/delete now persist a strict private immutable owner/object-ordered snapshot and
bind its SHA-256 into revision metadata before desired-state mutation. Typed activation requires
that binding, validates file identity/permissions/schema/hash, and requires exact equality with
complete current desired state. Missing, low-level-unbound, mismatched, or tampered bindings fail
without runtime change.

## Remaining Phase 15 work

Crash-safe typed rollback and coordinated snapshot retention; access-policy/certificate ownership;
remaining domain objects and contracts; migration/compatibility tests; transport module split;
full authorization/security review.

## Exact next task

Implement a crash-recoverable typed rollback transaction. It must load a bound historical snapshot,
create a new bound forward revision, durably journal prior/target desired state, coordinate exact
object-store epoch replacement with the existing activation coordinator, restore prior desired
state on activation failure, and recover an incomplete transaction on restart. Add tamper, stale,
audit-failure, activation-failure, persistence-failure, and restart tests before exposing the route.

## Known risks

- Configuration revision and typed desired-state updates remain two filesystem transactions.
  Typed rollback needs its own recovery journal before safely changing both.
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
