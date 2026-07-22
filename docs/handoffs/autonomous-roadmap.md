# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `cc25c84`
- Current phase: Phase 15, in progress
- Completed unit: audited owner-scoped Proxy Host update/delete with immutable non-active candidate
- Implementation commit: `7e8b47d`
- Documentation commit: `cc25c84`
- Working tree before this handoff: clean

## Validation status

Format, all-target/all-feature workspace check, Clippy with denied warnings, 294 workspace tests,
doc tests, Rustdoc, feature tree, fuzz-manifest check, configuration corpus, CLI integration,
OpenAPI YAML parsing/route check, changed documentation links, added-line secret review, and
`git diff --check` passed. Two intentional ignored tests remain: manual reload benchmark and
Docker-backed Pebble integration.

## Remaining Phase 15 work

Typed activation/rollback with current desired-state verification; access-policy/certificate
ownership; remaining domain objects and contracts; migration/compatibility tests; transport module
split; full authorization/security review.

## Exact next task

Implement typed Proxy Host candidate activation. Require exact activation scope and active revision,
load immutable candidate, snapshot and recompile complete current desired state against active
manual configuration, verify candidate hash/config equality, then invoke existing atomic activation
coordinator and audit outcome. Reject stale/orphan candidates without runtime change. Define typed
rollback semantics without creating a second activation system.

## Known risks

- Candidate revision and typed object store are separate durable stores. Safe ordering prevents an
  object without candidate, but a late object failure may leave an auditable non-active candidate.
- Typed activation does not yet verify candidate against complete current desired state.
- Access-policy and managed-HTTPS endpoint preparation fails closed until typed ownership metadata
  exists.
- Public error mapping must not leak policy or object existence across owner boundaries.
- Local Unix peer identity maps to stable `uid-<uid>`; user/session identity remains Phase 15/16.
- Transitive `proc-macro-error2 2.0.1` has a pre-existing future-incompatibility warning.
- Product remains production NO-GO pending later phases and independent review.
- Phase 15 growth puts private handler and CLI dispatch modules above approximate size guidance;
  split after contracts stabilize and before Phase 15 exit.

## Unavailable tooling

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, `cargo fuzz`,
`markdownlint`, `lychee`, and Ruby are unavailable in this environment. Python/PyYAML validated
OpenAPI; dated evidence is not substituted for current execution.
