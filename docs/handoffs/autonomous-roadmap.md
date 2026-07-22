# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `f380f98`
- Current phase: Phase 15, in progress
- Completed unit: audited owner-scoped Proxy Host create with immutable non-active candidate
- Store snapshot commit: `f204012`
- Endpoint implementation commit: `068f408`
- Documentation commit: `f380f98`
- Working tree before this handoff: clean

## Validation status

Format, all-target/all-feature workspace check, Clippy with denied warnings, 294 workspace tests,
doc tests, Rustdoc, feature tree, fuzz-manifest check, configuration corpus, CLI integration,
OpenAPI YAML parsing/route check, changed documentation links, added-line secret review, and
`git diff --check` passed. Two intentional ignored tests remain: manual reload benchmark and
Docker-backed Pebble integration.

## Remaining Phase 15 work

Audited generation-CAS update/delete; typed activation/rollback with current desired-state
verification; access-policy/certificate ownership; remaining domain objects and contracts;
migration/compatibility tests; full authorization/security review.

## Exact next task

Implement owner-scoped Proxy Host update and delete. Add distinct exact action scopes; require
active-revision `If-Match` plus object-generation precondition; snapshot complete desired state;
compile/validate replacement or removal; persist immutable non-active candidate before epoch-CAS
desired-state mutation; audit every outcome; prove runtime remains unchanged. Reuse create ordering
and extract only duplication that is already real.

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

## Unavailable tooling

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, `cargo fuzz`,
`markdownlint`, `lychee`, and Ruby are unavailable in this environment. Python/PyYAML validated
OpenAPI; dated evidence is not substituted for current execution.
