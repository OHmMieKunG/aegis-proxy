# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `9961231`
- Current phase: Phase 15, in progress
- Completed unit: owner-aware private Proxy Host validation and preview endpoints
- Implementation commit: `00cfa32`
- Documentation commit: `9961231`
- Working tree before this handoff: clean

## Validation status

Format, workspace check, Clippy with denied warnings, 287 workspace tests, doc tests, Rustdoc,
feature tree, fuzz-manifest check, changed documentation links, configuration corpus, and OpenAPI
YAML parsing passed. Two intentional ignored tests remain: manual reload benchmark and Docker-backed
Pebble integration. Admin OpenAPI intentionally changed for typed endpoints and token owner metadata.

## Remaining Phase 15 work

Add typed object persistence and complete ownership/RBAC metadata; typed mutation, activation, and
rollback endpoints; access-policy/certificate and remaining domain objects; remaining OpenAPI/CLI
contracts; migration/compatibility policy; full authorization/security review.

## Exact next task

Implement a bounded durable typed Proxy Host object store with strict schema/version validation,
owner-indexed reads, atomic file replacement, and no runtime or revision activation. Reuse it as the
state prerequisite for audited CAS mutation and typed update diffs.

## Known risks

- High-level object persistence and update semantics do not exist yet.
- Access-policy and managed-HTTPS endpoint preparation fails closed until typed ownership metadata
  exists.
- Public error mapping must not leak policy or object existence across ownership boundaries.
- Local Unix peer identity maps to stable `uid-<uid>`; user/session identity remains Phase 15/16.
- Transitive `proc-macro-error2 2.0.1` has a pre-existing future-incompatibility warning.
- Product remains production NO-GO pending later phases and independent review.

## Unavailable tooling

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, `cargo fuzz`,
`markdownlint`, `lychee`, and Ruby are unavailable in this environment. Python/PyYAML validated
OpenAPI; dated evidence is not substituted for current execution.
