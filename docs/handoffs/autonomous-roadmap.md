# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `89de6fc`
- Current phase: Phase 15, in progress
- Completed unit: deny-by-default API-token action scopes
- Implementation commit: `81bd500`
- Documentation commit: `89de6fc`
- Working tree before this handoff: clean

## Validation status

Format, workspace check, Clippy with denied warnings, 284 workspace tests, doc tests, Rustdoc,
feature tree, fuzz-manifest check, documentation links, configuration corpus, and manifest/schema/
OpenAPI validation passed. Two intentional ignored tests remain: manual reload benchmark and
Docker-backed Pebble integration. Admin OpenAPI intentionally changed for scoped tokens.

## Remaining Phase 15 work

Complete typed-object ownership/RBAC enforcement; typed validation, mutation, activation, and
rollback endpoints; remaining domain objects; remaining OpenAPI/CLI contracts;
migration/compatibility policy; full authorization/security review.

## Exact next task

Add owner-aware typed Proxy Host validation and preview endpoints. Authenticate and authorize before
deserialization/compilation; derive owner from the principal rather than trusting request metadata;
reuse compiler, preview, and diff; perform no persistence or activation; add strict OpenAPI/CLI and
cross-owner non-disclosure tests.

## Known risks

- High-level object persistence and update semantics do not exist yet.
- Compiler, preview, and diff are library-only until RBAC/scopes/endpoints are complete.
- Public error mapping must not leak policy existence across ownership boundaries.
- Local Unix peer identity currently maps to UID; typed owner mapping must be explicit and stable.
- Transitive `proc-macro-error2 2.0.1` has a pre-existing future-incompatibility warning.
- Product remains production NO-GO pending later phases and independent review.

## Unavailable tooling

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, `cargo fuzz`,
`markdownlint`, `lychee`, and Ruby are unavailable in this environment. Python/PyYAML validated
OpenAPI; dated evidence is not substituted for current execution.
