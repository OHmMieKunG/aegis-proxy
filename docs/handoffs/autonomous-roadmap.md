# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `ceb5207`
- Current phase: Phase 15, in progress
- Completed unit: deterministic bounded typed Proxy Host field-level diff
- Implementation commit: `2617f0e`
- Documentation commit: `ceb5207`
- Working tree before this handoff: clean

## Validation status

Format, workspace check, Clippy with denied warnings, 281 workspace tests, doc tests, Rustdoc,
feature tree, fuzz-manifest check, documentation links, configuration corpus, and manifest/schema/
OpenAPI compatibility passed. Two intentional ignored tests remain: manual reload benchmark and
Docker-backed Pebble integration.

## Remaining Phase 15 work

Complete ownership/RBAC enforcement; API-token scopes; typed validation, mutation, activation, and
rollback endpoints; remaining domain objects; OpenAPI/CLI contracts;
migration/compatibility policy; full authorization/security review.

## Exact next task

Define the deny-by-default API-token scope model and authorization matrix needed before typed Proxy
Host endpoints. Preserve existing role authorization, hash-only token storage, private Unix API,
ownership boundaries, and compatibility with current unscoped token records through an explicit
fail-closed migration policy.

## Known risks

- High-level object persistence and update semantics do not exist yet.
- Compiler, preview, and diff are library-only until RBAC/scopes/endpoints are complete.
- Public error mapping must not leak policy existence across ownership boundaries.
- Transitive `proc-macro-error2 2.0.1` has a pre-existing future-incompatibility warning.
- Product remains production NO-GO pending later phases and independent review.

## Unavailable tooling

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, `cargo fuzz`,
`markdownlint`, and `lychee` are unavailable in this environment. Dated evidence is not substituted
for current execution.
