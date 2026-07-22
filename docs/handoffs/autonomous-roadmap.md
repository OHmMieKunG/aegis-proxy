# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `b813116`
- Current phase: Phase 15, in progress
- Completed unit: bounded durable typed Proxy Host desired-state store
- Implementation commit: `5c8898b`
- Documentation commit: `b813116`
- Working tree before this handoff: clean

## Validation status

Format, workspace check, Clippy with denied warnings, 291 workspace tests, doc tests, Rustdoc,
feature tree, fuzz-manifest check, changed documentation links, configuration corpus, and OpenAPI
YAML parsing passed. Two intentional ignored tests remain: manual reload benchmark and Docker-backed
Pebble integration. Admin OpenAPI intentionally changed for typed endpoints and token owner metadata.

## Remaining Phase 15 work

Integrate typed persistence through audited owner-scoped API/CLI; typed candidate, activation, and
rollback endpoints; access-policy/certificate and remaining domain objects; remaining contracts;
migration/compatibility policy; full authorization/security review.

## Exact next task

Wire `ProxyHostStore` into server initialization and owner-scoped list/get/create. Create must
authorize before deserialization, compile and semantically validate, durably record audit intent,
require exact active revision, create canonical configuration revision, then persist typed desired
state without activation. Add strict OpenAPI/CLI and failure-order tests.

## Known risks

- Store exists but no endpoint opens it; high-level mutation/update semantics remain absent.
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
