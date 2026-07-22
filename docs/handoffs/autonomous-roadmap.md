# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `f735d0f`
- Current phase: Phase 15, in progress
- Completed unit: deterministic aggregate Proxy Host desired-state compiler
- Implementation commit: `35d7d38`
- Documentation commit: `f735d0f`
- Working tree before this handoff: clean

## Validation status

Format, workspace check, Clippy with denied warnings, 294 workspace tests, doc tests, Rustdoc,
feature tree, fuzz-manifest check, changed documentation links, configuration corpus, and OpenAPI
YAML parsing passed. Two intentional ignored tests remain: manual reload benchmark and Docker-backed
Pebble integration. Admin OpenAPI intentionally changed for typed endpoints and token owner metadata.

## Remaining Phase 15 work

Audited generation-CAS mutations; typed candidate, activation, and rollback endpoints;
access-policy/certificate and remaining domain objects; remaining contracts;
migration/compatibility policy; full authorization/security review.

## Exact next task

Implement audited owner-scoped Proxy Host create with authorization before deserialization, exact
active-revision `If-Match`, aggregate compilation over a read-only complete store snapshot, semantic
validation, durable audit intent, canonical revision creation, then desired-state persistence. It
must not activate; failure ordering must avoid a durable object without its revision and must record
outcome without leaking object/policy existence.

## Known risks

- Store is open for owner-scoped list/get; high-level mutation/update semantics remain absent.
- Cross-store transaction ordering between audit, immutable revision, and typed desired state needs
  explicit fail-closed compensation before mutation is exposed.
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
