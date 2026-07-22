# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `e2e0055`
- Current phase: Phase 15, in progress
- Completed unit: owner-scoped typed Proxy Host reads and stored conflict claims
- Implementation commit: `d1514dd`
- Documentation commit: `e2e0055`
- Working tree before this handoff: clean

## Validation status

Format, workspace check, Clippy with denied warnings, 291 workspace tests, doc tests, Rustdoc,
feature tree, fuzz-manifest check, changed documentation links, configuration corpus, and OpenAPI
YAML parsing passed. Two intentional ignored tests remain: manual reload benchmark and Docker-backed
Pebble integration. Admin OpenAPI intentionally changed for typed endpoints and token owner metadata.

## Remaining Phase 15 work

Aggregate typed desired-state compilation; audited generation-CAS mutations; typed candidate,
activation, and rollback endpoints; access-policy/certificate and remaining domain objects;
remaining contracts; migration/compatibility policy; full authorization/security review.

## Exact next task

Implement a deterministic aggregate Proxy Host compiler that takes all stored desired state plus one
proposed change and emits one canonical semantically validated candidate. It must preserve every
stored object, reject collisions with manual configuration and other owners, strip only verified
managed resources, and expose no persistence or activation handle. Add tests proving pending objects
cannot disappear before any create mutation endpoint is added.

## Known risks

- Store is open for owner-scoped list/get; high-level mutation/update semantics remain absent.
- Single-object compilation from active state can omit another persisted pending object, so mutation
  remains unsafe until aggregate compilation exists.
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
