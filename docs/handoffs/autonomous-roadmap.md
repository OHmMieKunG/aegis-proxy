# Autonomous roadmap handoff

Updated: 2026-07-27

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `926eb68`
- Current phase: Phase 15, in progress
- Completed unit: audited owner-scoped Access Policy create
- Implementation commit: `926eb68`
- Documentation commit: this handoff's documentation commit
- Remote target: `origin/work/autonomous-roadmap`
- Expected working tree after documentation commit: clean

## Validation status

Format, all-target/all-feature workspace check, Clippy with denied warnings, 318 workspace tests,
doc tests, Rustdoc, feature tree, fuzz-manifest check, targeted revision/object-store/Admin CLI
tests, repository documentation links, added-line secret review, and `git diff --check` passed. Two
intentional ignored tests remain:
manual reload benchmark and Docker-backed Pebble integration.

## Completed Access Policy boundary

The strict library object binds a globally unique ID and owner to explicit sharing, enabled state,
and bounded canonical middleware references. Its metadata compiler validates configuration,
permits only existing IP/limit/authentication stages, rejects ambiguous fixed-stage combinations,
canonicalizes order, and exposes no middleware contents or credentials. Proxy Host single and
aggregate compilers enforce sharing and complete route semantics. The bounded private store adds
global IDs, owner reads, canonical records, generation CAS, exclusive ownership, strict restart
validation, and failure-safe atomic replacement. Distinct read/create/update/delete actions
flow through roles, explicit token scopes, CLI issuance, and OpenAPI. Admin owns the store before
socket bind. Owner-scoped list/get now enforce exact read permission, stable order, cross-owner
not-found, and generation ETags. A post-rename durability failure now blocks every later mutation
until restart reloads the visible atomic file; reads remain available. Create authorizes and
records audit intent before parsing, requires exact
active-revision concurrency and owner equality, validates middleware references against active
configuration, persists generation one, returns an ETag, and never creates or activates a
configuration revision.

## Remaining Phase 15 work

Access Policy update/delete and Proxy Host wiring; certificate ownership; remaining domain objects and
contracts; migration/compatibility tests; transport module split; full authorization/security
review.

## Exact next task

Implement audited owner-scoped Access Policy update/delete with exact object-generation and active
revision preconditions, distinct scopes, owner isolation, semantic validation before update,
recovery-safe persistence errors, CLI/OpenAPI parity, and no runtime activation.

## Known risks

- Activation is intentionally global and Admin-only until candidate ownership/approval metadata
  supports safe narrower authority.
- Access-policy update/delete remain absent; managed HTTPS remains blocked on certificate
  ownership.
- Local Unix peer identity maps to stable `uid-<uid>`; user/session identity remains Phase 15/16.
- Transitive `proc-macro-error2 2.0.1` has a pre-existing future-incompatibility warning.
- Product remains production NO-GO pending later phases and independent review.
- Phase 15 transport modules exceed approximate size guidance; split after contracts stabilize and
  before Phase 15 exit.

## Unavailable tooling

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, `cargo fuzz`,
`markdownlint`, and `lychee` are unavailable in this environment. Python/PyYAML validated OpenAPI;
dated evidence is not substituted for current execution.
