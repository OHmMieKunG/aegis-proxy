# Autonomous roadmap handoff

Updated: 2026-07-22

- Current branch: `work/autonomous-roadmap`
- Current completed-unit commit: `bac470b`
- Current phase: Phase 15, in progress
- Completed unit: Admin-only verified typed Proxy Host candidate activation
- Implementation commit: `7c6f613`
- Documentation commit: `bac470b`
- Remote: `origin/work/autonomous-roadmap` through `bac470b`
- Working tree before this handoff: clean

## Validation status

Format, all-target/all-feature workspace check, Clippy with denied warnings, 295 workspace tests,
doc tests, Rustdoc, feature tree, fuzz-manifest check, targeted Proxy Host/RBAC/server/CLI tests,
OpenAPI YAML route/scope validation, CLI help contract, repository documentation links,
added-line secret review, and `git diff --check` passed. Two intentional ignored tests remain:
manual reload benchmark and Docker-backed Pebble integration.

## Completed activation boundary

Typed activation requires Admin role, exact `activate_proxy_host` bearer scope, active-revision
`If-Match`, complete current desired-state recompilation, semantic validation, immutable candidate
content equality, unchanged object-store epoch, and durable audit. Administrative mutations are
serialized while audit is open. Publication uses only the existing activation coordinator. Stale,
orphaned, repeated, and unauthorized candidates fail without runtime change.

## Remaining Phase 15 work

Durable typed desired-state binding and rollback; access-policy/certificate ownership; remaining
domain objects and contracts; migration/compatibility tests; transport module split; full
authorization/security review.

## Exact next task

Bind each typed Proxy Host candidate revision to an immutable, bounded, strict desired-state
snapshot in the existing control-plane persistence boundary. Use that binding to revalidate typed
activation and design forward-only typed rollback that restores both desired objects and canonical
configuration through the existing revision/activation coordinator. Add tamper, stale, ownership,
audit-failure, restart, and rollback-failure tests before exposing rollback.

## Known risks

- Current immutable configuration revisions do not retain their typed object snapshot. Low-level
  rollback can therefore diverge current Proxy Host desired state from runtime configuration.
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
