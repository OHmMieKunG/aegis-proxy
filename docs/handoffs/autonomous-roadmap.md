# Autonomous roadmap handoff

Updated: 2026-07-29

- Current branch: `feat/phase-16-gui-mvp`
- Baseline: merged Phase 15 closeout at `dev@714d6c4`
- Current phase: Phase 16 GUI MVP
- Phase 16 status: implementation candidate complete; external exit gates open

## Completed closeout work

Expanded administration handlers are split by health/configuration, Access Policy, Proxy Host,
runtime, and operational ownership. Candidate snapshot/rollback storage is separate from ordinary
Proxy Host persistence. Compiler, Access Policy, and object-store tests are external modules, and
CLI administration dispatch is separate from process wiring. No production Rust module exceeds
1,200 measured lines.

Regression coverage froze the exact Phase 15 role matrix, OpenAPI scope order, authorization
before typed deserialization, shared-store cross-owner hiding, schema-1 deprecated aliases versus
schema-2 canonical routes, legacy subjectless/unscoped token behavior, candidate tamper detection,
retention, and rollback recovery. The checked OpenAPI, configuration schema, manifests, defaults,
and dependency set are unchanged from `dev@eb107ec`.
Maintainer review found response-timeout cancellation, pre-authorization JSON parsing in
token/backup/restore handlers, and collapsed User mutation error classes. Follow-up review found
that timed-out handlers also needed an explicit shutdown drain and that User store limits needed a
capacity response. Candidate `efcd0c3` fixes all five findings. Candidates `5a32495` and `f1bfd08`
are retired; independent review must use `efcd0c3`.

Administration documentation describes all implemented Phase 15 typed domains, current certificate
route separation, compatibility, and downgrade rules.

## Phase 15 decision

The project owner approved merging and Phase 16 progression on 2026-07-28, waiving the independent
review prerequisite for phase progression only. The completion report records the exception.
Independent application-security review remains required for production release.

## Completed Phase 16 units

- ADR-0030 selects embedded React/Vite packaging with no Node production runtime.
- Default-disabled restart-only loopback web/OIDC configuration validates exact origin, issuer,
  group mappings, and secret-reference redaction.
- Private `GET /v1/web/status` and Admin/Unix-peer-only `POST /v1/web/setup-token` are frozen in
  OpenAPI. Setup tokens are 256-bit, ten-minute, hash-only, restart-ephemeral, owner-bound, audited,
  and displayed once through `rust-proxy web setup-token`.
- Bounded OIDC discovery/JWKS/token exchange, PKCE/state/nonce, rotating server-side sessions, exact
  Host/Origin/fetch/CSRF checks, and listener-authentication separation are implemented.
- Canonical SHA-256 identity bindings, recovery journal, setup redemption, JIT User provisioning,
  role synchronization, disabled-user checks, and per-request session revalidation are durable.
- The optional `web-ui` feature embeds the generated OpenAPI React/Vite client. All Phase 16 task
  routes, seven-field Proxy Host workflow, typed object writes, revisions, audit records, backup
  validation, read-only settings, responsive layouts, and axe/browser checks are present.
- Current working-tree startup reconciliation compiles durable typed desired state over the
  restart-time TOML base, resumes or creates an exact bound revision, and passes focused,
  real-daemon, and rebuilt Compose Proxy Host restart checks.

## Exact next task

Restore the file/DNS provider reconciliation task under typed startup without re-enabling TOML hot
reload or allowing an unbound revision to publish. Add restart tests with a manual configured
provider and a typed Discovery Source alongside typed Proxy Host state. Then run the Phase 16
failure campaign, obtain independent application-security/usability review, resolve every
critical/high finding, and disposition the locked React Router RSC-mode advisory. Do not begin
Phase 17 release claims before those gates close.

## Known risks

- Activation is global and Admin-only until candidate ownership/approval metadata supports safe
  narrower authority.
- Browser sessions remain process-local and disappear on restart.
- Typed startup currently disables the only provider reconciliation loop, leaving file/DNS
  provider groups on static fallback and provider status unable to advance.
- One OIDC issuer, loopback localhost origin, English UI, and four built-in roles are Phase 16
  limits.
- `npm audit` reports two high entries for React Router RSC/server functionality not used by this
  static SPA; independent review must disposition them.
- Transitive `proc-macro-error2 2.0.1` has a pre-existing future-incompatibility warning.
- Product remains production NO-GO pending later phases and independent review.

## Tooling

Final command results and exact unavailable-tool failures are recorded in `STATUS.md`. Historical
audit/deny/fuzz evidence is not substituted for current execution.
