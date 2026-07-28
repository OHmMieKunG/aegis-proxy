# Autonomous roadmap handoff

Updated: 2026-07-28

- Current branch: `chore/phase-15-closeout`
- Baseline: `dev@eb107ec`
- Current phase: Phase 15 completion
- Phase 16 status: approved to begin after merge
- Expected working tree after closeout commit: clean

## Completed closeout work

Expanded administration handlers are split by health/configuration, Access Policy, Proxy Host,
runtime, and operational ownership. Candidate snapshot/rollback storage is separate from ordinary
Proxy Host persistence. Compiler, Access Policy, and object-store tests are external modules, and
CLI administration dispatch is separate from process wiring. No production Rust module exceeds
1,200 measured lines.

Regression coverage freezes the exact 52-action role matrix, OpenAPI scope order, authorization
before typed deserialization, shared-store cross-owner hiding, schema-1 deprecated aliases versus
schema-2 canonical routes, legacy subjectless/unscoped token behavior, candidate tamper detection,
retention, and rollback recovery. The checked OpenAPI, configuration schema, manifests, defaults,
and dependency set are unchanged from `dev@eb107ec`.
Maintainer review found response-timeout cancellation, pre-authorization JSON parsing in
token/backup/restore handlers, and collapsed User mutation error classes. Follow-up review found
that timed-out handlers also needed an explicit shutdown drain and that User store limits needed a
capacity response. Candidate `efcd0c3` fixes all five findings. Candidates `5a32495` and `f1bfd08`
are retired; independent review must use `efcd0c3`.

Administration documentation now describes all implemented Phase 15 typed domains, current
certificate route separation, compatibility, and downgrade rules. No frontend dependency, TCP
listener, browser route, OIDC state, or session code has entered the branch.

## Phase 15 decision

The project owner approved merging and Phase 16 progression on 2026-07-28, waiving the independent
review prerequisite for phase progression only. The completion report records the exception.
Independent application-security review remains required for production release.

## Exact next task

Merge closeout to `dev`, branch `feat/phase-16-gui-mvp`, and begin the frontend/packaging ADR plus
default-disabled loopback web configuration.

## Known risks

- Activation is global and Admin-only until candidate ownership/approval metadata supports safe
  narrower authority.
- Local Unix peer identity remains `uid-<uid>`; browser identity and ownership binding are Phase 16.
- Transitive `proc-macro-error2 2.0.1` has a pre-existing future-incompatibility warning.
- Product remains production NO-GO pending later phases and independent review.

## Tooling

Final command results and exact unavailable-tool failures are recorded in `STATUS.md`. Historical
audit/deny/fuzz evidence is not substituted for current execution.
