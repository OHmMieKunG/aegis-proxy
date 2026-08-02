# Phase 16 operator-usability review

Review date: 2026-08-02
Disposition: **accepted with release conditions**

> Independent-style review of the implemented operator workflow. It is not an external human
> usability certification.

## Personas and environment

- **Administrator:** owns full Proxy Host lifecycle, activation, rollback, audit, and recovery.
- **Operator:** may create and edit inactive drafts without receiving activation or destructive
  authority.
- **Viewer:** reads permitted operational state without mutation controls.

Source and route inspection was combined with typecheck, production build, accessibility assertions,
and Chromium execution in the digest-pinned Playwright 1.62.0 Noble image documented in
[testing](../development/testing.md). The browser suite uses deterministic API boundary fixtures;
authorization itself is separately exercised through the real Unix HTTP daemon integration.

## Workflow results

| Workflow | Result | Evidence |
|---|---|---|
| Create, edit, enable, disable, duplicate, delete | Pass | [browser lifecycle](../../ui/tests/ui.spec.ts), [typed handlers](../../crates/proxy-admin/src/server/handlers/proxy_hosts.rs) |
| Save draft, reopen, edit, discard | Pass | [draft browser scenario](../../ui/tests/ui.spec.ts), [ADR-0031](../adr/0031-proxy-host-draft-application-state.md) |
| Promote draft with exact CAS | Pass | Browser lifecycle plus real HTTP stale-promotion denial |
| Stale browser state | Pass | Clear `Conflict detected`; no automatic retry or overwrite |
| Structured activation failure | Pass | `Activation failed`; explicitly retains previous routing |
| Lost activation response | Pass | `Activation status unavailable`; no routing claim; reload required |
| Persistence uncertainty | Pass | `Storage recovery required`; mutations remain blocked |
| Audit unavailable after save/activation | Pass | Saved-versus-active wording remains distinct |
| Destructive confirmation | Pass | Host domain appears in confirmation; cancellation sends no delete |
| Least-privilege draft editing | Pass | Operator sees New/Edit/Duplicate/Edit draft and Save draft without Enable, Disable, Delete, or Save and apply |
| Direct route and narrow viewport | Pass | Existing full browser suite and responsive checks |
| Candidate/revision terminology | Pass for ordinary path | Normal host workflow does not expose candidate, binding, or CAS mechanics; History remains explicitly advanced |

## Findings

### P16-UX-01 — Draft actions hidden without activation permission

- Severity: Moderate usability / Low security
- Impact: least-privileged Operators could use direct draft routes but could not discover them from
  the host list, encouraging unnecessary privilege requests.
- Remediation: list permissions now separate `canCreateDraft`, `canUpdateDraft`, `canApply`,
  `canToggle`, and destructive authorization. Draft links follow object mutation permission;
  runtime-changing actions additionally require activation permission.
- Disposition: **resolved** with pinned Playwright coverage.

### P16-UX-02 — Activation transport failure made a false runtime statement

- Severity: Major usability / Medium security correctness
- Impact: an operator could believe old traffic remained active after an activation actually
  committed but its response was lost.
- Remediation: unknown transport outcomes receive a dedicated status, make no active-state claim,
  disable further mutations on the current page, and provide a reload action.
- Disposition: **resolved** with deterministic response-abort coverage.

## Operator language

The normal workflow distinguishes `Draft not applied`, `Changes active`, `Saved but not active`,
`Save status unavailable`, `Activation status unavailable`, `Storage recovery required`,
`Rollback failed`, and `Changes active; audit unavailable`. It does not require knowledge of
candidate IDs, binding hashes, activation CAS, compiler snapshots, or persistence rename boundaries.

## Limitations

The review did not include moderated sessions with independent NPMPlus operators, screen-reader
users, or translated copy. Those are representative-operator and release-stage activities. The
current English workflow and automated accessibility evidence are sufficient for Phase 16, not for
production usability certification.

## Conclusion

The Phase 16 Proxy Host and draft workflows are understandable, least-privilege actions are
discoverable, destructive actions are explicit, and uncertain outcomes no longer overstate runtime
state. The operator baseline is **accepted with release conditions**.
