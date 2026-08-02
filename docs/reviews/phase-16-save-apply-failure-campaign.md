# Phase 16 Save-and-apply failure campaign

Date: 2026-08-01
Branch: `feat/phase-16-gui-mvp`
Release decision: **production NO-GO**

## Transaction and state model

The Proxy Host mutation endpoint and activation endpoint are deliberately separate. A normal
browser action hides that split, but uses this order:

1. authorize and durably append audit intent;
2. check the exact active revision, owner, object generation, and store epoch;
3. compile the complete desired typed state;
4. atomically persist the immutable canonical revision and its exact typed binding;
5. persist the desired Proxy Host mutation with epoch CAS;
6. durably append the mutation terminal audit and return the candidate;
7. recompile and verify the exact desired state and candidate binding;
8. prepare the runtime snapshot;
9. durably write activation intent and the active pointer;
10. atomically publish the prepared runtime, mark probation, probe, and durably commit;
11. durably append the activation terminal audit and return success.

This ordering means semantic compilation failure never leaves a newly saved Proxy Host. A failure
after step 5 may leave desired state newer than active state. The browser reports **Changes active**
only after step 11 returns success, except that `audit_failed_after_activation` explicitly reports
that routing is active while terminal audit durability is unavailable.

- **Desired state** is the last durably knowable typed object file.
- **Candidate state** is immutable canonical configuration plus an exact typed-state binding.
- **Active state** is the runtime snapshot selected by the durable pointer and activation journal.
- **Audit state** is the HMAC-chained intent and terminal outcome.
- **Recovery state** gates mutations when desired or activation durability cannot be established.

## Failure-boundary matrix

“Old” means the last-known-good active revision before the attempted operation. “New” means the
intended Proxy Host result. Candidate or revision identifiers never appear in normal browser copy.

| Boundary | Desired state | Candidate state | Active state | Recovery gate | API result | Browser result | Audit result | Retry / restart |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Authorization rejection | Unchanged | None | Old | No | `403 forbidden` | Permission denial | Durable `denied`, `authorization_denied` | Retry only with authorization; no restart |
| Stale active revision | Unchanged | None | Winning revision | No | `409 revision_conflict` | **Conflict detected**; reload | Durable `failed`, `revision_conflict` | Reload; no automatic retry |
| Stale object generation | Unchanged | None | Old | No | `409 object_conflict` | **Conflict detected**; reload | Durable `failed`, `object_conflict` | Reload; no automatic retry |
| Desired persistence fails before rename | Unchanged and known | Complete non-active candidate may remain | Old | No | `503 persistence_failed` | **Save failed**; desired and active unchanged | Durable `failed`, `persistence_failed` | Retry allowed; orphan candidate is never substituted |
| Desired persistence rename visible but directory sync fails | Old or new survival is uncertain; visible memory is new | Complete non-active candidate may remain | Old | Proxy Host recovery gate | `503 recovery_required` | **Storage recovery required**; mutations blocked | Durable `failed`, `recovery_required`, unless audit itself fails | Restart strictly rereads and validates desired storage |
| Canonical semantic compilation rejection | Unchanged | None | Old | No | `400 invalid_request` | **Validation failed** | Durable `failed`, `invalid_typed_candidate` | Correct input and retry |
| Compiler task failure | Unchanged | None | Old | No | `500 compilation_failed` | Save unavailable/failure | Durable `failed`, `compilation_failed` | Diagnose; retry only after service is healthy |
| Candidate publication fails before immutable link | Unchanged | No complete candidate | Old | No | `503 candidate_persistence_failed` | **Save failed**; compiled change not saved | Durable `failed`, `candidate_persistence_failed` | Retry allowed |
| Candidate publication is indeterminate after immutable link | Unchanged | Incomplete revision is not listed/activatable; a visible exact binding is idempotently reloadable | Old | No global gate; immutable identity prevents substitution | `503 candidate_persistence_failed` | **Save failed**; active unchanged | Durable `failed`, `candidate_persistence_failed` | Retry creates or loads only the exact complete immutable candidate |
| Candidate binding mismatch or missing binding | New if mutation already returned; otherwise unchanged | Rejected as non-exact | Old | No | `409 candidate_conflict` | **Conflict detected**; saved but not active | Durable `failed`, `candidate_conflict` | Reload desired state and create a new exact candidate |
| Activation CAS rejection | New | Complete and exact | Winning active revision | No | `409 revision_conflict` | **Conflict detected**; saved but not active | Durable `failed`, `revision_conflict` | Reload; no automatic retry |
| Runtime preparation failure | New | Complete and exact | Old; runtime was never published | No | `503 activation_failed` | **Activation failed**; old routing retained | Durable `failed`, `activation_failed` | Fix dependency/configuration, then use an existing supported activation operation |
| Runtime publication failure before active-pointer publication | Not representable: preparation is the fallible boundary and publication is an infallible `ArcSwap` after a durable pointer | Complete | Old until publication | No | Covered by preparation or pointer error | No false success | Matching earlier boundary | No extra failpoint is justified |
| Active-pointer rename fails | New | Complete and exact | Old; runtime not published | No | `503 activation_failed` | **Activation failed**; old routing retained | Durable `failed`, `activation_failed` | Retry allowed; restart rolls incomplete intent back |
| Active-pointer rename succeeds but directory sync fails | New | Complete and exact | Old; runtime not published | Activation recovery gate | `503 recovery_required` | **Storage recovery required** | Durable `failed`, `recovery_required` | Restart uses intent journal to restore the previous pointer |
| Probation or post-publication commit fails; rollback succeeds | New | Complete and exact | Old restored in memory and durably | No | `503 activation_failed` | **Activation failed**; old routing retained | Durable `failed`, `activation_failed` | Retry after correcting the cause |
| Post-publication journal durability is uncertain; rollback succeeds | New | Complete and exact | Old restored in memory and durably, including from a visibly `Committed` transition | No | `503 activation_failed` | **Activation failed**; old routing retained | Durable `failed`, `activation_failed` | Retry allowed after state inspection |
| Durable rollback fails | New | Complete and exact | Old restored in memory; durable pointer/journal needs recovery | Rollback-failed gate | `503 rollback_failed` | **Rollback failed**; mutations blocked | Durable `failed`, `rollback_failed`, unless audit also fails | Restart is required; startup validates/reconciles durable activation state |
| Terminal mutation audit append fails or is indeterminate | New is persisted | Complete and exact | Old; browser does not call activation | Audit writer gate | `503 audit_failed_after_save` | **Saved but audit unavailable**; old routing retained and actions blocked | Intent is durable; terminal record may be visible but is not claimed durable | Restart validates HMAC chain before audit/mutation becomes ready |
| Terminal activation audit append fails or is indeterminate | New | Complete and exact | New is active and durably committed | Audit writer gate | `503 audit_failed_after_activation` | **Changes active; audit unavailable**; actions blocked | Intent is durable; terminal record may be visible but is not claimed durable | Restart validates HMAC chain and recovers the committed active pointer |
| Failure-path terminal audit append fails | State follows the originating failure | State follows the originating failure | State follows the originating failure | Audit writer gate | `503 audit_failed` | **Audit unavailable**; outcome evidence unavailable | Terminal failure record is not claimed durable | Restart validates HMAC chain; runtime is not rolled back for audit failure |
| Browser/network loses mutation result publication | Server state may be unchanged or new | May be absent or complete | Old because browser did not request activation | Server gate only if its durable subsystem set one | No trustworthy HTTP result | **Save status unavailable**; reload before mutation | Server audit reflects the operation if its append completed | Reload; never auto-activate or auto-retry |
| Process stops after candidate persistence, before desired persistence | Unchanged | Complete orphan candidate may remain | Old | No | Connection lost | Save status unavailable after reconnect | Intent may lack terminal outcome | Startup retains/validates candidates but activates only exact durable active pointer |
| Process stops after desired persistence, before activation | New | Complete and exact | Old | No, unless desired write was indeterminate | Connection lost or save had returned | Saved state can differ from active | Intent/terminal mutation may or may not be complete at kill boundary | Startup resumes exact old active binding; newer desired state is not applied |
| Process stops after active pointer, before terminal activation audit | New | Complete and exact | New if journal committed; old if intent/probation was incomplete | Startup journal recovery | Connection lost | Reload derives status from exact active state | Activation intent may lack terminal success | Startup keeps `Committed`, rolls `Intent`/`Probation` back |
| Delete persisted but activation fails | Object absent | Complete candidate without object | Old still routes deleted host | Only for uncertainty/rollback failure | `503 activation_failed` or stronger typed code | Explicitly says deleted from saved configuration but old routing remains | Durable activation failure where audit is healthy | Restart resumes exact old active binding; it does not apply deletion |
| Disable persisted but activation fails | Object present and disabled | Complete candidate without active route | Old still routes enabled host | Only for uncertainty/rollback failure | `503 activation_failed` or stronger typed code | Explicitly says disabled in saved configuration but old routing remains | Durable activation failure where audit is healthy | Restart resumes exact old active binding; it does not apply disable |

## Deterministic evidence

- Proxy Host store failpoints cover failure before rename and uncertainty after rename, mutation
  blocking, strict reopen, failed reopen, delete uncertainty, generations, and stale CAS.
- Revision-store failpoints cover immutable candidate publication before link and after link,
  active-pointer failure before rename, active-pointer uncertainty after rename, and
  post-publication journal uncertainty followed by durable rollback.
- Candidate-binding failpoints cover known publication failure and post-link durability uncertainty;
  retries can only accept the exact integrity-checked immutable binding.
- Runtime tests cover stale activation CAS, preparation rejection, restart-only rejection,
  probation rollback, and a real durable rollback failure while the old `RuntimeSnapshot` remains
  published and administration becomes gated.
- Audit failpoints run after append/flush but before confirmed sync, gate the writer, and prove that
  reopen validates the visible HMAC-chained record before accepting new events.
- Typed startup tests persist newer desired additions, disable, and deletion after a committed
  active binding. Restart resumes the exact old active routes and does not activate those changes.
- Browser tests cover ordinary lifecycle, activation failure, recovery-required desired storage,
  mutation/activation audit uncertainty, rollback failure, lost mutation-result publication with
  no activation attempt, and absence of internal candidate/CAS terminology.

## Operator rules

- `conflict` and validation failures are known no-publication outcomes; reload or correct input.
- `persistence_failed` and `candidate_persistence_failed` are known runtime-no-change outcomes.
- `activation_failed` retains the last-known-good runtime but may leave desired newer than active.
- `recovery_required`, `rollback_failed`, and every `audit_failed*` result require operator
  attention; do not repeatedly mutate. Restart uses the existing strict file, journal, and HMAC
  validation paths. Preserve the state directory if restart fails closed.
- Missing terminal audit evidence never rolls back a successfully activated runtime. Conversely,
  audit failure is never reported as complete durable administrative evidence.

This campaign closes the systematic save-and-apply failure-evidence item. It does not complete
Phase 16's separate dependency disposition or independent application-security/usability gates.
