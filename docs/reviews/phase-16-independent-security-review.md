# Phase 16 independent-style application-security review

Review date: 2026-08-02
Branch reviewed: `feat/phase-16-gui-mvp`
Disposition: **accepted with release conditions**

> Independent-style source and runtime review performed as a fresh review pass without accepting
> earlier implementation conclusions as evidence. This is not external human certification, and
> it does not replace the unsigned reviews in
> [external-review signoff](../security/external-review-signoff.md).

## Scope and methodology

The review traced Proxy Host applied and draft operations from the React actions through the private
Unix HTTP API, role-and-token-scope authorization, owner checks, object/draft/active CAS, durable
stores, canonical compilation, immutable binding, activation, rollback, audit, and restart recovery.
It separately traced provider lifecycle ownership, typed/file startup boundaries, provider output,
candidate publication, activation, shutdown, and durable audit. Source inspection was checked
against focused Rust tests, a real daemon HTTP integration, production UI builds, the pinned
Playwright Chromium image, and the React Router module-graph gate.

Reviewed threat areas included IDOR and owner confusion, scope escalation, stale promotion,
indeterminate persistence, uncertain activation responses, draft inclusion, provider bypass,
secret disclosure, HMAC audit continuity, SSR/RSC reachability, destructive browser actions, and
restart behavior.

## Findings and remediation

| ID | Severity | Finding | Evidence and reproduction | Remediation and disposition |
|---|---|---|---|---|
| P16-SEC-01 | Medium | Provider activation lacked durable HMAC audit records. | Before remediation, provider lifecycle invoked revision creation/binding/activation without an `AuditLog` call. A typed provider update changed the active revision without a provider terminal record. | The Admin service now registers its single already-open HMAC writer as a bounded Core system-event sink. Reconciliation intent, validation rejection, candidate creation, activation success/failure, rollback, and no-change skip use actor `system_provider:provider-coordinator`. Audit absence/failure prevents later provider candidate activation; an audit failure after completed activation marks audit unavailable without rolling back a successful runtime. Real-daemon restart evidence verifies chain continuity and redaction. **Resolved.** |
| P16-SEC-02 | Medium | A lost activation response was described as a definite failed activation with old routing retained. | Abort the activation response after the desired mutation response. The previous browser path rendered `Activation failed` even though transport loss cannot prove runtime state. | Only stable structured `activation_failed` responses claim last-known-good retention. CAS conflicts and transport or unclassified responses make no routing claim and require refresh; transport loss renders `Activation status unavailable`. Pinned Playwright covers the distinction. **Resolved.** |
| P16-EVID-01 | Low | Draft route authorization lacked adversarial real-HTTP evidence. | Earlier coverage stopped at store tests, source-order assertions, and mocked browser routes. | The real-daemon Unix HTTP integration now tests cross-owner read/update/discard/promotion, provider-owned owner isolation, stale promotion/discard, and role/token-scope intersection. **Resolved.** |
| P16-EVID-02 | Low | The Router reachability gate was not executed by the production image build. | The web Docker stage ran generation, typecheck, and Vite directly. | The Docker web stage now runs `npm run security:router` before typecheck and Vite. A failed gate stops the image build. **Resolved.** |

No Critical or High finding was identified. No unresolved Medium finding remains in Phase 16 scope.

## Security conclusions by boundary

- **Authorization and isolation:** every draft/applied read is owner-scoped; every mutation combines
  built-in role permission with explicit token scope. Cross-owner resources remain hidden or fail
  closed, and provider-owned owner IDs cannot be converted or promoted by another owner.
- **Concurrency:** active revision, applied generation, draft generation, draft base generation,
  and store epoch are checked without automatic retry or silent merge.
- **Draft exclusion:** schema-2 drafts are structurally separate, absent from desired snapshots,
  compilation, candidate binding, startup activation, and provider reconciliation.
- **Durability:** known prepublication failures remain retryable; indeterminate publication gates
  mutation; exact-active startup does not apply newer desired state or drafts.
- **Activation:** preparation precedes publication; exact candidate and binding checks precede
  activation; CAS, pointer durability, rollback, and rollback-failure gates retain or recover the
  last-known-good runtime according to the failure matrix.
- **Audit:** Admin and provider operations share one serialized HMAC chain. Events contain bounded
  IDs and stable error codes, not source payloads, provider paths, credentials, tokens, headers, or
  object contents.
- **Browser:** React text rendering, exact-origin/CSRF session controls, no browser secret storage,
  explicit destructive confirmation, pending-action disablement, and uncertainty wording were
  verified in source and Chromium.

## React Router disposition

The review accepts the
[GHSA-qwww-vcr4-c8h2 non-reachability disposition](../security/react-router-advisory-disposition.md)
temporarily. The installed package remains scanner-affected, but AegisProxy has no SSR, RSC,
server action, React server resolution condition, server entry import, dynamic server import, or
Node production runtime. The repeatable module-graph gate passes and is now part of the production
container build.

Acceptance is invalidated by adding SSR/RSC, a Router server package, React server actions, a
`react-server` build condition, a Node request handler, or a changed bundle graph that fails the
gate. The scanner result must remain visible, the review must be repeated by 2026-11-01 and before a
production candidate, and the first compatible patched line must replace this disposition.
The final production graph contains one 279,160-byte JavaScript chunk with no dynamic imports or
forbidden server symbols. The older size in the dated disposition remains historical evidence, not
the current bundle measurement.

## Limitations and residual risk

This review did not perform an external hostile-network test, production-topology port scan,
third-party penetration test, 24-hour soak, long fuzz run, container vulnerability scan, or human
accessibility study. Provider audit failure after a completed activation cannot create a terminal
record that the failed audit medium cannot durably store; the runtime remains correct, audit
readiness becomes false, and subsequent provider mutation fails closed. These are release-stage
conditions, not Phase 16 design blockers.

## Conclusion

The four review findings are remediated without weakening CAS, owner boundaries, draft exclusion,
recovery gates, canonical compilation, transactional activation, rollback, or secret isolation.
Phase 16 is **accepted with the release conditions** listed in
[final acceptance](phase-16-final-acceptance.md). This conclusion does not make AegisProxy
production-ready.
