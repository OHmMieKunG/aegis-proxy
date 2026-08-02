# Phase 16 final acceptance

Decision date: 2026-08-02
Decision: **accepted with release conditions**
Production status: **NO-GO**

> Independent-style review and local evidence package. This is not external certification, a
> security-owner signature, or production approval.

## Exit-criteria traceability

| Phase 16 criterion | Evidence | Result | Open finding / release impact |
|---|---|---|---|
| NPMPlus-compatible product direction and controlled seven-field baseline | [direction reset](../product/npmplus-direction-reset.md), [matrix](../product/npmplus-compatibility-matrix.md) | Pass | Multiple domains and locations remain Phase 17, without blocking this baseline |
| Exactly one provider coordinator in typed and file modes | [provider architecture](../architecture/providers.md), lifecycle and signal tests | Pass | Docker/Kubernetes providers remain deferred |
| Typed startup keeps TOML restart-only and resumes Discovery Sources | Real-daemon restart test and [startup lifecycle](../operations/configuration-lifecycle.md) | Pass | None in Phase 16 scope |
| Provider output uses canonical candidate/binding/activation and retains last-known-good | Core lifecycle, revision tests, failure campaign | Pass | None |
| Provider changes have durable redacted audit | HMAC system-actor bridge and real-daemon audit assertions | Pass | Audit storage outage blocks later reconciliation; operational alert remains required |
| Proxy Host create/edit/enable/disable/duplicate/delete | Typed handlers and pinned browser lifecycle | Pass | Multiple-domain and Proxy Location behavior remain separate |
| Save draft and discard are durable and inactive | [ADR-0031](../adr/0031-proxy-host-draft-application-state.md), store/startup/browser tests | Pass | None |
| Draft promotion binds one exact revision | Draft generation, base generation, epoch, active CAS, immutable binding tests | Pass | None |
| Owner, RBAC, and token-scope separation | Role matrix and real Unix HTTP adversarial draft cases | Pass | Custom roles remain later work |
| Desired, candidate, active, audit, and recovery states remain distinguishable | [failure campaign](phase-16-save-apply-failure-campaign.md), application-state API, browser banners | Pass | None |
| Indeterminate desired/candidate/pointer/audit outcomes fail closed | Store/revision/audit failure injection and restart tests | Pass | Operator restart/recovery procedure remains mandatory |
| Activation and rollback retain deterministic last-known-good behavior | Activation coordinator, pointer/rollback tests, exact-active restart | Pass | Rollback-failed state requires operator recovery |
| Browser does not overstate lost activation responses | Deterministic Playwright transport-abort case | Pass | Refresh is required; automatic retry intentionally absent |
| Ordinary workflow hides candidate mechanics | Browser source and Chromium assertion | Pass | Advanced History intentionally exposes technical diagnostics |
| React Router advisory has defensible disposition and enforced gate | [disposition](../security/react-router-advisory-disposition.md), `security:router`, Docker web stage | Pass with condition | Scanner remains high; reassess and upgrade under documented triggers |
| Focused and full workspace/browser validation | Current command record in `STATUS.md` and this review | Pass | Environment-specific release gates remain below |
| Independent-style application-security and usability review | [security review](phase-16-independent-security-review.md), [usability review](phase-16-operator-usability-review.md) | Pass with disclosure | Not external human certification |

## Closed review findings

| Finding | Final disposition |
|---|---|
| P16-SEC-01 provider durable audit | Resolved |
| P16-SEC-02 activation response uncertainty | Resolved |
| P16-UX-01 least-privilege draft visibility | Resolved |
| P16-EVID-01 real HTTP draft authorization | Resolved |
| P16-EVID-02 production Router gate | Resolved |

No Critical or High finding remains. No Medium finding remains that undermines authorization,
durability, restart, activation, recovery, provider isolation, audit, or secret isolation.

## Release conditions

Phase 16 acceptance permits roadmap progression; it does not permit production release. Before a
production candidate:

1. obtain external human application, HTTP, TLS/ACME, container/host, and security-owner signoff;
2. keep `npm audit` nonzero result visible, retain the Router gate in every image/release build,
   reassess by 2026-11-01 and on every invalidation trigger, and upgrade to the first compatible
   patched Router line;
3. run long fuzz and soak campaigns, Pebble interoperability, restore/upgrade/canary drills, and
   production-topology abuse testing;
4. complete reproducible builds, SBOM, signing/provenance, multi-architecture image, and
   vulnerability scanning work assigned to Phase 23; and
5. preserve production **NO-GO** until the unsigned
   [external-review table](../security/external-review-signoff.md) is complete.

## Formal recommendation

**Accept Phase 16 with documented release conditions.** The accepted scope is the controlled GUI,
typed Proxy Host/draft state model, provider lifecycle, recovery/failure semantics, and evidence
package. It does not claim complete NPMPlus parity or production readiness.
