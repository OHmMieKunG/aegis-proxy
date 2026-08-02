# Phase 16 Proxy Host draft/application-state evidence

Date: 2026-08-01
Status: accepted by the 2026-08-02 independent-style local review with release conditions

The decision and invariants are in
[ADR-0031](../adr/0031-proxy-host-draft-application-state.md). This record maps product transitions
to the implemented control-plane boundary. “Active unchanged” always means the exact previous
bound runtime remains in service.

| Transition | Authorization and concurrency | Durable result | Compile/candidate/activation | Audit and browser result | Restart and conflict behavior |
|---|---|---|---|---|---|
| Create draft | `create_proxy_host`; owner equality; identity must have no applied base or draft | Draft generation 1, `base_generation = null` | None | `proxy_host_draft_create`; **Draft saved** | Draft reloads inactive; duplicate identity conflicts |
| Create edit draft | `update_proxy_host`; exact applied generation | Draft generation 1 with exact base | None | create audit action; **Draft saved** | Applied change before write conflicts |
| Edit/save draft | `update_proxy_host`; exact draft generation and unchanged base generation | Draft generation increments only | None | `proxy_host_draft_update`; **Draft saved** | Two editors cannot silently overwrite; stale draft conflicts |
| Discard/delete draft | `update_proxy_host`; exact draft generation | Draft removed only | None; desired and active unchanged | `proxy_host_draft_discard`; **Draft discarded** | Stale discard conflicts; reopen preserves known removal |
| Save and apply draft | create or update by base presence; exact active revision, draft generation, base generation, and desired epoch | Exact draft is promoted to desired and removed atomically | Complete desired state is canonically compiled and immutably bound before promotion; the returned exact candidate uses normal activation | promotion save terminal plus activation terminal; **Changes active** only after activation | Any stale precondition rejects; no automatic promotion on restart |
| Save and apply without draft | Existing create/update authorization, active revision, object generation, and desired epoch | Existing desired mutation behavior | Existing canonical candidate and activation path | Existing save/activation events | Existing exact-active restart behavior |
| Apply existing desired | `activate_typed_candidate` plus exact active revision | Desired unchanged | Existing exact candidate binding is reverified and activated | Existing activation event | No automatic retry; stale binding/revision conflicts |
| Activation failure after promotion | Promotion has completed | Promoted desired remains; draft is not recreated | Candidate remains non-active; active unchanged | **Saved but not active** / **Activation failed** | Startup restores exact older active binding; desired remains pending |
| Delete applied object | Existing `delete_proxy_host`, active/object/epoch CAS | Desired object removed; an unrelated draft is not silently removed | Complete desired state compiled and activated normally | Existing delete and activation events | Failed activation can leave active-only route; application-state API reports divergence |
| Restart with draft | None during startup | Draft reloads from schema 2 | Draft excluded from startup snapshot and candidate | No startup mutation audit | Exact active binding resumes; draft remains inactive |
| Restart with newer desired | None during startup | Desired reloads | Exact older active binding resumes when present | No implicit apply | Desired remains pending, never reclassified as draft |
| Restart with recovery required | Startup strictly rereads the atomic file | Valid known file reestablishes state; invalid/unreadable file fails startup | No uncertain state is compiled | Operator sees recovery status or startup failure | Gate clears only after successful validated reopen |

## Persistence and migration evidence

- `ProxyHostStore` schema 2 writes applied and draft namespaces in one fsynced atomic replacement.
- Schema 1 loads every existing record as applied and no draft; the next successful write publishes
  schema 2. Candidate binding schemas and hashes are unchanged.
- Known pre-rename failures restore memory and remain retryable. Parent-sync uncertainty retains the
  visible state, sets `recovery_required`, blocks applied and draft mutation plus mutation snapshots,
  and cannot trigger activation.
- Draft-local generations do not advance the applied desired-state epoch. Promotion advances the
  applied generation and epoch exactly once.
- Rollback changes only applied desired state and preserves drafts; a changed applied base makes an
  older draft stale instead of merging it.

## Provider, startup, and secret boundary

Canonical snapshots, startup compilation, candidate bindings, and provider binding clones contain
only applied objects. No provider API accepts a draft. Proxy Hosts contain no readable credential,
private key, or provider-secret field; owner filtering and existing audit redaction still apply.

## Review targets

Independent reviewers should attack cross-owner draft reads, create-versus-update scope selection,
draft/base races, candidate-before-promotion orphan handling, post-rename uncertainty, exact-active
restart, active-only deleted routes, and audit failure after a known draft write. The browser suite
must demonstrate Save draft, resumed edit, discard, promotion, activation failure, and absence of
candidate terminology in real Chromium.
