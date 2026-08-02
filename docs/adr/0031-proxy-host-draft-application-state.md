# ADR-0031: Proxy Host draft and application state

Status: Accepted
Date: 2026-08-01

## Context

Proxy Hosts already have durable desired objects, immutable compiled candidates, exact active
bindings, transactional activation, and recovery gates. A desired object can legitimately be newer
than active state after failed activation, but that pending application is not an intentional
draft. Phase 16 needs durable editable drafts that never enter compilation or startup activation.

Four models were evaluated:

- A revision flag couples editable and applied records and makes every compiler caller filter
  correctly.
- A second store duplicates atomic-write, ownership, recovery, backup, and promotion coordination.
- A workspace record adds an indirect revision graph without an existing workspace abstraction.
- Separate applied and draft namespaces in the existing Proxy Host store preserve one durability
  and recovery boundary while keeping compiler snapshots unchanged.

## Decision

Use the fourth model for Proxy Hosts only. Store schema 2 contains ordered `objects` (applied
desired state) and `drafts` (inactive working state) in one private atomic file. Each draft has a
draft-local generation and an optional `base_generation` identifying the exact applied object on
which it was created. Applied generations and the complete desired-state epoch remain independent.

Draft create, update, and discard persist both namespaces atomically but do not advance the desired
epoch, compile configuration, create a candidate, or activate runtime. Promotion checks the draft
generation, its base applied generation, the desired epoch, identity, owner, and domain claims;
then one atomic replacement updates applied state and removes the draft. The resulting exact
desired snapshot is the one already compiled and bound before promotion. Existing activation
remains a separate exact-CAS operation.

The owner-scoped API exposes draft list/create/read/update/discard/promotion and a read-only
application-state comparison. Existing create/update permissions protect initial drafts according
to whether an applied object exists; draft edits and discard require update; promotion requires
create or update plus typed activation for the subsequent activation request. No new broad scope is
introduced.

## State model and invariants

- **Draft:** an intentional editable record in `drafts`; never returned by desired snapshots.
- **Desired:** records in `objects`; the only Proxy Hosts accepted by canonical compilation.
- **Candidate:** immutable compilation bound to one exact complete desired snapshot.
- **Active:** exact bound candidate recorded by the active revision and serving traffic.
- **Pending application:** desired differs from active after promotion or another saved mutation.
- **Recovery required:** an atomic publication outcome is uncertain; all Proxy Host mutation and
  compilation snapshots are blocked until validated reopen.

Startup resumes the exact active bound revision when present. It neither promotes drafts nor
activates newer desired state. Provider reconciliation clones an exact active/desired binding and
has no draft-store API, so it cannot read, change, compile, or activate drafts. Discard touches only
the draft namespace. Activation failure after promotion leaves desired newer than active and does
not recreate the draft.

## Concurrency and failure semantics

Draft and applied generations are separate. Draft update/discard require exact draft generation.
Draft update and promotion also require the current applied generation to equal `base_generation`;
there is no automatic merge. Promotion additionally requires active-revision CAS at the API and
complete desired-epoch CAS at persistence.

A known failure before rename restores in-memory state and permits retry. Uncertainty after rename
keeps the visible state, sets `recovery_required`, prevents candidate creation/activation from that
result, and blocks later draft and applied mutations. Reopen strictly rereads and validates the
durable file before clearing the process-local gate. Candidate or activation failure after a known
promotion leaves the promoted desired state pending while last-known-good active routing remains.
Terminal audit failures retain the completed storage/runtime outcome and use the existing
`audit_failed_after_save` or `audit_failed_after_activation` classifications.

## Migration and backup

Schema-1 Proxy Host files load deterministically with every record classified as applied and no
drafts. The next successful store write publishes schema 2. Candidate binding schema numbers and
hash inputs do not change, so existing immutable candidates and exact active bindings stay valid.
Unknown fields and unsupported versions remain rejected. Downgrade to a binary that only accepts
schema 1 is unsupported; restore a matching binary and backup instead. Existing encrypted backups
already include the complete private Proxy Host file, including drafts.

## Security consequences

Drafts contain only the existing seven-field secret-free Proxy Host contract. Owner filtering,
RBAC/token-scope intersection, strict parsing, object identity, CAS, bounded counts/bytes, private
permissions, recovery gates, and redacted audit behavior remain mandatory. A draft may contain a
temporary route conflict, but promotion must pass canonical complete-state validation. Invalid or
corrupt durable draft bytes fail store opening; they are never skipped into runtime.

## Alternatives rejected

- A flag on applied revisions makes omission from compilation a distributed security condition.
- A separate store duplicates recovery and requires cross-file promotion coordination.
- A workspace/application-state graph is more machinery than the current one-object editing model
  needs and would invalidate fewer existing assumptions only in theory.

## Future implications

Proxy Locations and certificate workflows may reuse the state semantics after their own contracts
exist, but this ADR does not claim a generic draft framework. Any extension must preserve one exact
promotion boundary, secret isolation, and exclusion from provider/runtime compilation.
