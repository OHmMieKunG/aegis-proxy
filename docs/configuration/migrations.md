# Configuration and state migrations

AegisProxy has not published a supported release. Until a release policy is finalized, changes are
documented exactly and never silently broaden authorization.

## API-token scopes

Phase 15 adds a required `scopes` list to token creation. Each value is one checked administrative
action. A token is authorized only when both its role and scopes allow the action. The CLI requires
one or more repeated `--scope` options.

Existing private `admin/tokens.json` records without `scopes`, `owner_id`, or `user_ref` still parse under
token-file schema 1. Missing scopes become an empty set and authorize no action. A missing owner also
prevents typed-object access. This is intentional fail-closed compatibility, not an automatic
privilege migration. Token hashes and plaintext cannot be converted into newly scoped and owned
credentials.

To replace a legacy token:

1. Connect through an authorized local Unix peer without the legacy bearer token.
2. Create a replacement with the minimum role and explicit scopes.
3. Capture the returned plaintext once into an approved secret provider.
4. Verify only the intended operations through `--token-ref`.
5. Revoke the legacy token by ID.

Example:

```text
rust-proxy token create --socket SOCKET --expect REV --user-ref operator \
  --scope read-status --scope read-proxy-hosts
```

Typed Proxy Host creation adds distinct `create-proxy-host` CLI scope (`create_proxy_host` in
JSON). Existing tokens do not gain it automatically. Replace or issue a token explicitly when
automation needs create; list/get remain independently grantable.
Update and delete likewise add distinct `update-proxy-host` and `delete-proxy-host` CLI scopes
(`update_proxy_host` and `delete_proxy_host` in JSON). Existing tokens gain neither.
Typed activation adds `activate-proxy-host` (`activate_proxy_host` in JSON). It is Admin-only;
existing tokens gain no scope automatically and operator tokens cannot request it.
Typed rollback adds `rollback-proxy-host` (`rollback_proxy_host` in JSON) with the same Admin-only
role ceiling. Existing tokens gain no scope automatically.
Access Policy preparation adds `read-access-policies`, `create-access-policy`,
`update-access-policy`, and `delete-access-policy` (`*_access_policy` in JSON). Existing tokens gain
none automatically. The read scope is available to every built-in role; mutation scopes require
Operator or Admin. List/get require `read-access-policies`; create now requires
`create-access-policy`; update/delete require their corresponding exact scope plus current object
generation and active revision.

The checked OpenAPI contract is [`../schema/admin-openapi.yaml`](../../config/schema/admin-openapi.yaml).
No migration exposes token plaintext or stored password hashes.

## Typed Proxy Host store

The internal Proxy Host file now uses strict schema version 2 with separate `objects` (applied
desired state) and `drafts` (inactive working state). Schema version 1 loads additively: every
existing record remains applied and the draft set is empty. The next successful Proxy Host or draft
write publishes schema 2. Existing candidate binding schema numbers and hash inputs do not change,
so active bindings remain valid without rewrite. Unknown fields, future versions, zero generations,
duplicate owner/object identities, duplicate applied domains, malformed typed objects, oversized
state, symlinks, and broad file permissions fail opening the store. No automatic downgrade or
repair is attempted. Older binaries that only accept schema 1 cannot open schema 2; downgrade
requires restoring a matching binary/state backup. Administration opens the store at
`<state_dir>/admin/proxy-hosts.json`; corrupt or insecure state fails administration startup rather
than being skipped. Read endpoints do not rewrite it. Process-local store epoch is concurrency
state, is not serialized, and resets safely on restart because no in-flight request survives
restart. Draft-local and applied generations remain durable and separate. A release migration
command must exist before schema can change incompatibly.

Phase 17.1 keeps this store schema number and changes the Proxy Host field contract additively on
read: exactly one legacy `domain` or current `domains` is accepted, never both. A singular applied
or draft record becomes a normalized one-element list in memory; the next successful write emits
only `domains`. Lists contain 1–32 values and older binaries cannot read plural records, so
downgrade requires the matching old binary and backup. Candidate loading separately verifies the
exact former one-domain binding serialization. Old active bindings therefore remain authoritative
and are not automatically recompiled or activated; an explicit later apply creates a plural hash.

Phase 17.2 also keeps ProxyHostStore schema 2. Missing `locations` loads as an empty list for applied
and draft records, preserving both generations. New writes emit the bounded list. Candidate loading
accepts the exact Phase 17.1 plural-domain/no-location serialization as well as the earlier singular
form; no active candidate is rewritten or automatically applied. Once a nonempty location list is
written, older binaries cannot read it and downgrade requires a matching backup.

The internal Access Policy store follows the same no-repair rule at
`<state_dir>/admin/access-policies.json`. Its schema version is one, IDs are globally unique,
records use canonical ID order and exact generations, and Administration acquires exclusive
ownership before binding its socket.

The pre-release Phase 15 Rust API now constructs `AccessPolicyMetadata` only through
`compile_access_policy_metadata`; its fields are private and safe metadata is available through
getters. Library callers using the earlier public field literal must migrate to the validated
constructor. No JSON, TOML, OpenAPI, CLI, persisted-state, or data-plane schema changed in this
unit.

Typed candidate snapshots use strict schema versions 1 and 2 under
`<state_dir>/admin/proxy-host-candidates/`. Schema 1 contains Proxy Hosts plus optional Access
Policy bindings and remains accepted only by the deprecated Proxy Host activation/rollback aliases.
Schema 2 binds complete Proxy Host, Stream Host, Discovery Source, Access Policy, and Certificate
state and is accepted only by canonical typed activation/rollback routes. Revision metadata's
optional `binding_hash` is additive: old low-level revisions without it still load and remain
usable through low-level configuration operations, but every typed route rejects them. No
automatic binding is inferred from runtime configuration because disabled typed objects cannot be
recovered from generated routes. Older binaries cannot read schema-2 private derived state, so
downgrade requires restoring the matching binary/state backup rather than reusing that candidate
directory.
The configuration revision list is authoritative for snapshot retention. Admin startup and
pre-bind reconciliation remove valid snapshots only after their revision metadata has been pruned.
Operators must not manually add, edit, or remove entries: malformed, symlinked, insecure, or
retained-but-mismatched files fail Admin startup or candidate creation before cleanup proceeds.

Typed rollback uses strict schema version 1 at
`<state_dir>/admin/proxy-host-rollback.json` only while a desired-state/runtime transaction is in
progress. Startup fails closed on malformed, insecure, or oversized journal state and reconciles a
valid journal against the durable active revision. Operators must not edit or delete this file.
