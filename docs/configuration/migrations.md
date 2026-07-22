# Configuration and state migrations

AegisProxy has not published a supported release. Until a release policy is finalized, changes are
documented exactly and never silently broaden authorization.

## API-token scopes

Phase 15 adds a required `scopes` list to token creation. Each value is one checked administrative
action. A token is authorized only when both its role and scopes allow the action. The CLI requires
one or more repeated `--scope` options.

Existing private `admin/tokens.json` records without `scopes` or `owner_id` still parse under
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
rust-proxy token create --socket SOCKET --expect REV --role operator \
  --scope read-status --scope read-routes
```

The checked OpenAPI contract is [`../schema/admin-openapi.yaml`](../../config/schema/admin-openapi.yaml).
No migration exposes token plaintext or stored password hashes.

## Typed Proxy Host store

The internal Proxy Host desired-state file uses strict schema version 1. Unknown fields, future
versions, zero generations, duplicate owner/object identities, duplicate domains, malformed typed
objects, oversized state, symlinks, and broad file permissions fail opening the store. No automatic
downgrade or repair is attempted. This pre-release store is not yet opened by typed API endpoints; a
release migration command must exist before its schema can change incompatibly.
