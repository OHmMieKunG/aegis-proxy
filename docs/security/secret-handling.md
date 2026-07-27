# Secret handling

## Current boundary

Configuration accepts only `env://NAME` or absolute `file:///path` secret references. Relative
paths, shell expansion, commands, scripts, arbitrary URLs, and runtime plugins are rejected.
Resolved bytes are size-limited, permission-checked where supported, zeroized where practical, and
redacted in formatting. Private keys and ACME account credentials are age-encrypted at rest.

API tokens return plaintext once at creation; only Argon2 hashes and safe metadata persist. New
tokens require explicit bounded action scopes and inherit creator's stable typed owner. Effective
permission is the intersection of role and scope, while legacy records without scopes authorize no
action until replaced. Legacy records without owner metadata cannot use typed-object endpoints.
Mutation audit intent applies this same intersection before any state change; role permission alone
is insufficient for a bearer token.
Certificate, provider, audit, authentication, backup, and age identities are never returned as
plaintext through API or preview. Keys necessarily exist in process memory while used; encryption
at rest does not protect a compromised process.

## Target typed boundary

Phase 15 introduces opaque `secret_ref`, `certificate_ref`, `credential_ref`, and
`provider_credential_ref` fields. Secret inputs remain write-only after creation. Reads may expose
owner, fingerprint, scope, timestamps, expiration, last use, and rotation/revocation controls only.
GUI and advanced API use the same boundary.

Current Proxy Host compiler receives only access-policy and certificate identifiers plus existing
validated configuration. It has no secret resolver, environment access, network client, persistence
handle, or runtime handle. Candidate and context `Debug` output summarizes IDs/counts and omits full
configuration secret references. Typed candidate preview uses the existing complete redaction pass;
its `Debug` output omits the configuration. Typed field differences use a closed value enum and
compare only preview summaries; raw configuration and secret fields cannot enter the diff contract.
Aggregate compilation accepts typed objects and metadata-only policy/certificate maps, returns only
typed desired state plus canonical configuration, and exposes counts—not configuration—in `Debug`.
The Access Policy object contains only owner/share IDs, enabled state, and canonical
middleware IDs. Its validated metadata has no serialization implementation; redacted `Debug`
returns only enabled state and counts. BasicAuth and ForwardAuth contents stay in the already
validated canonical configuration and never enter the policy object, metadata, or compiler error.
Its private bounded store serializes only this secret-free object, uses mode `0700` parent and
`0600` files on Unix, rejects symlinks, broad permissions, and malformed state, and exposes only
record count through `Debug`. Audited Access Policy create accepts only this strict object, validates
middleware references against active configuration, and persists no middleware contents or
credentials.
Private typed Proxy Host validation/preview/create/update/delete endpoints apply authorization before JSON deserialization,
require exact principal ownership, and reuse this redaction boundary. They return fixed error
envelopes and cannot expose or resolve secrets. Validation/preview cannot persist or activate.
Create may persist only the secret-free seven-field object and a canonical immutable candidate; it
cannot activate. Access-policy and managed-HTTPS preparation remains unavailable until typed
ownership metadata can be checked. Remaining mutation and stored-credential contracts are still
Phase 15 work.

Typed Proxy Host desired-state persistence contains no secret-bearing field. Its private parent is
mode `0700`, file is mode `0600`, symlink and broad-permission inputs fail closed, bytes and object
count are bounded, and `Debug` exposes only object count. It has no secret resolver or activation
handle. Owner-scoped list/get require exact `read_proxy_hosts` action; cross-owner reads return not
found and expose no object contents. Create requires exact `create_proxy_host` action and owner
equality; update/delete use separate exact scopes and owner namespace. Stored contract has no
plaintext credential field.
Typed activation accepts only an opaque revision ID and metadata-only desired-state snapshot. It
recompiles and hashes the already validated configuration without resolving secret references;
errors and audit records use fixed codes, not configuration or secret contents.
Immutable typed candidate snapshots contain only strict seven-field Proxy Host objects. Their hash
is bound into revision metadata, and activation verifies file schema, permissions, size, revision
identity, hash, canonical object order, and equality with current desired state. The snapshot has no
field capable of carrying secret plaintext.
Snapshot reconciliation consumes only revision IDs and binding hashes. It validates every bounded
file before deleting valid snapshots whose authoritative revisions are absent; it never resolves
credentials or exposes object content. Malformed, symlinked, insecure, or retained-but-mismatched
entries fail closed before deletion.
Typed rollback loads only those bound snapshots and never resolves referenced secret material. Its
private recovery journal contains previous and target secret-free typed records, not configuration
or credentials. Audit and API errors use fixed failure codes. An unresolved journal blocks further
mutation until restart recovery reconciles desired state with the durable active revision.

Never put secret values in TOML, command arguments, logs, traces, audit records, screenshots,
tickets, backups without encryption, or repository fixtures. See
[certificate recovery](../operations/certificate-recovery.md) and [backup](../operations/backup.md).
