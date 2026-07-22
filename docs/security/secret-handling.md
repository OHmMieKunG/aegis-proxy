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
Private typed validation/preview endpoints apply authorization before JSON deserialization, require
exact principal ownership, and reuse this redaction boundary. They return fixed error envelopes and
cannot persist or activate. Access-policy and managed-HTTPS preparation remains unavailable until
typed ownership metadata can be checked. Remaining mutation and stored-credential contracts are
still Phase 15 work.

Typed Proxy Host desired-state persistence contains no secret-bearing field. Its private parent is
mode `0700`, file is mode `0600`, symlink and broad-permission inputs fail closed, bytes and object
count are bounded, and `Debug` exposes only object count. It has no secret resolver or activation
handle. Owner-scoped list/get require exact `read_proxy_hosts` action; cross-owner reads return not
found and expose no object contents. Current API does not write this store.

Never put secret values in TOML, command arguments, logs, traces, audit records, screenshots,
tickets, backups without encryption, or repository fixtures. See
[certificate recovery](../operations/certificate-recovery.md) and [backup](../operations/backup.md).
