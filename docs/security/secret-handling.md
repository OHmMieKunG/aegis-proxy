# Secret handling

## Current boundary

Configuration accepts only `env://NAME` or absolute `file:///path` secret references. Relative
paths, shell expansion, commands, scripts, arbitrary URLs, and runtime plugins are rejected.
Resolved bytes are size-limited, permission-checked where supported, zeroized where practical, and
redacted in formatting. Private keys and ACME account credentials are age-encrypted at rest.

API tokens return plaintext once at creation; only Argon2 hashes and safe metadata persist. New
tokens require explicit bounded action scopes. Effective permission is the intersection of role and
scope, while legacy records without scopes authorize no action until replaced.
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
Public endpoint error/redaction mapping and remaining stored-credential object contracts are still
Phase 15 work.

Never put secret values in TOML, command arguments, logs, traces, audit records, screenshots,
tickets, backups without encryption, or repository fixtures. See
[certificate recovery](../operations/certificate-recovery.md) and [backup](../operations/backup.md).
