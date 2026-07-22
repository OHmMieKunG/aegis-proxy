# Private administration

The v1 administration service listens only on a Unix socket. With no explicit
`admin.unix_socket`, the daemon uses `<runtime.state_dir>/admin/admin.sock`.
The socket parent is mode `0700`; the socket is mode `0660`. A configured
`admin.allowed_uids` list further restricts peer credentials. No TCP, plaintext
remote, public bind, browser session, or web UI exists in v1.

A strict Proxy Host object can be listed, read, validated, previewed, created, updated, deleted, and
its verified complete candidate activated through private typed endpoints. Create/update/delete
persist desired state and an immutable candidate but never activate it. Admin-only activation
recompiles current desired state, verifies candidate content, and uses the existing atomic
coordinator. Typed rollback and remaining high-level objects are planned for Phase 15; GUI work
remains Phase 16. All must use this same server-side authorization, audit, concurrency, secret,
revision, and activation boundary.

Local socket peers are authenticated by kernel credentials and receive the
fixed `admin` role. Automation may additionally send a bearer API token. Token
plaintext is returned once, only hashes are persisted, and tokens have explicit
expiry, revocation state, and action scopes. Effective permission is the intersection of the token's
role and explicit scopes. Legacy records without scopes load deny-all and must be replaced through a
local authorized Unix peer. New tokens inherit creator's typed owner. Legacy records without owner
metadata cannot use typed Proxy Host endpoints. CLI `--token-ref` accepts only `env://NAME` or an
absolute `file:///path`; token values never belong in command arguments.

## Mutation safety

Every state-changing request requires an exact quoted active revision through
`If-Match`. A stale revision returns exit/status conflict without changing the
runtime. Candidate activation prepares all resources before publication.
Rollback creates a new forward revision; it never rewrites retained history.

Set `admin.audit_key` to a 32–64 byte secret reference before enabling
mutations. The daemon durably appends authenticated intent before mutation and
records success or failure afterward. Missing, full, invalid, or unavailable
audit storage fails mutations closed while the data plane continues.

## CLI examples

```text
rust-proxy health --socket /run/rust-proxy/admin.sock
rust-proxy fleet status --socket SOCKET
rust-proxy drain --socket SOCKET --expect REV
rust-proxy config activate --socket SOCKET --file proxy.toml --expect REV
rust-proxy config rollback --socket SOCKET REV --expect CURRENT
rust-proxy token create --socket SOCKET --expect REV --role operator --scope read-status
rust-proxy token list --socket SOCKET --token-ref file:///run/secrets/admin-token
rust-proxy token revoke --socket SOCKET --expect REV TOKEN_ID
rust-proxy proxy-host list --socket SOCKET
rust-proxy proxy-host get --socket SOCKET OBJECT_ID
rust-proxy proxy-host create --socket SOCKET --expect REV proxy-host.json
rust-proxy proxy-host update --socket SOCKET --expect REV --generation N OBJECT_ID proxy-host.json
rust-proxy proxy-host delete --socket SOCKET --expect REV --generation N OBJECT_ID
rust-proxy proxy-host activate --socket SOCKET --expect REV CANDIDATE_ID
rust-proxy proxy-host validate --socket SOCKET proxy-host.json
rust-proxy proxy-host preview --socket SOCKET proxy-host.json
rust-proxy backup create --socket SOCKET --expect REV --output /backup/aegis.age
rust-proxy backup verify /backup/aegis.age --identity file:///run/secrets/age-identity
rust-proxy restore validate --socket SOCKET --expect REV /backup/aegis.age --identity file:///run/secrets/age-identity
```

The CLI defaults to `/run/rust-proxy/admin.sock`; pass `--socket` when the
configured path differs. Exit codes are `0` success, `2` usage, `3` invalid
input/configuration, `4` revision conflict, `5` authentication/authorization,
`6` unavailable/failure, and `7` reserved for partial operational warnings.

For local socket authentication, `metadata.owner_id` in `proxy-host.json` is `uid-<uid>`. Bearer
requests use owner persisted with token. Validation requires `validate-config`; preview requires
`preview-config`; list/get require `read-proxy-hosts`. Reads never cross authenticated owner and get
returns object generation as an ETag. Validation/preview compile and semantically validate a
redacted candidate without writing state,
creating a revision, or activating runtime configuration. Current endpoint policy rejects
access-policy references and managed HTTPS until typed ownership metadata is implemented.
Create additionally requires `create-proxy-host`, matching owner, exact active revision, durable
audit intent, complete-state compilation, and an unchanged object-store epoch. It creates an
immutable candidate before generation-one desired state and returns without activation. Failed
authorization, validation, or concurrency cannot modify desired or active state; a late store
failure may leave only an immutable non-active candidate for retention cleanup.
Update/delete use distinct `update-proxy-host`/`delete-proxy-host` scopes and additionally require
exact `--generation`. A stale generation returns conflict before candidate or object persistence.
Activation requires Admin role and the distinct `activate-proxy-host` scope for bearer tokens.
Exact active revision, current complete desired-state compilation, immutable candidate hash, and
unchanged desired-state epoch must all match. The request serializes with other audited mutations,
then invokes the normal atomic coordinator. Operator tokens cannot activate typed candidates.

## Recovery and review

Keep the audit key, API tokens, and age identity outside normal configuration
and backups. Escrow recovery identities separately. Verify backups before
off-host retention. The checked contract is
`config/schema/admin-openapi.yaml`; the daemon does not serve it.

Remote mTLS administration remains deferred. Use an OS-controlled local
forwarder only after an independent threat review; do not expose the socket or
wrap it with an unauthenticated TCP bridge.

HA rollout and load-balancer drain procedures are documented in
[high availability](high-availability.md).
