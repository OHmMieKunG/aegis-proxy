# Private administration

The v1 administration service listens only on a Unix socket. With no explicit
`admin.unix_socket`, the daemon uses `<runtime.state_dir>/admin/admin.sock`.
The socket parent is mode `0700`; the socket is mode `0660`. A configured
`admin.allowed_uids` list further restricts peer credentials. No TCP, plaintext
remote, public bind, browser session, or web UI exists in v1.

A strict Proxy Host object can be listed, read, validated, or previewed through private read-only
endpoints, but no high-level mutation endpoint exists. Remaining high-level API and GUI work is
planned for Phases 15–16 and must use this same server-side authorization, audit, concurrency,
secret, and activation boundary.

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
