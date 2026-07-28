# Private administration

The v1 administration service listens only on a Unix socket. With no explicit
`admin.unix_socket`, the daemon uses `<runtime.state_dir>/admin/admin.sock`.
The socket parent is mode `0700`; the socket is mode `0660`. A configured
`admin.allowed_uids` list further restricts peer credentials. Phase 16 web configuration and
first-run bootstrap routes exist, but no TCP browser listener, browser session, or web UI is
implemented yet.

Private typed endpoints cover Proxy Hosts, Stream Hosts, Discovery Sources, Certificates, Access
Policies, write-only Stored Credentials, Users, immutable Roles, revisions, backups, and runtime
status. Typed create/update/delete operations persist desired state and, where runtime state is
affected, an immutable candidate; they never activate implicitly. Canonical Admin-only typed
activation and rollback verify complete schema-2 state and dependencies through the existing
atomic coordinator. Deprecated Proxy Host activation/rollback aliases accept schema 1 only. GUI
and browser-session work remain Phase 16 and cannot bypass this API boundary.

Local socket peers are authenticated by kernel credentials and receive the
fixed `admin` role. Automation may additionally send a bearer API token. Token
plaintext is returned once, only hashes are persisted, and tokens have explicit
expiry, revocation state, user subject, and action scopes. New tokens require an enabled stored
user, inherit its fixed role/owner, and cannot exceed that role. Disabling the user immediately
blocks its tokens. Legacy records without subjects remain parseable automation identities; missing
scopes still load deny-all. CLI `--token-ref` accepts only `env://NAME` or an
absolute `file:///path`; token values never belong in command arguments.

After enabling and validating `[admin.web]` plus `[admin.web.oidc]`, a local Admin Unix peer can
run `rust-proxy web setup-token --socket SOCKET`. The response displays one random setup token once,
binds it to that peer's `uid-<uid>` owner, expires it after ten minutes, replaces any prior setup
token, and retains only its SHA-256 digest in process memory. Restart removes it. Bearer tokens are
rejected even if they carry `create-web-setup-token`. The browser claim and OIDC session routes are
not implemented yet, so do not generate a token until that next Phase 16 unit lands.

## Mutation safety

Durable state-changing requests require an exact quoted active revision through `If-Match`. A stale
revision returns exit/status conflict without changing the runtime. Ephemeral setup-token issuance
does not alter configuration and has no revision precondition, but it still requires durable audit
intent and terminal success before the hash is installed. Candidate activation prepares all
resources before publication. Rollback creates a new forward revision; it never rewrites retained
history.

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
rust-proxy user create --socket SOCKET --expect REV operator.json
rust-proxy token create --socket SOCKET --expect REV --user-ref operator --scope read-status
rust-proxy token list --socket SOCKET --token-ref file:///run/secrets/admin-token
rust-proxy token revoke --socket SOCKET --expect REV TOKEN_ID
rust-proxy web setup-token --socket SOCKET
rust-proxy proxy-host list --socket SOCKET
rust-proxy proxy-host get --socket SOCKET OBJECT_ID
rust-proxy proxy-host create --socket SOCKET --expect REV proxy-host.json
rust-proxy proxy-host update --socket SOCKET --expect REV --generation N OBJECT_ID proxy-host.json
rust-proxy proxy-host delete --socket SOCKET --expect REV --generation N OBJECT_ID
rust-proxy proxy-host activate --socket SOCKET --expect REV CANDIDATE_ID
rust-proxy proxy-host rollback --socket SOCKET --expect REV HISTORICAL_REVISION
rust-proxy proxy-host validate --socket SOCKET proxy-host.json
rust-proxy proxy-host preview --socket SOCKET proxy-host.json
rust-proxy access-policy list --socket SOCKET
rust-proxy certificate list --socket SOCKET
rust-proxy stream-host list --socket SOCKET
rust-proxy discovery-source list --socket SOCKET
rust-proxy credential list --socket SOCKET
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
redacted candidate without writing state, creating a revision, or activating runtime
configuration. Access-policy references require owned or explicitly shared policies. Managed HTTPS
requires one owned or explicitly shared typed Certificate object with unambiguous domain coverage.
Create additionally requires `create-proxy-host`, matching owner, exact active revision, durable
audit intent, complete-state compilation, and an unchanged object-store epoch. It creates an
immutable candidate plus private desired-state binding before generation-one desired state and
returns without activation. Failed
authorization, validation, or concurrency cannot modify desired or active state; a late store
failure may leave only an immutable non-active candidate for retention cleanup.
Update/delete use distinct `update-proxy-host`/`delete-proxy-host` scopes and additionally require
exact `--generation`. A stale generation returns conflict before candidate or object persistence.
Activation requires Admin role and the distinct `activate-proxy-host` scope for bearer tokens.
Exact active revision, current complete desired-state compilation, immutable candidate hash, and
immutable bound object snapshot plus unchanged desired-state epoch must all match. The request
serializes with other audited mutations, then invokes the normal atomic coordinator. Operator
tokens cannot activate typed candidates.
Rollback requires Admin role and `rollback-proxy-host` for bearer tokens. The historical revision
must carry a valid immutable typed binding. The server creates and activates a new forward revision;
it never rewrites history or activates the historical file directly. An interrupted operation is
recovered before Admin startup by comparing its private journal with the durable active revision.
Do not edit or remove `admin/proxy-host-rollback.json`; unresolved recovery blocks mutations while
the data plane continues serving its durable active configuration.

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
