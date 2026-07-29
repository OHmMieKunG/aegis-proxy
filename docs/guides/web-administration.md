# Web administration

Browser administration is optional, loopback-only, and served by the Rust process when built with
`web-ui`. Configure `[admin.web]` and one `[admin.web.oidc]` provider as described in the
[configuration reference](../configuration/reference.md), then restart. Use the exact configured
`http://localhost:PORT` origin; forwarded Host or scheme values are not trusted.

## First administrator

1. Start AegisProxy and sign in through `/v1/auth/login`.
2. From a local Admin Unix peer, run:

   ```text
   rust-proxy web setup-token --socket /run/rust-proxy/admin.sock
   ```

3. Paste the one-time value into `/setup` within ten minutes.

Only an OIDC identity mapped to `admin` receives a provisional setup session. Redemption binds its
issuer/subject fingerprint to the token's `uid-<uid>` User and owner, rotates the cookie and CSRF
token, and consumes the setup token. Restart loses unredeemed tokens and all browser sessions.
Generate a new token after either event. Do not put setup tokens in URLs, logs, screenshots, or
browser storage.

## Common tasks

- **Proxy Hosts:** enter domain, forward host/IP, port, protocol, HTTPS choice, access policy, and
  enabled state. Validate, inspect the redacted preview/diff, create a candidate, then confirm
  Admin activation.
- **Stream Hosts, Certificates, Access Policies, Users:** list owner-scoped records and submit
  versioned API objects. Updates and deletes carry the displayed object generation and current
  active revision.
- **Health:** inspect runtime certificate and provider state.
- **Logs:** view durable authenticated audit records. Operational log streaming is not exposed.
- **Revisions:** preview a typed candidate, activate it, or confirm a forward rollback.
- **Backups:** create encrypted archives or validate a restore archive. The UI never restores one.
- **Settings:** inspect web, session, active revision, and process information. Settings are
  read-only.

Navigation and buttons follow the session's `permitted_actions`; the server reauthorizes every
request. A `401` starts a fresh OIDC login. `403` means the role cannot perform the action. `409`,
`412`, or `503` means state changed or a durable dependency is unavailable; reload before retrying.

The client stores no session, OIDC, setup, API-token, credential, or secret value in local or
session storage. Sign out on shared systems. The secure cookie requires the configured localhost
origin and is intentionally invalid on the Unix listener.
