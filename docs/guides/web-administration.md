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

- **Proxy Hosts:** create, edit, enable, disable, duplicate, or delete a host from the host list.
  Add, remove, or reorder as many as 32 exact domains. The first is the primary display name and
  the list summarizes additional names as `+N more`; expanding it shows every normalized domain.
  All names share one default upstream, HTTPS choice, and access policy. Wildcards and per-domain
  settings are not supported. Add up to sixteen structured custom locations for exact paths or
  path-and-descendant prefixes. Each location has one explicit upstream, can inherit or override
  the host Access Policy, and can be disabled without deletion. More-specific paths win; `/api`
  matches `/api` and `/api/...` but not `/api2`. The default upstream remains fallback.
  Managed HTTPS requires one selectable certificate to cover the complete domain set. The API
  returns `certificate_coverage_failed`, and the editor keeps the entered names visible while it
  identifies the set that needs a covering certificate.
  **Save and apply** carries the active-state and object-generation preconditions through the
  existing typed mutation and transactional activation path. A duplicate opens as an unsaved,
  disabled form with a new object ID and fresh location IDs; change its domain before saving.
  **Save draft** durably stores an inactive working copy and performs no compilation or activation.
  The list labels it **Draft not applied**. Reopen it to edit, **Discard draft** without changing
  desired or active routing, or **Save and apply** to promote one exact draft generation before
  normal activation. Drafts survive restart and are never applied automatically.
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
Roles with Proxy Host create or update permission can create, reopen, edit, duplicate, save, and
discard drafts even when they lack activation permission. Enable, disable, delete, and **Save and
apply** remain hidden and server-denied without the corresponding mutation plus activation scope.

A successful save followed by failed activation is reported as **Saved but not active** or
**Activation failed**. The desired object change remains persisted, while the previously active
runtime continues serving traffic. This distinction is especially important for delete: the host
can disappear from saved configuration while its former route remains active until a later
successful activation. The browser does not silently retry conflicts or imply that traffic
changed.

If the activation request loses its response or returns an unclassified transport error, the
browser instead reports **Activation status unavailable** and asks the operator to refresh. It
does not claim activation failed or that the previous runtime remains active, because neither
routing outcome was proved by the response.

The list derives **Changes active** only when the saved desired object exactly matches the object
in the active bound state. A promoted draft whose activation fails is no longer a draft: it is
confirmed desired state marked **Saved but not active**, while the prior runtime keeps serving.
Draft and applied edits use separate generations; a stale browser must reload rather than merge or
overwrite a newer draft.

Known storage failure reports **Save failed**. If the browser loses the mutation response, it
instead reports **Save status unavailable** because it cannot know whether desired storage changed;
it never attempts activation in that case. **Rollback failed** means the previous runtime was
restored in memory but durable activation recovery needs a restart. **Saved but audit unavailable**
means desired state was written but activation was not requested. **Changes active; audit
unavailable** means the exact intended runtime committed before terminal audit durability failed.
All recovery and audit-unavailable results block further browser mutations. See the
[failure-boundary matrix](../reviews/phase-16-save-apply-failure-campaign.md) for exact API codes,
restart behavior, and operator action.

**Storage recovery required** means an atomic Proxy Host file replacement became visible but its
directory durability could not be confirmed. The outcome is uncertain: do not assume either the
old or new desired state will survive a crash. AegisProxy blocks further Proxy Host changes and
does not compile or activate that uncertain state. Restart the service; startup rereads and
strictly validates the visible durable file before mutations become available. If startup rejects
the file, preserve the state directory and inspect redacted service diagnostics rather than
editing the file in place. The previously active runtime remains the last-known-good state.

The client stores no session, OIDC, setup, API-token, credential, or secret value in local or
session storage. Sign out on shared systems. The secure cookie requires the configured localhost
origin and is intentionally invalid on the Unix listener.
