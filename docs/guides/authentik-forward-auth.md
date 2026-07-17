# Authentik ForwardAuth

Status: Phase 7 integration contract. Validate against the deployed Authentik version before rollout.

AegisProxy calls a configured HTTP-family upstream with an empty `GET` request. It supplies the canonical original URI, method, host, scheme, trusted client address, and request ID. Only explicitly allowlisted client headers are copied. A `2xx` response permits the request; `401`/`403` deny it; validated `301`, `302`, `303`, `307`, or `308` responses may redirect the client. Errors, timeouts, oversized responses, missing principals, malformed headers, and every other status fail closed with `503`.

The current Authentik Traefik contract uses `/outpost.goauthentik.io/auth/traefik` and returns explicitly selected `X-Authentik-*` identity headers. Authentik also requires `/outpost.goauthentik.io/` to be publicly routed to the outpost for login, callback, ping, and logout flows. Do not apply ForwardAuth to that dedicated route.

Representative middleware and upstream configuration:

```toml
[[upstream_groups]]
id = "authentik-outpost"
allowed_cidrs = ["10.20.0.0/24"]

[[upstream_groups.endpoints]]
id = "outpost-1"
url = "http://10.20.0.10:9000"
weight = 1

[middlewares.authentik]
type = "forward_auth"
upstream_group = "authentik-outpost"
path = "/outpost.goauthentik.io/auth/traefik"
request_headers = ["authorization", "cookie"]
response_headers = [
  "x-authentik-username",
  "x-authentik-groups",
  "x-authentik-entitlements",
  "x-authentik-email",
  "x-authentik-name",
  "x-authentik-uid",
]
principal_header = "x-authentik-username"
redirect_hosts = ["auth.example.com", "app.example.com"]
timeout_secs = 3

[[routes]]
id = "authentik-public"
listeners = ["https"]
hosts = ["app.example.com"]
path_prefixes = ["/outpost.goauthentik.io"]
priority = 100
upstream_group = "authentik-outpost"

[[routes]]
id = "protected-app"
listeners = ["https"]
hosts = ["app.example.com"]
path_prefixes = ["/"]
priority = 10
middlewares = ["authentik"]
upstream_group = "application"
```

Operational rules:

- Use HTTPS for the public application listener. ForwardAuth on plaintext listeners is rejected.
- Prefer HTTPS to a remote outpost. Configure its exact `server_name`, CA policy, and egress CIDRs; there is no certificate-verification bypass.
- Keep `request_headers` minimal. Cookies and authorization tokens are sensitive and must never be logged.
- Every returned identity header is stripped from the client request before the auth decision, then rebuilt only from the allowlisted auth response. All client-supplied `X-Authentik-*` headers are removed at the trust boundary.
- `principal_header` is mandatory on successful responses and becomes the bounded internal `X-AegisProxy-User` value sent to the application.
- Only relative redirects or HTTPS redirects to `redirect_hosts` are accepted. List every expected browser-facing Authentik/application host explicitly.
- Adding `authorization` to `response_headers` permits Authentik's optional generated Basic credential to replace the inbound authorization value. Enable it only when the protected application requires that feature.
- Check the outpost ping path through the dedicated public route before enabling the protected route. Alert on ForwardAuth `503`, timeout, invalid-response, and upstream-health signals when observability support lands in Phase 9.

This integration is a policy boundary and requires an independent security review before production use, especially when cookies, generated authorization headers, or domain-level ForwardAuth are enabled.

## Upstream references

- [Authentik Traefik ForwardAuth configuration](https://docs.goauthentik.io/add-secure-apps/providers/proxy/server_traefik/)
- [Authentik Caddy ForwardAuth configuration](https://docs.goauthentik.io/add-secure-apps/providers/proxy/server_caddy/)
- [Authentik proxy-provider headers and modes](https://docs.goauthentik.io/add-secure-apps/providers/proxy/)
