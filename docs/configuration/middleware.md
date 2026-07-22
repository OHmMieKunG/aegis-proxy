# Middleware contract

Route `middlewares` entries select policies; their TOML order never controls execution. AegisProxy compiles each referenced policy into the fixed stages below and rejects duplicate or incompatible stages before activation. A request is matched once. Redirects, maintenance responses, denials, and custom errors never trigger a second route match.

## Fixed stages

| Stage | Behavior | Important interaction |
|---:|---|---|
| 1 | Access-event guard | Emits one final structured event on completion, body error, or cancellation. It records stable listener/route IDs, normalized request ID, method, status, bytes, and duration; never path, query, headers, identity, or client IP. |
| 2 | Request ID and forwarded identity normalization | Untrusted forwarding and request-ID headers are removed. Trusted chains are parsed from the immediate peer toward the client and rebuilt canonically. |
| 3 | Request target, headers, framing, and declared body-size limits | Runs before route middleware, authentication, or upstream work. Hyper-parsed framing is the only forwarding source. |
| 4 | ACME HTTP-01 intercept | Exact internal challenge route only; user middleware cannot shadow or decorate it. |
| 5 | IP policy, non-queuing in-flight limit, client-IP rate limit | Uses only stage-2 trusted identity. Deny CIDRs win. Limits run before auth and never queue. |
| 6 | Redirect or unauthenticated maintenance terminal | Never dials an application upstream. Public redirects cannot authenticate or rewrite. |
| 7 | CORS preflight | A valid preflight short-circuits before auth. Invalid origins/methods/headers fail without proxying. |
| 8 | Basic or ForwardAuth | Exactly one auth policy per route. Both require HTTPS public listeners. ForwardAuth is fail closed and copies only allowlisted headers. |
| 9 | Principal rate limit | Valid only with one authentication stage; keys only the bounded authenticated principal. |
| 10 | Path rewrite and request-header mutation | Applies after routing/auth and only to the upstream request. A rewrite never rematches. Protected routing/framing/forwarding headers cannot be mutated. |
| 11 | Upstream in-flight, timeout, retry, circuit, and streaming proxy | Retries remain idempotent, bounded, replay-size limited, and disabled for WebSocket/gRPC. Generic body buffering is not provided. |
| 12 | Static custom error | May replace only configured upstream/internal 5xx statuses. Bodies are bounded static content with no interpolation. |
| 13 | Response mutation, security headers, and actual CORS headers | Hop-by-hop, routing, TLS, framing, and content-encoding fields remain protected. HSTS requires HTTPS and persistent directives require explicit acknowledgement. |
| 14 | Streaming gzip/Brotli compression | Exact media-type allowlist and known size threshold. Skips ranges, SSE, gRPC, WebSocket, trailers, `no-transform`, pre-encoded, unknown-size, and authenticated responses unless explicitly allowed. Encoder concurrency is bounded. |
| 15 | Final accounting and passive health | Response-body lifetime holds in-flight permits and produces final byte/status accounting. |

## Activation rules

- A route chooses exactly one terminal action: upstream proxy, fixed redirect, or maintenance response.
- At most one policy may occupy each fixed middleware stage. Exactly one of Basic or ForwardAuth may authenticate a route.
- Principal rate limiting requires authentication. Redirects cannot authenticate, rewrite, or mutate request headers.
- Maintenance authentication must match its `authenticated` flag. Maintenance cannot use unused request/CORS transforms.
- Custom errors and compression require an upstream proxy action.
- Basic password hashes are secret references (`env://NAME` or absolute `file:///path`), not inline PHC values. Argon2 work has a bounded semaphore and deadline.
- ForwardAuth request and response headers are allowlists. Client-supplied identity headers are stripped first. Hop-by-hop, framing, forwarding, routing, TLS, cookie-response, and other protected fields are rejected at configuration time.
- Rate-key stores, in-flight work, compression work, auth work, request bodies, retry bodies, headers, and timeouts are bounded. Reloads reuse equivalent limiter state rather than resetting quotas.

## Reviewed interaction matrix

| Combination | Required result | Black-box/regression evidence |
|---|---|---|
| Untrusted forwarding + IP/in-flight/rate | Spoofed forwarded IP cannot change the security key | `ip_policy_ignores_untrusted_forwarded_identity`, `route_in_flight_limit_uses_trusted_client_and_body_lifetime`, `trusted_proxy_headers_are_rebuilt_before_upstream` |
| Body limit + terminal/auth | Oversized declared body is rejected before middleware work | `rejects_oversized_body_before_terminal_middleware` |
| Redirect + proxy | Fixed redirect returns without upstream dial | `redirect_terminal_never_dials_upstream` |
| CORS preflight + auth | Valid preflight short-circuits; actual response remains origin-scoped | `cors_preflight_short_circuits_and_actual_response_is_scoped` |
| Basic + client identity | Hashing is bounded/off-path; client principal header is replaced | `basic_auth_runs_off_path_and_rebuilds_principal_header` |
| ForwardAuth + spoof/deny/timeout | Only allowlisted identity reaches app; deny and outage fail closed | `forward_auth_is_bounded_allowlisted_and_identity_scoped`, `forward_auth_denial_and_timeout_fail_closed` |
| Auth + principal rate | Only the authenticated principal keys the limiter | `principal_limits_use_only_authenticated_identity` |
| Rewrite + routing | Upstream target changes without route rematch | `rewrite_changes_only_the_upstream_request_target` |
| Retry + request method/body | Only bounded replay-safe idempotent work retries | `retries_bounded_idempotent_body_on_connect_failure`, `does_not_retry_non_idempotent_request` |
| Custom error + internal/upstream failure | Selected 5xx is replaced without leaking/rematching | `custom_error_replaces_selected_upstream_body_without_leakage`, `custom_error_replaces_internal_proxy_failure_without_rematching` |
| Compression + sensitive/streaming protocols | Negotiation works; excluded responses stay unchanged | `compression_is_negotiated_through_the_proxy`, `streams_gzip_and_skips_sensitive_or_unbounded_responses` |
| In-flight + streaming/WebSocket | Permit remains held through response/tunnel lifetime | `route_in_flight_limit_uses_trusted_client_and_body_lifetime`, `upstream_in_flight_limit_holds_until_response_body_finishes` |
| Maintenance + upstream | Static response returns without upstream dial | `public_maintenance_is_static_and_never_dials_upstream` |
| Full shipped configuration | Typed middleware combinations parse and validate together | `shipped_valid_and_invalid_corpus_has_expected_result` validates `config/examples/phase7.toml` |

## Operational notes

- `config/examples/phase7.toml` is a validation fixture, not a ready deployment. Replace certificate paths, endpoints, CIDRs, origins, domains, and secret references.
- Access events currently use the process tracing subscriber. Bounded exporters, rotation guidance, metrics, and OpenTelemetry are documented under operations.
- Basic authentication is suitable only for limited operational cases. Prefer ForwardAuth with a reviewed identity provider for browser applications.
- Native route OIDC, arbitrary middleware ordering, runtime plugins, cache/store plugins, and a general buffering middleware are absent or deferred.

See [Authentik ForwardAuth](../guides/authentik-forward-auth.md) for the current Authentik integration contract.
