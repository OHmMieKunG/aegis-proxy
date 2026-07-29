# Threat-to-control verification matrix

Evidence review date: 2026-07-29
Documentation rebaseline: 2026-07-29

Status meanings: **verified-local** means named automated/local evidence passed; **deferred** means
the feature is absent and guarded by scope; **external-gate** means local evidence exists but
independent review is still required. A status is not a vulnerability-free claim.

| Threat | Main implementation/control | Verification evidence | Status and residual risk |
|---|---|---|---|
| Malformed inbound HTTP | Hyper framing; `reject_unsafe_request_target`; header/target/body bounds | core malformed, slow-header, oversized body tests; `header_processing` fuzz target | external-gate: parser differential review pending |
| Request smuggling/desynchronization | parsed Hyper requests only; CL/TE ambiguity rejection; upstream reconstruction | `rejects_ambiguous_framing_before_upstream`, H2 connection-header tests; fuzz corpus | external-gate: expert H1/H2 translation review pending |
| Header/CRLF/log injection | typed `HeaderMap`; protected header mutations; structured logs | config header mutation tests; audit log-injection/canary tests | verified-local; downstream log sink escaping remains operator-owned |
| Host-header/open-proxy misuse | Host/authority consistency; configured route/upstream only; CONNECT/absolute-form rejection | route authority tests; `rejects_absolute_form_connect_and_missing_host` | external-gate: protocol review pending |
| SSRF | configured endpoints; CIDR policy at resolve/refresh/connect; pinned socket addresses | egress policy, raw-answer, rebind, custom resolver tests | external-gate: target-network review pending |
| DNS rebinding/poisoning | Hickory TTLs; bounded/deduplicated answers; revalidation and stale deadline | DNS rebind, mixed answer, stale/NXDOMAIN/provider tests | verified-local; DNSSEC not claimed |
| Provider task availability | static fallback; bounded provider state; fail-closed source validation | provider unit/failure tests; typed-startup source audit | external-gate: typed startup currently omits provider reconciliation and must be fixed before controlled GO |
| Path traversal/policy bypass | one ASCII canonical path; encoded separator/backslash/dot rejection | route property tests; encoded-separator integration test; path fuzz target | external-gate: corpus review pending |
| TLS downgrade/weak policy | Rustls TLS 1.2/1.3 only; no plaintext/insecure verification fallback | TLS 1.2/1.3 matrix, ALPN, wrong-name/custom-CA tests | external-gate: independent TLS scanner pending |
| Certificate/account-key theft | age-encrypted keys/accounts; restrictive files; redacted types | key/account round trips, permissions, wrong identity, backup tests | external-gate: host key custody review pending |
| Secret leakage | typed references; bounded providers; redaction; zeroization where practical | secret debug/export/canary, audit, backup tests | external-gate: artifact/log scan pending |
| Authentication bypass | Basic/ForwardAuth/admin token fail closed; subject tokens require an enabled durable user; untrusted identity headers stripped | auth negative/timeout/hash-only/token-expiry and user-disablement tests | external-gate: independent auth review pending |
| Authorization bypass | deny-by-default fixed user role and explicit token-scope intersection per operation and mutation preconditions | full role matrix; admin CLI proves an out-of-scope mutation creates no revision | external-gate: endpoint-by-endpoint review pending |
| Session fixation/CSRF/admin XSS | exact loopback origin and Host; PKCE/state/nonce; bounded rotating server sessions; secure `__Host-` cookie; exact Origin/fetch/CSRF before unsafe body parsing; CSP and React text rendering; no browser storage | OIDC negative/rotation/cookie tests; session and asset allowlist checks; Playwright storage/XSS/keyboard/axe/responsive scenarios | external-gate: independent application-security review pending |
| First-run administrator takeover | Admin Unix-peer setup token plus provisional Admin OIDC session; constant-time one-use redemption; fingerprint/User/owner binding with recovery journal and immediate session/CSRF rotation | setup-token replacement/expiry/replay; binding schema/permissions/collision/recovery/canary tests; setup browser scenario | external-gate: independent race and recovery review pending |
| SQL injection | no database/SQL layer in initial release | ADR-0018; dependency/source inventory | deferred; must reopen before database introduction |
| Command injection | no runtime shell/exec secret or plugin provider | secret provider rejection and provider schema tests; source review | verified-local; deployment wrapper scripts need separate review |
| Configuration injection | strict typed bounded TOML; unknown fields denied; transactional activation | config corpus/unit tests; config/route fuzz targets; failed activation tests | external-gate: malicious-config review pending |
| Sensitive headers in logs | no raw request headers; explicit structured fields; secret redaction | canary/redaction/audit serialization tests | external-gate: deployed collector/SIEM review pending |
| Forwarded-header spoofing | untrusted chain stripped; trusted CIDR/hop scan right-to-left; canonical rebuild | normalize tests and proxy integration; forwarded fuzz target | external-gate: topology-specific trust review pending |
| Rate-limit bypass | trusted effective IP/auth principal only; bounded token buckets/cardinality | spoof/principal/reconnect/capacity tests | verified-local; per-node limits are not global |
| DoS/Slowloris/large bodies | explicit timeouts, semaphores, body/header/buffer/queue bounds | slow header/upstream, oversized body, saturation and cancellation tests | external-gate: 24-hour soak and abuse review pending |
| Compression bombs/side channels | no request decompression; streaming response compression; sensitive exclusions | compression eligibility, highly compressible and sensitive-response tests | verified-local; CPU profiling under target traffic pending |
| FD/memory/CPU exhaustion | bounded accept/in-flight/upstream/background state; deployment limits | limit release, max-series, drain/cancellation tests | external-gate: host/container exhaustion campaign pending |
| ReDoS | exact/prefix routing only; no runtime regex feature | config schema/source inventory | deferred; reopen before regex matchers |
| Dependency supply chain | Rust and npm lockfiles; exact internal versions; registry-only sources; no Node production runtime or CDN assets | dependency review; source scan; current `npm audit`; Cargo audit/deny unavailable locally | external-gate: React Router RSC-mode high advisory remains in the locked SPA dependency; Rust scan tools unavailable |
| Malicious container metadata/socket | no Docker provider; no Docker socket mount | ADR-0017/0020; compose/Dockerfile inspection | deferred; reopen before container discovery |
| Unsafe defaults/privilege escalation | private admin Unix socket; non-root deploy; no implicit route; safe Rust | config defaults, admin permissions, deployment validation | external-gate: platform hardening review pending |
| Container escape impact | non-root, read-only root, dropped caps, no-new-privileges, limits | compose/Dockerfile/systemd inspection; confinement examples | external-gate: image/host scanner and reviewer pending |
| Admin API exposure | private Unix socket plus optional loopback-only exact-origin browser listener; listener identities are non-interchangeable | broad-parent/loopback/origin/bearer rejection and admin integration tests | external-gate: deployed bind/port scan pending |
| Insecure backups | age encryption, bounded archive, manifest hashes, symlink rejection | backup tamper, wrong identity, restore verification tests | external-gate: independent restore drill pending |
| Rollback attacks | authorized forward revision; CAS; durable audit/hash chain | revision rollback/tamper/crash and admin authorization tests; local compromise tabletop | external-gate: independent live restore drill pending |
| Configuration races | serialized coordinator; CAS; immutable snapshot and atomic pointer | concurrent candidate, activation, crash/probation/HA chaos tests | verified-local; formal concurrency review pending |
| Certificate renewal races | per-certificate lock; staged validation; atomic generation; retained prior cert | scheduler single-flight, rotation/rejection, TLS challenge reload tests | external-gate: current Pebble campaign not run |

## Release blockers

- Qualified external HTTP/TLS/application/container review has not occurred.
- Required 24-hour soak and long fuzz campaigns have not occurred.
- Security-owner residual-risk recommendation is unsigned.
- Container image scanning and Pebble interoperability were not run. Docker Desktop's Linux engine
  is available, but no scanner or current Pebble campaign was installed/executed.

Any new threat, enabled deferred feature, or failed control changes this matrix before release.
