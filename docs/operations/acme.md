# ACME operations

ACME automation runs inside the single proxy process. It owns accounts, challenge state, renewal scheduling, encrypted certificate generations, and atomic runtime publication. A failed order does not replace the active certificate.

## Safety model

- Every issuer has an explicit directory URL and `production` or `staging` classification. Classification is never inferred and no staging-to-production switch is automatic.
- Each certificate selects exactly one challenge. There is no fallback to a different challenge or CA.
- Wildcards require DNS-01. HTTP-01 and TLS-ALPN-01 require an explicit listener of the matching protocol.
- Global and per-issuer order semaphores plus a durable per-certificate lock prevent unbounded or duplicate local orders.
- Account credentials and certificate private keys are age-encrypted before durable storage. The age identity remains an external `env://` or absolute `file:///` secret.
- A candidate is checked for key match, validity, hostname coverage, issuer environment, and expiry improvement before the durable pointer changes.
- The durable certificate generation changes before the prepared in-memory resolver is published. A publication failure leaves recoverable durable state and does not publish partial TLS state.
- The previous valid generation is retained. Invalid, wrong-name, mismatched-key, expired, staging-over-production, or unexpectedly non-extending candidates are rejected.
- ACME errors are sanitized. Secret values and key authorization bodies are not logged.

ACME automation reduces certificate-lifecycle risk; it does not guarantee issuance or eliminate vulnerabilities. Alerting and restore drills remain required.

## Required secrets

Generate an age X25519 identity using an approved age tool. Inject the private identity through a protected file or environment variable and put only its public recipient in configuration:

```toml
[runtime]
state_dir = "/var/lib/aegisproxy"

[tls]
identity = "file:///run/secrets/aegisproxy-age-identity"
state_encryption_recipients = ["age1REPLACE_WITH_PUBLIC_RECIPIENT"]
```

The identity file must be readable only by the proxy account. Back it up separately from encrypted state; loss makes stored account and private-key generations unrecoverable. Never commit the identity, DNS token, EAB HMAC key, or certificate private key.

## Configuration shapes

The snippets below show ACME fields only. They must be merged into a complete validated configuration with routes and upstreams.

### HTTP-01

```toml
[acme]
max_concurrent_orders = 4
renewal_owner = "edge-a" # required for managed certificates in HA mode

[[acme.issuers]]
id = "public-production"
directory_url = "https://ca.example/acme/directory"
environment = "production"
account_email = "ops@example.com"
terms_of_service_agreed = true
max_concurrent_orders = 2

[[acme.certificates]]
id = "public-site"
hosts = ["example.com", "www.example.com"]
issuer = "public-production"
challenge = "http-01"
challenge_listener = "public-http"
renew_before_days = 30

[[listeners]]
id = "public-http"
bind = "0.0.0.0:80"
protocol = "http"

[[listeners]]
id = "public-https"
bind = "0.0.0.0:443"
protocol = "https"
certificates = ["public-site"]
```

HTTP-01 responses exist only for an exact active token, configured listener, and identifier. Normal routing cannot manufacture a challenge response.

### DNS-01 and wildcard

```toml
[[acme.dns_providers]]
kind = "cloudflare"
id = "cloudflare-example"
zone_id = "0123456789abcdef0123456789abcdef"
api_token = "file:///run/secrets/cloudflare-dns-token"

[[acme.certificates]]
id = "wildcard-site"
hosts = ["*.example.com"]
issuer = "public-production"
challenge = "dns-01"
dns_provider = "cloudflare-example"
renew_before_days = 30
```

Use a Cloudflare API token limited to DNS edit access for the one configured zone. Do not use a global API key. The proxy uses the configured zone ID; it does not discover zones. Issuance waits for the exact TXT value through bounded DNS lookups and fails on timeout or excessive answers. Cleanup failure is logged and the order is not activated.

### TLS-ALPN-01

```toml
[[acme.certificates]]
id = "alpn-site"
hosts = ["example.com"]
issuer = "public-production"
challenge = "tls-alpn-01"
challenge_listener = "public-https"
renew_before_days = 30
```

TLS-ALPN-01 installs a short-lived exact-SNI `acme-tls/1` identity. It is selected only when the client offers that ALPN protocol. Wildcards are rejected.

### Private or test CA

```toml
[[acme.issuers]]
id = "lab-staging"
directory_url = "https://acme.lab.example/directory"
environment = "staging"
account_email = "ops@example.com"
terms_of_service_agreed = true
ca_bundle = "file:///run/secrets/lab-acme-ca.pem"
max_concurrent_orders = 1
```

Only loopback staging directories may use plain HTTP. A custom CA bundle adds trust only for that issuer; production public trust is not silently replaced.

## Validate and start

```text
rust-proxy validate --config /etc/aegisproxy/config.toml
rust-proxy preview --config /etc/aegisproxy/config.toml
rust-proxy run --config /etc/aegisproxy/config.toml
```

Preview redacts ACME CA-bundle, EAB, and DNS-token references. Startup fails if configured encrypted state cannot be decrypted or existing managed certificate state is corrupt or inconsistent. A certificate with no generation starts fail-closed on HTTPS until issuance succeeds; other valid certificates continue serving.

## Status and manual renewal

```text
rust-proxy cert status --config /etc/aegisproxy/config.toml
rust-proxy cert renew --config /etc/aegisproxy/config.toml --id public-site
```

`status` reports `missing`, `active`, `renewal_due`, or `expired`, the expiry and deterministic fallback renewal time, and whether an operator request exists. It reads state and does not contact a CA.

`renew` writes an idempotent durable request marker. It does not start a second ACME client. The running proxy remains the single order owner, observes the marker during reconciliation, and clears it only after durable storage and runtime publication succeed. Repeating the command is safe.

In an HA fleet, invoke renewal only through the named `acme.renewal_owner`. Replica requests fail closed. Do not share writable ACME or certificate state. Follow the stopped-owner transfer and encrypted-generation distribution procedure in [high availability](high-availability.md).

The scheduler reconciles at most once per minute, applies stable jitter to the configured renewal window, uses capped retry backoff after failure, and logs expiry thresholds. Alert on:

- `ACME certificate expiry threshold reached`;
- `ACME certificate order failed`;
- `ACME account unavailable`;
- `ACME partial challenge cleanup failed`;
- repeated `ACME reconciliation failed` or `ACME schedule inspection failed`.

Phase 9 adds durable metrics and alert rules. Until then, route structured process logs to the operational log system and alert on these event names.

## Durable state

Do not edit live state by hand.

```text
<state>/
|-- acme/
|   |-- accounts/<issuer>/current.json
|   |-- accounts/<issuer>/generations/<generation>/credentials.age
|   |-- locks/<certificate>.lock
|   `-- renewal-requests/<certificate>.request
`-- certificates/<certificate>/
    |-- current.json
    `-- generations/<generation>/
        |-- chain.pem
        |-- key.age
        `-- metadata.toml
```

Pointer and generation writes are atomic on the supported local filesystem model. Persist the entire state directory and the external age identity as separate protected backup items. Keep filesystem permissions restrictive and do not place state on an eventually consistent object-store mount.

## Failure and recovery

| Failure | Behavior | Operator action |
|---|---|---|
| CA, DNS API, or network unavailable | Active valid certificate remains; retry is delayed and bounded | Fix reachability/token scope; inspect expiry; request renewal after repair |
| Challenge validation fails | Challenge state is removed; no certificate publication | Check public port/DNS/SNI reachability and CA validation logs |
| DNS cleanup fails | Error logged; candidate is not activated | Remove the exact stale TXT record, then renew |
| Issued key/name/validity invalid | Candidate rejected before persistence | Treat as CA/integration incident; preserve logs and prior generation |
| Encrypted state identity unavailable | Existing managed TLS state cannot load; startup fails clearly | Restore the original age identity; do not delete encrypted generations |
| Renewal request remains set | Last attempt did not fully publish | Correct the logged failure; the marker intentionally survives |
| Active certificate expired | That identity is not treated as valid fallback | Restore a valid backed-up generation or fix issuance; do not bypass validation |

Use `rust-proxy cert inspect --state-dir <state> --identity <secret-ref> <id>` during a controlled offline restore drill. It decrypts and revalidates the active private key without printing it.

## Staging to production

1. Test with a staging issuer and verify real challenge reachability.
2. Add a separate production issuer ID and explicit production directory URL.
3. Change the managed certificate's `issuer` while keeping its ID and hosts stable.
4. Validate and activate configuration.
5. Confirm `cert status`, logs, and the served chain.

A production certificate may replace staging material only after all candidate checks pass. Once production material is active, later staging material cannot replace it. There is no implicit environment promotion.

## Account rollover

There is no in-place account-key rollover command in Phase 6. To rotate safely, configure a new issuer ID with the same directory and update managed certificates to that issuer through validated configuration. The proxy creates and encrypts a new account; old account state remains available for rollback. Remove retained account state only during a separately reviewed retention/backup operation.

## Revocation and compromise

ACME revocation is not implemented in Phase 6. For suspected key compromise:

1. Remove or isolate the affected listener/route if exposure must stop immediately.
2. Revoke the certificate using the CA's authenticated external procedure.
3. Rotate the age identity, DNS/EAB credentials, and ACME issuer account when their exposure is plausible.
4. Issue replacement material under a reviewed new certificate or issuer policy.
5. Preserve encrypted state and logs for incident review; do not delete evidence during response.

The proxy does not currently consume revocation status for its own served certificate. Revocation alone therefore does not stop the process from presenting a configured certificate; configuration activation or shutdown is required.

## Local Pebble interoperability test

Pebble is test-only. The harness binds management and directory ports to loopback, uses official images pinned by digest, trusts only the committed public Pebble test CA, and never contacts a production CA.

```text
docker compose -f tests/pebble/compose.yml up -d
cargo test -p aegisproxy-tls --test pebble -- --ignored --nocapture
docker compose -f tests/pebble/compose.yml down
```

The test creates and restores an account, then issues and verifies certificates through HTTP-01, wildcard DNS-01, and TLS-ALPN-01. The higher-level manager's locking, cleanup, scheduling, durable generation, and atomic publication behavior remains covered by its Rust tests; this harness targets ACME protocol interoperability.
