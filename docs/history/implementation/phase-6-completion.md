# Phase 6 completion: ACME certificate automation

> Historical document — records phase evidence at completion time. See [`STATUS.md`](../../../STATUS.md) for current verification.

Date: 2026-07-17

## 1. Phase title

Phase 6: ACME certificate automation.

## 2. Original objectives

- Automate issuance and renewal through HTTP-01, DNS-01, and explicitly gated TLS-ALPN-01.
- Support explicit multiple CA directories/accounts and staging/production classification.
- Support wildcard issuance through DNS-01 only.
- Encrypt account credentials and certificate private keys at rest.
- Preserve the last working certificate through issuance, storage, and publication failure.
- Provide bounded scheduling, locking, challenge cleanup, status, manual renewal, tests, and operator guidance.

## 3. Implemented scope

- Strict typed ACME issuer, managed-certificate, EAB, challenge, profile, renewal, global/per-issuer order limit, and Cloudflare provider configuration.
- Recursive unknown-field rejection, reference validation, explicit terms acceptance, wildcard/challenge constraints, listener protocol checks, and staging/production classification.
- `instant-acme` adapter with an application-owned bounded Hyper/Rustls transport, same-origin enforcement, explicit CA roots, response/header limits, and timeouts.
- Account create/restore with bounded credential JSON and age-encrypted immutable account generations.
- Stateful order stages: create, prepare, provision, notify, authorize, finalize, retrieve, validate.
- HTTP-01 exact listener/host/token registry and response path.
- TLS-ALPN-01 exact-SNI bounded registry, RFC 8737 `acmeIdentifier` certificate, ALPN isolation, expiry, and reload retention.
- DNS-01 Cloudflare adapter using explicit zone ID, exact TXT create/list/delete, bounded response parsing, and secret-reference token.
- Exact TXT propagation checks with bounded Hickory lookups, answer count, value size, timeout, and retry interval.
- Per-certificate OS lock plus same-process lock set; global and per-issuer semaphores.
- Stable renewal jitter, capped retry backoff, expiry alerts at 30/14/7/3/1/0 days, and durable idempotent operator renewal requests.
- Managed certificate candidate validation, age-encrypted immutable generations, versioned current/previous pointer, and production/staging provenance.
- Prepare-before-persist runtime publication; publication serialized with config activation and guarded against stale order policy.
- Missing/expired managed identities start fail-closed while renewal remains possible. Corrupt/mismatched persisted state fails startup.
- CLI `cert status` and `cert renew` commands.
- Local loopback-only, digest-pinned Pebble/challtestsrv interoperability harness.
- ACME operations, staging promotion, account rollover, revocation-response, backup, and recovery guidance.

## 4. Deferred scope

- Authenticated ACME administrative REST endpoints: Phase 8 with common private transport, authentication, RBAC, audit, rate/body/time limits, and concurrency controls.
- Prometheus/OpenTelemetry ACME metrics and durable alert rules: Phase 9.
- Web UI: Phase 10 only if approved.
- Providers beyond Cloudflare: demand-driven compile-time additions after review.
- In-place RFC account-key rollover CLI and ACME certificate revocation API.
- ACME Renewal Information consumption; deterministic fallback scheduling is active.
- OCSP stapling pending evidence and Rustls/provider evaluation.
- Multi-node certificate ownership and shared issuance: Phase 12.
- HTTP/3, UDP, runtime plugins, and clustering remain out of v1 scope.

## 5. Architecture decisions

- ADR-0009: immutable age-encrypted certificate generations and atomic pointers.
- ADR-0010: `instant-acme 0.8.5` behind a narrow adapter with an owned bounded transport.
- ADR-0011: REST administration remains Phase 8; Phase 6 does not create an ad hoc endpoint.
- One process owns accounts, orders, renewals, challenges, persistence, and resolver publication.
- Durable certificate pointer changes before an already-prepared, non-failing runtime resolver swap.
- Cloudflare is the only production DNS provider. Pebble challtestsrv is test-only.

Plan correction `85a4bfa` resolved a verified phase contradiction. Building an ACME-specific API in Phase 6 would lack Phase 8 authentication/audit controls; moving the entire admin plane early would expand scope. Local CLI/status plus Phase 8 REST was selected.

## 6. Files created

- `crates/proxy-core/src/acme_manager.rs`
- `crates/proxy-tls/src/acme/{mod,account,challenge,client,dns_provider,order,scheduler,transport}.rs`
- `crates/proxy-tls/tests/pebble.rs`
- `docs/operations/acme.md`
- `tests/pebble/compose.yml`
- `tests/pebble/pebble.minica.pem` (public test CA only; no private key)
- This report.

## 7. Files modified

- `.gitignore`, `Cargo.lock`, `README.md`, `PLAN.md`
- `crates/proxy-config/{Cargo.toml,src/lib.rs,src/redact.rs,src/revision.rs}`
- `crates/proxy-core/{Cargo.toml,src/lib.rs,src/route.rs,src/runtime.rs,tests/grpc.rs}`
- `crates/proxy-secrets/src/lib.rs`
- `crates/proxy-tls/{Cargo.toml,src/acceptor.rs,src/generation.rs,src/lib.rs,src/selector.rs}`
- `crates/rust-proxy/src/main.rs`, `crates/rust-proxy/tests/cert_cli.rs`
- `docs/adr/{0009-certificate-storage,0010-acme-client,0011-admin-api}.md`
- `docs/{configuration-v1,dependencies}.md`

## 8. Dependencies added

- `instant-acme 0.8.5`: ACME account/order protocol; defaults disabled, AWS-LC and Hyper/Rustls only.
- `rcgen 0.14`: CSR/private-key generation and ephemeral TLS-ALPN challenge certificates.
- `time 0.3`: bounded ephemeral certificate validity.
- Direct TLS-crate use of existing workspace HTTP/Hyper body, Hyper-Rustls, Tokio, URL, JSON, zeroize, bytes, and `fs2` capabilities.
- `age` as a configuration test dependency for valid generated public recipients.
- `proxy-core -> proxy-secrets` for approved secret resolution.

No Git dependency or runtime scripting/subprocess dependency was added. Direct dependency purpose, license, native/unsafe surface, alternative, and policy are recorded in `docs/dependencies.md`.

## 9. Configuration introduced

- `[acme].max_concurrent_orders`
- `[[acme.issuers]]`: ID, exact directory, environment, contact, explicit terms, custom CA, optional EAB, order bound.
- `[[acme.certificates]]`: ID, hosts, issuer, challenge, listener/provider, optional profile, renewal lead.
- `[[acme.dns_providers]]`: tagged Cloudflare provider with explicit zone and token secret reference.
- `[tls].identity` and `state_encryption_recipients` are mandatory when ACME certificates exist.

All ACME secret-bearing fields accept only `env://NAME` or absolute `file:///path`. Preview redacts the references.

## 10. Tests added

- Strict ACME parsing, unknown fields, terms acceptance, counts, references, wildcard/challenge combinations, listener protocol, custom CA/EAB, recipients, and redaction.
- Account credential bounds/redaction, create policy, encryption/decryption, wrong identity/directory, immutable generation rotation, and previous retention.
- Order input, stage transitions, token/key authorization redaction, CSR/key handling, issued key/name/chain verification.
- Bounded/same-origin transport response and timeout tests.
- HTTP-01 collision, capacity, expiry, exact path/listener/host/token, and response isolation.
- TLS-ALPN collision, exact SNI, critical extension, ALPN, expiry, and reload retention.
- Cloudflare request origin/path/body, exact record adoption, ambiguous record rejection, bounded response, and cleanup.
- Renewal scheduling, retry cap/jitter, expiry alerts, durable request marker, cross-handle lock, and same-process single-flight.
- Managed generation wrong-name/key/expiry/staging/shorter-candidate rejection, previous retention, and atomic resolver preparation/publication.
- Missing managed identity fail-closed then atomic publication.
- CLI status and idempotent manual-renew request integration tests.
- Pebble account create/restore, three accelerated cycles each of HTTP-01, wildcard DNS-01, and TLS-ALPN-01, issued identity verification, cleanup, and invalid HTTP-01 rejection.

## 11. Commands executed

Final required gate:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo tree -e features
```

Pebble gate:

```text
docker compose -f tests/pebble/compose.yml config --quiet
docker compose -f tests/pebble/compose.yml up -d
cargo test -p aegisproxy-tls --test pebble -- --ignored --nocapture
docker compose -f tests/pebble/compose.yml down
```

Dependency tools probed:

```text
cargo audit --version
cargo deny --version
```

Focused config, TLS, core, CLI, and individual regression tests were also run after their logical changes.

## 12. Actual command results

- Format: passed.
- Workspace check/all targets: passed.
- Workspace Clippy/all targets/all features with warnings denied: passed.
- Workspace tests/all features: passed; 167 passed, 0 failed, 2 ignored. Ignored tests were the manual reload benchmark and explicit local Pebble test.
- Pebble explicit ignored test: passed in 5.79 seconds; nine valid orders plus one invalid authorization case.
- Docker Compose validation/start/stop: passed. Only the disposable `aegisproxy-pebble` containers/network were removed; no volume exists.
- Feature-tree resolution: passed (`exit 0`).
- `cargo audit`: unavailable (`cargo: no such command`, exit 101). No audit success is claimed.
- `cargo deny`: unavailable (`cargo: no such command`, exit 101). No deny/license-policy execution success is claimed.
- Known GNU Windows linker message during tests: `corrupt .drectve at end of def file`. It did not fail linking or Clippy and remains an environment/toolchain risk.
- Rust reported future incompatibility in transitive `proc-macro-error2 2.0.1`; it is not ignored as resolved.

## 13. Security checks

- No production CA or real DNS credential was used.
- Pebble/challtestsrv ports bind only to `127.0.0.1`; images are pinned by immutable multi-architecture digest.
- The committed Pebble file is a public test CA certificate only.
- Key/token canaries are absent from Debug output and preview tests.
- Wildcard HTTP-01/TLS-ALPN-01 is rejected in config and order validation.
- Cross-origin ACME endpoints, credentialed endpoints, remote plaintext directories, malformed credentials, oversized responses/material, invalid tokens, collision/capacity overflow, wrong key/name/expiry, and staging-over-production replacements fail closed.
- DNS tokens stay in redacted secret wrappers; provider requests use one fixed HTTPS origin and explicit zone.
- Existing valid material is retained until a candidate is completely validated and durably committed.
- Own crates continue to forbid unsafe code. No project unsafe block was introduced.

Internal ACME/key review covered order sequencing, secret lifetime, challenge isolation, bounded work, cleanup, crash/lock behavior, durable ordering, stale-config publication, and recovery documentation. This is not an independent external review.

## 14. Performance checks

- Three accelerated issuance cycles for each challenge completed locally in 5.79 seconds total under Pebble.
- No production throughput, CA latency, DNS-provider latency, or long-duration renewal benchmark was performed. No performance claim is made.
- Order, response, resolver, scheduler, semaphore, queue, challenge, state, and polling resources have explicit bounds.

## 15. Known limitations

- Only Cloudflare DNS-01 is implemented for production use.
- No ARI, in-place account rollover, revocation client, OCSP stapling, or public-CA interoperability run exists yet.
- Pebble validates the protocol adapter; manager orchestration is tested separately rather than through one full daemon-to-Pebble black-box test.
- Phase 9 metrics/alert exports are absent; current signals are structured logs and CLI status.
- Phase 8 authenticated admin endpoints are absent by design.
- The local full gate ran on Windows GNU, not the required later Linux/cross-platform CI matrix.
- `cargo-audit` and `cargo-deny` were unavailable.

## 16. Residual risks

- **High / medium likelihood:** external age identity loss makes encrypted account/key state unrecoverable. Mitigation: separate backup and restore drill. Owner: operations/security.
- **High / low likelihood:** ACME/library/protocol defect publishes wrong material. Mitigation: host/key/validity/provenance validation, durable previous generation, Pebble regression, independent review before release. Owner: TLS/security.
- **High / low likelihood:** DNS credential compromise changes zone records. Mitigation: one-zone least-privilege token, secret injection, token rotation, no global API key. Owner: operations/security.
- **Medium / medium likelihood:** Cloudflare API or CA behavior changes. Mitigation: pinned client, bounded adapter, exact response validation, staging tests, controlled upgrades. Owner: dependency/TLS maintainers.
- **Medium / medium likelihood:** cleanup failure leaves stale TXT data. Mitigation: activation fails, exact record ID retained for cleanup attempt, high-signal log and manual runbook. Owner: operations.
- **Medium / low likelihood:** process crash occurs after durable pointer change and before runtime publication. Mitigation: restart loads validated durable pointer; old connections retain old resolver Arc until exit. Owner: runtime/TLS.
- **Medium / medium likelihood:** unavailable audit/license tooling hides dependency risk. Mitigation: CI installation and Phase 14 release gate. Owner: supply-chain maintainer.

## 17. Acceptance-criteria checklist

- [x] Renewal scheduler alerts at documented 30/14/7/3/1/0-day windows.
- [x] Simulated issuance failure does not produce a certificate; storage/replacement/reload failures retain prior valid material in their focused tests.
- [x] HTTP/TLS leases and DNS cleanup remove stale challenge state; cleanup failure blocks activation and is logged.
- [x] Wildcards cannot select HTTP-01 or TLS-ALPN-01.
- [x] No production CA is contacted by tests or CI defaults.
- [x] HTTP-01, DNS-01 wildcard, and TLS-ALPN-01 interoperate with local Pebble.
- [x] Multiple explicit issuer/account configurations and environment binding validate; account state is directory/environment bound.
- [x] Manual renewal is durable/idempotent and the daemon remains the only ACME owner.
- [x] Working certificate publication is atomic and stale configuration cannot publish.

## 18. Exit-criteria checklist

- [x] Internal ACME/key expert review completed and residual risks recorded.
- [x] Multi-cycle accelerated local renewal-like soak completed: three cycles for all three challenges.
- [x] Full required Rust workspace gate passed.
- [x] Local Pebble test passed without production CA access.
- [x] Configuration and operations documentation matches implementation.

Later release gates remain: independent external ACME/protocol/key review in Phase 13 and a long-duration renewal soak against Linux release builds in Phase 13/14. They are not claimed by this phase's internal review or accelerated exit soak.

## 19. Commit list

- `4ebe319 feat(acme): isolate HTTP-01 challenges`
- `f744ab5 feat(acme): serve isolated HTTP-01 responses`
- `e95f335 feat(acme): add client dependency boundary`
- `9c6f60f feat(config): add strict ACME schema`
- `2773f22 feat(acme): encrypt account credentials`
- `3fa1aaf feat(acme): schedule bounded renewals`
- `d0c750e feat(acme): persist account generations`
- `efe1cdc fix(config): require ACME terms agreement`
- `3d660f3 feat(acme): create bounded accounts`
- `baafd0f security(acme): bound CA transport`
- `473ca4a feat(acme): enforce order stages`
- `60ba1b4 feat(acme): verify issued material`
- `e4357e3 feat(tls): version certificate pointers`
- `07f49ce feat(tls): rotate managed generations`
- `f909e20 feat(acme): isolate TLS-ALPN challenges`
- `695be03 feat(acme): add Cloudflare DNS provider`
- `d9fe7a6 fix(acme): retain TLS challenges on reload`
- `8536cb9 feat(acme): lock certificate orders`
- `ccf6f6a feat(tls): prepare managed publication`
- `ddbd462 feat(acme): activate bounded certificate manager`
- `c54ebdc feat(acme): add renewal control commands`
- `ea2bb1a feat(acme): expose TLS challenge response`
- `2b34ecb test(acme): add Pebble interoperability`
- `ecf9017 docs(acme): add operations runbook`
- `f06a4c8 test(acme): exercise renewal cycles`
- `85a4bfa docs(plan): align ACME admin phase`

The separate phase-report commit is the next commit after this list.

## 20. Readiness for the next phase

Phase 6 implementation and its phase-specific exit evidence are complete. Independent review and long soak remain release gates, not claims of production readiness. The working tree was clean before this report. Phase 7 may implement only the fixed-order middleware/authentication scope; it must not add the deferred admin API, UI, clustering, UDP, HTTP/3, or arbitrary plugins.
