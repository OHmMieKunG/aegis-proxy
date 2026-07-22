# Phase 2: TLS termination and certificate loading

> Historical document — records phase evidence at completion time. See [`STATUS.md`](../../../STATUS.md) for current verification.

## 1. Phase title

TLS termination and certificate loading.

## 2. Original objectives

Add HTTP/2 over ALPN, secure Rustls termination, deterministic SNI certificate selection, verified HTTPS upstreams, and a bring-your-own encrypted certificate lifecycle without expanding into ACME.

## 3. Implemented scope

- Rustls TLS 1.2/1.3 termination with explicit AWS-LC provider selection.
- ALPN negotiation for HTTP/2 and HTTP/1.1 with bounded handshakes and HTTP/2 streams.
- Exact SNI selection before single-label wildcard selection; unknown names have no default-certificate fallback.
- Certificate-chain, private-key, key-pair, validity-period, and hostname-coverage validation.
- SNI versus HTTP authority enforcement with `421 Misdirected Request` on mismatch.
- Verified HTTPS upstream pools with WebPKI roots or endpoint-scoped custom CA roots.
- Endpoint-scoped client pools isolate SNI and trust policy; no certificate-verification bypass exists.
- gRPC unary and streaming forwarding over verified HTTP/2, including frames, deadlines, and response trailers.
- Atomic in-memory certificate-map replacement while existing `Arc` owners retain the previous map.
- Immutable first-import certificate generations encrypted with age X25519 recipients.
- Bounded, redacted `env://` and absolute `file://` secret providers.
- `cert import`, `cert list`, and `cert inspect`; inspect can decrypt and fully revalidate a stored identity offline.
- Operator key-recovery and restore procedure.
- A strict TLS configuration example covering downstream and verified custom-CA upstream TLS.

## 4. Deferred scope

ACME, renewal scheduling, OCSP stapling, HTTP/3, certificate replacement/rotation for an existing identity, automatic expiry background jobs, and external TLS-scanner integration remain deferred. No web UI, database, clustering, or runtime plugin work was introduced.

## 5. Architecture decisions

- ADR 0002 now records Rustls with the AWS-LC provider, TLS 1.2/1.3 only, and explicit provider installation.
- Private keys are accepted by the runtime only through age-encrypted envelopes; plaintext key references cannot activate TLS.
- Bundled WebPKI roots are the default upstream trust source. A configured CA bundle replaces, rather than supplements, those roots for that endpoint.
- Certificate identity maps use atomic snapshot replacement. Disk generations are immutable and a failed candidate cannot alter the active pointer.
- The initial import path rejects an already-existing identity rather than pretending to provide safe rotation before the reload phase.

## 6. Files created

- `crates/proxy-tls/src/acceptor.rs`
- `crates/proxy-tls/src/client.rs`
- `crates/proxy-tls/src/generation.rs`
- `crates/proxy-tls/src/selector.rs`
- `crates/proxy-tls/src/store.rs`
- `crates/proxy-secrets/src/envelope.rs`
- `crates/proxy-core/tests/grpc.rs`
- `crates/rust-proxy/tests/cert_cli.rs`
- `config/examples/tls.toml`
- `docs/tls-key-recovery.md`

## 7. Files modified

- Workspace and affected crate `Cargo.toml` files and `Cargo.lock`.
- `crates/proxy-config/src/lib.rs`
- `crates/proxy-core/src/lib.rs`
- `crates/proxy-secrets/src/lib.rs`
- `crates/proxy-tls/src/lib.rs`
- `crates/rust-proxy/src/main.rs`
- Rustls ADR and dependency inventory.

## 8. Dependencies added

- `hyper-rustls 0.27.9`: verified upstream HTTPS and HTTP/2 connector.
- `webpki-roots 1.0.8`: explicit bundled public trust roots.
- `x509-parser 0.18.1`: bounded certificate metadata and hostname inspection.
- `age 0.11.5`: X25519 private-key envelope encryption.
- `arc-swap`: non-failing atomic certificate-map publication.
- `futures-util` as a development dependency for protocol test fixtures.

The dependency inventory records purpose, feature scope, license, native/unsafe exposure, alternatives, and upgrade policy. `Cargo.lock` is committed.

## 9. Configuration introduced

TLS listeners reference certificate identities. Identities declare validated host coverage plus certificate-chain and age-encrypted private-key secret references. HTTPS endpoints require explicit host, port, SNI, and an optional explicit CA-bundle reference. TLS handshake concurrency/timeouts and HTTP/2 concurrent-stream limits are bounded. Portable offline validation accepts absolute POSIX and drive-qualified Windows file references; runtime resolution still requires a path absolute on the executing platform.

## 10. Tests added

- Secret-reference parsing, portability, bounds, redaction, file permissions, and age encryption/decryption.
- Certificate/key matching, hostname coverage, validity, malformed input, exact/wildcard precedence, and unknown-name rejection.
- TLS 1.2 and TLS 1.3 handshake matrix plus H1/H2 ALPN.
- Atomic certificate-map swap with an existing connection retaining its previous key snapshot.
- Encrypted generation import, tamper detection, restart/load, expiry scan primitive, and offline recovery.
- Verified custom-CA HTTPS upstream and downstream gRPC/H2 unary/streaming scenarios with trailers.
- CLI import/list/inspect/recovery workflow.
- Portable strict TLS example validation through the real CLI.

## 11. Commands executed

- `cargo fmt --all -- --check` — passed.
- `cargo check --workspace --all-targets` — passed on the configured Windows GNU toolchain during Phase 2.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed after the final path-portability fix.
- Targeted secret, TLS, proxy-core, gRPC, and certificate-CLI tests — passed.
- `cargo test --workspace --all-features` — individual Windows binaries pass; the combined Windows GNU run is not claimed stable because of the local linker defect described below.
- `docker build --target test .` — exited 0 on the final source; the final test layer was cached from the preceding successful Linux workspace run.
- `rust-proxy validate --config config/examples/tls.toml` — passed.
- `docker compose config --quiet` — passed.
- `cargo audit --version` and `cargo deny --version` — previously verified unavailable; no audit or deny success is claimed.

## 12. Actual command results

The authoritative Linux container run passed 48 tests: eight configuration tests, 21 proxy-core unit/integration tests, one gRPC integration test, five secret tests, 12 TLS tests, and one certificate-CLI integration test; documentation tests also passed. The final cached Docker test-stage build exited 0. The strict workspace Clippy and formatting checks exited 0 after the last code change. The checked-in TLS example validates through the real CLI.

On this machine, the Windows GNU linker intermittently emits a corrupted `.drectve` artifact that can produce a pre-test access violation in the combined workspace run. Isolated Windows test binaries pass and the Linux Docker suite is clean. This is recorded as environment/toolchain instability, not hidden as an application success.

Cargo also reports that transitive `proc-macro-error2 2.0.1` may become incompatible with a future Rust release. It is not a present test failure and must be tracked during dependency upgrades.

## 13. Security checks

- No plaintext runtime private-key fallback exists.
- Private-key canaries are covered by redaction tests and are absent from CLI output.
- Failed certificate validation/import does not replace a working in-memory map or disk generation.
- Unknown SNI cannot receive another tenant's certificate.
- Upstream TLS always verifies chains and configured server names.
- Custom trust roots are scoped per endpoint and connection pool.
- Secret input, certificate files, generation files, handshakes, streams, and inspect output are bounded.
- Unix secret and state permissions are checked/set where supported.

This work has not received the independent TLS and secret-storage expert review required before production use.

## 14. Performance checks

No performance benchmark was run and no throughput, latency, handshake-rate, or capacity claim is made. Tests establish bounded behavior and protocol correctness only. Reproducible performance baselines remain assigned to the later performance phase.

## 15. Known limitations

- Existing certificate identities cannot yet be rotated through the CLI; duplicate IDs fail closed.
- Expiry scanning is an implemented/tested primitive, not a scheduled alerting task.
- A human-operated restore drill has not been executed; automated offline decrypt/revalidate recovery passes.
- Windows ACL equivalence is not programmatically enforced; Unix mode checks are implemented.
- The public trust source is bundled WebPKI roots, not the operating-system store.
- No OCSP stapling, ACME, HTTP/3, or external cipher-scanner job exists.

## 16. Residual risks

TLS and X.509 interoperability require independent review against diverse real clients and certificate chains. age identity loss makes encrypted keys unrecoverable, so operators must maintain tested split-custody backups. The immutable store needs transactional rotation and last-known-good pointer handling in later phases. The Windows GNU linker instability can obscure local aggregate-test results. Dependency auditing and license policy automation remain unavailable until their tools are installed.

## 17. Acceptance-criteria checklist

- [x] TLS 1.2 and TLS 1.3 handshake matrix passes.
- [x] H1 and H2 ALPN behavior passes.
- [x] Exact certificate names precede wildcard names.
- [x] Unknown names fail without cross-tenant fallback.
- [x] Certificate/key/name/expiry validation passes covered positive and negative cases.
- [x] Plaintext private keys cannot activate TLS.
- [x] Failed candidates do not replace the working TLS map.
- [x] Atomic map swap preserves an existing holder of the previous snapshot.
- [x] Verified HTTPS upstream and gRPC/H2 unary/streaming tests pass.
- [x] Private-key material is redacted from CLI/debug output in covered paths.
- [x] Encrypted-store restart and offline recovery tests pass.
- [ ] External TLS scanner job exists; deferred to CI/release hardening.

## 18. Exit-criteria checklist

- [x] Mandatory Phase 2 implementation and automated acceptance checks are complete.
- [x] ACME, OCSP, and HTTP/3 remain outside Phase 2.
- [x] Automated key-recovery path is documented and tested.
- [ ] Independent TLS/secret-storage expert review is complete.
- [ ] Human restore drill is complete.

Phase 3 may begin because its routing/configuration work does not weaken or depend on falsely claiming these operational review gates. Production release remains blocked on both unchecked exit items.

## 19. Commit list

- `d29e815` — select and document the AWS-LC Rustls provider.
- `77e591d` — bound and redact secret reads.
- `b526b63` — add strict TLS identity schema.
- `bff9de1` — validate and select certificate identities.
- `2729f0d` — bound HTTP/2 streams.
- `df88dd7` — terminate TLS and negotiate HTTP/2 ALPN.
- `5fd367d` — require encrypted runtime private keys.
- `935e7db` — atomically replace certificate maps.
- `99b7c72` — verify HTTPS upstreams.
- `1718637` — store encrypted certificate generations.
- `787713d` — add certificate management CLI.
- `2a75069` — verify offline certificate recovery.
- `9e06aaa` — document key recovery.
- `230be8e` — preserve valid gRPC trailers.
- `2d59d0c` — cover TLS 1.2 and TLS 1.3.
- `61e1774` — validate portable secret file paths.
- `8a11aee` — add strict TLS configuration example.

## 20. Readiness for the next phase

The implemented TLS boundary is ready for Phase 3's schema freeze, route canonicalization, deterministic compilation, conflict analysis, preview, and redaction work. Phase 3 must preserve current fail-closed certificate references and must not introduce dynamic activation, ACME, query/regex routing, or arbitrary providers. The project is not production-ready.
