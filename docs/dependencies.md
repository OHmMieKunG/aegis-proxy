# Direct dependency inventory

Versions are locked in `Cargo.lock` and must be re-reviewed on upgrade. The table records the
2026-07-19 review unless a row carries a newer date. On 2026-07-22, `cargo tree -e features`
completed; `cargo audit` and `cargo deny check` were unavailable in this environment and therefore
were not re-verified. See [`STATUS.md`](../STATUS.md).

| Crate | Purpose | Features | License | Native/unsafe surface | Alternative | Upgrade policy |
|---|---|---|---|---|---|---|
| tokio | Async runtime, sockets, signals, timers | `macros`, `net`, `rt-multi-thread`, `signal`, `sync`, `time` | MIT | Platform integration; transitive unsafe reviewed | async-std | Stable compatible releases, full CI |
| hyper | HTTP protocol/client/server | `full` in initial spike; reduce before release | MIT | No first-party unsafe policy exception | Pingora | Pin lockfile, protocol regression tests |
| http | Canonical HTTP method/header validation shared by config and proxy boundaries | default | MIT/Apache-2.0 | No native code; transitive unsafe review | custom parsers | Review with Hyper releases |
| hyper-util | Tokio adapters, client pooling | Client/server HTTP1/2/Tokio features | MIT | Transitive audit | direct hyper | Review with hyper |
| http-body/http-body-util | Bounded streaming body traits, combinators, collectors, and length limiter | default | MIT | No native code; transitive unsafe review | hand-written body polling | Review with Hyper releases; retain ACME oversized-body regression |
| serde/toml | Typed strict config and preview | derive | MIT/Apache-2.0 | Proc macros; audited | JSON-only | Lockfile/advisory gate |
| url/ipnet | URL and CIDR parsing | serde | MIT/Apache-2.0 | None expected | custom parsers | Keep standard parsers |
| rustls/rustls-pki-types | TLS and strict mixed-section PEM parsing | `aws_lc_rs`, `std`, `tls12`; defaults disabled | Apache-2.0/MIT/ISC | Crypto provider/native build reviewed | OpenSSL | Security advisory gate |
| tokio-rustls | Async Rustls accept/connect adapters | `aws_lc_rs`, `tls12` | MIT/Apache-2.0 | AWS-LC native build | manual Tokio adapter | Review with Rustls |
| hyper-rustls | Verified pooled HTTPS/H2 upstream connections | `aws-lc-rs`, `http1`, `http2`, `tls12`, `webpki-tokio` | Apache-2.0/ISC/MIT | Rustls/AWS-LC native build | custom connector | Review with Hyper and Rustls |
| hickory-resolver | Bounded async A/AAAA resolution and TTL metadata | `system-config`, `tokio`; defaults/TLS/DNSSEC disabled | MIT/Apache-2.0 | No native code in selected features; transitive safe/unsafe review required | system resolver, custom DNS client | Pin 0.26 lockfile; resolver/rebinding tests and advisory gate on upgrade |
| getrandom | Cryptographically random request IDs and 256-bit administrative API tokens from the operating system | default | MIT/Apache-2.0 | Platform syscalls and small reviewed platform-specific unsafe surface; no native library | AWS-LC RNG, `rand` | Pin 0.3 lockfile; fail closed if the OS RNG fails; advisory gate on upgrade |
| fs2 | Cross-platform exclusive state-directory and per-certificate order locks on MSRV 1.88 | default | MIT/Apache-2.0 | Platform locking through libc/Windows APIs; no project unsafe | stale create-new lockfile, newer std lock API above current MSRV | Pin 0.4 lockfile; multi-owner and crash-release tests |
| sha2 | SHA-256 revision identity and configuration change detection | default | MIT/Apache-2.0 | Pure Rust selected path; transitive review | AWS-LC digest, blake3 | Pin 0.10 lockfile; tamper and reload tests |
| hmac | HMAC-SHA256 administrative audit-chain authentication | default | MIT/Apache-2.0 | Pure Rust; no native code | AWS-LC HMAC, keyed BLAKE3 | Pin 0.12 lockfile; tamper and key-rotation tests |
| serde_json | Strict revision metadata and pointer serialization | default | MIT/Apache-2.0 | No native code; parser input remains bounded | TOML metadata | Track with Serde; bounded unknown-field tests |
| tower-service | Custom Hyper DNS resolver service contract | default | MIT | No native code; no known direct unsafe surface | direct connector implementation | Track with Hyper utility stack |
| webpki-roots | Mozilla-derived default upstream trust-anchor data | default | CDLA-Permissive-2.0 | Static data; no native code | OS trust store | Preserve license notices; review root and license updates with Rustls releases |
| rustls-webpki | Certificate metadata, path, validity, and name validation | `aws-lc-rs`, `std` | ISC | AWS-LC native build | Rustls verifier internals | Review with Rustls |
| x509-parser | Bounded certificate issuer/validity metadata | no optional features | MIT/Apache-2.0 | Crate forbids unsafe; untrusted ASN.1 parser | custom DER parser | Pin; retain parser/fuzz review on upgrade |
| rcgen | ACME CSRs plus ephemeral TLS test certificates | `aws_lc_rs`, `crypto`, `pem` | MIT/Apache-2.0 | AWS-LC native build; private-key generation runs off Tokio workers | instant-acme `rcgen` feature, custom PKCS#10 | Review with Rustls; retain CSR/key-match and Pebble tests |
| time | Explicit short validity windows for ephemeral TLS-ALPN-01 certificates | `std`; defaults disabled | MIT/Apache-2.0 | No native code; crate unsafe policy reviewed transitively | rcgen default validity | Pin 0.3 lockfile; retain validity-bound TLS-ALPN tests |
| futures-util | Fallible streaming body adapters plus multi-frame gRPC tests | default | MIT/Apache-2.0 | No project unsafe; transitive review | custom stream adapter | Lockfile pin; review features on upgrade |
| proptest (dev) | Shrinking property tests for route determinism and canonicalization | `std`; fork/timeout/bit-set disabled | MIT/Apache-2.0 | Test-only transitive surface; no runtime code | hand-written case matrices | Pin lockfile; keep bounded case counts and inputs |
| libfuzzer-sys (dev, fuzz workspace only) | LLVM libFuzzer runtime for eight security parser and canonicalizer targets | default | MIT/Apache-2.0/NCSA | Test-only C++/LLVM sanitizer runtime; never linked into release binary | honggfuzz, AFL++ | Pin fuzz lockfile; review runner/nightly compatibility before campaigns |
| zeroize | Clear owned secret, password, and one-time API-token buffers on drop | `std` | Apache-2.0/MIT | Safe API; compiler optimization limits documented | manual volatile clearing | Review with secret-boundary changes |
| age | X25519 encrypted private-key envelopes and authenticated state backups | no optional features | Apache-2.0/MIT | Pure-Rust cryptography with audited unsafe/transitive surface | custom AEAD envelope | Pin lockfile; restore, backup-tamper, and interoperability tests |
| instant-acme | Async RFC 8555 accounts, orders, and challenge protocol | `aws-lc-rs`, `hyper-rustls`; defaults disabled | Apache-2.0 | Reuses existing AWS-LC native crypto and Hyper/Rustls transport; transitive review required | rustls-acme, external Certbot, custom protocol | Pin 0.8.5; Pebble regression, advisory, API, and MSRV review before upgrade |
| arc-swap | Atomic immutable certificate/runtime snapshots | default | Apache-2.0/MIT | Small unsafe internals implementing atomic pointer ownership | `RwLock<Arc<_>>` | Concurrency tests; review upgrades |
| argon2 | Bounded Basic-auth verification and hash-only administrative API-token records using Argon2id PHC hashes | `alloc`, `password-hash`; defaults disabled | MIT/Apache-2.0 | Pure Rust; memory/CPU cost comes from validated hash parameters | external ForwardAuth only | Pin 0.5.3; advisory/MSRV review and auth timing/resource tests |
| base64 | Strict HTTP Basic decoding and URL-safe administrative token encoding | `alloc`; defaults disabled | MIT/Apache-2.0 | No native code; small parser surface | handwritten encoder/decoder | Pin 0.22 lockfile; malformed-input regression tests |
| async-compression | Streaming gzip and Brotli response encoders | `tokio`, `gzip`, `brotli`; defaults disabled | MIT/Apache-2.0 | Pure-Rust selected codecs; CPU work uses a default four-slot policy and aggregate 64-slot cap | no v1 compression, handwritten codecs | Pin 0.4.42; advisory/MSRV review, exclusion and resource tests |
| axum | Private Unix-socket administrative HTTP API, typed routing, bounded JSON/query extractors, and graceful shutdown | `http1`, `json`, `query`, `tokio`; defaults disabled | MIT | No project unsafe; reuses audited Hyper/Tokio stack | raw Hyper services | Pin 0.8.9 lockfile; API/RBAC/resource-limit tests and advisory gate on upgrade |
| prometheus-client | Typed OpenMetrics registry with explicit bounded label sets | defaults disabled | Apache-2.0/MIT | No native code; transitive synchronization/derive code reviewed through lockfile | custom text encoder, metrics facade | Pin 0.25.0; contract/cardinality tests and advisory gate on upgrade |
| opentelemetry | W3C trace-context propagation and trace API | `trace`; defaults disabled | Apache-2.0 | No native code; transitive synchronization surface | tracing-only correlation | Pin 0.32.0; propagation and redaction regressions on upgrade |
| opentelemetry_sdk | Parent-aware sampling and bounded batch span processing | `trace`; defaults disabled | Apache-2.0 | No native code; bounded worker thread and queue | synchronous exporter, no trace export | Pin 0.32.1; exporter-outage and shutdown tests on upgrade |
| opentelemetry-otlp | Optional OTLP/HTTP protobuf trace exporter using Rustls roots | `http-proto`, `reqwest-blocking-client`, `reqwest-rustls-webpki-roots`, `trace`; defaults disabled | Apache-2.0 | Pure-Rust HTTP/TLS selected path; protobuf and HTTP transitive surface | external log-only tracing, gRPC OTLP | Pin 0.32.0; collector interoperability, advisory, feature-tree, and MSRV review on upgrade |
| tracing-opentelemetry | Bridge structured request spans to OpenTelemetry | defaults disabled | MIT | No native code; no project unsafe | direct OpenTelemetry span construction | Pin 0.33.0; verify compatibility with tracing and OpenTelemetry upgrades |
| tracing/tracing-subscriber | Structured logs | JSON/env filter | MIT | None expected | log | Keep exporter bounded |
| clap | CLI parsing | derive | MIT/Apache-2.0 | None expected | std::env | Stable CLI contract |
| thiserror | Typed internal errors | default | MIT/Apache-2.0 | Proc macro | manual impl | Keep small |

`cargo tree -e features`, `cargo audit`, `cargo deny check`, source/license review, and transitive
unsafe review are release gates. Phase 21 must make them reproducible in CI. No Git dependency is
permitted.
