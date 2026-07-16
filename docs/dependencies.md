# Direct dependency inventory

Phase 0 inventory; versions are locked in `Cargo.lock` and must be re-reviewed on upgrade.

| Crate | Purpose | Features | License | Native/unsafe surface | Alternative | Upgrade policy |
|---|---|---|---|---|---|---|
| tokio | Async runtime, sockets, signals, timers | `macros`, `net`, `rt-multi-thread`, `signal`, `sync`, `time` | MIT | Platform integration; transitive unsafe reviewed | async-std | Stable compatible releases, full CI |
| hyper | HTTP protocol/client/server | `full` in initial spike; reduce before release | MIT | No first-party unsafe policy exception | Pingora | Pin lockfile, protocol regression tests |
| http | Canonical HTTP method/header validation shared by config and proxy boundaries | default | MIT/Apache-2.0 | No native code; transitive unsafe review | custom parsers | Review with Hyper releases |
| hyper-util | Tokio adapters, client pooling | Client/server HTTP1/2/Tokio features | MIT | Transitive audit | direct hyper | Review with hyper |
| http-body/http-body-util | Bounded streaming body traits, combinators, collectors, and length limiter | default | MIT | No native code; transitive unsafe review | hand-written body polling | Review with Hyper releases; retain ACME oversized-body regression |
| serde/toml | Typed strict config and preview | derive | MIT/Apache-2.0 | Proc macros; audited | JSON-only | Lockfile/advisory gate |
| url/ipnet | URL and CIDR parsing | serde | MIT/Apache-2.0 | None expected | custom parsers | Keep standard parsers |
| rustls/rustls-pemfile | TLS and certificate parsing | Phase 2 selected provider | Apache-2.0/MIT/ISC | Crypto provider/native build reviewed | OpenSSL | Security advisory gate |
| tokio-rustls | Async Rustls accept/connect adapters | `aws_lc_rs`, `tls12` | MIT/Apache-2.0 | AWS-LC native build | manual Tokio adapter | Review with Rustls |
| hyper-rustls | Verified pooled HTTPS/H2 upstream connections | `aws-lc-rs`, `http1`, `http2`, `tls12`, `webpki-tokio` | Apache-2.0/ISC/MIT | Rustls/AWS-LC native build | custom connector | Review with Hyper and Rustls |
| hickory-resolver | Bounded async A/AAAA resolution and TTL metadata | `system-config`, `tokio`; defaults/TLS/DNSSEC disabled | MIT/Apache-2.0 | No native code in selected features; transitive safe/unsafe review required | system resolver, custom DNS client | Pin 0.26 lockfile; resolver/rebinding tests and advisory gate on upgrade |
| fs2 | Cross-platform exclusive state-directory file lock on MSRV 1.85 | default | MIT/Apache-2.0 | Platform locking through libc/Windows APIs; no project unsafe | stale create-new lockfile, newer std lock API above current MSRV | Pin 0.4 lockfile; multi-owner and crash-release tests |
| sha2 | SHA-256 revision identity and configuration change detection | default | MIT/Apache-2.0 | Pure Rust selected path; transitive review | AWS-LC digest, blake3 | Pin 0.10 lockfile; tamper and reload tests |
| serde_json | Strict revision metadata and pointer serialization | default | MIT/Apache-2.0 | No native code; parser input remains bounded | TOML metadata | Track with Serde; bounded unknown-field tests |
| tower-service | Custom Hyper DNS resolver service contract | default | MIT | No native code; no known direct unsafe surface | direct connector implementation | Track with Hyper utility stack |
| webpki-roots | Mozilla-derived default upstream trust anchors | default | MPL-2.0 | Static data; no native code | OS trust store | Review root updates with Rustls releases |
| rustls-webpki | Certificate metadata, path, validity, and name validation | `aws-lc-rs`, `std` | ISC | AWS-LC native build | Rustls verifier internals | Review with Rustls |
| x509-parser | Bounded certificate issuer/validity metadata | no optional features | MIT/Apache-2.0 | Crate forbids unsafe; untrusted ASN.1 parser | custom DER parser | Pin; retain parser/fuzz review on upgrade |
| rcgen | ACME CSRs plus ephemeral TLS test certificates | `aws_lc_rs`, `crypto`, `pem` | MIT/Apache-2.0 | AWS-LC native build; private-key generation runs off Tokio workers | instant-acme `rcgen` feature, custom PKCS#10 | Review with Rustls; retain CSR/key-match and Pebble tests |
| futures-util (dev) | Multi-frame gRPC test bodies | default | MIT/Apache-2.0 | No project unsafe; transitive review | custom Body fixture | Test-only, track with futures |
| proptest (dev) | Shrinking property tests for route determinism and canonicalization | `std`; fork/timeout/bit-set disabled | MIT/Apache-2.0 | Test-only transitive surface; no runtime code | hand-written case matrices | Pin lockfile; keep bounded case counts and inputs |
| zeroize | Clear owned secret buffers on drop | `std` | Apache-2.0/MIT | Safe API; compiler optimization limits documented | manual volatile clearing | Review with secret-boundary changes |
| age | X25519 encrypted private-key envelopes | no optional features | Apache-2.0/MIT | Pure-Rust cryptography with audited unsafe/transitive surface | custom AEAD envelope | Pin lockfile; restore and interoperability tests |
| instant-acme | Async RFC 8555 accounts, orders, and challenge protocol | `aws-lc-rs`, `hyper-rustls`; defaults disabled | Apache-2.0 | Reuses existing AWS-LC native crypto and Hyper/Rustls transport; transitive review required | rustls-acme, external Certbot, custom protocol | Pin 0.8.5; Pebble regression, advisory, API, and MSRV review before upgrade |
| arc-swap | Atomic immutable certificate/runtime snapshots | default | Apache-2.0/MIT | Small unsafe internals implementing atomic pointer ownership | `RwLock<Arc<_>>` | Concurrency tests; review upgrades |
| axum | Private admin REST API | Phase 8 | MIT | Safe first-party policy | raw hyper | Add only Phase 8 |
| tracing/tracing-subscriber | Structured logs | JSON/env filter | MIT | None expected | log | Keep exporter bounded |
| clap | CLI parsing | derive | MIT/Apache-2.0 | None expected | std::env | Stable CLI contract |
| thiserror | Typed internal errors | default | MIT/Apache-2.0 | Proc macro | manual impl | Keep small |

`cargo tree -e features`, `cargo audit`, `cargo deny check`, source/license review, and transitive unsafe review are Phase 0/CI gates. No Git dependency is permitted.
