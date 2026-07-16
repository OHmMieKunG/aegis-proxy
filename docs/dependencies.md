# Direct dependency inventory

Phase 0 inventory; versions are locked in `Cargo.lock` and must be re-reviewed on upgrade.

| Crate | Purpose | Features | License | Native/unsafe surface | Alternative | Upgrade policy |
|---|---|---|---|---|---|---|
| tokio | Async runtime, sockets, signals, timers | `macros`, `net`, `rt-multi-thread`, `signal`, `sync`, `time` | MIT | Platform integration; transitive unsafe reviewed | async-std | Stable compatible releases, full CI |
| hyper | HTTP protocol/client/server | `full` in initial spike; reduce before release | MIT | No first-party unsafe policy exception | Pingora | Pin lockfile, protocol regression tests |
| hyper-util | Tokio adapters, client pooling | Client/server HTTP1/2/Tokio features | MIT | Transitive audit | direct hyper | Review with hyper |
| http-body-util | Streaming body combinators | default | MIT | None expected | custom body types | Review with hyper |
| serde/toml | Typed strict config and preview | derive | MIT/Apache-2.0 | Proc macros; audited | JSON-only | Lockfile/advisory gate |
| url/ipnet | URL and CIDR parsing | serde | MIT/Apache-2.0 | None expected | custom parsers | Keep standard parsers |
| rustls/rustls-pemfile | TLS and certificate parsing | Phase 2 selected provider | Apache-2.0/MIT/ISC | Crypto provider/native build reviewed | OpenSSL | Security advisory gate |
| tokio-rustls | Async Rustls accept/connect adapters | `aws_lc_rs`, `tls12` | MIT/Apache-2.0 | AWS-LC native build | manual Tokio adapter | Review with Rustls |
| rustls-webpki | Certificate metadata, path, validity, and name validation | `aws-lc-rs`, `std` | ISC | AWS-LC native build | Rustls verifier internals | Review with Rustls |
| rcgen (dev) | Ephemeral TLS test certificates | `aws_lc_rs`, `crypto`, `pem` | MIT/Apache-2.0 | AWS-LC native build | checked-in private fixtures | Test-only, review with Rustls |
| zeroize | Clear owned secret buffers on drop | `std` | Apache-2.0/MIT | Safe API; compiler optimization limits documented | manual volatile clearing | Review with secret-boundary changes |
| age | X25519 encrypted private-key envelopes | no optional features | Apache-2.0/MIT | Pure-Rust cryptography with audited unsafe/transitive surface | custom AEAD envelope | Pin lockfile; restore and interoperability tests |
| arc-swap | Atomic immutable certificate/runtime snapshots | default | Apache-2.0/MIT | Small unsafe internals implementing atomic pointer ownership | `RwLock<Arc<_>>` | Concurrency tests; review upgrades |
| axum | Private admin REST API | Phase 8 | MIT | Safe first-party policy | raw hyper | Add only Phase 8 |
| tracing/tracing-subscriber | Structured logs | JSON/env filter | MIT | None expected | log | Keep exporter bounded |
| clap | CLI parsing | derive | MIT/Apache-2.0 | None expected | std::env | Stable CLI contract |
| thiserror | Typed internal errors | default | MIT/Apache-2.0 | Proc macro | manual impl | Keep small |

`cargo tree -e features`, `cargo audit`, `cargo deny check`, source/license review, and transitive unsafe review are Phase 0/CI gates. No Git dependency is permitted.
