# Dependency and unsafe-code review

Review date: 2026-07-19  
Scope: release workspace at `7668f98`, plus Phase 13 dependency fixes in progress  
Owner: dependency maintainer; security owner must approve release exceptions

## Result

No first-party unsafe block, function, implementation, trait, or extern block was found. Every
owned crate root uses `#![forbid(unsafe_code)]`; fuzz entry points call owned safe APIs. This does
not prove transitive dependencies memory-safe.

All internal path dependencies now carry exact `=0.1.0` versions. No Git dependency or unknown
registry exists. `cargo tree -e features` resolves the selected feature graph. Duplicate versions
remain where independent upstream semver lines require them; `cargo-deny` reports them as warnings.

## High-impact transitive surface

| Surface | Why present | Containment and evidence | Residual risk |
|---|---|---|---|
| `aws-lc-sys` / CMake-built AWS-LC | Rustls crypto provider, certificate generation | Selected once by ADR-0003; no key logging; TLS, key-match, protocol, and fuzz tests | Native/FFI defects remain possible; require advisory and independent review |
| `arc-swap` unsafe internals | atomic immutable runtime/certificate snapshots | no owned unsafe; publication/concurrency/rollback tests | dependency ownership invariant defect could affect memory safety |
| OS bindings in Tokio, Mio, fs2, getrandom | sockets, locks, entropy | bounded use, error propagation, fail-closed RNG/lock behavior tests | kernel/platform binding defects |
| parsers (`toml`, Hyper, Rustls, x509-parser) | untrusted configuration/protocol/certificate inputs | strict bounds, regression suites, eight ASan fuzz targets | parser logic and resource-abuse defects |
| proc macros/build scripts | derives, localization, AWS-LC build | lockfiles, registry-only sources, release binary excludes tooling | build-host and supply-chain compromise |

## Advisory exception

| Advisory | Exposure | Exploitability | Mitigation | Upgrade blocker | Residual risk | Owner | Expiry |
|---|---|---|---|---|---|---|---|
| RUSTSEC-2026-0173 (`proc-macro-error2` unmaintained) | transitive build-time dependency through `age -> i18n-embed-fl`; not linked as request-processing logic | no vulnerability is reported; requires build dependency compromise or future unfixed defect | crates.io-only locked source, reproducible lock review, advisory checks; monitor `age` and localization chain | `age` 0.12.1 still depends on same macro and advisory reports no safe direct upgrade | maintenance/supply-chain response may lag | dependency maintainer | 2026-10-19 |

Expiry blocks release unless the dependency is removed/upgraded or a security owner renews the
exception with fresh evidence. No vulnerability advisory is ignored.

## License review

`webpki-roots` and `webpki-root-certs` contain Mozilla-derived trust-anchor data under
CDLA-Permissive-2.0. SPDX lists the exact license, and the Linux Foundation describes it as a
permissive data license without a share-back requirement. It is allowed for this static data;
redistributors must preserve applicable license notices. Sources:

- https://spdx.org/licenses/CDLA-Permissive-2.0.html
- https://www.linuxfoundation.org/press/press-release/enabling-easier-collaboration-on-open-data-for-ai-and-ml-with-cdla-permissive-2-0

This engineering review is not independent legal advice. A distributor with different license
policy must perform its own review.

## Rejected and removed dependency

RUSTSEC-2025-0134 marks `rustls-pemfile` unmaintained. It was a direct dependency, so Phase 13
replaced it with Rustls' underlying `rustls-pki-types::pem::PemObject` parser while preserving
strict rejection of mixed recognized PEM sections. Existing certificate/key tests pass.

## Required recurring checks

Run on every release candidate and dependency change:

```bash
target/tools/bin/cargo-audit audit
target/tools/bin/cargo-deny check
RUSTUP_TOOLCHAIN=stable cargo tree -e features
RUSTUP_TOOLCHAIN=1.88.0 cargo check --workspace --all-targets
```

Also review new build scripts, native libraries, source registries, duplicate-version growth, and
exception expiry. `cargo-geiger` was not installed or run; first-party enforcement and source scan
are the available local evidence, not a full transitive unsafe statement.
