# Phase 3: Routing engine and typed configuration

## 1. Phase title

Routing engine and typed configuration.

## 2. Original objectives

Freeze configuration schema v1; implement deterministic host, path, header, and method routing; provide complete offline validation and redacted preview; reject ambiguous or unsupported behavior before activation.

## 3. Implemented scope

- Strict typed TOML schema v1 with recursive unknown-field rejection and bounded collections and strings.
- Explicit default routes; no implicit catch-all behavior.
- Exact and wildcard host matching, exact and segment-boundary path-prefix matching, method matching, and exact/header-presence matching.
- Canonical ASCII hostname policy, authority/Host consistency checks, and IPv4/IPv6 authority support.
- Single-pass path canonicalization with encoded-separator, dot-segment, malformed-escape, duplicate-slash, control-byte, and request-target bounds.
- Deterministic immutable per-listener route index compiled once at startup.
- Explicit priority followed by documented host/path/method/header specificity.
- Duplicate matcher and ambiguous equal-precedence overlap rejection.
- Stable FNV-1a diagnostic route fingerprint. It is not a cryptographic integrity mechanism.
- Exact field-path errors for missing listener, upstream, and certificate references.
- `validate`, `preview`, and `fmt` CLI workflows. Preview is deterministic and removes secret references.
- Checked-in tooling JSON Schema, valid examples, invalid corpus, and schema compatibility documentation.
- Fail-closed gates for represented but unimplemented TCP, trusted-proxy, middleware, and multi-endpoint behavior.

## 4. Deferred scope

TCP proxying and TLS passthrough remain assigned to Phase 4 because ADR 0016 has not selected and reviewed a bounded ClientHello parser. Dynamic DNS/providers, weighted pools, health state, query/regex matching, middleware execution, trusted-proxy reconstruction, dynamic activation, UDP, and HTTP/3 remain deferred to their planned phases.

## 5. Architecture decisions

- Route configuration is compiled into an immutable index; request paths do not scan or reinterpret raw configuration.
- Declaration order is not a routing tie-breaker. Equal-precedence overlaps fail validation unless explicit priority resolves them.
- Exact hosts outrank wildcards, exact paths outrank prefixes, and explicit defaults always rank last.
- Incoming Unicode U-label hostnames are rejected. Operators configure and clients send canonical lowercase ASCII A-labels.
- The canonical path used for routing is also forwarded upstream, preventing route/forward interpretation drift.
- Security-affecting fields without runtime enforcement are rejected rather than accepted as no-ops.
- The checked-in JSON Schema assists editors; the Rust CLI remains authoritative for semantic validation.

## 6. Files created

- `crates/proxy-config/src/conflict.rs`
- `crates/proxy-config/src/redact.rs`
- `crates/proxy-core/src/route.rs`
- `crates/rust-proxy/tests/config_cli.rs`
- `docs/configuration-v1.md`
- `config/schema-v1.json`
- `config/examples/default-route.toml`
- `config/invalid/unknown-field.toml`
- `config/invalid/encoded-route-path.toml`
- `config/invalid/ambiguous-routes.toml`

## 7. Files modified

- Workspace and affected crate `Cargo.toml` files and `Cargo.lock`.
- `crates/proxy-config/src/lib.rs`
- `crates/proxy-core/src/lib.rs`
- `crates/rust-proxy/src/main.rs`
- `docs/dependencies.md`
- Existing valid configuration examples.

The planned `schema.rs` and `validate.rs` physical split was not forced: the current schema and validation remain in `proxy-config/src/lib.rs`, while conflict and redaction logic were split when independently useful. This is a source-layout difference, not missing behavior.

## 8. Dependencies added

- Direct runtime `http 1.x` in `proxy-config` for validated HTTP methods and header names.
- Development-only `proptest 1.11.0`, default features disabled and `std` enabled, for bounded routing determinism properties.

The dependency inventory records purpose, features, license, native/unsafe exposure, alternatives, and upgrade policy. `Cargo.lock` is committed.

## 9. Configuration introduced

Schema v1 adds explicit route defaults, exact `paths`, path prefixes, methods, and header presence/exact predicates. Route IDs, listener/upstream references, collection counts, URL components, endpoint weights, and inactive features are validated. Examples document specific-route plus explicit-default behavior. Compatibility rules require unknown fields and unsupported schema versions to fail closed.

## 10. Tests added

- Predicate, bounds, canonicality, explicit-default, exact-reference-path, and inactive-feature validation.
- Conflict analysis for duplicates, priorities, overlap, defaults, and disjoint predicates.
- Host/authority, IDNA, path normalization, target bounds, and canonical forwarding tests.
- Deterministic compilation, ordering, and route fingerprint tests.
- Property tests for canonical path idempotence and declaration-order-independent selection.
- Black-box encoded-path separator rejection and canonical path forwarding.
- CLI preview redaction, deterministic formatting, valid examples, and invalid corpus coverage.

## 11. Commands executed

- `cargo fmt --all -- --check` — passed.
- `cargo check --workspace --all-targets` — passed on the configured Windows GNU toolchain.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed.
- Targeted configuration, route, property, and CLI integration tests — passed.
- `docker build --no-cache-filter test --target test .` — passed with a fresh Linux test layer.
- Checked-in examples through `rust-proxy validate` — passed.
- `config/schema-v1.json` through PowerShell `ConvertFrom-Json` — passed syntax parsing.
- `cargo audit` and `cargo deny` — unavailable as previously recorded; no success is claimed.

## 12. Actual command results

The fresh authoritative Linux container suite passed 72 tests: 21 configuration tests, 31 proxy-core tests, one gRPC test, five secret tests, 12 TLS tests, one certificate CLI test, and two configuration CLI tests. All documentation test binaries passed. Formatting, workspace check, and strict all-target/all-feature Clippy exited zero.

Windows GNU aggregate-test behavior remains affected by the previously recorded local linker instability; isolated targeted tests pass. Linux is the authoritative complete-suite result. Cargo reports that transitive `proc-macro-error2 2.0.1` may be rejected by a future Rust release; this is not a current failure.

## 13. Security checks

- Unknown fields, ambiguous routes, malformed host/path/header predicates, unsafe URL components, and missing references fail validation.
- Absolute-form request targets and CONNECT remain rejected.
- Canonical routing and forwarding use the same bounded request path.
- Preview output removes certificate-chain, private-key, CA-bundle, and identity references.
- TCP, middleware, trusted-proxy, and multi-endpoint configuration cannot silently activate before enforcement exists.
- No client value can select an arbitrary upstream.

No independent protocol/security review has yet been completed. Automated dependency advisory and license-policy tools remain unavailable.

## 14. Performance checks

No performance benchmark or soak was run and no throughput, latency, route-count, or reload-time claim is made. Property tests prove bounded functional invariants only. The route index avoids per-request schema compilation, but its performance must be measured later under the documented benchmark methodology.

## 15. Known limitations

- TCP/TLS passthrough is rejected until Phase 4 resolves ADR 0016 and adds bounded parsing/tests.
- IDNA policy accepts canonical ASCII A-label input but does not convert Unicode U-label input.
- JSON Schema covers structural/common bounds; cross-reference and conflict semantics require the CLI.
- The route fingerprint is diagnostic, not collision-resistant or suitable for revision authenticity.
- Configured middleware, trusted proxies, and multiple/weighted endpoints intentionally fail validation until their runtime phases.
- Query and regex matching are not supported.

## 16. Residual risks

Conflict-analysis coverage must evolve with every new predicate. Canonicalization needs independent HTTP interoperability and request-smuggling review. The future TCP ClientHello boundary requires expert parser review. The Windows GNU toolchain instability can obscure local aggregate results. Supply-chain policy checks remain incomplete without `cargo-audit` and `cargo-deny`.

## 17. Acceptance-criteria checklist

- [x] Same validated input compiles to the same route order and diagnostic fingerprint.
- [x] Declaration/set order does not change route selection in covered property tests.
- [x] Ambiguous equal-precedence overlaps are rejected unless explicit priority resolves them.
- [x] Host/path/header/method precedence is deterministic and documented.
- [x] Explicit default route is required and always lower precedence.
- [x] All shipped valid examples pass the real CLI validator.
- [x] Shipped invalid corpus fails validation.
- [x] Invalid listener, upstream, and certificate references identify exact field paths.
- [x] Redacted preview contains no covered secret-reference canaries.
- [ ] TCP/SNI passthrough tests pass; deferred to Phase 4 because no parser decision is approved.

## 18. Exit-criteria checklist

- [x] Schema v1 preview is frozen and compatibility policy documented.
- [x] Mandatory HTTP routing/configuration behavior is implemented and tested.
- [x] Unsupported security-affecting features fail closed.
- [x] Fresh Linux workspace test suite passes.
- [ ] Independent HTTP canonicalization/protocol review is complete.
- [ ] TCP/TLS passthrough implementation is complete; explicitly deferred to Phase 4.

Phase 4 may begin without weakening these gates. Production release remains blocked on independent review and all later mandatory phases.

## 19. Commit list

- `4731dd3` — enforce strict route predicates.
- `9dd3f4f` — reject ambiguous route overlaps.
- `4f30cf6` — add exact and presence matches.
- `b716055` — compile immutable route index.
- `5c20a27` — add deterministic redacted preview.
- `eaf0de6` — reject inactive policies.
- `a19bd9d` — add routing determinism properties.
- `2a6ca8f` — freeze and document schema v1.

## 20. Readiness for the next phase

The immutable validated route model is ready for Phase 4 endpoint pools, bounded DNS, load balancing, health state, safe retries, draining, and circuit control. Phase 4 must resolve ADR 0016 before enabling TCP/TLS passthrough and must replace the intentional single-endpoint/weight-one gate only when the new pool behavior and SSRF controls are tested. The project is not production-ready.
