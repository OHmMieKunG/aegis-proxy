# Phase 15 Proxy Host compiler review

Recorded: 2026-07-22

Implementation commit: `fa7913f`

Phase decision: compiler unit complete; Phase 15 remains in progress

## 1. Scope

This unit compiles one strict `ApiObject<ProxyHostSpec>` into a full schema-v1 `Config` candidate.
It adds no API route, CLI command, persistence service, activation path, schema field, dependency,
DNS lookup, network operation, or runtime behavior.

## 2. Motivation

High-level objects must converge on the existing validated configuration, revision, and atomic
activation model. A pure compiler proves that boundary before mutation endpoints exist.

## 3. Files and modules changed

- `crates/proxy-admin/src/compile.rs`: compiler, context, candidate, errors, tests.
- `crates/proxy-admin/src/api.rs`: unsupported protocol regression assertion.
- `crates/proxy-admin/src/lib.rs`: public compiler contract exports.
- `crates/proxy-config/src/lib.rs` and `validation_routing.rs`: shared exact-domain and DNS-host
  validators; no schema/default change.
- Current-state, roadmap, architecture, configuration, security, operations, changelog, and review
  documents listed by this documentation commit.

## 4. Typed input contract

Input remains seven fields: domain, forward host/IP, forward port, `http`/`https`, automatic HTTPS,
opaque access-policy reference, and enabled state. Strict Serde envelopes still reject unknown
fields, invalid IDs, unsupported API versions, and unsupported protocol enum values.

## 5. Compilation context

`CompileContext` contains immutable references to validated base configuration, authenticated owner
ID, selected HTTP listener and upstream template IDs, access-policy metadata, claimed object/domain
indexes, and optional managed-HTTPS listener/certificate metadata. It contains no secret resolver,
runtime handle, revision store, database, environment access, or network client. RBAC evaluation
must happen before context construction.

## 6. Exact Proxy Host-to-configuration mapping

| Proxy Host field | Canonical mapping |
|---|---|
| metadata owner/ID | SHA-256 namespace over `owner_id`, NUL, `object_id`; first 128 bits encode lowercase hex after `ph-` |
| domain | one exact route host; lowercase canonical ASCII only |
| forward host | endpoint URL host; DNS name validated without lookup or IP literal accepted |
| forward port | explicit endpoint URL port; zero rejected |
| forward protocol | endpoint `http` or verified `https`; HTTPS also sets exact server name |
| automatic HTTPS disabled | selected existing HTTP listener |
| automatic HTTPS managed | selected existing HTTPS listener and covering static/ACME certificate |
| access policy | ordered existing middleware IDs from authorized policy metadata |
| enabled | adds route/group/endpoint only when true |

Generated IDs end in `-route`, `-upstream`, and `-endpoint`. Selected upstream template contributes
egress, DNS, balancing, health, retry, circuit, drain, and resource-limit policy. Its first endpoint
is only a structural template; user destination replaces endpoint ID, URL, and TLS server name.

## 7. Candidate output boundary

`ProxyHostCandidate` retains typed object state and a complete canonical `Config`. Compiler validates
base configuration, compiles, then calls `aegisproxy_config::validate` on output. Candidate may later
enter existing `RevisionStore`; compilation itself neither persists nor activates it.

## 8. Determinism guarantees

Context indexes use `BTreeMap`/`BTreeSet`. Generated IDs depend only on immutable owner/object IDs.
Input plus context produce byte-identical JSON serialization in tests. No clock, randomness, DNS,
environment, or iteration over hash collections affects compiler output.

## 9. Ownership behavior

Authenticated context owner must equal object owner. Existing `(owner_id, object_id)` claims reject
creation. Generated route/group/endpoint collisions also reject. Compiler does not grant RBAC; caller
must authorize action before context construction.

## 10. Access-policy behavior

Reference remains opaque. Missing and disabled policies return one unavailable class. Policy owner
or explicit share must include Proxy Host owner; otherwise compilation returns internal unauthorized
class. Middleware references still pass fixed-order semantic validation. Future public error mapping
must avoid turning internal distinction into unsafe object-existence disclosure.

## 11. Domain and ID conflict behavior

Domains reject empty/malformed labels, Unicode U-labels, trailing dots, IP literals, and every
wildcard form. Operators must supply canonical lowercase ASCII A-labels. Claimed domains and existing
exact or covering single-label wildcard routes reject rather than overwrite. Object and generated ID
collisions also reject.

## 12. Disabled-object behavior

Disabled typed state is retained in `ProxyHostCandidate::object`; candidate configuration remains
identical to base route/upstream counts. No dormant route or upstream is generated, so activation
cannot keep this object active.

## 13. TLS and automatic-HTTPS desired-state behavior

Managed selection requires an already configured HTTPS listener that references an existing static
or ACME certificate covering the exact domain. Compiler does not issue, renew, inspect, or claim
successful issuance. HTTP-to-HTTPS redirect and automated policy derivation remain Phase 17.

## 14. Secret-isolation guarantees

Typed Proxy Host and compilation metadata contain no plaintext-secret field. Compiler never resolves
existing secret references. Candidate/context `Debug` implementations expose bounded metadata, not
full configuration. Error messages are fixed classes without values, paths, or credentials.

## 15. Runtime-nonmutation guarantees

Production compiler module imports no runtime, activation, persistence, filesystem, environment, or
network API. Candidate/rejection tests show no revision or active pointer appears during compilation;
explicit later candidate persistence still leaves active pointer unset.

## 16. Error model

`ProxyHostCompileError` distinguishes invalid/unsupported domain, invalid upstream/port, unsupported
protocol, missing/unauthorized policy, unauthorized owner, object/domain conflict, unsupported config
version, certificate/listener policy failure, internal invariant failure, and semantic-validation
failure. Messages are stable, bounded, and secret-free.

## 17. Tests added

- Deterministic serialization and exact generated ID.
- HTTP, HTTPS upstream, managed HTTPS, protected, and disabled cases.
- Domain forms, upstream, zero port, owner, policy, object/domain, certificate, and config-version
  failures.
- Unsupported protocol, API version, unknown field, and invalid-ID deserialization coverage.
- Existing semantic validator, revision isolation, inactive pointer, candidate serialization, and
  redacted debug/error checks.

## 18. Validation commands and results

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; existing future-incompatibility warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 274 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed; public Rustdoc generated |
| `cargo tree -e features` | passed |
| `cargo report future-incompatibilities --id 1` | passed; warning traced to `age` through `i18n-embed-fl` and `proc-macro-error2` |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| targeted compiler/admin/config/corpus tests | passed |
| JSON Schema and OpenAPI parsing | passed |
| manifest/schema/OpenAPI diff against `2d533a8` | passed: byte-identical |
| changed relative-link check and `git diff --check` | passed |

`cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`, `cargo llvm-cov`, and `cargo fuzz`
were unavailable (`cargo: no such command`, exit 101). `markdownlint` and `lychee` were unavailable
(`command not found`, exit 127). No unavailable check is claimed as passed. Cargo still reports the
pre-existing transitive `proc-macro-error2 2.0.1` future-incompatibility warning.

## 19. Compatibility evidence

Cargo manifests, lockfile, TOML schema, JSON Schema, OpenAPI, defaults, and API routes are unchanged.
Existing valid/invalid configuration corpus, administration suite, runtime/protocol suite, and all
workspace tests pass. Public API only adds compiler types/functions and shared validators.

## 20. Known limitations

- Create-only context rejects an already claimed owner/object ID; update semantics belong in object
  persistence/candidate service.
- One Proxy Host maps to one exact domain and one endpoint cloned from one configured template.
- Managed HTTPS needs a prepared listener/certificate; issuance and redirects are not automated.
- No public preview redaction or field-level diff consumes this candidate yet.
- No high-level endpoint, OpenAPI entry, CLI command, or durable object store exists.
- Compiler clones full `Config` because existing revisions store complete immutable candidates;
  measurement is required before considering optimization.

## 21. Remaining Phase 15 work

Typed candidate/preview service; field-level diff; complete ownership/RBAC rules; API-token scopes;
typed mutation/activation endpoints; remaining domain objects; OpenAPI/CLI contracts; migration and
compatibility policy/tests; full authorization and security review.

## 22. Completion decision for this unit

Compiler unit meets its local gate: deterministic canonical output, semantic validation, fail-closed
references/conflicts, secret isolation, disabled safety, no persistence/activation side effects,
compatibility evidence, and passing available checks. Phase 15 and product remain incomplete and
production NO-GO.
