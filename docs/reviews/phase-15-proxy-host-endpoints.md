# Phase 15 Proxy Host endpoint review

Recorded: 2026-07-22

Implementation commit: `00cfa32`

Decision: validation/preview endpoint unit complete; Phase 15 remains in progress

## 1. Scope

Private Unix-socket API and CLI now validate and preview one strict typed Proxy Host. Work adds
principal ownership to token metadata and no object persistence, mutation, audit mutation, revision
creation, activation, GUI, database, public listener, dependency, or configuration-schema field.

## 2. Motivation

Compiler, preview, and diff had no authenticated transport. This unit proves owner-aware read-only
transport before typed mutation exists.

## 3. Files and modules changed

- `crates/proxy-admin/src/proxy_host.rs`: pure endpoint preparation and tests.
- `crates/proxy-admin/src/auth.rs`: stable owner metadata for newly issued tokens.
- `crates/proxy-admin/src/server.rs` and `server/handlers.rs`: authorization-first extractors and
  handlers.
- `crates/proxy-admin/src/server/tests.rs`: route-contract and principal updates.
- `crates/rust-proxy/src/main.rs` and `tests/admin_cli.rs`: bounded JSON CLI and integration proof.
- `config/schema/admin-openapi.yaml`: checked request/response and owner metadata contracts.

## 4. Typed input contract

`ApiObject<ProxyHostSpec>` remains strict `v1` with object/owner IDs and seven fields: domain,
forward host, forward port, protocol, automatic HTTPS, access-policy reference, and enabled state.
Unknown fields and future versions fail during deserialization.

## 5. Compilation context

Preparation builds immutable, request-local `BTreeMap`/`BTreeSet` indexes around active validated
configuration. It supplies authenticated owner, exactly one HTTP listener, and exactly one upstream
group whose endpoints are all HTTP-family. It performs no DNS, environment, secret, filesystem,
network, persistence, or runtime mutation.

## 6. Exact mapping

Endpoint reuses `compile_proxy_host`; domain, destination, generated IDs, enabled state, and upstream
policy therefore follow compiler review. Current endpoint policy permits automatic HTTPS disabled
and no access-policy reference. Managed HTTPS and access policies fail closed until typed ownership
metadata exists. This avoids inferring ownership from low-level configuration IDs.

## 7. Candidate boundary

Preparation returns `PreparedProxyHost { preview, diff }`. Preview contains canonical summary plus
fully redacted candidate configuration. Diff is deterministic creation diff. Neither type owns a
revision store, activation coordinator, audit writer, or runtime handle.

## 8. Determinism

Same object, owner, and active configuration serialize identically. Template selection rejects zero
or multiple eligible resources; it never depends on declaration or hash-map iteration order.

## 9. Ownership

Unix peers map to `uid-<uid>`. New bearer tokens persist creator's owner. Request owner must equal
authenticated owner. Legacy tokens without owner metadata receive forbidden. Token metadata exposes
owner ID but never hash or plaintext.

## 10. Access policies

Every non-null reference returns same unavailable class. No missing/unauthorized distinction is
exposed and no public policy is substituted.

## 11. Domain and ID conflicts

Canonical compiler conflict checks remain mandatory. Existing routes and generated identifiers
reject rather than overwrite. Endpoint preparation never mutates active configuration.

## 12. Disabled objects

Disabled objects retain typed summary state but generate no route, group, or endpoint. Preview and
diff therefore cannot represent object as active.

## 13. TLS and automatic HTTPS

Managed HTTPS fails closed because current low-level certificate/listener records have no typed
owner. Endpoint does not claim issuance or infer a cross-owner certificate. Compiler's explicit
managed-policy interface remains available to a future authorized certificate service.

## 14. Secret isolation

Input contract has no plaintext-secret field. Complete redaction runs before response serialization.
Errors are fixed classes without request values, paths, credentials, or policy existence details.

## 15. Runtime isolation

Handlers clone active immutable configuration, perform bounded preparation in `spawn_blocking`, and
return a value. Integration proves active revision is unchanged. No candidate is persisted and no
activation function is reachable from preparation.

## 16. Error model

`ProxyHostPreparationError` distinguishes owner, contract, listener/template, policy/HTTPS,
compiler, preview, and diff failures internally. Cross-owner maps to forbidden; public invalid input
classes remain generic; impossible preview/diff invariants map to internal error.

## 17. Tests

- Deterministic redacted preparation and unchanged active input.
- Cross-owner, policy, managed-HTTPS, and ambiguous-template fail-closed behavior.
- Full CLI validation/preview, owner denial, scope enforcement before malformed JSON parsing, and
  unchanged active revision.
- Existing strict contract, compiler, preview, diff, admin, configuration corpus, runtime, and
  security regressions.

## 18. Validation

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed; transitive warning below |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 287 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo doc --workspace --all-features --no-deps` | passed |
| `cargo tree -e features` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| Python/PyYAML OpenAPI parse | passed |
| `git diff --check` | passed |

Transitive `proc-macro-error2 2.0.1` retains its existing future-incompatibility warning. Optional
tools remain unavailable as recorded in `STATUS.md`.

## 19. Compatibility

TOML schema, defaults, manifests, lockfile, and runtime behavior are unchanged. Token-file schema 1
accepts missing legacy owner metadata but denies typed-object access. Token creation and metadata add
stable ownership. OpenAPI and CLI intentionally add endpoints and fields.

## 20. Known limitations

Only creation previews exist because no typed object store exists. Endpoint rejects managed HTTPS,
access policies, ambiguous listener/template selection, and every mutation. Error responses do not
yet expose typed field-level validation codes.

## 21. Remaining Phase 15 work

Typed object persistence; mutation/revision/activation endpoints; certificate and access-policy
ownership; complete ownership/RBAC matrix; remaining objects and contracts; migration and
compatibility tests; full security review.

## 22. Completion decision

This read-only endpoint unit meets its boundary and validation gate. Phase 15 remains in progress;
production assessment remains NO-GO.
