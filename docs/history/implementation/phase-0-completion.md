# Phase 0: Repository assessment and architecture decisions

> Historical document — records phase evidence at completion time. See [`STATUS.md`](../../../STATUS.md) for current verification.

## Original objectives

Assess the empty repository, establish a reproducible Rust workspace, record architecture decisions, and define the first safe implementation boundary.

## Implemented scope

- Audited the repository and recorded the result in `docs/implementation-readiness-review.md`.
- Initialized a Rust 2024 workspace with five crates: configuration, secrets, TLS boundary, proxy core, and CLI.
- Added strict TOML configuration types and bounded validation primitives.
- Added a minimal HTTP proxy configuration example.
- Added dependency, license, security, and repository policy files.
- Recorded ADRs 0001-0025 for the material Phase 0 decisions.

## Deferred scope

TLS termination, ACME, dynamic reload, administration, middleware execution, discovery, HTTP/2, WebSocket, TCP passthrough, observability, deployment images, and clustering remain assigned to later phases.

## Architecture decisions

Hyper plus Tokio is the initial data-plane foundation. Configuration is typed TOML with no database. The first release is one process and one binary, with administration private by default. Own crates forbid unsafe Rust.

## Files created

`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `.gitignore`, licenses, `README.md`, `SECURITY.md`, `config/examples/minimal.toml`, all five crate manifests and source files, `docs/dependencies.md`, and ADRs 0001-0025.

## Files modified

None from the pre-existing repository. The readiness review was committed before implementation.

## Dependencies added

Tokio, Hyper, Hyper-util, HTTP body utilities, Serde, TOML, URL, IP network parsing, Rustls boundary crates, Clap, Tracing, and focused error/secret helpers. The direct dependency inventory is in `docs/dependencies.md`.

## Configuration introduced

Schema version 1 supports listeners, resource limits, trusted proxy CIDRs, upstream groups/endpoints, routes, middleware declarations, and private admin socket metadata. Unknown fields are rejected recursively by Serde attributes. Validation rejects duplicate IDs/binds, invalid protocols, empty groups, zero endpoint weights, and unresolved references.

## Tests added

Configuration validation regression coverage for duplicate listener binds. Additional protocol and reload tests are assigned to Phases 1-5.

## Commands executed

- `git status --short --branch` — passed; clean initial repository.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all` — passed after installing GNU rustfmt.
- `cargo +stable-x86_64-pc-windows-gnu check -p aegisproxy-config` — passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p aegisproxy-core` — passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p aegisproxy-config -p aegisproxy-core --all-targets -- -D warnings` — passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets --all-features -- -D warnings` — passed after adding the CLI crate-level doc.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace --all-features` — passed; one configuration unit test ran. The GNU linker shim emitted a non-fatal `.drectve` warning.
- The default MSVC build could not link because `link.exe` is unavailable in the environment. Validation used the installed GNU toolchain with a local linker-library shim; this is an environment limitation, not a product design choice.

## Security checks

No production secrets, certificates, Docker sockets, or external systems were accessed. Secret references are restricted to `env://` and absolute `file://` forms. Security-sensitive protocol controls are not complete until their assigned phases.

## Performance checks

Not applicable in Phase 0. No performance claim is made.

## Known limitations

The data plane is an HTTP/1 forwarding skeleton. It does not yet provide TLS, HTTP/2, WebSocket, streaming body enforcement, health-aware balancing, dynamic activation, administration, or the full threat-control matrix.

## Residual risks

The GNU validation path differs from the pinned MSVC toolchain. Rustls provider selection and native build portability require the Phase 2 ADR review. The current proxy implementation must receive protocol and resource-boundary tests before any production assessment.

## Acceptance-criteria checklist

- [x] Repository state documented.
- [x] Workspace and crate boundaries created.
- [x] ADR set created for material initial choices.
- [x] Strict configuration foundation builds and has a regression test.
- [ ] Full workspace validation on the pinned MSVC toolchain.
- [ ] Phase 1 protocol acceptance criteria.

## Exit-criteria checklist

- [x] Phase 0 artifacts committed locally.
- [x] Next phase identified: Phase 1, minimal secure HTTP reverse proxy.
- [ ] Phase 1 implementation complete.

## Commit list

- `3197b1e` — readiness review.
- `341aaf7` — Rust workspace bootstrap.
- `3fbc2cf` — Phase 0 ADRs and dependency inventory.

## Readiness for next phase

Ready for Phase 1 implementation after a final workspace check and a focused HTTP forwarding test. The system is not production-ready.
