# ADR-0028: Raise MSRV to Rust 1.88

Status: Accepted | Date: 2026-07-19

## Context

Phase 0 selected Rust 1.85. Phase 13 reproduced that the locked dependency graph no longer
resolves on Rust 1.85: Hickory 0.26.1 requires 1.88, as do locked certificate/time crates.
`RUSTUP_TOOLCHAIN=1.85.0 cargo check --workspace --all-targets` exits 101 before compilation
and names those unsupported packages.

## Constraints

Use stable Rust, keep one documented MSRV, preserve bounded DNS TTL/rebinding behavior, avoid
unreviewed dependency downgrades, and make breaking toolchain requirements explicit.

## Options considered

1. Raise MSRV to 1.88 and retain the reviewed dependency graph.
2. Downgrade Hickory to 0.25 and pin older certificate, time, URL/ICU dependencies.
3. Replace Hickory with the system resolver and lose authoritative TTL/answer controls.

## Decision

Raise the workspace MSRV to stable Rust 1.88. Keep production on stable Rust; nightly remains
test-only for libFuzzer.

## Rationale

Rust 1.88 is the lowest version satisfying the security-sensitive DNS and current locked
certificate dependency requirements. Downgrading several crates expands change and review risk;
the system resolver cannot meet the approved DNS rebinding and TTL model.

## Consequences

Builders and downstream packagers need Rust 1.88 or newer. MSRV CI must compile all targets with
1.88, while normal CI may use newer stable Rust.

## Security implications

Retains reviewed DNS answer/TTL enforcement and current certificate parsing fixes. A newer
compiler does not itself prove security.

## Reliability implications

One resolvable dependency graph replaces a declared but unusable build baseline. Older build
hosts fail clearly through Cargo metadata.

## Operational implications

Upgrade build images and developer toolchains before compiling new revisions. Running binaries
have no new kernel or libc requirement from this decision.

## Migration implications

This is a build-toolchain breaking change only. Existing configuration, state, and binaries need
no migration or restart solely because of the MSRV correction.

## Alternatives rejected

Multi-crate downgrade was rejected because it requires broader protocol regression and advisory
review. System DNS was rejected because it weakens required TTL, answer-limit, and rebinding
controls.

## Revisit conditions

Revisit when dependency MSRVs rise, Rust 1.88 reaches project end-of-support, or a maintained
lower-MSRV resolver demonstrably meets the same security contract.
