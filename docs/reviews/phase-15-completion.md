# Phase 15 completion: stable typed control plane

Completed: 2026-07-28

## Scope delivered

- Added strict versioned objects for Proxy Hosts, Stream Hosts, Discovery Sources, Certificates,
  Access Policies, Stored Credentials, Users, and immutable Roles.
- Added owner-scoped API and CLI operations with deny-by-default role and token-scope enforcement.
- Added bounded durable desired-state stores, exact revision and generation concurrency, immutable
  typed candidate binding, side-effect-free preview and diff, explicit activation, and forward
  rollback.
- Preserved schema-1 deprecated Proxy Host aliases, schema-2 canonical typed routes, legacy
  subjectless tokens, certificate route separation, and downgrade behavior.
- Split expanded administration, candidate-store, compiler, Access Policy, and CLI responsibilities;
  no production Rust module exceeds the recorded 1,200-line review threshold.
- Closed maintainer findings in candidate `efcd0c3`: response-timeout cancellation, shutdown drain,
  authorization-before-deserialization, User error separation, and hard-capacity classification.

No browser listener, OIDC flow, session state, frontend dependency, or GUI behavior is part of this
phase.

## Security and contract result

- The checked OpenAPI exposes 52 unique actions/scopes with a complete deny-by-default role matrix.
- Authorization and durable audit intent precede typed mutation deserialization.
- Owner-scoped reads and writes hide cross-owner existence; Admin does not broaden ownership.
- Typed changes remain non-active until explicit verified activation or forward rollback.
- Credential and token plaintext remain write-only or one-time; previews, diffs, audit, errors, and
  durable typed state remain secret-free.
- Accepted requests retain bounded capacity after caller timeout, and administrative shutdown drains
  detached handlers before returning.

Maintainer review of `efcd0c3` reported no unresolved critical, high, medium, or low findings.

## Validation evidence

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 339 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed; no doctests defined |
| `cargo tree -e features` | passed; 2,440 output lines |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| valid/invalid configuration corpus | passed: seven accepted, three rejected |
| OpenAPI/config-schema/manifest/lock comparison against `dev@eb107ec` | passed |
| changed documentation link targets and `git diff --check` | passed |

Cargo continued to report the pre-existing future-incompatibility warning for transitive
`proc-macro-error2 2.0.1`.

Unavailable commands remain `cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`,
`cargo llvm-cov`, and `cargo fuzz`. Docker-backed checks, long fuzz/soak, automated Markdown tools,
SBOM, signing, and container scans were not run and are not claimed as passes.

## Approval and exception

The project owner explicitly approved merging and beginning Phase 16 in the interactive session on
2026-07-28. That approval waives Phase 15's independent-review prerequisite for phase progression.
It is not represented as independent application-security evidence and does not satisfy the
two-person release signoff in
[`external-review-signoff.md`](../security/external-review-signoff.md).

The release recommendation therefore remains **NO-GO**, and external application-security review
remains required before production release.

## Exit decision

Phase 15 is complete for roadmap progression under the recorded project-owner exception. The
closeout branch may merge into `dev`, and Phase 16 may begin from that merge.
