# Phase 15 Access Policy preview wiring

Date: 2026-07-27

Status: non-persistent preview unit complete; Phase 15 remains in progress

Implementation commit: `c12f1c3`

Proxy Host validation/preview now loads only its referenced Access Policy as immutable secret-free
metadata. Existing compiler checks require an enabled policy owned by, or explicitly shared with,
the authenticated owner. Missing, disabled, and unauthorized references fail through one safe
validation class. Recovery uncertainty returns unavailable. The redacted preview exposes only
canonical middleware IDs already present in configuration.

This unit itself cannot persist an object, create a revision, bind a candidate, activate runtime
state, or perform rollback. Revision-bound dependency wiring subsequently landed in `20449a3`; see
[`phase-15-access-policy-candidate-binding.md`](phase-15-access-policy-candidate-binding.md).

Full workspace format, check, Clippy, 318 tests (2 intentionally ignored), doc tests, Rustdoc,
feature-tree, Admin CLI integration, and `git diff --check` passed. One Rust 1.97 incremental ICE
occurred after a normal ownership compile error; all gates then passed with
`CARGO_INCREMENTAL=0`. The pre-existing `proc-macro-error2 2.0.1` future warning remains.
