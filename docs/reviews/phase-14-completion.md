# Phase 14 completion: behavior-preserving modularization

Completed: 2026-07-22

## Scope delivered

- Extracted large inline tests before production moves. Test names, assertions, visibility, and
  ignored status remain unchanged.
- Grouped core and configuration tests by behavior without creating new test semantics.
- Split core lifecycle, HTTP serving, request helpers, and upstream runtime preparation.
- Split configuration schema from orchestration and ACME, middleware, platform, and routing
  validation domains.
- Split private administration routing/contracts from handlers and support/audit/socket helpers.
- Evaluated runtime, telemetry, and revision ownership. Test extraction reduced runtime to 784
  production-file lines and telemetry to 990; revision remains a cohesive 1,131-line module. No
  further mechanical split was justified.
- Added a current [workspace ownership map](../development/workspace.md).

No product feature, dependency, configuration field/default, API route, protocol, persistence
format, or security policy was intentionally changed.

## Measured result

Counts include comments and blank lines.

| Baseline file | Before | Resulting production modules |
|---|---:|---|
| `proxy-core/src/lib.rs` | 5,415 | root 308; lifecycle 481; upstream runtime 250; HTTP 1,093; request 188 |
| `proxy-core/src/runtime.rs` | 1,278 | runtime 784; tests 486 |
| `proxy-core/src/telemetry.rs` | 1,109 | telemetry 990; tests 118 |
| `proxy-config/src/lib.rs` | 4,749 | root 888; schema 958; validations 297/630/297/444 |
| `proxy-admin/src/server.rs` | 2,159 | routing/contracts 700; handlers 968; support 292; tests 211 |

Largest production Rust module is `proxy-config/src/revision.rs` at 1,131 lines. No production
module exceeds Phase 14's 1,200-line review threshold.

## Contract and security review

- Cargo manifests, `Cargo.lock`, configuration schema, and admin OpenAPI document are byte-identical
  to baseline commit `10aae8c`.
- Existing public names are re-exported from original crate roots; moved helpers remain crate
  private.
- Workspace tests exercise request validation/order, authority/SNI, forwarding trust, fixed
  middleware stages, egress policy, retries, circuits, health, reload, shutdown, secret redaction,
  audit, and private administration.
- No `unsafe` block or dependency was added.
- Review found no intentional hot-path algorithm, allocation, lock, queue, label, or timeout change;
  no performance improvement is claimed.

## Validation evidence

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets --all-features` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 268 passed, 2 intentionally ignored |
| `cargo test --workspace --doc` | passed: five crate targets, zero doctests |
| `cargo tree -e features` | passed |
| shipped configuration corpus | passed through `tests/config_cli.rs`: 7 valid accepted, 3 invalid rejected |
| baseline manifest/schema/OpenAPI diff | passed: no differences |
| changed documentation link targets | passed: every relative target exists |
| `git diff --check` | passed before implementation commits and completion documentation |

Cargo continued to report the pre-existing future-incompatibility warning for transitive
`proc-macro-error2 2.0.1`.

Unavailable commands remain exactly: `cargo nextest`, `cargo audit`, `cargo deny`, `cargo machete`,
`cargo llvm-cov`, and `cargo fuzz`; Cargo reports `no such command` for each. Docker-backed Pebble
remains intentionally ignored. `markdownlint` and `lychee` are also unavailable (`command not
found`), so a repository-wide Markdown scan was not rerun. These gaps block release evidence, not
this behavior-preserving phase.

## Commits

- `89ceb5a` — `docs(phase-14): record modularization baseline`
- `1e7509b` — `test: extract inline module tests`
- `cef5382` — `test: split proxy tests by behavior`
- `440c058` — `refactor(core): split runtime responsibilities`
- `b85a089` — `refactor(config): separate schema validation domains`
- `8f41180` — `refactor(admin): separate routing handlers support`
- Completion documentation is the commit containing this report.

## Acceptance and exit decision

- [x] Tests extracted before production restructuring.
- [x] Domain ownership and module guidance documented.
- [x] Public API, schemas, OpenAPI paths, defaults, dependencies, and unsafe-code policy unchanged.
- [x] Available format, check, Clippy, unit, integration, doc, config, and feature-tree gates pass.
- [x] Security-boundary and complete-diff review found no intentional behavior change.
- [x] No unrelated change, secret, generated artifact, or build output is included.

Phase 14 is complete. Phase 15 may begin with versioned typed control-plane contracts. Release
assessment remains NO-GO because later roadmap and independent review gates remain open.
