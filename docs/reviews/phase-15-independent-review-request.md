# Phase 15 independent API/security review request

Status: **awaiting independent reviewer**

Prepared: 2026-07-28

This is a review request, not completion evidence or maintainer signoff. The reviewer must be
independent of the Phase 15 implementation author.

## Immutable candidate

- Candidate commit: `5a32495`
- Candidate branch: `chore/phase-15-closeout`
- Phase 15 baseline: `b685449` (Phase 14 completion)
- Immediate closeout base: `eb107ec`
- Scope: private typed control plane and its closeout; no browser listener, OIDC, session, GUI, or
  frontend dependency exists

Review the cumulative `b685449..5a32495` change. Use `eb107ec..5a32495` only to isolate the final
module split and contract-freeze tests.

## Required qualifications and independence

Record reviewer identity, relevant application-security/API/Rust experience, employer or
affiliation, and any relationship to the implementation. A repository maintainer may assist with
reproduction but cannot supply the independent decision.

## Security invariants to review

1. All 52 serialized actions are deny-by-default and effective bearer authority is the
   intersection of built-in role and explicit token scopes.
2. Unix-peer and bearer authentication cannot downgrade on malformed, duplicate, unknown,
   expired, revoked, disabled-subject, or legacy token input.
3. Authorization and durable audit intent precede typed deserialization and all mutation,
   candidate, desired-state, or runtime work.
4. Owner-scoped reads and mutations make cross-owner IDs indistinguishable from missing IDs.
   Admin role does not broaden typed-object visibility.
5. Every mutation requires the exact active revision. Object updates/deletes additionally require
   the exact generation, and stale state is never retried automatically.
6. Typed create/update/delete never activate implicitly. Canonical activation and rollback alone
   may publish schema-2 state through the existing coordinator.
7. Deprecated Proxy Host aliases accept schema 1 only; canonical typed routes accept schema 2
   only; low-level activation/rollback reject every typed-bound revision.
8. Candidate hashes bind complete typed desired state and exact Access Policy/Certificate
   generations. Missing, drifted, orphaned, tampered, or replayed candidates fail closed.
9. Recovery journals and candidate retention converge from the durable active revision without
   accepting malformed, insecure, symlinked, or mismatched state.
10. Credential plaintext, token plaintext/hashes, ciphertext, secret references, private paths,
    and arbitrary typed values cannot enter reads, previews, diffs, errors, logs, metrics, audit,
    or unencrypted backup content.
11. Configuration, objects, payloads, stores, queues, authentication work, and returned
    collections remain bounded.
12. Admin remains a private Unix socket and failure of administration cannot stop the data plane.

## Primary review entry points

- Contract and action vocabulary: `config/schema/admin-openapi.yaml`,
  `crates/proxy-admin/src/api.rs`, and `crates/proxy-admin/src/rbac.rs`.
- Authentication and identity: `crates/proxy-admin/src/auth.rs`,
  `crates/proxy-admin/src/user.rs`, and `crates/proxy-admin/src/server.rs`.
- Request ordering and error mapping: `crates/proxy-admin/src/server/`, especially
  `support.rs`, `handlers/`, `domains.rs`, `certificates.rs`, `credentials.rs`, and `users.rs`.
- Candidate and recovery boundaries: `crates/proxy-admin/src/object_store.rs`,
  `object_store/candidate_store.rs`, `server/unified.rs`, and
  `crates/proxy-config/src/revision.rs`.
- Secret-bearing boundaries: `crates/proxy-admin/src/credential.rs`, `backup.rs`, `audit.rs`,
  `preview.rs`, and `diff.rs`.
- End-to-end private API/CLI behavior: `crates/rust-proxy/tests/admin_cli.rs`.

## Required attacks and negative cases

- Enumerate every route and method against viewer, auditor, operator, Admin, and representative
  narrower token scopes. Include malformed JSON/TOML so denial ordering is observable.
- Attempt cross-owner list/get/update/delete for every owned domain and compare missing-ID
  responses, audit results, revisions, desired stores, and runtime state.
- Exercise stale active revisions, stale object generations, simultaneous typed mutations,
  repeated activation, rollback replay, and audit write failure.
- Tamper revision metadata, candidate schemas, binding hashes, bound objects/dependencies,
  recovery journals, retained snapshots, permissions, and symlink targets.
- Attempt schema-2 activation through deprecated aliases and typed-bound activation through
  low-level routes.
- Inject secret canaries into credentials, policies, configuration, requests, backups, errors, and
  observability output; inspect every response and durable file.
- Attempt traversal, oversized input/state, duplicate IDs/scopes/headers, invalid encodings, and
  capacity exhaustion.

## Maintainer verification available

The exact candidate passed:

- formatting, all-target/all-feature check, and Clippy with warnings denied;
- 337 workspace tests with two intentional ignores and the separate doc-test gate;
- 84 Admin tests, including the exact action matrix, authorization ordering, owner hiding,
  schema route separation, tamper detection, and recovery;
- private Admin CLI integration, seven valid and three invalid configuration fixtures;
- fuzz-crate manifest check and the 2,440-line feature tree;
- byte-identical checked OpenAPI, configuration schema, manifests, and lockfile versus
  `dev@eb107ec`;
- production-module size gate, with the largest measured module at 1,129 lines.

Unavailable locally: `cargo audit`, `cargo deny`, `cargo nextest`, `cargo fuzz`, Docker-backed
checks, long fuzz/soak, and automated Markdown/link tools. These gaps must not be reported as
passes.

## Required report

Return:

- reviewer identity, qualifications, independence statement, exact commit, date, environment, and
  tool versions;
- commands and payload/corpus hashes sufficient to reproduce results;
- one row per finding with ID, severity, affected invariant/path, reproduction, impact, and
  recommended remediation;
- explicit count of unresolved critical, high, medium, low, and informational findings;
- decision: approve, approve with recorded non-blocking findings, or reject.

Critical/high findings block Phase 15. Medium findings require an owner, deadline, and compensating
control. Maintainers must not create `docs/reviews/phase-15-completion.md`, merge closeout into
`dev`, or start Phase 16 until the independent report approves the exact candidate with no
unresolved critical/high finding.
