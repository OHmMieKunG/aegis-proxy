# Phase 15 typed control-plane baseline

Recorded: 2026-07-22

## Starting state

- Branch `dev`, commit `b685449`, clean and equal to `origin/dev`.
- Phase 14 complete; private administration modules have explicit routing, handler, and support
  ownership.
- Existing `/v1` API is strict and private but low-level: TOML candidates, revisions, runtime
  summaries, token roles, audit, backup creation, and restore validation.
- Existing optimistic concurrency, immutable revisions, activation, rollback, secret references,
  token hashing, fixed RBAC, and durable audit must be reused rather than replaced.

## Verified gaps

- No high-level Proxy Host, Stream Host, Access Policy, Stored Credential, user, or discovery-source
  object contract exists.
- API token authorization has fixed roles but no explicit scopes or object ownership.
- Preview lacks a field-level typed diff.
- OpenAPI describes low-level routes only; no high-level mutation endpoint exists.
- No migration compiler maps high-level objects into canonical `aegisproxy_config::Config`.
- No browser session or GUI exists; both remain Phase 16 non-scope for this phase.

## Execution order

1. Define versioned strict object envelopes, stable IDs, ownership, references, and common Proxy
   Host contract without exposing an endpoint.
2. Define remaining high-level objects and deny-by-default action/scope/ownership matrix.
3. Compile objects into the existing canonical typed configuration and run existing semantic
   validation; provide no alternate activation path.
4. Add typed preview/diff, candidate, activation, rollback, revision, audit, and CLI contracts.
5. Update OpenAPI, migration/compatibility/error/security documentation, then run full gates and
   independent API/security diff review.

## Initial invariant

Contract types alone do not make a feature implemented. No high-level endpoint is advertised until
its object compiles through existing validation, revision, audit, RBAC, and activation machinery.

## Progress

Strict envelope and Proxy Host contract landed before deterministic compiler in `fa7913f`.
Compiler, preview, diff, token-scope, and private owned endpoint evidence is indexed in
[`docs/README.md`](../README.md). Phase 15 remains in progress; typed object persistence,
mutation/activation, complete ownership/RBAC metadata, remaining objects, and compatibility policy
remain open.
