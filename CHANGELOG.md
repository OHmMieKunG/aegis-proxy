# Changelog

AegisProxy has not published a supported release.

## Unreleased

- Implemented Rust reverse-proxy foundation through historical phases 0–13.
- Rebased documentation around verified current state and phases 14–21.
- Adopted user-first GUI and typed-control-plane direction with secret isolation.
- Completed behavior-preserving modularization: focused tests and domain-owned core, configuration,
  and administration modules now replace oversized mixed-responsibility files.
- Began Phase 15 with a strict fail-closed `v1` object envelope and library-only Proxy Host contract;
  it is not yet exposed as an administrative endpoint.
- Added side-effect-free deterministic Proxy Host compilation into canonical validated configuration
  candidates, with fail-closed ownership, policy, domain, identifier, and certificate checks.
- Added deterministic typed Proxy Host candidate previews with mandatory semantic validation,
  secret-reference redaction, generated-resource summaries, fingerprints, and restart classification.
- Added bounded deterministic Proxy Host field differences with typed values, stable ordering,
  identity checks, and explicit generated-resource add/remove operations.
- Required explicit API-token action scopes, enforced as role-and-scope intersection; legacy
  unscoped records load deny-all and token metadata remains hash-free.
- Added private owner-aware Proxy Host validation and redacted preview endpoints plus CLI commands;
  authorization precedes typed deserialization and these endpoints cannot persist or activate.
- Added bounded private Proxy Host desired-state storage with strict schema loading, deterministic
  owner indexing, generation compare-and-swap, atomic replacement, and write-failure rollback.

See [`STATUS.md`](STATUS.md) and [`docs/history/`](docs/history/README.md).
