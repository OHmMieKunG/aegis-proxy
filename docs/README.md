# AegisProxy documentation

## Canonical documents

- [`STATUS.md`](../STATUS.md): verified current implementation and release blockers.
- [`PLAN.md`](../PLAN.md): future phases 14–21.
- [`README.md`](../README.md): product overview and quick start.
- [`SECURITY.md`](../SECURITY.md): private vulnerability reporting.
- [Repository documentation audit](reviews/repository-documentation-audit.md): detailed capability
  evidence.
- [Phase 15 Proxy Host compiler](reviews/phase-15-proxy-host-compiler.md): current high-level object
  compilation boundary and validation evidence.
- [Phase 15 candidate preview](reviews/phase-15-candidate-preview.md): safe typed preview boundary
  and validation evidence.
- [Phase 15 typed diff](reviews/phase-15-typed-diff.md): deterministic bounded field-level change
  contract and validation evidence.
- [Phase 15 API-token scopes](reviews/phase-15-api-token-scopes.md): role-intersection authorization,
  migration behavior, and validation evidence.
- [Phase 15 Proxy Host endpoints](reviews/phase-15-proxy-host-endpoints.md): owner-aware private
  validation/preview boundary, CLI contract, and validation evidence.
- [Phase 15 Proxy Host store](reviews/phase-15-proxy-host-store.md): bounded durable desired-state
  contract, generation concurrency, and failure evidence.
- [Phase 15 Proxy Host reads](reviews/phase-15-proxy-host-reads.md): exact read scope, owner-scoped
  API/CLI, stored conflict claims, and validation evidence.
- [Phase 15 aggregate Proxy Host compiler](reviews/phase-15-proxy-host-aggregate-compiler.md):
  complete desired-state compilation, managed namespace verification, and pending-state evidence.
- [Phase 15 Proxy Host create](reviews/phase-15-proxy-host-create.md): audited immutable-candidate
  creation, desired-state epoch CAS, non-activation, and validation evidence.
- [Phase 15 Proxy Host update/delete](reviews/phase-15-proxy-host-update-delete.md): dual CAS,
  owner-scoped mutation, immutable candidates, and non-activation evidence.
- [Phase 15 Proxy Host activation](reviews/phase-15-proxy-host-activation.md): complete desired-state
  verification, serialized audit boundary, atomic activation reuse, and rejection evidence.
- [Phase 15 typed candidate binding](reviews/phase-15-proxy-host-candidate-binding.md): immutable
  desired-state snapshots, metadata linkage, tamper rejection, and compatibility evidence.
- [Phase 15 typed rollback](reviews/phase-15-proxy-host-rollback.md): bound historical desired
  state, forward revision, recovery journal, authorization, and validation evidence.
- [Phase 15 typed snapshot retention](reviews/phase-15-proxy-host-snapshot-retention.md):
  authoritative revision reconciliation, bounded cleanup, tamper rejection, and validation
  evidence.
- [Phase 15 Access Policy ownership](reviews/phase-15-access-policy-ownership.md): strict
  secret-free ownership/sharing contract, fixed-stage validation, and endpoint non-scope.
- [Phase 15 Access Policy store](reviews/phase-15-access-policy-store.md): bounded canonical
  persistence, owner/generation CAS, exclusive ownership, and durability-failure evidence.
- [Phase 15 Access Policy scopes](reviews/phase-15-access-policy-scopes.md): dedicated RBAC/token
  actions, CLI/OpenAPI parity, private startup ownership, and endpoint non-scope.
- [Phase 15 Access Policy reads](reviews/phase-15-access-policy-reads.md): owner-scoped list/get,
  scope enforcement, generation ETags, OpenAPI/CLI contracts, and isolation evidence.
- [Phase 15 Access Policy recovery gate](reviews/phase-15-access-policy-recovery-gate.md):
  fail-closed write blocking after indeterminate atomic replacement.

## Operators

- [Installation](operations/installation.md)
- [Deployment](operations/deployment.md)
- [Configuration reference](configuration/reference.md)
- [Configuration examples](configuration/examples.md)
- [Migrations](configuration/migrations.md)
- [Configuration lifecycle](operations/configuration-lifecycle.md)
- [Private administration](operations/admin.md)
- [ACME](operations/acme.md)
- [Certificate recovery](operations/certificate-recovery.md)
- [Service discovery](operations/service-discovery.md)
- [Observability](operations/observability.md)
- [Backup and recovery](operations/backup.md)
- [High availability](operations/high-availability.md)
- [Upgrades](operations/upgrades.md)
- [Troubleshooting](operations/troubleshooting.md)
- [Incident response](operations/incident-response.md)

## Architecture and security

- [Architecture overview](architecture/overview.md)
- [Data plane](architecture/data-plane.md)
- [Control plane](architecture/control-plane.md)
- [Providers](architecture/providers.md)
- [Middleware stages](configuration/middleware.md)
- [Secret handling](security/secret-handling.md)
- [Trusted proxies](security/trusted-proxies.md)
- [Threat/control matrix](security/threat-control-matrix.md)
- [ADRs](adr/)

## Developers

- [Contributing](../CONTRIBUTING.md)
- [Agent guide](../AGENTS.md)
- [Testing](development/testing.md)
- [Workspace ownership](development/workspace.md)
- [Soak plan](development/soak-testing.md)
- [Benchmarks](benchmarks/README.md)
- [Fuzzing](../fuzz/README.md)
- [Dependencies](dependencies.md)

## History

[Historical phase, validation, and security evidence](history/README.md) is retained for
traceability. Dated results are not current test results.

User-facing GUI guides do not exist yet because GUI and stable high-level domain objects are planned,
not implemented. Creating them now would document fictional behavior.
