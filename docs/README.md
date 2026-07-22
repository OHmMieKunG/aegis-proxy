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
