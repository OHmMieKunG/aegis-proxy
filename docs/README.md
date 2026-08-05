# AegisProxy documentation

## Canonical documents

- [`STATUS.md`](../STATUS.md): verified current implementation and release blockers.
- [`PLAN.md`](../PLAN.md): active roadmap and next work.
- [`README.md`](../README.md): product overview and quick start.
- [`SECURITY.md`](../SECURITY.md): private vulnerability reporting.
- [NPMPlus product direction](product/npmplus-direction-reset.md): product definition, reuse/gap
  analysis, object model, activation workflow, migration risks, and first implementation unit.
- [NPMPlus compatibility matrix](product/npmplus-compatibility-matrix.md): workflow-level GUI,
  API, runtime, migration, security, evidence, classification, and target-phase inventory.
- [Phase 0–16 repository readiness audit](reviews/repository-readiness-phase-0-16.md): current
  implementation, runtime acceptance, and open gates.
- [Phase 16 implementation candidate](reviews/phase-16-completion.md): browser/OIDC/UI scope,
  verification, and open production gates.
- [Phase 16 Save-and-apply failure campaign](reviews/phase-16-save-apply-failure-campaign.md):
  desired/candidate/active/audit/recovery boundary matrix, deterministic failpoints, and operator
  outcomes.
- [Phase 16 Proxy Host draft/application-state evidence](reviews/phase-16-proxy-host-drafts.md):
  durable transition, CAS, migration, startup, provider-exclusion, and browser contract.
- [Phase 16 independent-style security review](reviews/phase-16-independent-security-review.md),
  [operator-usability review](reviews/phase-16-operator-usability-review.md), and
  [final acceptance](reviews/phase-16-final-acceptance.md): final bounded findings, remediation,
  traceability, and release conditions.
- [Phase 17.1 multiple-domain Proxy Hosts](reviews/phase-17-multiple-domains.md): bounded contract,
  migration, compiler, certificate, restart, API, and browser evidence.
- [Phase 17.2 Proxy Locations](reviews/phase-17-proxy-locations.md): stable nested identity, path
  precedence, migration, policy inheritance, compiler, restart, API, and browser evidence.
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
- [Phase 15 Access Policy create](reviews/phase-15-access-policy-create.md): audited owner-scoped
  persistence with active-config validation and no runtime activation.
- [Phase 15 Access Policy update/delete](reviews/phase-15-access-policy-update-delete.md): dual
  concurrency, owner isolation, semantic update validation, and non-activation evidence.
- [Phase 15 Access Policy preview wiring](reviews/phase-15-access-policy-preview-wiring.md):
  secret-free owner/share resolution for non-persistent Proxy Host validation and preview.
- [Phase 15 Access Policy candidate binding](reviews/phase-15-access-policy-candidate-binding.md):
  exact dependency generations, activation/rollback revalidation, and compatibility evidence.
- [Phase 15 certificate ownership](reviews/phase-15-certificate-ownership.md): secret-free existing
  certificate binding and fail-closed managed-HTTPS selection evidence.
- [Phase 15 Stream Host and Discovery Source review](reviews/phase-15-stream-discovery.md): strict
  transport/provider contracts, persistence, no-I/O compilation, and authorization evidence.
- [Phase 15 independent review request](reviews/phase-15-independent-review-request.md): immutable
  candidate, reviewer scope, required attacks, evidence, and signoff format. This is not completion
  evidence.

## Operators

- [Installation](operations/installation.md)
- [Deployment](operations/deployment.md)
- [Configuration reference](configuration/reference.md)
- [Configuration examples](configuration/examples.md)
- [Migrations](configuration/migrations.md)
- [Configuration lifecycle](operations/configuration-lifecycle.md)
- [Private administration](operations/admin.md)
- [Web administration](guides/web-administration.md)
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
- [React Router advisory disposition](security/react-router-advisory-disposition.md)
- [Trusted proxies](security/trusted-proxies.md)
- [Threat/control matrix](security/threat-control-matrix.md)
- [ADRs](adr/)
  - [ADR-0031: Proxy Host draft and application state](adr/0031-proxy-host-draft-application-state.md)
  - [ADR-0032: Bounded exact domains on Proxy Hosts](adr/0032-proxy-host-multiple-domains.md)
  - [ADR-0033: Embedded typed Proxy Locations](adr/0033-embedded-proxy-locations.md)

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
[The 2026-07-22 repository documentation audit](history/validation/repository-documentation-audit-2026-07-22.md)
is retained there as superseded evidence.

The web-administration guide documents implemented browser behavior. Unsupported product workflows
remain classified in the compatibility matrix and scheduled only in the roadmap.
