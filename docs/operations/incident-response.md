# Security incident response

Use this runbook for suspected configuration, admin, certificate, dependency, container, or host
compromise. Protect people and production policy first; preserve evidence without copying secrets
into tickets or chat.

## First 15 minutes

1. Declare incident owner, severity, time source, affected fleet/candidate revision, and private
   coordination channel. Do not use a possibly compromised admin token for attribution.
2. Preserve current binary/config hashes, audit chain, service logs, process/container metadata,
   listener state, and load-balancer state. Copy only to approved evidence storage.
3. Contain externally: drain or remove affected nodes at the load balancer. Prefer isolation over
   destructive cleanup. Keep a known-good node serving only if its trust basis is independent.
4. Revoke exposed admin/API tokens, ACME/DNS credentials, age identities, and certificates from a
   clean control host. Rotate audit keys only after preserving the old chain/key for verification.
5. Mark readiness false or stop service if traffic confidentiality/integrity is uncertain. A data
   plane serving attacker policy is not an availability win.

## Class-specific containment

| Incident | Immediate containment | Recovery validation |
|---|---|---|
| malicious/accidental config | block mutations, identify actor/hash, activate reviewed forward rollback revision | `validate`, `preview`, `diff`, audit chain, representative routes, SSRF policy |
| stolen admin token | revoke token from clean authorized peer, inspect all mutations since issue time, rotate related credentials | token list/revocation, RBAC matrix, audit before/after hashes |
| certificate/private-key compromise | remove node, revoke certificate/account as CA supports, rotate DNS provider and age identities | key/domain/validity match, non-staging provenance, TLS scanner |
| dependency/build compromise | halt rollout, quarantine artifacts/build runner, compare source/lock/SBOM/provenance, rebuild clean | audit/deny, source signatures, two-person artifact review |
| DoS/resource abuse | rate-limit or filter externally, preserve samples, shed load, do not weaken parsing/auth | bounded recovery, queue/FD/memory metrics, slow/oversize regressions |
| container/host compromise | remove host from service, snapshot evidence, rotate all host-readable credentials, rebuild host | clean image/host scan, confinement, backup validation, new node identity |
| audit/backup tampering | fail mutations closed, isolate affected store, retain ciphertext/logs | chain/checksum/authentication verification from clean binary |

## Clean recovery

1. Select a verified binary and configuration/revision predating compromise; rollback is a new
   authorized revision, never pointer/history rewriting.
2. Verify encrypted backup before extraction. Restore into a new private state directory on a
   clean host following `docs/operations/backup.md`.
3. Rotate every secret the compromised boundary could read. Do not restore revoked tokens or old
   private identities merely because they exist in backup.
4. Start on isolated listeners, verify readiness, TLS/SNI, representative routes, egress policy,
   audit durability, metrics, and drain. Canary through external load balancer.
5. Monitor security/reload/TLS/upstream/audit indicators. Keep prior evidence and recovery state
   immutable through review and retention period.

## Closure

Record timeline, root cause, blast radius, data/credential exposure, findings/severity, fix/test
commits, reviewer retest, second-person verification, notifications, residual risk, and prevention
owner/deadline. Critical/high findings block release. Coordinate public disclosure through
`SECURITY.md`; never promise a disclosure date before impact and fixes are understood.
