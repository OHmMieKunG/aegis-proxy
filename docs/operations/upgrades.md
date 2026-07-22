# Upgrades and rollback

AegisProxy has no supported release channel yet. Test every binary/config pair in staging.

1. Back up and verify encrypted state.
2. Preserve old binary, configuration, external identities, and active revision evidence.
3. Review `CHANGELOG.md`, `STATUS.md`, schema version, ADRs, and known dependency warnings.
4. Run `validate`, `preview`, full tests, and deployment-specific smoke checks with new binary.
5. Drain one node, replace binary/config, start, verify readiness/TLS/routes/audit, then canary.
6. For fleets, increment generation and use exact hash/inventory gate.

Schema v1 is current. Future breaking changes require new schema version and explicit offline
migration; startup must not silently rewrite source. No migration command exists today.

Rollback is a forward operation: restore retained prior content as a new revision or restore old
binary/config pair after compatibility validation. Never rewrite revision or Git history. Keep old
state until rollback window and recovery checks end.

See [configuration lifecycle](configuration-lifecycle.md), [high availability](high-availability.md),
and [backup](backup.md).
