# Backup and recovery

Backups are versioned JSON manifests encrypted as age X25519 archives. They
include bounded regular files beneath `config`, `certificates`, `acme`, `admin`,
and `audit`. Symlinks, special files, traversal, broad source permissions,
temporary locks, and the age identity are rejected or excluded. Existing
backup destinations are never replaced.

## Create and verify

Configure one or more public X25519 recipients in
`tls.state_encryption_recipients`. Keep corresponding identities outside the
proxy state directory and escrow them under organizational recovery policy.

```text
rust-proxy backup create --socket SOCKET --expect ACTIVE_REV --output /backup/aegis-2026-07-18.age
rust-proxy backup verify /backup/aegis-2026-07-18.age --identity file:///run/secrets/aegis-age-identity
```

Creation takes a bounded read-consistent snapshot, checks source stamps before
and after reads, encrypts in memory, writes a private temporary file, fsyncs,
and publishes with create-new semantics. Verification authenticates and
decrypts into zeroizing memory, then checks schema, path, mode, size, and every
SHA-256 digest. It writes no restored state.

Copy verified ciphertext off-host and preferably off-account with immutable
retention. Never treat a local staging file as the only backup. Back up at least
every 15 minutes only if that proposed metadata RPO is approved and storage
capacity has been measured.

## Clean-host recovery procedure

1. Install a compatible, independently verified binary on a clean host.
2. Copy one encrypted archive to private staging storage without overwriting it.
3. Provide the age identity through a mode-restricted file or environment
   secret, separate from proxy state.
4. Run `backup verify`. Reject any authentication, schema, path, mode, size, or
   checksum failure.
5. Restore verified manifest entries with an offline reviewed extraction tool
   into a new mode-`0700` state directory. v1 deliberately has no blind or
   in-place extractor.
6. Run offline configuration validation and certificate inspection against the
   new directory. Bind only test listeners on the recovery host.
7. Start with explicit last-known-good recovery, verify readiness and
   representative routes, then promote traffic externally.
8. Preserve old state and binary through the rollback window. Audit recovery
   and rotate credentials when compromise caused restoration.

## Current measured gap

Local tests authenticate, decrypt, and checksum a small archive in under one
second; this is not an RTO benchmark. Automated clean-host extraction and a
topology-specific 60-minute RTO drill remain unverified. Phase 21 deployment
drills must measure real archive size, transfer, identity access, binary
installation, listener validation, traffic promotion, and rollback. Until then,
the proposed 15-minute RPO and 60-minute RTO are objectives, not guarantees.
