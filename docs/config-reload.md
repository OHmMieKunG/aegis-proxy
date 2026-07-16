# Configuration reload and recovery

## Supported storage contract

Configuration state must use a local filesystem with atomic same-directory rename and reliable file `fsync`. Intended production support targets local ext4 or XFS on Linux, subject to the Phase 5 crash campaign on the deployment storage stack. NTFS is exercised by development tests, but Windows directory `fsync` is unavailable through the current safe standard-library path, so equivalent crash-durability is not claimed. NFS, SMB, distributed filesystems, overlay state directories, and concurrent writers are unsupported.

The daemon exclusively locks `<state-dir>/config/owner.lock`. Failure to acquire the lock exits; it never guesses that another writer is dead. Immutable TOML revisions and JSON metadata use exclusive creation, bounded reads, SHA-256 verification, file sync, and directory sync where supported. Mutable `active.json` and `activation.json` are replaced from a synced temporary file in the same directory.

Revision retention keeps every revision for at least 30 days and always keeps the newest 70. The active revision, immediate previous revision, and activation-journal references are protected regardless of age. Candidate creation fails at the hard 1,000-revision ceiling when protected or minimum-age revisions cannot be removed; it does not delete recovery state to make space.

## Normal startup

```text
rust-proxy run --config /etc/rust-proxy/proxy.toml
```

Normal startup reads and validates the configured file before opening durable state. An invalid file exits nonzero. After runtime preparation and listener binding succeed, the candidate revision and activation journal are committed before traffic is accepted.

The daemon polls the file by SHA-256 content hash at `runtime.config_poll_secs`. Unix `SIGHUP` triggers the same path immediately. Unchanged bytes are not reparsed. Invalid candidates, preparation failures, restart-only changes, and stale compare-and-swap attempts leave the active pointer and runtime unchanged.

Hot reload currently requires the same listener IDs, bind addresses, protocols, resource limits, state directory, and TLS handshake concurrency. Route, certificate assignment, TLS policy except handshake concurrency, and upstream changes are prepared in a new immutable snapshot. Unsupported listener/resource changes report `restart required`.

## Explicit last-known-good recovery

Use recovery only after inspecting the invalid configured file and durable state:

```text
rust-proxy run \
  --config /etc/rust-proxy/proxy.toml \
  --resume-last-known-good \
  --state-dir /var/lib/rust-proxy
```

Both recovery flags are mandatory together. Recovery verifies the journal, pointer, metadata, revision hash, schema, and semantic configuration before binding. It does not read or overwrite the bad file during bootstrap. The watcher remains active so a later valid edit can activate normally. The selected revision is logged at warning level.

Offline inspection requires the daemon to be stopped:

```text
rust-proxy config revisions --state-dir /var/lib/rust-proxy
```

Offline activation and rollback are intentionally absent. Mutation requires prepared runtime publication and durable audit; authenticated commands arrive with the Phase 8 administrative interface.

## Crash behavior

- Crash before journal replacement: the prior committed pointer remains.
- Crash after intent but before pointer replacement: restart restores the journal's previous revision.
- Crash after pointer replacement or during probation: restart restores the previous revision.
- Crash after committed journal replacement: restart verifies and retains the new revision.
- Corrupt, oversized, unknown-field, hash-mismatched, or missing referenced state fails closed.
- If in-memory rollback succeeds but durable rollback fails, traffic uses the old snapshot and further administrative mutation is disabled until restart/recovery.

Automated tests cover same-hash concurrency, stale compare-and-swap, journal-before-pointer recovery, incomplete probation, committed restart, invalid live reload, explicit recovery, Unix SIGHUP activation, and accepted requests returning either the old or new successful response during reload. Power-loss guarantees still require Linux filesystem crash testing on the deployment storage stack.
