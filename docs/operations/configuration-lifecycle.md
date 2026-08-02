# Configuration reload and recovery

## Supported storage contract

Configuration state must use a local filesystem with atomic same-directory rename and reliable file `fsync`. Local ext4 has dated crash/recovery evidence: the logical crash/reopen campaign passed on an isolated WSL2 Docker ext4 volume. Exact production storage still requires deployment-specific power-loss qualification. XFS remains a candidate but is unverified. NTFS is exercised by development tests, but Windows directory `fsync` is unavailable through the current safe standard-library path, so equivalent crash-durability is not claimed. NFS, SMB, XFS, distributed filesystems, overlay state directories, and concurrent writers are unsupported until separately qualified.

The daemon exclusively locks `<state-dir>/config/owner.lock`. Failure to acquire the lock exits; it never guesses that another writer is dead. Immutable TOML revisions and JSON metadata use exclusive creation, bounded reads, SHA-256 verification, file sync, and directory sync where supported. Mutable `active.json` and `activation.json` are replaced from a synced temporary file in the same directory.

Revision retention keeps every revision for at least 30 days and always keeps the newest 70. The active revision, immediate previous revision, and activation-journal references are protected regardless of age. Candidate creation fails at the hard 1,000-revision ceiling when protected or minimum-age revisions cannot be removed; it does not delete recovery state to make space.

## Normal startup

```text
rust-proxy run --config /etc/rust-proxy/proxy.toml
```

Normal startup reads and validates the configured file before opening durable state. An invalid file exits nonzero. If durable typed Proxy Hosts, Stream Hosts, or Discovery Sources exist, startup recompiles their complete applied desired state over that file, creates or resumes a bound revision, and exits nonzero on any reconciliation error. Intentional Proxy Host drafts are loaded and validated but excluded from this snapshot. When an exact active typed binding exists, startup resumes it rather than activating a newer desired object or draft. It never silently starts from the file-only routes. After runtime preparation and listener binding succeed, the candidate revision and activation journal are committed before traffic is accepted.

Without durable typed state, the daemon polls the file by SHA-256 content hash at `runtime.config_poll_secs`. Unix `SIGHUP` triggers the same path immediately. Unchanged bytes are not reparsed. Invalid candidates, preparation failures, restart-only changes, and stale compare-and-swap attempts leave the active pointer and runtime unchanged. With durable typed state, the mounted file is the restart-time base and is not hot-reloaded; use the typed API for live changes and restart to apply a base-file edit.

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

Offline activation and rollback are intentionally absent. Mutation requires prepared runtime publication and durable audit; authenticated commands use the current administrative interface.

## Crash behavior

- Crash before journal replacement: the prior committed pointer remains.
- Crash after intent but before pointer replacement: restart restores the journal's previous revision.
- Crash after pointer replacement or during probation: restart restores the previous revision.
- Crash after committed journal replacement: restart verifies and retains the new revision.
- Corrupt, oversized, unknown-field, hash-mismatched, or missing referenced state fails closed.
- Proxy Host drafts survive restart but remain outside desired compilation, candidates, providers,
  and active routing. A promoted desired state that failed activation remains pending and is not
  changed back into a draft.
- If in-memory rollback succeeds but durable rollback fails, traffic uses the old snapshot and further administrative mutation is disabled until restart/recovery.

Automated tests cover same-hash concurrency, stale compare-and-swap, journal-before-pointer recovery, incomplete probation, committed restart, invalid live reload, explicit recovery, Unix SIGHUP activation, removed-endpoint idle connection eviction, active-work drain deadlines, and accepted requests returning either the old or new successful response during reload. The ext4 campaign is recorded in [dated crash-recovery evidence](../history/validation/phase-5-crash-recovery.md); physical power-loss guarantees still require testing on the deployment storage stack.
