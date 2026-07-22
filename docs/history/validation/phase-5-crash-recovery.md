# Phase 5 crash/recovery campaign

> Historical validation
>
> Results apply to the dated implementation campaign. See [`STATUS.md`](../../../STATUS.md) for current verification.

Date: 2026-07-16

## Environment

- Docker Desktop 4.81.0, engine 29.6.1.
- Linux kernel `5.15.167.4-microsoft-standard-WSL2`.
- Isolated Docker volume `aegisproxy-phase5-state` mounted at `/state`.
- `findmnt` reported `/dev/sdc[/data/docker/volumes/aegisproxy-phase5-state/_data]`, filesystem `ext4`, options `rw,relatime`.
- Rust builder image `aegisproxy-builder:local`; locked workspace dependencies.
- `TMPDIR=/state/tmp` and `CARGO_TARGET_DIR=/state/target`, so revision state and test temporary directories used the ext4 volume rather than the bind-mounted Windows workspace or container overlay.

## Command

```powershell
docker run --rm `
  --mount "type=bind,source=$((Get-Location).Path),target=/work,readonly" `
  --mount type=volume,source=aegisproxy-phase5-state,target=/state `
  --workdir /work `
  --env CARGO_TARGET_DIR=/state/target `
  --env TMPDIR=/state/tmp `
  --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin `
  aegisproxy-builder:local `
  sh -c "mkdir -p /state/tmp; findmnt -T /state/tmp -o TARGET,SOURCE,FSTYPE,OPTIONS; cargo test --locked -p aegisproxy-config revision::tests:: -- --nocapture --test-threads=1"
```

## Result

All eight revision tests passed in 0.70 seconds:

- exact compare-and-swap activation and rollback;
- candidate integrity, deduplication, and tamper rejection;
- concurrent same-content candidate creation;
- committed-pointer restart recovery;
- incomplete-probation rollback on restart;
- intent-before-pointer-switch rollback on restart;
- bounded retention with active/previous protection;
- exclusive state ownership and traversal-resistant IDs.

The recovery fixtures inject durable states at activation boundaries, close the store, reopen it, and require either the prior committed pointer or the fully committed candidate. No test accepts a partial pointer/revision pair.

## Failed setup attempts

- The first container command confirmed ext4 but `sh -lc` reset Cargo's path; no project test ran.
- A second command attempted to export the host-expanded PowerShell `PATH`; the shell rejected it before tests.
- The final command used an explicit container `PATH` and passed.

## Limits

- This is a logical crash/reopen campaign on ext4, not a physical power-cut or storage-controller fault-injection test.
- XFS was not available and remains unverified.
- Docker Desktop/WSL2 storage is not evidence for every kernel, mount option, hypervisor, disk cache, or storage controller.
- Production qualification must repeat the campaign and a power-loss/storage-fault exercise on the exact deployment storage stack.
