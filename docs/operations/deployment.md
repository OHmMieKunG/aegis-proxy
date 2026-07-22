# Deployment

Deployment artifacts are evaluation examples, not production certification.

## Container

`Dockerfile` builds `rust-proxy` and runs as UID/GID 65532. `compose.yaml` uses a read-only root,
bounded tmpfs, no new privileges, dropped capabilities, resource limits, private loopback port, and
no Docker socket. State is the only persistent writable volume.

```bash
docker compose config
docker compose build proxy
docker compose up
```

Optional seccomp/AppArmor examples live under `deploy/security/`. Validate them on target host;
syntax checks do not prove runtime compatibility. Current WSL environment lacks Docker integration.

## systemd

`deploy/systemd/aegisproxy.service` uses `DynamicUser`, private state/runtime directories, strict
filesystem protections, and pre-start validation. Install binary and config before verification:

```bash
sudo install -m 0755 target/release/rust-proxy /usr/local/bin/rust-proxy
sudo install -m 0600 config.toml /etc/aegisproxy/config.toml
systemd-analyze verify deploy/systemd/aegisproxy.service
```

Public ports below 1024 require an explicitly reviewed socket-activation or capability design;
current examples avoid granting broad privileges. Administration stays on host-local Unix socket.

## Writable state and secrets

Use local storage with qualified atomic rename/fsync behavior. Keep state and external age identity
separate, private, backed up, and never shared writable between nodes. See
[configuration lifecycle](configuration-lifecycle.md), [backup](backup.md), and
[certificate recovery](certificate-recovery.md).
