# Deployment

Deployment artifacts are evaluation examples, not production certification.

## Container

`Dockerfile` performs a clean Node build, embeds the generated UI into `rust-proxy`, and runs only
that binary as UID/GID 65532. `compose.yaml` remains the data-plane-only bridge example. It uses a
read-only root, bounded tmpfs, no new privileges, dropped capabilities, resource limits, a private
loopback port, and no Docker socket. State is the only persistent writable volume.

```bash
docker compose config
docker compose build proxy
docker compose up
```

The disposable [browser evaluation stack](../../deploy/evaluation/README.md) uses Linux host
networking to preserve the loopback-only administration and OIDC boundaries. It is not a production
deployment template.

Optional seccomp/AppArmor examples live under `deploy/security/`. Validate them on target host;
syntax checks do not prove runtime compatibility. Docker Desktop runtime testing does not replace
the evaluation stack's native Linux host-network requirement.

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
