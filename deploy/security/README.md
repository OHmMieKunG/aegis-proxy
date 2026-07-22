# Optional Linux confinement examples

These profiles supplement the existing non-root, read-only, capability-free,
`no-new-privileges` container. They are examples, not portable guarantees. Kernel, libc, Rust,
crypto provider, DNS, telemetry, and container-runtime changes can alter required syscalls and
paths.

Validate and load AppArmor on the target host:

```bash
sudo apparmor_parser -Q -T -W deploy/security/aegisproxy.apparmor
sudo apparmor_parser -r deploy/security/aegisproxy.apparmor
docker compose -f compose.yaml -f deploy/security/compose-hardening.override.yaml config
docker compose -f compose.yaml -f deploy/security/compose-hardening.override.yaml up --build
```

Exercise startup, DNS refresh, HTTP/TLS, ACME, config activation/rollback, audit, backup, telemetry,
signals, and graceful drain. Any `EPERM`, AppArmor denial, or missing operation blocks use until the
minimal required rule is reviewed and tested. Never switch either profile to unconfined merely to
make a test pass.

The AppArmor profile permits UDP only for DNS/ACME name resolution; it does not enable UDP
proxying. It denies executing other packaged binaries. The seccomp allowlist denies mount,
namespace, module, ptrace, BPF, reboot, keyring, and raw kernel-management syscalls by omission.

Dated local evidence parsed the JSON and AppArmor policy in query mode. Current WSL environment
lacks Docker integration, so runtime compatibility and Compose merge remain unverified release
gates.
