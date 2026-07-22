# Elysium validation — 2026-07-19

> Historical validation
>
> Results apply to the dated commit and environment below, not current HEAD. See [`STATUS.md`](../../../STATUS.md) for current verification.

## Scope and environment

This report records disposable validation performed over SSH on the operator-provided host
`elysium` (`10.60.99.98`). The checkout began clean at `fab080e` on branch `dev`. Observed tools
were Rust/Cargo 1.97.0, Docker 29.6.1, Docker Compose 5.3.1, OpenSSL, age, and AppArmor parser. The
observed kernel was `6.8.0-134-generic`; this run therefore does not verify the separately described
custom kernel 7 environment.

The remote checkout was patched only for test execution. It was restored to `fab080e` without
resetting history after validation. Disposable listeners, Pebble containers, and temporary files
were removed. The temporary SSH public key `aegis-test-20260719` was removed, a subsequent
authentication attempt was rejected, and the local temporary private key was deleted.

## Results

### Rust gates

The final patched source passed on both the local workspace and `elysium`:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`

The final workspace run executed 268 passing tests with zero failures. Two tests remained
intentionally ignored in the aggregate command: the manual release reload benchmark and the
Pebble test that requires its Compose fixture. The Pebble test was run separately and passed.

### ACME interoperability

`tests/pebble/compose.yml` was started on the remote Docker engine and:

```text
cargo test -p aegisproxy-tls --test pebble -- --ignored --nocapture
```

passed. It exercised three accelerated issuance cycles each for HTTP-01, wildcard DNS-01, and
TLS-ALPN-01, validated issued runtime identities, cleaned challenges, and rejected an invalid
HTTP-01 response. Pebble containers and their test network were removed by the test trap.

### Live HTTP and HTTPS traffic

A disposable Python upstream listened on `127.0.0.1:19000`. A generated CA:FALSE server leaf for
`example.test` was imported through `rust-proxy cert import`, encrypting the private key with a
temporary age identity. One proxy process listened on `127.0.0.1:18080` for HTTP and
`127.0.0.1:18443` for HTTPS.

Verified behavior:

- strict configuration validation and redacted preview;
- HTTP forwarding with path and query preservation;
- HTTPS termination with hostname verification against the generated certificate;
- HTTP/2 negotiated through ALPN on the HTTPS listener;
- 40 successful requests at concurrency 8;
- client-supplied `X-Forwarded-For: 203.0.113.9` did not reach the upstream;
- an unmatched host returned 404;
- CONNECT returned 400;
- an absolute-form request target returned 400;
- SIGTERM drained the proxy and produced a successful process exit after the runtime fix.

All listeners, processes, plaintext fixture keys, age identity, encrypted state, and temporary
configuration were removed by an exact-scope cleanup trap.

### Containers and confinement

- The Docker `test` target built and ran the then-current aggregate suite successfully.
- The final source built as `aegis-proxy:elysium-final`.
- The image ran as UID/GID `65532:65532` with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, no network, and the repository seccomp profile.
- `docker compose -f compose.yaml -f deploy/security/compose-hardening.override.yaml config`
  rendered successfully without duplicate security options.
- `apparmor_parser -Q -K deploy/security/aegisproxy.apparmor` passed syntax/query validation.

The AppArmor policy was not loaded into the host kernel because that requires privileged host
mutation. Consequently, a full container run with both AppArmor enforcement and seccomp remains
an environment-specific deployment gate.

### Dependency and source checks

- `cargo tree -e features` passed.
- `cargo audit` scanned 405 dependencies and found no vulnerability advisory. It reported the
  documented allowed unmaintained warning `RUSTSEC-2026-0173` for `proc-macro-error2 2.0.1`.
- `cargo deny -L error check` passed advisories, bans, licenses, and sources.
- No Git dependency source was found.
- A first-party unsafe-code scan found no match. The only private-key marker found was an expected
  test canary.

### Fuzz smoke

Prebuilt AddressSanitizer/libFuzzer targets ran 500 inputs each without a parser crash:

- configuration parser;
- route conflict analysis;
- host canonicalization;
- path normalization;
- header processing;
- forwarded-header parsing;
- ClientHello parsing;
- certificate metadata parsing.

LeakSanitizer could not run under the local ptrace/sandbox environment and terminated after the
first completed 500-run target. The generated empty sanitizer artifact and grown corpus were
removed. All eight targets were rerun in isolated temporary corpora with
`ASAN_OPTIONS=detect_leaks=0` and passed. This is a fuzz smoke result, not long-duration fuzzing or
a substitute for independent parser review.

## Defects found and corrected

| Commit | Defect | Correction | Verification |
| --- | --- | --- | --- |
| `9913f17` | Backup test inherited umask `0002`, creating a deliberately rejected mode-0664 state file | Set the private fixture file to mode 0600 on Unix | Focused, aggregate, container, local, and remote tests |
| `8ff754e` | Pebble CA fixture was mode 0644 but the secret-reference loader requires private file permissions | Copy the public test CA into an isolated mode-0600 temporary file | Full Pebble challenge run passed |
| `e46b4d4` | Compose appended a duplicate `no-new-privileges:true` entry from the hardening override | Keep the option in the base file and remove the duplicate override entry | Merged Compose rendering passed |
| `439411e` | Linux SIGTERM used the default terminating action and exited 143 instead of invoking bounded drain | Listen for SIGTERM as well as Ctrl-C and cancel through the existing graceful path | New process-level regression and live traffic shutdown passed |
| `35fca6c` | The seccomp allowlist denied read-only syscalls required by modern runc and the dynamic loader | Add only `fstatfs` and `pread64`; mount-family syscalls remain denied | Final hardened container smoke passed |

No verified critical or high-severity security defect remained from this validation. This statement
is limited to the checks above and is not a security certification.

## Unavailable or incomplete checks

- LeakSanitizer: unavailable under the ptrace/sandbox execution model; AddressSanitizer fuzz smoke
  ran with leak detection disabled.
- AppArmor enforcement: syntax parsed, but the profile was not loaded because privileged host
  mutation was outside the authorized test scope.
- Independent penetration test, protocol interoperability review, and source audit: not performed.
- Public CA issuance, real DNS provider mutation, production credentials, production traffic, and
  production deployment: deliberately not performed.
- Long-duration release soak, multi-architecture container execution, external TLS scanners,
  container vulnerability scanners, and reproducible performance benchmarks: not performed in
  this session.

Remote `rg` was unavailable; bounded `grep` checks were used where applicable. The existing
future-incompatibility warning for `proc-macro-error2 2.0.1` remains and should be removed through
its upstream dependency path when available.

## Readiness assessment

The binary is suitable for continued controlled local and staging evaluation. This evidence does
not change the repository's production no-go status. Production consideration still requires the
documented long-duration soak, independently owned application-security and reverse-proxy
protocol reviews, target-host AppArmor enforcement testing, recovery drills, and environment-
specific capacity validation.
