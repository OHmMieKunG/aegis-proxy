# Testing

## Standard gates

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
cargo tree -e features
```

Current aggregate suite contains unit, black-box protocol, CLI, gRPC, admin, HA, TLS, security, and
configuration tests. Two tests are intentionally ignored in normal aggregate run: manual reload
benchmark and Docker-backed Pebble integration.

## Configuration corpus

```bash
for file in config/examples/*.toml; do
  cargo run -q -p rust-proxy -- validate --config "$file"
done
```

Every `config/invalid/*.toml` must fail validation. `crates/rust-proxy/tests/config_cli.rs` enforces
both sets.

## Focused suites

```bash
cargo test -p aegisproxy-core
cargo test -p aegisproxy-core --test grpc
cargo test -p rust-proxy --test admin_cli
cargo test -p rust-proxy --test ha_chaos
cargo test -p rust-proxy --test signal_cli
```

## Browser tests

Before browser execution, verify that the client-only production graph excludes React Router's RSC
server request/action handler:

```bash
npm --prefix ui run security:router
```

This is a module-graph and generated-chunk check, not a replacement for `npm audit` or browser
execution. See the [advisory disposition](../security/react-router-advisory-disposition.md).

The checked-in Playwright package is version 1.62.0. A Linux host with Docker can run Chromium in
the matching pinned Noble image without changing repository file ownership. Build and serve the
production UI in one terminal:

```bash
npm --prefix ui run build
cd ui
npm exec vite -- preview --host 0.0.0.0 --port 4173
```

Run the focused Proxy Host suite from the repository root in another terminal:

```bash
docker run --rm --network host --ipc host \
  -e HOME=/tmp/playwright-home \
  -v "$PWD:/work:ro" \
  -w /work/ui \
  mcr.microsoft.com/playwright@sha256:baed2032d533817f3dbe6425de795788430ba345e819a1201337009ba17c9d07 \
  npx playwright test tests/ui.spec.ts --grep "Proxy Host" \
  --output /tmp/aegis-playwright-results --reporter=line
```

The read-only repository mount and container-local output avoid host-owned Vite/Playwright cache
artifacts. This command executes Chromium; `playwright --list` is not browser evidence.
The focused lifecycle scenario covers inactive draft save/reopen/discard/promotion, activation
failure after promotion, desired-versus-active labels, and the existing create/edit/toggle/copy/
delete/conflict/recovery/audit outcomes.

Pebble requires disposable local Docker fixture:

```bash
docker compose -f tests/pebble/compose.yml up -d
cargo test -p aegisproxy-tls --test pebble -- --ignored --nocapture
docker compose -f tests/pebble/compose.yml down
```

## Environment failures

Unix-socket tests may fail with `Operation not permitted` inside restricted sandboxes. Rerun only
on an authorized normal host and report both results. Docker absence, missing installed systemd
binary, privileged AppArmor enforcement, or unavailable audit tools must be recorded, not treated as
passes.

See [fuzzing](../../fuzz/README.md), [benchmarks](../benchmarks/README.md), and
[soak plan](soak-testing.md).
