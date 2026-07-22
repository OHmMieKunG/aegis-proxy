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
