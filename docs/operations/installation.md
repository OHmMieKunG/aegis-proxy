# Installation

AegisProxy is pre-release. Use only controlled local or staging environments.

## Build from source

Requirements: Linux, stable Rust 1.88 or newer, CMake, C compiler, and Git checkout.

```bash
rustc --version
cargo build --locked --release --bin rust-proxy
cargo run -q -p rust-proxy -- validate --config config/examples/minimal.toml
```

Binary output is `target/release/rust-proxy`. No release artifact or installer is published.

## Local evaluation

Start a disposable upstream in another terminal:

```bash
mkdir -p /tmp/aegis-upstream-test
python3 -m http.server 9000 --bind 127.0.0.1 --directory /tmp/aegis-upstream-test
```

If port 9000 is already used, stop or identify that process before testing. Do not assume content
received through proxy came from new fixture.

```bash
cargo run -p rust-proxy -- run --config config/examples/minimal.toml
curl -v -H 'Host: example.test' http://127.0.0.1:8080/
```

See [configuration examples](../configuration/examples.md), [deployment](deployment.md), and
[troubleshooting](troubleshooting.md).
