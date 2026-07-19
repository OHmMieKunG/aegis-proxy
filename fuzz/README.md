# Security fuzzing

The fuzz crate is intentionally outside the release workspace. It enables only thin
`fuzzing` entry points and never changes production defaults.

| Target | Boundary | Maximum input |
|---|---|---:|
| `config_parser` | bounded strict TOML parse and semantic validation | 2 MiB |
| `route_conflict` | validated route conflict analysis and index compilation | 2 MiB |
| `host_canonicalization` | canonical host parser | 8 KiB |
| `path_normalization` | request URI and path canonicalization | 8 KiB |
| `header_processing` | HTTP framing checks and hop-by-hop stripping | 8 KiB |
| `forwarded_headers` | trusted forwarding chain and request-ID parsing | 8 KiB |
| `client_hello` | Rustls bounded ClientHello state machine | 64 KiB |
| `certificate_metadata` | strict stored-certificate TOML metadata parser | 64 KiB |

Install a nightly toolchain and a repo-local runner, then run a smoke campaign:

```bash
rustup toolchain install nightly --profile minimal
RUSTUP_TOOLCHAIN=stable cargo install cargo-fuzz --locked --root target/tools
RUSTUP_TOOLCHAIN=nightly target/tools/bin/cargo-fuzz run host_canonicalization \
  fuzz/corpus/host_canonicalization -- -runs=500 -max_len=8192 -timeout=5
```

Release-candidate campaigns must run every target for at least 24 worker-hours,
retain and review coverage-minimized corpus changes, use the limits above, and archive
the exact toolchain, command, exit status, crash artifacts, and corpus hash. Any crash,
timeout, sanitizer finding, or unbounded growth blocks release until triaged.

Phase 13 local smoke on 2026-07-19 ran 500 cases per target under ASan with
`cargo-fuzz 0.13.2` and `rustc 1.99.0-nightly (eff8269f7 2026-07-18)`. All eight
targets exited successfully with no crash artifact. This smoke is not the required
long campaign.
