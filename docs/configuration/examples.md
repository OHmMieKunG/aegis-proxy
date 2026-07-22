# Configuration examples

Examples are low-level operator fixtures, not the planned GUI workflow. Validate before running:

```bash
for file in config/examples/*.toml; do
  cargo run -q -p rust-proxy -- validate --config "$file"
done
```

| File | Purpose | Important limitation |
|---|---|---|
| `minimal.toml` | HTTP host route to loopback upstream | Port 9000 must contain intended test service |
| `default-route.toml` | Explicit catch-all route | Default routes must be declared, never implicit |
| `tls.toml` | HTTPS termination and verified HTTPS upstream | Replace certificate generation and secret paths |
| `tcp.toml` | Raw TCP and SNI TLS passthrough | No HTTP middleware on TCP routes |
| `phase7.toml` | Full current middleware combinations | Historical filename; behavior remains current |
| `phase11-file.toml` | File endpoint provider | Provider path is deployment-specific |
| `phase11-dns.toml` | Disabled A/AAAA provider | Documentation-only hostname; SRV unsupported |

Invalid fixtures under `config/invalid/` must remain rejected. `preview` redacts secret references;
`fmt` preserves reference paths/names and should still be treated as operational configuration.

```bash
cargo run -q -p rust-proxy -- preview --config config/examples/minimal.toml
cargo run -q -p rust-proxy -- fmt --config config/examples/minimal.toml
```

Normal users should eventually use Phase 16 Proxy Host workflow. Current examples expose internal
routes, upstream pools, middleware, listeners, SNI, and ACME details because high-level objects do
not yet exist.
