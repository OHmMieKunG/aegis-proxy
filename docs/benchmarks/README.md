# Benchmarks

No general performance claim exists. Current repository has one dated atomic-reload microbenchmark:
[2026-07-16 reload result](reload-2026-07-16.md). It excludes parsing, file polling, compilation,
and full traffic loss measurement.

Future results must record hardware, OS/kernel, Rust version, commit/lockfile, build profile,
configuration, upstream, body size, connections, protocol/TLS, warmup, duration, statistical
method, and raw results. Correctness/security gates take priority. Phase 21 requires representative
throughput, latency, memory, CPU, TLS, HTTP/2, WebSocket, route lookup, certificate lookup, reload,
failure, and soak evidence before any support envelope.
