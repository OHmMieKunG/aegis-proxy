# Architecture overview

AegisProxy currently runs one Rust process and binary per node. Product name is `AegisProxy`;
current executable is `rust-proxy`.

```text
public HTTP/HTTPS/TCP listeners
             |
      bounded protocol edge
             |
 route + fixed middleware stages
             |
 validated upstream pools and TLS

private Unix administration socket
             |
 RBAC + exact revision + audit
             |
 candidate validation and preparation
             |
 durable revision + atomic snapshot publish
```

Workspace ownership:

- `aegisproxy-core`: Hyper data plane, routing, middleware, upstreams, providers, runtime.
- `aegisproxy-config`: strict TOML, semantic validation, route conflicts, revisions.
- `aegisproxy-tls`: Rustls, certificate selection/storage, ACME.
- `aegisproxy-secrets`: approved references, redaction, age envelopes.
- `aegisproxy-admin`: private Axum API, RBAC, tokens, audit, backup validation.
- `rust-proxy`: CLI, telemetry setup, lifecycle wiring, fleet checker.

Runtime requests read one immutable `Arc<RuntimeSnapshot>` through `ArcSwap`. Activation validates
and prepares a complete candidate before durable intent/pointer changes and one non-failing snapshot
publication. Old work retains old state until drain. Invalid candidates never replace active state.

No database, runtime plugin, public administration listener, embedded cluster, HTTP/3, or UDP proxy
exists. See [data plane](data-plane.md), [control plane](control-plane.md), and
[providers](providers.md).
