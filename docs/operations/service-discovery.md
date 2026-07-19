# Service discovery operations

Phase 11 supports only bounded file and DNS A/AAAA providers. Providers replace endpoint lists in one predeclared upstream group; trusted base configuration still owns routes, listeners, transport, TLS, egress, balancing, health, retry, and circuit policy. Providers default disabled. Static endpoints are mandatory and serve as startup and post-stale fallback.

## File provider

Configure one absolute regular-file path:

```toml
[[providers]]
kind = "file"
id = "app-nodes"
enabled = true
upstream_group = "app"
path = "/run/aegisproxy/providers/app-nodes.toml"
scheme = "http"
refresh_secs = 5
debounce_millis = 250
stale_after_secs = 300
max_endpoints = 64
```

Provider documents accept only schema version, matching provider ID, and literal socket-address records:

```toml
schema_version = 1
provider_id = "app-nodes"

[[endpoints]]
id = "node-a"
address = "127.0.0.1:9100"
weight = 1
```

Unknown fields, duplicate keys/IDs, hostnames, policy, empty sets, oversized files, symlinks, non-files, and addresses outside group egress policy fail closed. Publish by writing a sibling temporary regular file, syncing it according to local durability requirements, then atomically renaming it over configured path. In-place partial writes remain inactive; one unchanged hash must survive debounce before activation.

## DNS provider

DNS provider fixes hostname, port, transport, weight, optional HTTPS server name/CA, answer cap, refresh, and stale deadline in trusted configuration. Set `enabled = true` only after group `allowed_cidrs` and `denied_cidrs` express intended network. Every complete A/AAAA answer set is bounded and validated before activation. Existing connect-time policy rechecks each literal result. Any forbidden answer rejects entire refresh, preventing mixed-answer and rebinding bypass.

DNS providers do not implement SRV, TXT metadata, labels, port discovery, or policy discovery. Phase 4 configured-hostname DNS remains separate transport resolution.

## Activation and failure behavior

1. Poll/read source under configured bounds.
2. Normalize only endpoint IDs, literal addresses, and weights through trusted template.
3. Replace endpoints in provider-owned group on cloned base configuration.
4. Run full configuration and egress validation.
5. Persist immutable candidate and activate through Phase 5 CAS, prepare, atomic publish, probation, and drain flow.

Invalid refresh never replaces active snapshot. Last accepted provider endpoints remain until `stale_after_secs`; expiry activates static endpoints. Recovery needs one new valid/stable result. Initial startup serves static endpoints until first provider poll succeeds. Removing or disabling provider activates static endpoints.

## Status and metrics

Authenticated users allowed to read upstreams can call private Unix-socket endpoint `GET /v1/providers`. Response contains only configured ID, kind, bounded state/error class, SHA-256 source hash, last-success/stale timestamps, and endpoint count. It never returns path, hostname, source records, or secret references.

OpenMetrics exposes four bounded series per configured provider:

- `aegisproxy_provider_fresh`
- `aegisproxy_provider_stale`
- `aegisproxy_provider_endpoints`
- `aegisproxy_provider_last_success_timestamp_seconds`

Alert on stale state, repeated degraded state, unexpected endpoint count, and no successful refresh within policy. Metric labels use configured provider IDs only.

## Namespace and privilege rules

- One provider owns at most one group; one group has at most one provider.
- Provider output cannot create routes, listeners, middleware, certificates, secrets, hostnames, or arbitrary destinations.
- No generic registry plugin, shell command, script, Docker provider, Kubernetes provider, Consul provider, SRV provider, or raw metadata escape hatch exists.
- Proxy binary never opens or mounts Docker socket. Docker helper remains unapproved design-only scope.
- Administrative interface remains private Unix socket by default.

Validate fixtures without activation:

```text
rust-proxy validate --config config/examples/phase11-file.toml
rust-proxy validate --config config/examples/phase11-dns.toml
```

See [ADR 0017](../adr/0017-service-discovery.md) for authority boundaries and deferred designs.
