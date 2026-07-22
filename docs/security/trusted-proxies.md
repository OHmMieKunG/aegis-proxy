# Trusted proxies and client identity

Forwarded headers and existing request IDs are untrusted by default and removed. Without explicit
`trusted_proxies`, security decisions use immediate peer address.

When configured, AegisProxy verifies immediate peer CIDR, limits trusted hops, parses chain from
right to left, stops at first untrusted address, rejects malformed/excess chains, and rebuilds
canonical forwarding headers. Client-controlled values never directly key IP policy, rate limits,
authentication, audit attribution, or metrics.

Example:

```toml
[trusted_proxies]
cidrs = ["192.0.2.0/24"]
trusted_hops = 1
```

Configure only networks whose proxy behavior and direct-bypass prevention are verified. If clients
can reach AegisProxy around trusted proxy, forwarded identity is not a safe security source. Current
HA guidance preserves source address directly because PROXY protocol is absent.
