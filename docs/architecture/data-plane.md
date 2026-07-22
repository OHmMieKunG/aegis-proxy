# Data plane

## Current protocols

Hyper serves HTTP/1.1 and HTTP/2. Rustls terminates HTTPS with exact-before-wildcard SNI selection.
Raw TCP and bounded Rustls ClientHello-based TLS passthrough use separate listener protocols.
WebSocket and gRPC use streaming Hyper bodies/upgrades. Upstream HTTP and HTTPS use pooled clients;
TCP connections pin one selected configured endpoint.

HTTP/3, UDP proxying, PROXY protocol, client-certificate mTLS, and gRPC-Web are absent.

## Request boundary

Only Hyper-parsed requests are forwarded. The edge validates target, authority/Host, SNI
consistency, framing metadata, headers, body limits, and HTTP/2 connection-specific fields. It
strips hop-by-hop and protected identity headers, normalizes trusted forwarding, canonicalizes path,
matches once, and never rematches after rewrite or error.

Routes support canonical exact/wildcard hosts, exact/prefix paths, methods, exact/presence headers,
and explicit priority. Query is preserved but not matched. TCP uses one default route; TLS
passthrough may use exact/single-label wildcard SNI and optional explicit default.

## Upstreams and resilience

Destinations originate only from validated configuration or bounded providers. Literal and resolved
addresses pass configured CIDR policy during validation, refresh, and connection. Selection supports
round robin, smooth weighted round robin, random, and power-of-two. Active/passive health, bounded
retry, circuit breaker, group capacity, and endpoint draining are node-local.

All externally influenced work is bounded by configuration or fixed protocol limits. See
[configuration reference](../configuration/reference.md) and
[middleware stages](../configuration/middleware.md).
