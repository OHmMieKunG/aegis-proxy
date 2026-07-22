#[tokio::test]
async fn forwards_http_request_and_response() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = vec![0_u8; 4096];
        let count = stream.read(&mut request).await.expect("upstream read");
        let request = std::str::from_utf8(&request[..count]).expect("request text");
        assert!(request.contains(&format!("host: {upstream_addr}")));
        assert!(request.starts_with("GET /hello/~user HTTP/1.1\r\n"));
        assert!(!request.contains("trace-canary"));
        request_seen_tx.send(()).expect("signal request");
        release_rx.await.expect("release response");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .expect("upstream write");
    });
    let proxy_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve proxy port");
    let proxy_addr = proxy_listener.local_addr().expect("proxy address");
    drop(proxy_listener);
    let mut config = config(RouteConfig {
        id: "app".into(),
        listeners: vec!["public".into()],
        hosts: vec!["example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/".into()],
        methods: vec![],
        headers: vec![],
        default: false,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    });
    config.listeners[0].bind = proxy_addr;
    config.upstream_groups[0].endpoints[0].url = format!("http://{upstream_addr}")
        .parse()
        .expect("endpoint url");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(Arc::new(config), shutdown.clone()));
    let mut client = connect_to_proxy(proxy_addr).await;
    client
            .write_all(
                b"GET /hello/%7euser HTTP/1.1\r\nHost: example.test\r\nTraceparent: trace-canary\r\nTracestate: trace-canary\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("client write");
    request_seen_rx.await.expect("upstream saw request");
    shutdown.cancel();
    release_tx.send(()).expect("release upstream");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client read");
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response.ends_with(b"ok"));
    task.await.expect("proxy task").expect("proxy run");
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn trusted_proxy_headers_are_rebuilt_before_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (captured_tx, captured_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = vec![0_u8; 4096];
        let count = stream.read(&mut request).await.expect("upstream read");
        captured_tx
            .send(String::from_utf8(request[..count].to_vec()).expect("request text"))
            .expect("capture request");
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n")
            .await
            .expect("upstream write");
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.trusted_proxies = TrustedProxyConfig {
            cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
            trusted_hops: 1,
        };
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 198.51.100.9\r\nForwarded: for=malicious\r\nX-Forwarded-Host: malicious.test\r\nX-Request-Id: edge-valid-id\r\nConnection: close, x-forwarded-for, x-request-id\r\n\r\n",
            )
            .await
            .expect("client write");
    let request = captured_rx.await.expect("captured request");
    assert!(request.contains("x-forwarded-for: 198.51.100.9\r\n"));
    assert!(request.contains("x-real-ip: 198.51.100.9\r\n"));
    assert!(request.contains("x-forwarded-host: example.test\r\n"));
    assert!(request.contains("x-forwarded-proto: http\r\n"));
    assert!(request.contains("x-request-id: edge-valid-id\r\n"));
    assert!(request.contains("forwarded: for=198.51.100.9;proto=http;host=\"example.test\"\r\n"));
    assert!(!request.contains("malicious"));
    shutdown.cancel();
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client read");
    assert!(response.starts_with(b"HTTP/1.1 204 No Content"));
    proxy_task.await.expect("proxy task").expect("proxy run");
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn redirect_terminal_never_dials_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "redirect".into(),
            MiddlewareConfig::Redirect {
                location: "/maintenance".into(),
                status: 307,
                preserve_query: true,
            },
        );
        config.routes[0].middlewares = vec!["redirect".into()];
        config.routes[0].upstream_group = None;
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(b"GET /old?page=2 HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("client write");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client read");
    let response = String::from_utf8(response).expect("response text");
    assert!(response.starts_with("HTTP/1.1 307 Temporary Redirect\r\n"));
    assert!(response.contains("location: /maintenance?page=2\r\n"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn public_maintenance_is_static_and_never_dials_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "maintenance".into(),
            MiddlewareConfig::Maintenance {
                status: 503,
                body: "planned outage".into(),
                content_type: "text/plain; charset=utf-8".into(),
                retry_after_secs: Some(120),
                authenticated: false,
            },
        );
        config.routes[0].middlewares = vec!["maintenance".into()];
        config.routes[0].upstream_group = None;
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("client write");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client read");
    let response = String::from_utf8(response).expect("response text");
    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.contains("retry-after: 120\r\n"));
    assert!(response.ends_with("planned outage"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn custom_error_replaces_selected_upstream_body_without_leakage() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("upstream read");
        stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 13\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\nupstream leak",
                )
                .await
                .expect("upstream response");
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "errors".into(),
            MiddlewareConfig::CustomError {
                statuses: vec![502],
                body: "service unavailable".into(),
                content_type: "text/plain; charset=utf-8".into(),
            },
        );
        config.routes[0].middlewares = vec!["errors".into()];
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("client write");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client read");
    let response = String::from_utf8(response).expect("response text");
    assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    assert!(!response.contains("content-encoding:"));
    assert!(!response.contains("upstream leak"));
    assert!(response.ends_with("service unavailable"));
    upstream_task.await.expect("upstream task");
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn custom_error_replaces_internal_proxy_failure_without_rematching() {
    let unavailable = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve failed upstream");
    let upstream_addr = unavailable.local_addr().expect("upstream address");
    drop(unavailable);
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "errors".into(),
            MiddlewareConfig::CustomError {
                statuses: vec![502],
                body: "edge unavailable".into(),
                content_type: "text/plain; charset=utf-8".into(),
            },
        );
        config.routes[0].middlewares = vec!["errors".into()];
    })
    .await;
    let response = String::from_utf8(proxy_get(proxy_addr).await).expect("response text");
    assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    assert!(response.ends_with("edge unavailable"));
    assert!(!response.contains("upstream request failed"));
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn compression_is_negotiated_through_the_proxy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("upstream read");
        let body = vec![b'a'; 2_048];
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("upstream headers");
        stream.write_all(&body).await.expect("upstream body");
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "compress".into(),
            MiddlewareConfig::Compression {
                encodings: vec![CompressionEncoding::Gzip],
                content_types: vec!["text/plain".into()],
                min_bytes: 1_024,
                max_concurrent: 2,
                allow_authenticated: false,
            },
        );
        config.routes[0].middlewares = vec!["compress".into()];
    })
    .await;
    let response = proxy_request(
            proxy_addr,
            b"GET / HTTP/1.1\r\nHost: example.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
        )
        .await;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers");
    let headers = String::from_utf8(response[..header_end].to_vec()).expect("header text");
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(headers.contains("content-encoding: gzip\r\n"));
    assert!(headers.contains("vary: Accept-Encoding\r\n"));
    assert!(!headers.contains("content-length:"));
    assert!(
        response[header_end + 4..]
            .windows(2)
            .any(|bytes| bytes == [0x1f, 0x8b])
    );
    upstream_task.await.expect("upstream task");
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn upstream_in_flight_limit_holds_until_response_body_finishes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (ready_tx, ready_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("upstream read");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
            .await
            .expect("upstream headers");
        ready_tx.send(()).expect("signal response");
        release_rx.await.expect("release body");
        stream.write_all(b"first").await.expect("upstream body");
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.upstream_groups[0].max_in_flight = 1;
    })
    .await;
    let first = tokio::spawn(proxy_get(proxy_addr));
    ready_rx.await.expect("first response started");
    let second = tokio::time::timeout(Duration::from_secs(1), proxy_get(proxy_addr))
        .await
        .expect("capacity response");
    assert!(second.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    release_tx.send(()).expect("release first body");
    let first = first.await.expect("first client");
    assert!(first.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with(b"first"));
    upstream_task.await.expect("upstream task");
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn route_in_flight_limit_uses_trusted_client_and_body_lifetime() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (ready_tx, ready_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("upstream read");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
            .await
            .expect("upstream headers");
        ready_tx.send(()).expect("signal response");
        release_rx.await.expect("release body");
        stream.write_all(b"first").await.expect("upstream body");
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "inflight".into(),
            MiddlewareConfig::InFlightLimit {
                max_requests: 1,
                max_per_client: 1,
                status: 429,
            },
        );
        config.routes[0].middlewares = vec!["inflight".into()];
    })
    .await;
    let first = tokio::spawn(proxy_get(proxy_addr));
    ready_rx.await.expect("first response started");
    let second = tokio::time::timeout(
            Duration::from_secs(1),
            proxy_request(
                proxy_addr,
                b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 192.0.2.9\r\nConnection: close\r\n\r\n",
            ),
        )
        .await
        .expect("limit response");
    assert!(second.starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(
        second
            .windows(16)
            .any(|bytes| bytes == b"retry-after: 1\r\n")
    );
    release_tx.send(()).expect("release first body");
    assert!(first.await.expect("first client").ends_with(b"first"));
    upstream_task.await.expect("upstream task");
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn rewrite_changes_only_the_upstream_request_target() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let count = stream.read(&mut request).await.expect("upstream read");
        stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nX-Upstream-Private: remove\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("upstream response");
        String::from_utf8(request[..count].to_vec()).expect("request text")
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "rewrite".into(),
            MiddlewareConfig::Rewrite {
                from_prefix: Some("/api".into()),
                to: "/internal".into(),
            },
        );
        config.middlewares.insert(
            "mutate".into(),
            MiddlewareConfig::HeaderMutation {
                request_set: BTreeMap::from([("x-environment".into(), "production".into())]),
                request_add: BTreeMap::new(),
                request_remove: vec!["x-client-private".into()],
                response_set: BTreeMap::from([("x-edge".into(), "aegis".into())]),
                response_add: BTreeMap::new(),
                response_remove: vec!["x-upstream-private".into()],
            },
        );
        config.routes[0].path_prefixes = vec!["/api".into()];
        config.routes[0].default = false;
        config.routes[0].middlewares = vec!["rewrite".into(), "mutate".into()];
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
            .write_all(
                b"GET /api/users?page=2 HTTP/1.1\r\nHost: example.test\r\nX-Client-Private: remove\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("client write");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client read");
    assert!(response.starts_with(b"HTTP/1.1 204 No Content"));
    let response = String::from_utf8(response).expect("response text");
    assert!(response.contains("x-edge: aegis\r\n"));
    assert!(!response.contains("x-upstream-private:"));
    let request = upstream_task.await.expect("upstream task");
    assert!(request.starts_with("GET /internal/users?page=2 HTTP/1.1\r\n"));
    assert!(request.contains("x-environment: production\r\n"));
    assert!(!request.contains("x-client-private:"));
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn ip_policy_ignores_untrusted_forwarded_identity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "local-deny".into(),
            MiddlewareConfig::IpPolicy {
                allow: vec![],
                deny: vec!["127.0.0.0/8".parse().expect("CIDR")],
            },
        );
        config.routes[0].middlewares = vec!["local-deny".into()];
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("client write");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client read");
    assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn edge_rate_limit_runs_before_redirect_across_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "edge".into(),
            MiddlewareConfig::RateLimit {
                key: RateLimitKey::ClientIp,
                requests_per_second: 1,
                burst: 1,
                max_keys: 2,
                idle_secs: 60,
            },
        );
        config.middlewares.insert(
            "redirect".into(),
            MiddlewareConfig::Redirect {
                location: "/maintenance".into(),
                status: 307,
                preserve_query: false,
            },
        );
        config.routes[0].middlewares = vec!["redirect".into(), "edge".into()];
        config.routes[0].upstream_group = None;
    })
    .await;

    let mut responses = Vec::new();
    for _ in 0..2 {
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("client write");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("client read");
        responses.push(response);
    }
    assert!(responses[0].starts_with(b"HTTP/1.1 307 Temporary Redirect\r\n"));
    assert!(responses[1].starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(
        responses[1]
            .windows(16)
            .any(|line| line == b"retry-after: 1\r\n")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn cors_preflight_short_circuits_and_actual_response_is_scoped() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 2048];
        let count = stream.read(&mut request).await.expect("upstream read");
        assert!(request[..count].starts_with(b"GET / HTTP/1.1\r\n"));
        stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\naccess-control-allow-origin: https://evil.test\r\nconnection: close\r\n\r\n")
                .await
                .expect("upstream write");
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.middlewares.insert(
            "cors".into(),
            MiddlewareConfig::Cors {
                origins: vec!["https://app.example.test".into()],
                methods: vec!["GET".into()],
                headers: vec!["content-type".into()],
                allow_credentials: true,
                max_age_secs: 600,
            },
        );
        config.routes[0].middlewares = vec!["cors".into()];
    })
    .await;

    let requests: [&[u8]; 3] = [
            b"OPTIONS / HTTP/1.1\r\nHost: example.test\r\nOrigin: https://app.example.test\r\nAccess-Control-Request-Method: GET\r\nAccess-Control-Request-Headers: Content-Type\r\nConnection: close\r\n\r\n",
            b"OPTIONS / HTTP/1.1\r\nHost: example.test\r\nOrigin: https://app.example.test\r\nAccess-Control-Request-Method: DELETE\r\nConnection: close\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.test\r\nOrigin: https://app.example.test\r\nConnection: close\r\n\r\n",
        ];
    let mut responses = Vec::new();
    for request in requests {
        let mut client = connect_to_proxy(proxy_addr).await;
        client.write_all(request).await.expect("client write");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("client read");
        responses.push(response);
    }
    assert!(responses[0].starts_with(b"HTTP/1.1 204 No Content\r\n"));
    assert!(
        String::from_utf8_lossy(&responses[0])
            .contains("access-control-allow-origin: https://app.example.test\r\n")
    );
    assert!(responses[1].starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    assert!(responses[2].starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        String::from_utf8_lossy(&responses[2])
            .contains("access-control-allow-origin: https://app.example.test\r\n")
    );
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn balances_real_requests_across_weighted_endpoints() {
    let (first_addr, first_task) = identified_upstream(b"first").await;
    let (second_addr, second_task) = identified_upstream(b"second").await;
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(first_addr, |config| {
        let group = &mut config.upstream_groups[0];
        group.algorithm = BalancingAlgorithm::SmoothWeightedRoundRobin;
        group.endpoints[0].weight = 2;
        group.endpoints.push(EndpointConfig {
            id: "app-2".into(),
            url: format!("http://{second_addr}")
                .parse()
                .expect("endpoint URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        });
    })
    .await;

    let mut counts = [0_usize; 2];
    for _ in 0..6 {
        let response = proxy_get(proxy_addr).await;
        if response.ends_with(b"first") {
            counts[0] += 1;
        } else if response.ends_with(b"second") {
            counts[1] += 1;
        } else {
            panic!("unexpected upstream response");
        }
    }

    assert_eq!(counts, [4, 2]);
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy result");
    first_task.abort();
    second_task.abort();
}

#[tokio::test]
async fn active_http_health_excludes_failed_endpoint() {
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve failed endpoint");
    let failed_addr = reserved.local_addr().expect("failed endpoint address");
    drop(reserved);
    let (healthy_addr, healthy_task) = identified_upstream(b"healthy").await;
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(failed_addr, |config| {
        let group = &mut config.upstream_groups[0];
        group.health = Some(aegisproxy_config::HealthCheckConfig {
            interval_secs: 2,
            timeout_secs: 1,
            unhealthy_threshold: 1,
            healthy_threshold: 1,
            ..aegisproxy_config::HealthCheckConfig::default()
        });
        group.endpoints.push(EndpointConfig {
            id: "app-2".into(),
            url: format!("http://{healthy_addr}")
                .parse()
                .expect("endpoint URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        });
    })
    .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut consecutive_healthy = 0;
    while consecutive_healthy < 4 && tokio::time::Instant::now() < deadline {
        if proxy_get(proxy_addr).await.ends_with(b"healthy") {
            consecutive_healthy += 1;
        } else {
            consecutive_healthy = 0;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(consecutive_healthy, 4);
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy result");
    healthy_task.abort();
}

#[tokio::test]
async fn active_tcp_probe_observes_listener_state() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let address = listener.local_addr().expect("upstream address");
    let mut config = config(RouteConfig {
        id: "test".into(),
        listeners: vec!["public".into()],
        hosts: vec!["example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/".into()],
        methods: vec![],
        headers: vec![],
        default: false,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    });
    config.upstream_groups[0].endpoints[0].url =
        format!("http://{address}").parse().expect("endpoint URL");
    let (clients, dns_endpoints) = build_upstream_clients(&config).expect("upstream clients");
    let client = clients.get("app/app-1").expect("upstream client");
    let dns_endpoint = dns_endpoints.get("app/app-1").expect("DNS endpoint");
    let policy = aegisproxy_config::HealthCheckConfig {
        kind: HealthCheckKind::Tcp,
        ..aegisproxy_config::HealthCheckConfig::default()
    };
    assert!(
        active_health_probe(
            Some(client),
            dns_endpoint,
            &config.upstream_groups[0].endpoints[0],
            &policy,
        )
        .await
    );
    drop(listener);
    assert!(
        !active_health_probe(
            Some(client),
            dns_endpoint,
            &config.upstream_groups[0].endpoints[0],
            &policy,
        )
        .await
    );
}
