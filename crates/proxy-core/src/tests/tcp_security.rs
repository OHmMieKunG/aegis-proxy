#[tokio::test]
async fn tls_passthrough_rejects_unknown_sni_without_upstream_dial() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, task) = start_tcp_test_proxy(upstream_addr, true).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(&client_hello("unknown.test"))
        .await
        .expect("ClientHello write");
    let mut byte = [0_u8; 1];
    let count = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("unknown SNI connection remained open")
        .expect("client read");
    assert_eq!(count, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn tls_passthrough_bounds_malformed_oversized_and_slow_client_hello() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn rejected(address: SocketAddr, input: &[u8]) {
        let mut client = connect_to_proxy(address).await;
        client.write_all(input).await.expect("untrusted TLS input");
        let mut byte = [0_u8; 1];
        let count = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
            .await
            .expect("TLS input was not bounded")
            .expect("client read");
        assert_eq!(count, 0);
    }

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |config| {
        config.listeners[0].protocol = "tls_passthrough".into();
        config.upstream_groups[0].endpoints[0].url = format!("tcp://{upstream_addr}")
            .parse()
            .expect("TCP endpoint URL");
        config.routes[0].paths.clear();
        config.routes[0].path_prefixes.clear();
        config.routes[0].methods.clear();
        config.routes[0].headers.clear();
        config.tls.handshake_timeout_secs = 1;
    })
    .await;

    rejected(proxy_addr, b"not tls").await;
    let mut oversized = vec![0_u8; 16 * 1024];
    oversized[..5].copy_from_slice(&[22, 3, 3, 0x40, 0]);
    rejected(proxy_addr, &oversized).await;
    rejected(proxy_addr, &[22, 3, 3, 0, 100]).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn rejects_oversized_body_before_terminal_middleware() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |config| {
        config.limits.max_request_body = 4;
        config.middlewares.insert(
            "redirect".into(),
            MiddlewareConfig::Redirect {
                location: "/maintenance".into(),
                status: 307,
                preserve_query: false,
            },
        );
        config.routes[0].middlewares = vec!["redirect".into()];
        config.routes[0].upstream_group = None;
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
            .write_all(b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .expect("request write");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("response read");
    assert!(response.starts_with(b"HTTP/1.1 413 Payload Too Large"));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn rejects_ambiguous_framing_before_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
            .write_all(b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
            .await
            .expect("request write");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.read_to_end(&mut response),
    )
    .await;
    assert!(!response.starts_with(b"HTTP/1.1 200"));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn rejects_encoded_path_separator_before_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(
            b"GET /public%2fadmin HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("request write");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("response read");
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request"));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn closes_slow_request_headers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |config| {
        config.limits.request_header_timeout_secs = 1;
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost:")
        .await
        .expect("partial header write");
    let mut byte = [0_u8; 1];
    let count = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut byte))
        .await
        .expect("header timeout did not fire")
        .expect("read after timeout");
    assert_eq!(count, 0);
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}
