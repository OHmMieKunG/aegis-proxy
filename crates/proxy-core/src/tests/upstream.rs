#[tokio::test]
async fn custom_dns_resolver_connects_only_to_pinned_address() {
    let (upstream_addr, upstream_task) = identified_upstream(b"dns").await;
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
        format!("http://app.internal:{}", upstream_addr.port())
            .parse()
            .expect("DNS endpoint URL");
    let (clients, dns_endpoints) = build_upstream_clients(&config).expect("upstream clients");
    dns_endpoints
        .get("app/app-1")
        .expect("DNS endpoint")
        .install_test_answers(vec![upstream_addr.ip()])
        .expect("DNS answer");
    let request = Request::builder()
        .uri(format!("http://app.internal:{}/", upstream_addr.port()))
        .header(HOST, format!("app.internal:{}", upstream_addr.port()))
        .body(full_body(b""))
        .expect("request");
    let response = clients
        .get("app/app-1")
        .expect("client")
        .request(request)
        .await
        .expect("resolved request")
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    assert_eq!(response, b"dns".as_slice());
    upstream_task.abort();
}

#[tokio::test]
async fn circuit_opens_after_configured_upstream_failures() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = Arc::clone(&requests);
    let upstream_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = upstream.accept().await else {
                return;
            };
            let request_count = Arc::clone(&request_count);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |_| {
                    request_count.fetch_add(1, Ordering::Relaxed);
                    async {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(bytes::Bytes::from_static(b"failed")))
                                .expect("response"),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.upstream_groups[0].circuit_breaker = Some(aegisproxy_config::CircuitBreakerConfig {
            sample_size: 1,
            minimum_requests: 1,
            failure_percent: 100,
            open_secs: 10,
            half_open_requests: 1,
        });
    })
    .await;

    assert!(proxy_get(proxy_addr).await.starts_with(b"HTTP/1.1 500"));
    assert!(proxy_get(proxy_addr).await.starts_with(b"HTTP/1.1 503"));
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy result");
    upstream_task.abort();
}

#[tokio::test]
async fn retries_bounded_idempotent_body_on_connect_failure() {
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve failed endpoint");
    let failed_addr = reserved.local_addr().expect("failed endpoint address");
    drop(reserved);
    let (healthy_addr, healthy_task) = identified_upstream(b"healthy").await;
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(failed_addr, |config| {
        let group = &mut config.upstream_groups[0];
        group.retry.max_attempts = 2;
        group.retry.replay_body_bytes = 16;
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

    let response = proxy_request(
            proxy_addr,
            b"PUT / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
        )
        .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"healthy"));
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy result");
    healthy_task.abort();
}

#[tokio::test]
async fn does_not_retry_non_idempotent_request() {
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve failed endpoint");
    let failed_addr = reserved.local_addr().expect("failed endpoint address");
    drop(reserved);
    let (healthy_addr, healthy_task) = identified_upstream(b"unexpected").await;
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(failed_addr, |config| {
        let group = &mut config.upstream_groups[0];
        group.retry.max_attempts = 2;
        group.retry.replay_body_bytes = 16;
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

    let response = proxy_request(
            proxy_addr,
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
        )
        .await;
    assert!(response.starts_with(b"HTTP/1.1 502"));
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy result");
    healthy_task.abort();
}

#[tokio::test]
async fn tunnels_websocket_upgrade_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("handshake read");
        stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .expect("handshake write");
        let mut bytes = [0_u8; 4];
        stream.read_exact(&mut bytes).await.expect("tunnel read");
        stream.write_all(&bytes).await.expect("tunnel write");
    });

    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve proxy port");
    let proxy_addr = reserved.local_addr().expect("proxy address");
    drop(reserved);
    let mut config = config(RouteConfig {
        id: "websocket".into(),
        listeners: vec!["public".into()],
        hosts: vec!["example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/ws".into()],
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
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .await
            .expect("client handshake");
    let mut headers = Vec::new();
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 256];
        let count = client.read(&mut chunk).await.expect("handshake response");
        assert!(count > 0, "proxy closed before upgrade response");
        headers.extend_from_slice(&chunk[..count]);
    }
    assert!(headers.starts_with(b"HTTP/1.1 101"));
    client.write_all(b"ping").await.expect("tunnel send");
    let mut echo = [0_u8; 4];
    client.read_exact(&mut echo).await.expect("tunnel receive");
    assert_eq!(&echo, b"ping");

    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn maps_upstream_response_timeout_to_gateway_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("request read");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve proxy port");
    let proxy_addr = reserved.local_addr().expect("proxy address");
    drop(reserved);
    let mut config = config(RouteConfig {
        id: "timeout".into(),
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
    config.limits.response_header_timeout_secs = 1;
    config.upstream_groups[0].endpoints[0].url = format!("http://{upstream_addr}")
        .parse()
        .expect("endpoint url");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(Arc::new(config), shutdown.clone()));
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
    assert!(response.starts_with(b"HTTP/1.1 504 Gateway Timeout"));
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
    upstream_task.abort();
}

#[tokio::test]
async fn streams_response_before_upstream_finishes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("request read");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\na")
            .await
            .expect("first response chunk");
        release_rx.await.expect("release second chunk");
        stream.write_all(b"b").await.expect("second response chunk");
    });
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("request write");
    let mut first = [0_u8; 1024];
    let count = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut first))
        .await
        .expect("proxy buffered the response")
        .expect("response read");
    assert!(first[..count].ends_with(b"a"));
    release_tx.send(()).expect("release upstream");
    let mut rest = Vec::new();
    client
        .read_to_end(&mut rest)
        .await
        .expect("remaining response");
    assert!(rest.ends_with(b"b"));
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
    upstream_task.await.expect("upstream task");
}
