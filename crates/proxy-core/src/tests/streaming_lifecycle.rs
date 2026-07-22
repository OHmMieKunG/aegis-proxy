#[tokio::test]
async fn streams_upload_before_client_finishes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (first_body_tx, first_body_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut received = Vec::new();
        let mut first_body_tx = Some(first_body_tx);
        loop {
            let mut chunk = [0_u8; 512];
            let count = stream.read(&mut chunk).await.expect("upstream read");
            assert!(count > 0, "proxy closed upload early");
            received.extend_from_slice(&chunk[..count]);
            if first_body_tx.is_some()
                && received
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .is_some_and(|header_end| received.len() > header_end + 4)
                && let Some(sender) = first_body_tx.take()
            {
                sender.send(()).expect("signal first body bytes");
            }
            if received.ends_with(b"0\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .expect("response write");
    });
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
            .write_all(b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n")
            .await
            .expect("first upload chunk");
    tokio::time::timeout(std::time::Duration::from_secs(1), first_body_rx)
        .await
        .expect("proxy buffered upload")
        .expect("upstream signal");
    client
        .write_all(b"1\r\nb\r\n0\r\n\r\n")
        .await
        .expect("finish upload");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("response read");
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn supports_http1_keep_alive() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut pending = Vec::new();
        for (body, close) in [(b"a", false), (b"b", true)] {
            while !pending.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0_u8; 512];
                let count = stream.read(&mut chunk).await.expect("request read");
                assert!(count > 0, "proxy closed keep-alive upstream");
                pending.extend_from_slice(&chunk[..count]);
            }
            pending.clear();
            let connection = if close { "close" } else { "keep-alive" };
            let response =
                format!("HTTP/1.1 200 OK\r\ncontent-length: 1\r\nconnection: {connection}\r\n\r\n");
            stream
                .write_all(response.as_bytes())
                .await
                .expect("response headers");
            stream.write_all(body).await.expect("response body");
        }
    });
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .expect("first request");
    let mut first = Vec::new();
    while !first
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .is_some_and(|headers| first.len() >= headers + 5)
    {
        let mut chunk = [0_u8; 512];
        let count = client.read(&mut chunk).await.expect("first response");
        assert!(count > 0, "proxy closed downstream keep-alive");
        first.extend_from_slice(&chunk[..count]);
    }
    assert!(first.ends_with(b"a"));
    client
        .write_all(b"GET /two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("second request");
    let mut second = Vec::new();
    client
        .read_to_end(&mut second)
        .await
        .expect("second response");
    assert!(second.starts_with(b"HTTP/1.1 200 OK"));
    assert!(second.ends_with(b"b"));
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn invalid_startup_never_binds_listener() {
    use tokio::net::TcpListener;

    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve listener");
    let address = reserved.local_addr().expect("listener address");
    drop(reserved);
    let mut config = config(RouteConfig {
        id: "invalid".into(),
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
    config.listeners[0].bind = address;
    config.limits.max_connections = 0;
    let error = run(Arc::new(config), CancellationToken::new())
        .await
        .expect_err("invalid startup must fail");
    assert!(matches!(error, ProxyError::Config(_)));
    let rebound = TcpListener::bind(address)
        .await
        .expect("invalid startup bound the listener");
    drop(rebound);
}

#[tokio::test]
async fn propagates_client_cancellation_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let count = stream.read(&mut request).await.expect("request read");
        assert!(count > 0);
        request_seen_tx.send(()).expect("signal request");
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut request))
                .await
                .expect("upstream connection stayed open after client cancellation")
                .expect("upstream read after cancellation");
        assert_eq!(count, 0);
    });
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .expect("request write");
    request_seen_rx.await.expect("upstream saw request");
    drop(client);
    upstream_task.await.expect("upstream task");
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn stops_accepting_when_drain_begins() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
    let idle_client = connect_to_proxy(proxy_addr).await;
    shutdown.cancel();
    wait_for_listener_close(proxy_addr).await;
    drop(idle_client);
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn proxies_plain_tcp_bidirectionally() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .expect("upstream read");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.expect("upstream write");
    });
    let (proxy_addr, shutdown, task) = start_tcp_test_proxy(upstream_addr, false).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client.write_all(b"ping").await.expect("client write");
    let mut response = [0_u8; 4];
    client.read_exact(&mut response).await.expect("client read");
    assert_eq!(&response, b"pong");
    drop(client);
    upstream_task.await.expect("upstream task");
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn drains_existing_tcp_connection_after_listener_shutdown() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
    };

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (request_tx, request_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .expect("upstream read");
        request_tx.send(()).expect("request signal");
        release_rx.await.expect("release signal");
        stream.write_all(b"pong").await.expect("upstream write");
    });
    let (proxy_addr, shutdown, task) = start_tcp_test_proxy(upstream_addr, false).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client.write_all(b"ping").await.expect("client write");
    request_rx.await.expect("upstream request");
    shutdown.cancel();
    wait_for_listener_close(proxy_addr).await;
    release_tx.send(()).expect("release upstream");
    let mut response = [0_u8; 4];
    client
        .read_exact(&mut response)
        .await
        .expect("drained response");
    assert_eq!(&response, b"pong");
    drop(client);
    upstream_task.await.expect("upstream task");
    task.await.expect("proxy task").expect("proxy run");
}

#[tokio::test]
async fn tls_passthrough_routes_fragmented_sni_and_preserves_prefix() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let hello = client_hello("example.test");
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let expected = hello.clone();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut received = vec![0_u8; expected.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("forwarded ClientHello");
        assert_eq!(received, expected);
        stream.write_all(b"routed").await.expect("upstream write");
    });
    let (proxy_addr, shutdown, task) = start_tcp_test_proxy(upstream_addr, true).await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client.write_all(&hello[..3]).await.expect("first fragment");
    tokio::task::yield_now().await;
    client
        .write_all(&hello[3..])
        .await
        .expect("second fragment");
    let mut response = [0_u8; 6];
    client
        .read_exact(&mut response)
        .await
        .expect("routed response");
    assert_eq!(&response, b"routed");
    drop(client);
    upstream_task.await.expect("upstream task");
    shutdown.cancel();
    task.await.expect("proxy task").expect("proxy run");
}
