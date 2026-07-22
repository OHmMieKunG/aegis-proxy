use super::*;
use aegisproxy_config::{
    AcmeCertificateConfig, AcmeChallenge, AdminConfig, BalancingAlgorithm, CertificateConfig,
    CompressionEncoding, Config, EndpointConfig, LimitsConfig, ListenerConfig, MiddlewareConfig,
    RateLimitKey, RouteConfig, RuntimeConfig, TrustedProxyConfig, UpstreamGroupConfig,
};
use http_body_util::Empty;
use std::collections::BTreeMap;

fn request(method: &str, host: &str, path: &str) -> Request<Empty<bytes::Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, host)
        .body(Empty::<bytes::Bytes>::new())
        .expect("test request is valid")
}

#[test]
fn recognizes_grpc_content_types_without_case_bypass() {
    assert!(is_grpc_content_type(b"application/grpc"));
    assert!(is_grpc_content_type(b"Application/Grpc+Proto"));
    assert!(!is_grpc_content_type(b"application/json"));
}

#[tokio::test]
async fn serves_only_active_http01_host_listener_and_token() {
    let registry = HttpChallengeRegistry::default();
    let _lease = registry
        .install(
            "public",
            "example.test",
            "token_123",
            b"token_123.thumbprint",
            Duration::from_secs(60),
        )
        .expect("install challenge");
    let challenge = request(
        "GET",
        "example.test",
        "/.well-known/acme-challenge/token_123",
    );
    let response = http_challenge_response(&registry, "public", &challenge)
        .expect("challenge lookup")
        .expect("active response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes(),
        &b"token_123.thumbprint"[..]
    );
    assert!(
        http_challenge_response(&registry, "other", &challenge)
            .expect("lookup")
            .is_none()
    );
    let wrong_host = request("GET", "other.test", "/.well-known/acme-challenge/token_123");
    assert!(
        http_challenge_response(&registry, "public", &wrong_host)
            .expect("lookup")
            .is_none()
    );
    let post = request(
        "POST",
        "example.test",
        "/.well-known/acme-challenge/token_123",
    );
    assert_eq!(
        http_challenge_response(&registry, "public", &post)
            .expect("lookup")
            .expect("method response")
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}

fn select_route<'a, B>(
    config: &'a Config,
    request: &Request<B>,
    listener_id: &str,
) -> Option<&'a RouteConfig> {
    RouteIndex::compile(config).select(config, request, listener_id)
}

fn config(route: RouteConfig) -> Config {
    Config {
        schema_version: 1,
        runtime: RuntimeConfig::default(),
        limits: LimitsConfig::default(),
        listeners: vec![ListenerConfig {
            id: "public".into(),
            bind: "127.0.0.1:8080".parse().expect("address"),
            protocol: "http".into(),
            certificates: vec![],
        }],
        tls: aegisproxy_config::TlsConfig::default(),
        certificates: vec![],
        acme: aegisproxy_config::AcmeConfig::default(),
        trusted_proxies: TrustedProxyConfig::default(),
        upstream_groups: vec![UpstreamGroupConfig {
            id: "app".into(),
            allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
            endpoints: vec![EndpointConfig {
                id: "app-1".into(),
                url: "http://127.0.0.1:9000".parse().expect("url"),
                weight: 1,
                server_name: None,
                ca_bundle: None,
            }],
            ..UpstreamGroupConfig::default()
        }],
        providers: vec![],
        middlewares: BTreeMap::new(),
        routes: vec![route],
        admin: AdminConfig::default(),
        observability: aegisproxy_config::ObservabilityConfig::default(),
    }
}

#[test]
fn fleet_acme_owner_fails_before_runtime_preparation() {
    let mut config = config(RouteConfig {
        id: "default".into(),
        listeners: vec!["public".into()],
        hosts: vec![],
        paths: vec![],
        path_prefixes: vec![],
        methods: vec![],
        headers: vec![],
        default: true,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    });
    config.acme.certificates.push(AcmeCertificateConfig {
        id: "site".into(),
        hosts: vec!["example.test".into()],
        issuer: "issuer".into(),
        challenge: AcmeChallenge::Http01,
        challenge_listener: Some("public".into()),
        dns_provider: None,
        profile: None,
        renew_before_days: 30,
    });
    let fleet = NodeIdentity::new("node-a".into(), 1).expect("fleet identity");
    assert!(validate_node_policy(&config, &fleet).is_err());
    config.acme.renewal_owner = Some("node-a".into());
    assert!(validate_node_policy(&config, &fleet).is_ok());
    config.acme.renewal_owner = None;
    assert!(validate_node_policy(&config, &NodeIdentity::standalone()).is_ok());
}

async fn start_test_proxy(
    upstream_addr: SocketAddr,
    configure: impl FnOnce(&mut Config),
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<Result<(), ProxyError>>,
) {
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve proxy port");
    let proxy_addr = reserved.local_addr().expect("proxy address");
    drop(reserved);
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
    config.listeners[0].bind = proxy_addr;
    config.upstream_groups[0].endpoints[0].url = format!("http://{upstream_addr}")
        .parse()
        .expect("endpoint URL");
    configure(&mut config);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(Arc::new(config), shutdown.clone()));
    tokio::task::yield_now().await;
    (proxy_addr, shutdown, task)
}

async fn start_tcp_test_proxy(
    upstream_addr: SocketAddr,
    tls_passthrough: bool,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<Result<(), ProxyError>>,
) {
    start_test_proxy(upstream_addr, |config| {
        config.listeners[0].protocol = if tls_passthrough {
            "tls_passthrough".into()
        } else {
            "tcp".into()
        };
        config.upstream_groups[0].endpoints[0].url = format!("tcp://{upstream_addr}")
            .parse()
            .expect("TCP endpoint URL");
        config.routes[0].paths.clear();
        config.routes[0].path_prefixes.clear();
        config.routes[0].methods.clear();
        config.routes[0].headers.clear();
        config.routes[0].default = !tls_passthrough;
        if !tls_passthrough {
            config.routes[0].hosts.clear();
        }
    })
    .await
}

fn client_hello(server_name: &str) -> Vec<u8> {
    use rustls::{ClientConfig, ClientConnection, RootCertStore, crypto::aws_lc_rs};

    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("TLS versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let name =
        rustls::pki_types::ServerName::try_from(server_name.to_owned()).expect("test server name");
    let mut connection = ClientConnection::new(Arc::new(config), name).expect("client connection");
    let mut output = Vec::new();
    connection.write_tls(&mut output).expect("ClientHello");
    output
}

async fn connect_to_proxy(address: SocketAddr) -> tokio::net::TcpStream {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(error) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                drop(error);
            }
            Err(error) => panic!("proxy did not become ready: {error}"),
        }
    }
}

async fn wait_for_listener_close(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        match TcpStream::connect(address).await {
            Err(_) => return,
            Ok(stream) if tokio::time::Instant::now() < deadline => {
                drop(stream);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(stream) => {
                drop(stream);
                panic!("listener remained open during drain");
            }
        }
    }
}

async fn proxy_get(address: SocketAddr) -> Vec<u8> {
    proxy_request(
        address,
        b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    )
    .await
}

async fn proxy_request(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut client = connect_to_proxy(address).await;
    client.write_all(request).await.expect("write request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");
    response
}

async fn identified_upstream(body: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let address = listener.local_addr().expect("upstream address");
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |_| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(bytes::Bytes::from_static(body))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, task)
}

async fn identified_tcp_upstream(
    identity: &'static [u8],
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TCP upstream bind");
    let address = listener.local_addr().expect("TCP upstream address");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = [0_u8; 1];
                if stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                if stream.write_all(identity).await.is_err() {
                    return;
                }
                let mut remainder = [0_u8; 32];
                while stream
                    .read(&mut remainder)
                    .await
                    .is_ok_and(|count| count > 0)
                {}
            });
        }
    });
    (address, task)
}

async fn https_h2_upstream_response(server_name: &str) -> Vec<u8> {
    use rustls::{ServerConfig, crypto::aws_lc_rs, pki_types::PrivateKeyDer};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    let generated = rcgen::generate_simple_self_signed(vec!["upstream.test".into()])
        .expect("generate upstream identity");
    let certificate_pem = generated.cert.pem();
    let private_key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
    let mut server_config =
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![generated.cert.der().clone()], private_key)
            .expect("server identity");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("upstream accept");
        let Ok(stream) = acceptor.accept(stream).await else {
            return;
        };
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
            assert_eq!(request.version(), hyper::Version::HTTP_2);
            Ok::<_, Infallible>(Response::new(Full::new(bytes::Bytes::from_static(b"ok"))))
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("serve HTTP/2 upstream");
    });
    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let ca_path = std::env::temp_dir().join(format!(
        "aegisproxy-upstream-ca-{}-{sequence}.pem",
        std::process::id()
    ));
    fs::write(&ca_path, certificate_pem).expect("write CA");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600)).expect("secure CA");
    }
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        let endpoint = &mut config.upstream_groups[0].endpoints[0];
        endpoint.url = format!("https://{upstream_addr}")
            .parse()
            .expect("HTTPS endpoint");
        endpoint.server_name = Some(server_name.to_owned());
        endpoint.ca_bundle = Some(format!("file://{}", ca_path.display()));
    })
    .await;
    let mut client = connect_to_proxy(proxy_addr).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("client request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client response");
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
    upstream_task.await.expect("upstream task");
    fs::remove_file(ca_path).expect("remove CA");
    response
}

#[tokio::test]
async fn managed_file_reload_is_atomic_and_rejects_invalid_change() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    let idle_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("idle upstream bind");
    let idle_upstream = idle_listener.local_addr().expect("idle upstream address");
    let (idle_closed_tx, idle_closed_rx) = oneshot::channel();
    let idle_task = tokio::spawn(async move {
        let (mut stream, _) = idle_listener.accept().await.expect("idle accept");
        let mut request = [0_u8; 4096];
        loop {
            let count = stream.read(&mut request).await.expect("idle request");
            if count == 0 {
                break;
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nidle")
                .await
                .expect("idle response");
        }
        idle_closed_tx.send(()).expect("signal idle close");
    });
    let first_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("first upstream bind");
    let first_upstream = first_listener.local_addr().expect("first upstream address");
    let (release_tx, release_rx) = oneshot::channel();
    let first_task = tokio::spawn(async move {
        let mut release_rx = Some(release_rx);
        loop {
            let (mut stream, _) = first_listener.accept().await.expect("first accept");
            let release = release_rx.take();
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await.expect("first request");
                if let Some(release) = release {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\na",
                        )
                        .await
                        .expect("first response chunk");
                    release.await.expect("release old snapshot stream");
                    stream.write_all(b"b").await.expect("second response chunk");
                } else {
                    stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nfirst",
                            )
                            .await
                            .expect("ordinary first response");
                }
            });
        }
    });
    let (second_upstream, second_task) = identified_upstream(b"second").await;
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve proxy port");
    let proxy_addr = reserved.local_addr().expect("proxy address");
    drop(reserved);
    let root = std::env::temp_dir().join(format!(
        "aegisproxy-managed-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("test directory");
    let config_path = root.join("proxy.toml");
    let mut managed = config(RouteConfig {
        id: "managed".into(),
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
    managed.listeners[0].bind = proxy_addr;
    managed.runtime.state_dir = root.join("state").to_string_lossy().into_owned();
    #[cfg(not(unix))]
    {
        managed.runtime.config_poll_secs = 1;
    }
    #[cfg(unix)]
    {
        managed.runtime.config_poll_secs = 60;
    }
    managed.upstream_groups[0].endpoints[0].id = "app-idle".into();
    managed.upstream_groups[0].endpoints[0].url = format!("http://{idle_upstream}")
        .parse()
        .expect("idle upstream");
    managed.upstream_groups[0].endpoints.push(EndpointConfig {
        id: "app-stream".into(),
        url: format!("http://{first_upstream}")
            .parse()
            .expect("stream upstream"),
        weight: 1,
        server_name: None,
        ca_bundle: None,
    });
    fs::write(
        &config_path,
        toml::to_string_pretty(&managed).expect("serialize first config"),
    )
    .expect("write first config");
    let shutdown = CancellationToken::new();
    let proxy_task = tokio::spawn(run_managed(config_path.clone(), shutdown.clone()));
    assert!(proxy_get(proxy_addr).await.ends_with(b"idle"));
    let mut in_flight = connect_to_proxy(proxy_addr).await;
    in_flight
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("in-flight request");
    let mut first_chunk = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !first_chunk.ends_with(b"a") {
            assert!(first_chunk.len() < 1024, "unexpected response header size");
            let count = in_flight
                .read_buf(&mut first_chunk)
                .await
                .expect("old snapshot response");
            assert!(count > 0, "old snapshot response closed early");
        }
    })
    .await
    .expect("old snapshot response timed out");
    assert!(first_chunk.starts_with(b"HTTP/1.1 200 OK"));

    managed.upstream_groups[0].endpoints = vec![EndpointConfig {
        id: "app-new".into(),
        url: format!("http://{second_upstream}")
            .parse()
            .expect("second upstream"),
        weight: 1,
        server_name: None,
        ca_bundle: None,
    }];
    fs::write(
        &config_path,
        toml::to_string_pretty(&managed).expect("serialize second config"),
    )
    .expect("write second config");
    #[cfg(unix)]
    assert!(
        std::process::Command::new("kill")
            .args(["-HUP", &std::process::id().to_string()])
            .status()
            .expect("send SIGHUP")
            .success()
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let response = proxy_get(proxy_addr).await;
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(
            response.ends_with(b"idle")
                || response.ends_with(b"first")
                || response.ends_with(b"second")
        );
        if response.ends_with(b"second") {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "reload timed out");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::timeout(Duration::from_secs(1), idle_closed_rx)
        .await
        .expect("retired idle upstream remained pooled")
        .expect("idle-close signal dropped");
    release_tx.send(()).expect("release old snapshot stream");
    let mut old_tail = Vec::new();
    in_flight
        .read_to_end(&mut old_tail)
        .await
        .expect("finish old snapshot response");
    assert!(old_tail.ends_with(b"b"));

    fs::write(&config_path, "schema_version = 1\nunknown = true\n").expect("write invalid config");
    #[cfg(unix)]
    assert!(
        std::process::Command::new("kill")
            .args(["-HUP", &std::process::id().to_string()])
            .status()
            .expect("send invalid-config SIGHUP")
            .success()
    );
    #[cfg(not(unix))]
    {
        tokio::time::sleep(Duration::from_millis(1_100)).await;
    }
    #[cfg(unix)]
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(proxy_get(proxy_addr).await.ends_with(b"second"));
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");

    let recovery_shutdown = CancellationToken::new();
    let recovery_task = tokio::spawn(run_last_known_good(
        config_path.clone(),
        root.join("state"),
        recovery_shutdown.clone(),
    ));
    assert!(proxy_get(proxy_addr).await.ends_with(b"second"));
    recovery_shutdown.cancel();
    recovery_task
        .await
        .expect("recovery task")
        .expect("last-known-good run");
    first_task.abort();
    idle_task.await.expect("idle upstream task");
    second_task.abort();
    fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn managed_reload_cancels_tcp_at_drain_deadline() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (first_upstream, first_task) = identified_tcp_upstream(b"old").await;
    let (second_upstream, second_task) = identified_tcp_upstream(b"new").await;
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve proxy port");
    let proxy_addr = reserved.local_addr().expect("proxy address");
    drop(reserved);
    let root = std::env::temp_dir().join(format!(
        "aegisproxy-managed-tcp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("test directory");
    let config_path = root.join("proxy.toml");
    let mut managed = config(RouteConfig {
        id: "managed-tcp".into(),
        listeners: vec!["public".into()],
        hosts: vec![],
        paths: vec![],
        path_prefixes: vec![],
        methods: vec![],
        headers: vec![],
        default: true,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    });
    managed.listeners[0].bind = proxy_addr;
    managed.listeners[0].protocol = "tcp".into();
    managed.runtime.state_dir = root.join("state").to_string_lossy().into_owned();
    managed.runtime.config_poll_secs = 1;
    managed.upstream_groups[0].drain_timeout_secs = 1;
    managed.upstream_groups[0].endpoints[0].url = format!("tcp://{first_upstream}")
        .parse()
        .expect("first upstream");
    fs::write(
        &config_path,
        toml::to_string_pretty(&managed).expect("serialize first config"),
    )
    .expect("write first config");
    let shutdown = CancellationToken::new();
    let proxy_task = tokio::spawn(run_managed(config_path.clone(), shutdown.clone()));
    let mut old_connection = connect_to_proxy(proxy_addr).await;
    old_connection.write_all(b"x").await.expect("old request");
    let mut identity = [0_u8; 3];
    old_connection
        .read_exact(&mut identity)
        .await
        .expect("old identity");
    assert_eq!(&identity, b"old");

    managed.upstream_groups[0].endpoints[0].id = "app-new".into();
    managed.upstream_groups[0].endpoints[0].url = format!("tcp://{second_upstream}")
        .parse()
        .expect("second upstream");
    fs::write(
        &config_path,
        toml::to_string_pretty(&managed).expect("serialize second config"),
    )
    .expect("write second config");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        let mut probe = connect_to_proxy(proxy_addr).await;
        probe.write_all(b"x").await.expect("probe request");
        probe
            .read_exact(&mut identity)
            .await
            .expect("probe identity");
        if &identity == b"new" {
            break;
        }
        assert_eq!(&identity, b"old");
        assert!(
            tokio::time::Instant::now() < deadline,
            "TCP reload timed out"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let closed = tokio::time::timeout(Duration::from_secs(2), old_connection.read_u8())
        .await
        .expect("old TCP relay exceeded drain deadline");
    assert!(closed.is_err());

    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
    first_task.abort();
    second_task.abort();
    fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn verifies_custom_ca_and_proxies_https_over_http2() {
    let response = https_h2_upstream_response("upstream.test").await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response.ends_with(b"ok"));
}

#[tokio::test]
async fn rejects_wrong_upstream_tls_name() {
    let response = https_h2_upstream_response("wrong.test").await;
    assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway"));
}

async fn tls_request(
    http2: bool,
    authority: &str,
) -> (
    Vec<u8>,
    Option<rustls::ProtocolVersion>,
    StatusCode,
    bytes::Bytes,
) {
    tls_request_with_versions(
        http2,
        authority,
        "1.2",
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    )
    .await
}

async fn tls_request_with_versions(
    http2: bool,
    authority: &str,
    minimum_version: &str,
    client_versions: &[&'static rustls::SupportedProtocolVersion],
) -> (
    Vec<u8>,
    Option<rustls::ProtocolVersion>,
    StatusCode,
    bytes::Bytes,
) {
    let (alpn, version, status, body, _) = tls_request_custom(
        http2,
        authority,
        minimum_version,
        client_versions,
        None,
        |_| {},
    )
    .await;
    (alpn, version, status, body)
}

async fn tls_request_custom(
    http2: bool,
    authority: &str,
    minimum_version: &str,
    client_versions: &[&'static rustls::SupportedProtocolVersion],
    authorization: Option<String>,
    configure: impl FnOnce(&mut Config),
) -> (
    Vec<u8>,
    Option<rustls::ProtocolVersion>,
    StatusCode,
    bytes::Bytes,
    Option<String>,
) {
    use age::secrecy::ExposeSecret;
    use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs, pki_types::ServerName};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    let generated = rcgen::generate_simple_self_signed(vec!["example.test".into()])
        .expect("generate test identity");
    let age_identity = age::x25519::Identity::generate();
    let encrypted_private_key = age::encrypt(
        &age_identity.to_public(),
        generated.signing_key.serialize_pem().as_bytes(),
    )
    .expect("encrypt private key");
    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let base =
        std::env::temp_dir().join(format!("aegisproxy-tls-{}-{sequence}", std::process::id()));
    let certificate_path = base.with_extension("cert.pem");
    let private_key_path = base.with_extension("key.age");
    let identity_path = base.with_extension("identity.txt");
    fs::write(&certificate_path, generated.cert.pem()).expect("write certificate");
    fs::write(&private_key_path, encrypted_private_key).expect("write private-key envelope");
    fs::write(
        &identity_path,
        age_identity.to_string().expose_secret().as_bytes(),
    )
    .expect("write age identity");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o600))
            .expect("secure certificate");
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
            .expect("secure private key");
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .expect("secure identity");
    }

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("upstream accept");
        let mut request = [0_u8; 4096];
        let count = stream.read(&mut request).await.expect("upstream read");
        let request = std::str::from_utf8(&request[..count])
            .expect("request text")
            .to_owned();
        assert!(request.contains(&format!("host: {upstream_addr}")));
        captured_tx.send(request).expect("capture request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .expect("upstream response");
    });
    let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
        config.listeners[0].protocol = "https".into();
        config.listeners[0].certificates = vec!["site".into()];
        config.tls.identity = Some(format!("file://{}", identity_path.display()));
        config.tls.minimum_version = minimum_version.to_owned();
        config.certificates.push(CertificateConfig {
            id: "site".into(),
            hosts: vec!["example.test".into()],
            certificate_chain: format!("file://{}", certificate_path.display()),
            private_key: format!("file://{}", private_key_path.display()),
        });
        configure(config);
    })
    .await;
    let stream = connect_to_proxy(proxy_addr).await;
    let mut roots = RootCertStore::empty();
    roots
        .add(generated.cert.der().clone())
        .expect("add test root");
    let mut client_config =
        ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(client_versions)
            .expect("TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_config.alpn_protocols = if http2 {
        vec![b"h2".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    let tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect(
            ServerName::try_from("example.test").expect("server name"),
            stream,
        )
        .await
        .expect("TLS connect");
    let negotiated = tls
        .get_ref()
        .1
        .alpn_protocol()
        .expect("ALPN negotiated")
        .to_vec();
    let protocol_version = tls.get_ref().1.protocol_version();
    let mut request = if http2 {
        Request::builder().uri(format!("https://{authority}/"))
    } else {
        Request::builder().uri("/").header(HOST, authority)
    };
    if let Some(authorization) = authorization {
        request = request.header(AUTHORIZATION, authorization);
    }
    let request = request
        .body(Empty::<bytes::Bytes>::new())
        .expect("TLS HTTP request");
    let (status, body) = if http2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .expect("HTTP/2 handshake");
        let connection_task = tokio::spawn(connection);
        let response = sender.send_request(request).await.expect("HTTP/2 response");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("HTTP/2 body")
            .to_bytes();
        connection_task.abort();
        (status, body)
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .expect("HTTP/1.1 handshake");
        let connection_task = tokio::spawn(connection);
        let response = sender
            .send_request(request)
            .await
            .expect("HTTP/1.1 response");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("HTTP/1.1 body")
            .to_bytes();
        connection_task.abort();
        (status, body)
    };
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
    let captured = if status == StatusCode::OK {
        upstream_task.await.expect("upstream task");
        captured_rx.await.ok()
    } else {
        upstream_task.abort();
        None
    };
    fs::remove_file(certificate_path).expect("remove certificate");
    fs::remove_file(private_key_path).expect("remove private key");
    fs::remove_file(identity_path).expect("remove age identity");
    (negotiated, protocol_version, status, body, captured)
}

#[tokio::test]
async fn terminates_tls_with_http1_alpn() {
    let (alpn, _, status, body) = tls_request(false, "example.test").await;
    assert_eq!(alpn, b"http/1.1");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn basic_auth_runs_off_path_and_rebuilds_principal_header() {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_HASH: AtomicU64 = AtomicU64::new(0);
    let salt = SaltString::encode_b64(b"0123456789abcdef").expect("salt");
    let hash = Argon2::default()
        .hash_password(b"correct horse", &salt)
        .expect("hash")
        .to_string();
    let path = std::env::temp_dir().join(format!(
        "aegisproxy-basic-integration-{}-{}",
        std::process::id(),
        NEXT_HASH.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, hash).expect("write hash");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
    }
    let authorization = format!("Basic {}", STANDARD.encode(b"alice:correct horse"));
    let (_, _, status, _, captured) = tls_request_custom(
        false,
        "example.test",
        "1.2",
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        Some(authorization),
        |config| {
            config.middlewares.insert(
                "basic".into(),
                MiddlewareConfig::BasicAuth {
                    realm: "Private".into(),
                    users: BTreeMap::from([("alice".into(), format!("file://{}", path.display()))]),
                    max_concurrent_verifications: 2,
                    timeout_secs: 5,
                },
            );
            config.routes[0].middlewares = vec!["basic".into()];
        },
    )
    .await;
    fs::remove_file(path).expect("remove hash");
    assert_eq!(status, StatusCode::OK);
    let captured = captured.expect("upstream request");
    assert!(captured.contains("x-aegisproxy-user: alice\r\n"));
    assert!(!captured.contains("authorization:"));
}

#[tokio::test]
async fn forward_auth_is_bounded_allowlisted_and_identity_scoped() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let auth = TcpListener::bind("127.0.0.1:0").await.expect("auth bind");
    let auth_addr = auth.local_addr().expect("auth address");
    let auth_task = tokio::spawn(async move {
        let (mut stream, _) = auth.accept().await.expect("auth accept");
        let mut request = [0_u8; 4096];
        let count = stream.read(&mut request).await.expect("auth read");
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Authentik-Username: alice\r\nX-Authentik-Email: alice@example.test\r\nX-Authentik-Untrusted: discard\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("auth response");
        String::from_utf8(request[..count].to_vec()).expect("auth request")
    });
    let (_, _, status, _, captured) = tls_request_custom(
        false,
        "example.test",
        "1.2",
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        Some("Bearer client-token".into()),
        |config| {
            add_forward_auth(config, auth_addr, 3);
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let auth_request = auth_task.await.expect("auth task");
    assert!(auth_request.starts_with("GET /outpost.goauthentik.io/auth/traefik HTTP/1.1\r\n"));
    assert!(auth_request.contains("authorization: Bearer client-token\r\n"));
    assert!(auth_request.contains("x-original-uri: /\r\n"));
    assert!(auth_request.contains("x-forwarded-host: example.test\r\n"));
    assert!(auth_request.contains("x-forwarded-proto: https\r\n"));
    let captured = captured.expect("application request");
    assert!(captured.contains("x-authentik-username: alice\r\n"));
    assert!(captured.contains("x-authentik-email: alice@example.test\r\n"));
    assert!(captured.contains("x-aegisproxy-user: alice\r\n"));
    assert!(!captured.contains("x-authentik-untrusted:"));
}

#[tokio::test]
async fn forward_auth_denial_and_timeout_fail_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let denied = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("deny auth bind");
    let denied_addr = denied.local_addr().expect("deny auth address");
    let denied_task = tokio::spawn(async move {
        let (mut stream, _) = denied.accept().await.expect("deny auth accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("deny auth read");
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .expect("deny auth response");
    });
    let (_, _, denied_status, _, _) = tls_request_custom(
        false,
        "example.test",
        "1.2",
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        None,
        |config| add_forward_auth(config, denied_addr, 3),
    )
    .await;
    denied_task.await.expect("deny auth task");
    assert_eq!(denied_status, StatusCode::FORBIDDEN);

    let slow = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("slow auth bind");
    let slow_addr = slow.local_addr().expect("slow auth address");
    let slow_task = tokio::spawn(async move {
        let (mut stream, _) = slow.accept().await.expect("slow auth accept");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("slow auth read");
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let (_, _, timeout_status, _, _) = tls_request_custom(
        false,
        "example.test",
        "1.2",
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        None,
        |config| add_forward_auth(config, slow_addr, 1),
    )
    .await;
    slow_task.abort();
    assert_eq!(timeout_status, StatusCode::SERVICE_UNAVAILABLE);
}

fn add_forward_auth(config: &mut Config, auth_addr: SocketAddr, timeout_secs: u64) {
    config.upstream_groups.push(UpstreamGroupConfig {
        id: "auth".into(),
        allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
        endpoints: vec![EndpointConfig {
            id: "auth-1".into(),
            url: format!("http://{auth_addr}").parse().expect("auth URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        }],
        ..UpstreamGroupConfig::default()
    });
    config.middlewares.insert(
        "forward".into(),
        MiddlewareConfig::ForwardAuth {
            upstream_group: "auth".into(),
            path: "/outpost.goauthentik.io/auth/traefik".into(),
            request_headers: vec!["authorization".into()],
            response_headers: vec!["x-authentik-username".into(), "x-authentik-email".into()],
            principal_header: "x-authentik-username".into(),
            redirect_hosts: vec![],
            timeout_secs,
        },
    );
    config.routes[0].middlewares = vec!["forward".into()];
}

#[tokio::test]
async fn proxies_http2_selected_by_alpn() {
    let (alpn, _, status, body) = tls_request(true, "example.test").await;
    assert_eq!(alpn, b"h2");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn rejects_authority_that_differs_from_sni() {
    let (_, _, status, _) = tls_request(true, "other.test").await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn supports_explicit_tls12_and_tls13_matrix() {
    for (minimum, client_version, expected) in [
        (
            "1.2",
            &rustls::version::TLS12,
            rustls::ProtocolVersion::TLSv1_2,
        ),
        (
            "1.3",
            &rustls::version::TLS13,
            rustls::ProtocolVersion::TLSv1_3,
        ),
    ] {
        let (_, negotiated, status, _) =
            tls_request_with_versions(false, "example.test", minimum, &[client_version]).await;
        assert_eq!(negotiated, Some(expected));
        assert_eq!(status, StatusCode::OK);
    }
}

#[test]
fn route_matching_is_deterministic_and_header_aware() {
    let route = RouteConfig {
        id: "app".into(),
        listeners: vec!["public".into()],
        hosts: vec!["*.example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/api".into()],
        methods: vec!["GET".into()],
        headers: vec![aegisproxy_config::HeaderMatch {
            name: "x-tenant".into(),
            value: Some("blue".into()),
        }],
        default: false,
        priority: 10,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    };
    let config = config(route);
    let good_request = Request::builder()
        .method("GET")
        .uri("/api/v1")
        .header(HOST, "API.Example.Test:443")
        .header("x-tenant", "blue")
        .body(Empty::<bytes::Bytes>::new())
        .expect("request");
    assert_eq!(
        select_route(&config, &good_request, "public").map(|route| route.id.as_str()),
        Some("app")
    );
    let miss = request("POST", "api.example.test", "/api/v1");
    assert!(select_route(&config, &miss, "public").is_none());
}

#[test]
fn explicit_default_route_never_overrides_a_specific_match() {
    let specific = RouteConfig {
        id: "specific".into(),
        listeners: vec!["public".into()],
        hosts: vec!["example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/".into()],
        methods: vec![],
        headers: vec![],
        default: false,
        priority: -10,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    };
    let mut config = config(specific);
    config.routes.push(RouteConfig {
        id: "fallback".into(),
        listeners: vec!["public".into()],
        hosts: vec![],
        paths: vec![],
        path_prefixes: vec![],
        methods: vec![],
        headers: vec![],
        default: true,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    });

    assert_eq!(
        select_route(&config, &request("GET", "example.test", "/"), "public")
            .map(|route| route.id.as_str()),
        Some("specific")
    );
    assert_eq!(
        select_route(&config, &request("GET", "other.test", "/"), "public")
            .map(|route| route.id.as_str()),
        Some("fallback")
    );
}

#[test]
fn exact_host_and_path_outrank_prefix_with_presence_predicate() {
    let prefix = RouteConfig {
        id: "prefix".into(),
        listeners: vec!["public".into()],
        hosts: vec!["*.example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/api".into()],
        methods: vec![],
        headers: vec![],
        default: false,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    };
    let mut config = config(prefix);
    config.routes.push(RouteConfig {
        id: "exact".into(),
        listeners: vec!["public".into()],
        hosts: vec!["api.example.test".into()],
        paths: vec!["/api/users".into()],
        path_prefixes: vec![],
        methods: vec!["GET".into()],
        headers: vec![aegisproxy_config::HeaderMatch {
            name: "x-authenticated".into(),
            value: None,
        }],
        default: false,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    });

    let exact = Request::builder()
        .method("GET")
        .uri("/api/users")
        .header(HOST, "api.example.test")
        .header("x-authenticated", "")
        .body(Empty::<bytes::Bytes>::new())
        .expect("request");
    assert_eq!(
        select_route(&config, &exact, "public").map(|route| route.id.as_str()),
        Some("exact")
    );

    let no_header = request("GET", "api.example.test", "/api/users");
    assert_eq!(
        select_route(&config, &no_header, "public").map(|route| route.id.as_str()),
        Some("prefix")
    );
    let trailing = request("GET", "api.example.test", "/api/users/");
    assert_eq!(
        select_route(&config, &trailing, "public").map(|route| route.id.as_str()),
        Some("prefix")
    );
}

#[test]
fn rejects_absolute_form_connect_and_missing_host() {
    let absolute = Request::builder()
        .method("GET")
        .uri("http://example.test/")
        .body(Empty::<bytes::Bytes>::new())
        .expect("absolute request");
    assert_eq!(
        reject_unsafe_request_target(&absolute),
        Some(StatusCode::BAD_REQUEST)
    );
    let connect = Request::builder()
        .method("CONNECT")
        .uri("/")
        .header(HOST, "example.test")
        .body(Empty::<bytes::Bytes>::new())
        .expect("connect request");
    assert_eq!(
        reject_unsafe_request_target(&connect),
        Some(StatusCode::BAD_REQUEST)
    );
    let no_host = Request::builder()
        .method("GET")
        .uri("/")
        .body(Empty::<bytes::Bytes>::new())
        .expect("request");
    assert_eq!(
        reject_unsafe_request_target(&no_host),
        Some(StatusCode::BAD_REQUEST)
    );
}

#[test]
fn validates_http2_authority_and_connection_headers() {
    let valid = Request::builder()
        .version(hyper::Version::HTTP_2)
        .uri("https://example.test/")
        .body(Empty::<bytes::Bytes>::new())
        .expect("HTTP/2 request");
    assert_eq!(reject_unsafe_request_target(&valid), None);

    let conflicting = Request::builder()
        .version(hyper::Version::HTTP_2)
        .uri("https://example.test/")
        .header(HOST, "other.test")
        .body(Empty::<bytes::Bytes>::new())
        .expect("HTTP/2 request");
    assert_eq!(
        reject_unsafe_request_target(&conflicting),
        Some(StatusCode::BAD_REQUEST)
    );

    let connection_header = Request::builder()
        .version(hyper::Version::HTTP_2)
        .uri("https://example.test/")
        .header(CONNECTION, "close")
        .body(Empty::<bytes::Bytes>::new())
        .expect("HTTP/2 request");
    assert_eq!(
        reject_unsafe_request_target(&connection_header),
        Some(StatusCode::BAD_REQUEST)
    );
}

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
