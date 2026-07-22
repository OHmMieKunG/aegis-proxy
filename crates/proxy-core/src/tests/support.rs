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
