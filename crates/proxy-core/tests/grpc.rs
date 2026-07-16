#![forbid(unsafe_code)]

use std::{
    convert::Infallible,
    fs,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use aegisproxy_config::{
    AdminConfig, CertificateConfig, Config, EndpointConfig, LimitsConfig, ListenerConfig,
    RouteConfig, RuntimeConfig, TlsConfig, TrustedProxyConfig, UpstreamGroupConfig,
};
use age::secrecy::ExposeSecret;
use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    Request, Response, StatusCode,
    body::{Frame, Incoming},
    header::{CONTENT_TYPE, TE},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::aws_lc_rs,
    pki_types::{PrivateKeyDer, ServerName},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

fn private_file(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("write test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure test file");
    }
}

async fn connect(address: std::net::SocketAddr) -> TcpStream {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(error) if tokio::time::Instant::now() < deadline => {
                drop(error);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(error) => panic!("proxy did not become ready: {error}"),
        }
    }
}

#[tokio::test]
async fn proxies_unary_and_streaming_grpc_with_trailers() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("aegisproxy-grpc-{}-{nonce}", std::process::id()));
    fs::create_dir(&root).expect("create root");

    let upstream_identity = rcgen::generate_simple_self_signed(vec!["upstream.test".into()])
        .expect("upstream identity");
    let upstream_ca_path = root.join("upstream-ca.pem");
    private_file(&upstream_ca_path, upstream_identity.cert.pem().as_bytes());
    let upstream_key = PrivateKeyDer::Pkcs8(upstream_identity.signing_key.serialize_der().into());
    let mut upstream_tls =
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![upstream_identity.cert.der().clone()], upstream_key)
            .expect("upstream TLS identity");
    upstream_tls.alpn_protocols = vec![b"h2".to_vec()];
    let upstream_acceptor = TlsAcceptor::from(Arc::new(upstream_tls));
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let calls = Arc::new(AtomicUsize::new(0));
    let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
    let completed_tx = Arc::new(Mutex::new(Some(completed_tx)));
    let upstream_task = tokio::spawn({
        let calls = Arc::clone(&calls);
        let completed_tx = Arc::clone(&completed_tx);
        async move {
            let (stream, _) = upstream.accept().await.expect("upstream accept");
            let stream = upstream_acceptor
                .accept(stream)
                .await
                .expect("upstream TLS handshake");
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                let calls = Arc::clone(&calls);
                let completed_tx = Arc::clone(&completed_tx);
                async move {
                    assert_eq!(request.version(), hyper::Version::HTTP_2);
                    assert_eq!(
                        request.headers().get(CONTENT_TYPE),
                        Some(&hyper::header::HeaderValue::from_static("application/grpc"))
                    );
                    assert_eq!(
                        request.headers().get(TE),
                        Some(&hyper::header::HeaderValue::from_static("trailers"))
                    );
                    assert_eq!(
                        request.headers().get("grpc-timeout"),
                        Some(&hyper::header::HeaderValue::from_static("1S"))
                    );
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .expect("upstream request body")
                        .to_bytes();
                    let call = calls.fetch_add(1, Ordering::SeqCst);
                    if call == 0 {
                        assert_eq!(body, Bytes::from_static(b"\0\0\0\0\x01a"));
                    } else {
                        assert_eq!(body, Bytes::from_static(b"\0\0\0\0\x01b\0\0\0\0\x01c"));
                        if let Ok(mut sender) = completed_tx.lock()
                            && let Some(sender) = sender.take()
                        {
                            let _ = sender.send(());
                        }
                    }
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert("grpc-status", hyper::header::HeaderValue::from_static("0"));
                    let mut frames = vec![Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                        b"\0\0\0\0\x01r",
                    )))];
                    if call > 0 {
                        frames.push(Ok(Frame::data(Bytes::from_static(b"\0\0\0\0\x01s"))));
                    }
                    frames.push(Ok(Frame::trailers(trailers)));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/grpc")
                            .body(StreamBody::new(stream::iter(frames)))
                            .expect("upstream response"),
                    )
                }
            });
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
                .expect("serve upstream HTTP/2");
        }
    });

    let downstream_identity = rcgen::generate_simple_self_signed(vec!["example.test".into()])
        .expect("downstream identity");
    let age_identity = age::x25519::Identity::generate();
    let encrypted_key = age::encrypt(
        &age_identity.to_public(),
        downstream_identity.signing_key.serialize_pem().as_bytes(),
    )
    .expect("encrypt downstream key");
    let downstream_cert_path = root.join("downstream-cert.pem");
    let downstream_key_path = root.join("downstream-key.age");
    let age_identity_path = root.join("age-identity.txt");
    private_file(
        &downstream_cert_path,
        downstream_identity.cert.pem().as_bytes(),
    );
    private_file(&downstream_key_path, &encrypted_key);
    private_file(
        &age_identity_path,
        age_identity.to_string().expose_secret().as_bytes(),
    );
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve proxy port");
    let proxy_addr = reserved.local_addr().expect("proxy address");
    drop(reserved);
    let config = Config {
        schema_version: 1,
        runtime: RuntimeConfig {
            shutdown_grace_secs: 2,
            ..RuntimeConfig::default()
        },
        limits: LimitsConfig {
            response_header_timeout_secs: 2,
            ..LimitsConfig::default()
        },
        listeners: vec![ListenerConfig {
            id: "public".into(),
            bind: proxy_addr,
            protocol: "https".into(),
            certificates: vec!["site".into()],
        }],
        tls: TlsConfig {
            identity: Some(format!("file://{}", age_identity_path.display())),
            ..TlsConfig::default()
        },
        certificates: vec![CertificateConfig {
            id: "site".into(),
            hosts: vec!["example.test".into()],
            certificate_chain: format!("file://{}", downstream_cert_path.display()),
            private_key: format!("file://{}", downstream_key_path.display()),
        }],
        trusted_proxies: TrustedProxyConfig::default(),
        upstream_groups: vec![UpstreamGroupConfig {
            id: "grpc".into(),
            allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
            endpoints: vec![EndpointConfig {
                id: "grpc-1".into(),
                url: format!("https://{upstream_addr}")
                    .parse()
                    .expect("upstream URL"),
                weight: 1,
                server_name: Some("upstream.test".into()),
                ca_bundle: Some(format!("file://{}", upstream_ca_path.display())),
            }],
            ..UpstreamGroupConfig::default()
        }],
        middlewares: std::collections::BTreeMap::new(),
        routes: vec![RouteConfig {
            id: "grpc".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec!["POST".into()],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("grpc".into()),
        }],
        admin: AdminConfig::default(),
    };
    let shutdown = CancellationToken::new();
    let proxy_task = tokio::spawn(aegisproxy_core::run(Arc::new(config), shutdown.clone()));

    let stream = connect(proxy_addr).await;
    let mut roots = RootCertStore::empty();
    roots
        .add(downstream_identity.cert.der().clone())
        .expect("downstream root");
    let mut client_tls =
        ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h2".to_vec()];
    let stream = TlsConnector::from(Arc::new(client_tls))
        .connect(
            ServerName::try_from("example.test").expect("server name"),
            stream,
        )
        .await
        .expect("downstream TLS");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("downstream HTTP/2");
    let connection_task = tokio::spawn(connection);

    for (path, chunks, expected_response) in [
        (
            "/grpc.Service/Unary",
            vec![Bytes::from_static(b"\0\0\0\0\x01a")],
            Bytes::from_static(b"\0\0\0\0\x01r"),
        ),
        (
            "/grpc.Service/Stream",
            vec![
                Bytes::from_static(b"\0\0\0\0\x01b"),
                Bytes::from_static(b"\0\0\0\0\x01c"),
            ],
            Bytes::from_static(b"\0\0\0\0\x01r\0\0\0\0\x01s"),
        ),
    ] {
        let frames = chunks
            .into_iter()
            .map(|chunk| Ok::<_, Infallible>(Frame::data(chunk)))
            .collect::<Vec<_>>();
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://example.test{path}"))
            .header(CONTENT_TYPE, "application/grpc")
            .header(TE, "trailers")
            .header("grpc-timeout", "1S")
            .body(StreamBody::new(stream::iter(frames)))
            .expect("gRPC request");
        let response = sender.send_request(request).await.expect("gRPC response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE),
            Some(&hyper::header::HeaderValue::from_static("application/grpc"))
        );
        let collected = response.into_body().collect().await.expect("gRPC body");
        assert_eq!(
            collected
                .trailers()
                .and_then(|trailers| trailers.get("grpc-status")),
            Some(&hyper::header::HeaderValue::from_static("0"))
        );
        assert_eq!(collected.to_bytes(), expected_response);
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), completed_rx)
        .await
        .expect("upstream completion timeout")
        .expect("upstream handled both calls");
    drop(sender);
    connection_task.abort();
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
    upstream_task.abort();
    fs::remove_dir_all(root).expect("remove test root");
}
