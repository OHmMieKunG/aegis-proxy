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
