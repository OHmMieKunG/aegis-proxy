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
async fn file_managed_startup_still_reconciles_provider_output() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aegisproxy_config::provider::{
        FileProviderConfig, ProviderConfig, ProviderScheme,
    };

    let (upstream, upstream_task) = identified_upstream(b"provider").await;
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve proxy port");
    let proxy_addr = reserved.local_addr().expect("proxy address");
    drop(reserved);
    let root = std::env::temp_dir().join(format!(
        "aegisproxy-file-provider-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("test directory");
    let provider_path = root.join("endpoints.toml");
    fs::write(
        &provider_path,
        format!(
            "schema_version=1\nprovider_id=\"nodes\"\n[[endpoints]]\nid=\"node\"\naddress=\"{upstream}\"\n"
        ),
    )
    .expect("provider document");
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
    managed.runtime.config_poll_secs = 1;
    managed.providers = vec![ProviderConfig::File(FileProviderConfig {
        id: "nodes".into(),
        enabled: true,
        upstream_group: "app".into(),
        path: provider_path.to_string_lossy().into_owned(),
        scheme: ProviderScheme::Http,
        server_name: None,
        ca_bundle: None,
        refresh_secs: 1,
        debounce_millis: 50,
        stale_after_secs: 5,
        max_endpoints: 4,
    })];
    fs::write(
        &config_path,
        toml::to_string_pretty(&managed).expect("serialize config"),
    )
    .expect("write config");

    let shutdown = CancellationToken::new();
    let proxy_task = tokio::spawn(run_managed_with_control(
        config_path,
        shutdown.clone(),
        |control, shutdown| async move {
            control.install_provider_audit_sink(|_| true);
            shutdown.cancelled().await;
        },
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        if proxy_get(proxy_addr).await.ends_with(b"provider") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "file provider reconciliation timed out"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    shutdown.cancel();
    proxy_task.await.expect("proxy task").expect("proxy run");
    upstream_task.abort();
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
