#[test]
fn validates_private_admin_settings() {
    let mut config = base_config();
    config.admin = AdminConfig {
        unix_socket: Some("/run/aegisproxy/admin.sock".into()),
        allowed_uids: vec![1000, 1001],
        audit_key: Some("file:///run/secrets/audit-key".into()),
        ..AdminConfig::default()
    };
    validate(&config).expect("private admin settings");

    config.admin.unix_socket = Some("relative/admin.sock".into());
    assert!(validate(&config).is_err());
    config.admin.unix_socket = None;
    config.admin.allowed_uids = vec![1000, 1000];
    assert!(validate(&config).is_err());
    config.admin.allowed_uids.clear();
    config.admin.audit_key = Some("exec://audit-key".into());
    assert!(validate(&config).is_err());
    config.admin.audit_key = None;
    config.admin.max_auth_in_flight = 0;
    assert!(validate(&config).is_err());
}

fn valid_admin_web() -> AdminWebConfig {
    AdminWebConfig {
        enabled: true,
        bind: "127.0.0.1:9090".parse().expect("web bind"),
        origin: "http://localhost:9090".into(),
        oidc: Some(AdminWebOidcConfig {
            issuer: "https://idp.example.test/tenant".into(),
            client_id: "aegis-proxy".into(),
            client_secret: "file:///run/secrets/oidc-client".into(),
            ca_bundle: None,
            groups_claim: "groups".into(),
            groups: AdminWebOidcGroups {
                viewer: vec!["aegis-viewers".into()],
                auditor: vec!["aegis-auditors".into()],
                operator: vec!["aegis-operators".into()],
                admin: vec!["aegis-admins".into()],
            },
        }),
    }
}

#[test]
fn validates_loopback_web_origin_and_oidc_policy() {
    let mut config = base_config();
    assert!(!config.admin.web.enabled);
    validate(&config).expect("default-disabled browser administration");

    config.admin = toml::from_str(
        r#"
            [web]
            enabled = true
            bind = "127.0.0.1:9090"
            origin = "http://localhost:9090"

            [web.oidc]
            issuer = "https://idp.example.test/tenant"
            client_id = "aegis-proxy"
            client_secret = "file:///run/secrets/oidc-client"

            [web.oidc.groups]
            viewer = ["aegis-viewers"]
            auditor = ["aegis-auditors"]
            operator = ["aegis-operators"]
            admin = ["aegis-admins"]
        "#,
    )
    .expect("browser administration TOML");
    assert_eq!(
        config
            .admin
            .web
            .oidc
            .as_ref()
            .expect("OIDC")
            .groups_claim,
        "groups"
    );
    validate(&config).expect("valid browser administration");

    for bind in ["0.0.0.0:9090", "192.0.2.1:9090", "127.0.0.1:0"] {
        let mut invalid = config.clone();
        invalid.admin.web.bind = bind.parse().expect("invalid bind shape");
        assert!(validate(&invalid).is_err(), "accepted web bind {bind}");
    }
    for origin in [
        "http://127.0.0.1:9090",
        "http://localhost:9091",
        "https://localhost:9090",
        "http://localhost:9090/",
        "http://localhost:9090/path",
        "http://user@localhost:9090",
        "http://localhost:9090?query",
        "http://localhost:9090#fragment",
    ] {
        let mut invalid = config.clone();
        invalid.admin.web.origin = origin.into();
        assert!(validate(&invalid).is_err(), "accepted web origin {origin}");
    }

    let mut missing_oidc = config.clone();
    missing_oidc.admin.web.oidc = None;
    assert!(validate(&missing_oidc).is_err());
}

#[test]
fn rejects_unsafe_oidc_and_conflicting_role_groups() {
    let mut config = base_config();
    config.admin.web = valid_admin_web();

    for issuer in [
        "http://idp.example.test",
        "https://user@idp.example.test",
        "https://idp.example.test?query",
        "https://IDP.example.test",
    ] {
        let mut invalid = config.clone();
        invalid
            .admin
            .web
            .oidc
            .as_mut()
            .expect("OIDC")
            .issuer = issuer.into();
        assert!(validate(&invalid).is_err(), "accepted issuer {issuer}");
    }

    let oidc = config.admin.web.oidc.as_mut().expect("OIDC");
    oidc.groups.viewer.push("aegis-admins".into());
    assert!(validate(&config).is_err());

    let mut no_admin = base_config();
    no_admin.admin.web = valid_admin_web();
    no_admin
        .admin
        .web
        .oidc
        .as_mut()
        .expect("OIDC")
        .groups
        .admin
        .clear();
    assert!(validate(&no_admin).is_err());

    let mut bad_secret = base_config();
    bad_secret.admin.web = valid_admin_web();
    bad_secret
        .admin
        .web
        .oidc
        .as_mut()
        .expect("OIDC")
        .client_secret = "https://idp.example.test/secret".into();
    assert!(validate(&bad_secret).is_err());
}

#[test]
fn rejects_remote_admin_listener_configuration() {
    let source = r#"
            schema_version = 1

            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"

            [admin]
            tcp_bind = "0.0.0.0:9090"
        "#;

    let error = toml::from_str::<Config>(source)
        .expect_err("the schema must not expose an unimplemented remote admin listener");
    assert!(error.to_string().contains("unknown field `tcp_bind`"));
}

#[test]
fn validates_bounded_private_observability_policy() {
    let mut config = base_config();
    config.observability.access_log_sample_per_million = 100_000;
    config.observability.otlp_traces = Some(OtlpTraceConfig {
        endpoint: "http://127.0.0.1:4318/v1/traces".parse().expect("OTLP URL"),
        sample_per_million: 10_000,
        max_queue_size: 2_048,
        max_export_batch_size: 512,
        export_timeout_secs: 5,
    });
    validate(&config).expect("bounded loopback exporter");

    config
        .observability
        .otlp_traces
        .as_mut()
        .expect("OTLP")
        .endpoint = "http://collector.example/v1/traces".parse().expect("URL");
    assert!(validate(&config).is_err());
    config
        .observability
        .otlp_traces
        .as_mut()
        .expect("OTLP")
        .endpoint = "https://collector.example/v1/traces?token=secret"
        .parse()
        .expect("URL");
    assert!(validate(&config).is_err());
    config
        .observability
        .otlp_traces
        .as_mut()
        .expect("OTLP")
        .endpoint = "https://collector.example/v1/traces".parse().expect("URL");
    config
        .observability
        .otlp_traces
        .as_mut()
        .expect("OTLP")
        .max_export_batch_size = 2_049;
    assert!(validate(&config).is_err());

    let mut excessive = base_config();
    excessive.routes = (0..600)
        .map(|index| RouteConfig {
            id: format!("route-{index}"),
            listeners: vec!["public".into()],
            hosts: vec![format!("host-{index}.example")],
            paths: vec![],
            path_prefixes: vec![],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: None,
        })
        .collect();
    assert!(estimated_metric_series(&excessive) > MAX_METRIC_SERIES);
    assert!(validate(&excessive).is_err());
    excessive.observability.metrics = false;
    assert_eq!(estimated_metric_series(&excessive), 0);
}

#[test]
fn rejects_unknown_observability_fields() {
    let source = r#"
            schema_version = 1

            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"

            [observability]
            secret_headers = ["authorization"]
        "#;
    assert!(toml::from_str::<Config>(source).is_err());
}

#[test]
fn parses_strict_disabled_file_provider() {
    let source = r#"
            schema_version = 1

            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"

            [[upstream_groups]]
            id = "app"
            allowed_cidrs = ["127.0.0.1/32"]
            [[upstream_groups.endpoints]]
            id = "fallback"
            url = "http://127.0.0.1:9000"

            [[providers]]
            kind = "file"
            id = "nodes"
            upstream_group = "app"
            path = "/run/aegisproxy/nodes.toml"
            scheme = "http"
        "#;
    let config = load_bytes(source.as_bytes()).expect("provider config");
    assert!(!config.providers[0].enabled());

    let unknown = source.replace("scheme = \"http\"", "scheme = \"http\"\nlabels = true");
    assert!(load_bytes(unknown.as_bytes()).is_err());
    let socket = source.replace(
        "scheme = \"http\"",
        "scheme = \"http\"\ndocker_socket = \"/var/run/docker.sock\"",
    );
    assert!(load_bytes(socket.as_bytes()).is_err());
    let docker = source.replace("kind = \"file\"", "kind = \"docker\"");
    assert!(load_bytes(docker.as_bytes()).is_err());
}

#[test]
fn rejects_provider_namespace_and_template_conflicts() {
    use crate::provider::{FileProviderConfig, ProviderConfig, ProviderScheme};

    let mut config = base_config();
    add_http_upstream(&mut config);
    let provider = ProviderConfig::File(FileProviderConfig {
        id: "nodes".into(),
        enabled: true,
        upstream_group: "app".into(),
        path: "/run/aegisproxy/nodes.toml".into(),
        scheme: ProviderScheme::Http,
        server_name: None,
        ca_bundle: None,
        refresh_secs: 1,
        debounce_millis: 50,
        stale_after_secs: 10,
        max_endpoints: 8,
    });
    config.providers.push(provider.clone());
    validate(&config).expect("one declared namespace");

    config.providers.push(provider);
    assert!(validate(&config).is_err());
    config.providers.pop();
    if let ProviderConfig::File(provider) = &mut config.providers[0] {
        provider.upstream_group = "missing".into();
    }
    assert!(validate(&config).is_err());
}

#[test]
fn rejects_provider_policy_escape_and_unsafe_paths() {
    use crate::provider::{DnsProviderConfig, ProviderConfig, ProviderScheme};

    let mut config = base_config();
    add_http_upstream(&mut config);
    config
        .providers
        .push(ProviderConfig::Dns(DnsProviderConfig {
            id: "nodes".into(),
            enabled: true,
            upstream_group: "app".into(),
            hostname: "nodes.example.test".into(),
            port: 443,
            scheme: ProviderScheme::Https,
            server_name: None,
            ca_bundle: None,
            weight: 1,
            refresh_secs: 5,
            stale_after_secs: 10,
            max_answers: 4,
        }));
    assert!(validate(&config).is_err());

    config.providers.clear();
    let source = r#"
            schema_version = 1
            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"
            [[upstream_groups]]
            id = "app"
            allowed_cidrs = ["127.0.0.1/32"]
            [[upstream_groups.endpoints]]
            id = "fallback"
            url = "http://127.0.0.1:9000"
            [[providers]]
            kind = "file"
            id = "nodes"
            enabled = true
            upstream_group = "app"
            path = "/run/../tmp/nodes.toml"
            scheme = "http"
        "#;
    assert!(load_bytes(source.as_bytes()).is_err());
}
