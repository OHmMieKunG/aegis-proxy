#[test]
fn validates_upstream_tls_policy() {
    let mut config = base_config();
    config.upstream_groups.push(UpstreamGroupConfig {
        id: "app".into(),
        allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
        endpoints: vec![EndpointConfig {
            id: "app-1".into(),
            url: "https://127.0.0.1:8443".parse().expect("URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        }],
        ..UpstreamGroupConfig::default()
    });
    assert!(validate(&config).is_err());
    config.upstream_groups[0].endpoints[0].server_name = Some("upstream.test".into());
    config.upstream_groups[0].endpoints[0].ca_bundle = Some("inline-ca".into());
    assert!(validate(&config).is_err());
    config.upstream_groups[0].endpoints[0].ca_bundle = Some(format!(
        "file://{}",
        std::env::temp_dir().join("upstream-ca.pem").display()
    ));
    let result = validate(&config);
    assert!(result.is_ok(), "{result:?}");
    config.upstream_groups[0].endpoints[0].url = "http://127.0.0.1:8080".parse().expect("URL");
    config.upstream_groups[0].endpoints[0].server_name = None;
    assert!(validate(&config).is_err());
}

#[test]
fn accepts_canonical_dns_upstream_and_rejects_invalid_label() {
    let mut config = base_config();
    config.upstream_groups.push(UpstreamGroupConfig {
        id: "app".into(),
        endpoints: vec![EndpointConfig {
            id: "app-1".into(),
            url: "http://app.internal:8080"
                .parse()
                .expect("DNS endpoint URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        }],
        ..UpstreamGroupConfig::default()
    });
    validate(&config).expect("canonical DNS endpoint");

    config.upstream_groups[0].endpoints[0].url = "http://bad_name.internal:8080"
        .parse()
        .expect("invalid DNS endpoint URL");
    assert!(
        validate(&config)
            .expect_err("underscore label must fail")
            .to_string()
            .contains("invalid DNS name")
    );
}

fn test_route() -> RouteConfig {
    RouteConfig {
        id: "route".into(),
        listeners: vec!["public".into()],
        hosts: vec!["example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/api".into()],
        methods: vec!["GET".into()],
        headers: vec![HeaderMatch {
            name: "x-tenant".into(),
            value: Some("blue".into()),
        }],
        default: false,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    }
}

#[test]
fn requires_explicit_default_route() {
    let mut route = test_route();
    route.hosts.clear();
    route.path_prefixes = vec!["/".into()];
    route.methods.clear();
    route.headers.clear();
    assert!(validate_route_matchers(&route).is_err());

    route.path_prefixes.clear();
    route.default = true;
    assert!(validate_route_matchers(&route).is_ok());
    route.priority = 1;
    assert!(validate_route_matchers(&route).is_err());
}

#[test]
fn rejects_noncanonical_route_predicates() {
    let mut route = test_route();
    route.hosts = vec!["Example.Test".into()];
    assert!(validate_route_matchers(&route).is_err());

    let mut route = test_route();
    route.path_prefixes = vec!["/api/%2fadmin".into()];
    assert!(validate_route_matchers(&route).is_err());

    let mut route = test_route();
    route.methods = vec!["get".into()];
    assert!(validate_route_matchers(&route).is_err());

    let mut route = test_route();
    route.headers[0].value = Some("blue\r\ninjected: true".into());
    assert!(validate_route_matchers(&route).is_err());
}

#[test]
fn rejects_ambiguous_route_predicate_lists() {
    let mut route = test_route();
    route.hosts.push("example.test".into());
    assert!(validate_route_matchers(&route).is_err());

    let mut route = test_route();
    route.headers.push(HeaderMatch {
        name: "x-tenant".into(),
        value: Some("green".into()),
    });
    assert!(validate_route_matchers(&route).is_err());

    let mut route = test_route();
    route.headers[0].name = "connection".into();
    assert!(validate_route_matchers(&route).is_err());
}

#[test]
fn validates_exact_paths_and_header_presence() {
    let mut route = test_route();
    route.paths = vec!["/api/".into()];
    route.path_prefixes.clear();
    route.headers[0].value = None;
    assert!(validate_route_matchers(&route).is_ok());

    route.paths.clear();
    route.path_prefixes = vec!["/api/".into()];
    assert!(validate_route_matchers(&route).is_err());
}

fn add_http_upstream(config: &mut Config) {
    config.upstream_groups.push(UpstreamGroupConfig {
        id: "app".into(),
        allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
        endpoints: vec![EndpointConfig {
            id: "app-1".into(),
            url: "http://127.0.0.1:9000".parse().expect("URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        }],
        ..UpstreamGroupConfig::default()
    });
}

fn add_tcp_upstream(config: &mut Config) {
    config.upstream_groups.push(UpstreamGroupConfig {
        id: "tcp-app".into(),
        allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
        health: Some(HealthCheckConfig {
            kind: HealthCheckKind::Tcp,
            ..HealthCheckConfig::default()
        }),
        endpoints: vec![EndpointConfig {
            id: "tcp-app-1".into(),
            url: "tcp://127.0.0.1:9000".parse().expect("URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        }],
        ..UpstreamGroupConfig::default()
    });
}

#[test]
fn reference_errors_include_exact_field_paths() {
    let mut config = base_config();
    add_http_upstream(&mut config);
    let mut route = test_route();
    route.listeners = vec!["missing".into()];
    config.routes.push(route);
    let error = validate(&config).expect_err("unknown listener must fail");
    assert!(error.to_string().contains("routes[0].listeners[0]"));
}
