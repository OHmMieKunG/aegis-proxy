#[test]
fn validates_plain_tcp_and_tls_passthrough_routes() {
    let mut config = base_config();
    config.listeners[0].protocol = "tcp".into();
    add_tcp_upstream(&mut config);
    config.routes.push(RouteConfig {
        id: "tcp-default".into(),
        listeners: vec!["public".into()],
        hosts: vec![],
        paths: vec![],
        path_prefixes: vec![],
        methods: vec![],
        headers: vec![],
        default: true,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("tcp-app".into()),
    });
    validate(&config).expect("plain TCP route");
    config.upstream_groups[0].retry.max_attempts = 2;
    assert!(validate(&config).is_err());
    config.upstream_groups[0].retry = RetryConfig::default();

    config.listeners[0].protocol = "tls_passthrough".into();
    config.routes[0].default = false;
    config.routes[0].hosts = vec!["example.test".into(), "*.example.test".into()];
    validate(&config).expect("TLS passthrough SNI route");
}

#[test]
fn rejects_tcp_cross_protocol_and_http_matchers() {
    let mut config = base_config();
    config.listeners[0].protocol = "tcp".into();
    add_http_upstream(&mut config);
    let mut route = RouteConfig {
        id: "tcp-default".into(),
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
    };
    config.routes.push(route.clone());
    assert!(validate(&config).is_err());

    config.upstream_groups.clear();
    add_tcp_upstream(&mut config);
    route.upstream_group = Some("tcp-app".into());
    route.paths = vec!["/http-only".into()];
    config.routes[0] = route;
    assert!(validate(&config).is_err());
}

#[test]
fn rejects_tcp_endpoint_tls_options_and_mixed_group() {
    let mut config = base_config();
    add_tcp_upstream(&mut config);
    config.upstream_groups[0].endpoints[0].server_name = Some("example.test".into());
    assert!(validate(&config).is_err());

    config.upstream_groups[0].endpoints[0].server_name = None;
    config.upstream_groups[0].endpoints.push(EndpointConfig {
        id: "http-app".into(),
        url: "http://127.0.0.1:9001".parse().expect("URL"),
        weight: 1,
        server_name: None,
        ca_bundle: None,
    });
    assert!(validate(&config).is_err());
}

#[test]
fn accepts_multiple_weighted_endpoints_after_pool_activation() {
    let mut config = base_config();
    add_http_upstream(&mut config);
    config.upstream_groups[0].algorithm = BalancingAlgorithm::SmoothWeightedRoundRobin;
    config.upstream_groups[0].endpoints[0].weight = 2;
    config.upstream_groups[0].endpoints.push(EndpointConfig {
        id: "app-2".into(),
        url: "http://127.0.0.1:9001".parse().expect("URL"),
        weight: 1,
        server_name: None,
        ca_bundle: None,
    });
    assert!(validate(&config).is_ok());
}

#[test]
fn bounds_phase4_upstream_policy_before_activation() {
    let mut group = UpstreamGroupConfig {
        id: "app".into(),
        ..UpstreamGroupConfig::default()
    };
    assert!(validate_upstream_policy(0, &group).is_ok());

    group.dns.max_answers = 0;
    assert!(
        validate_upstream_policy(0, &group)
            .expect_err("zero DNS answers must fail")
            .to_string()
            .contains("upstream_groups[0].dns")
    );
    group.dns = DnsConfig::default();

    group.dns.max_answers = 8;
    validate_upstream_policy(0, &group).expect("active DNS policy must validate");
    group.dns = DnsConfig::default();

    group.drain_timeout_secs = 10;
    validate_upstream_policy(0, &group).expect("bounded drain policy");
    group.drain_timeout_secs = 0;
    assert!(validate_upstream_policy(0, &group).is_err());
    group.drain_timeout_secs = default_drain_timeout_secs();

    group.max_in_flight = 1;
    validate_upstream_policy(0, &group).expect("bounded in-flight policy");
    group.max_in_flight = 0;
    assert!(validate_upstream_policy(0, &group).is_err());
    group.max_in_flight = default_upstream_max_in_flight();

    group.retry.max_attempts = 6;
    assert!(
        validate_upstream_policy(0, &group)
            .expect_err("excess attempts must fail")
            .to_string()
            .contains("unsafe")
    );
    group.retry.max_attempts = 2;
    group.retry.replay_body_bytes = 1_024;
    validate_upstream_policy(0, &group).expect("active retries must validate");
    group.retry = RetryConfig::default();

    group.health = Some(HealthCheckConfig::default());
    validate_upstream_policy(0, &group).expect("active health checks must validate");
    group.health.as_mut().expect("health").timeout_secs = 10;
    assert!(
        validate_upstream_policy(0, &group)
            .expect_err("probe timeout must be below interval")
            .to_string()
            .contains("unsafe")
    );
    group.health = None;

    group.circuit_breaker = Some(CircuitBreakerConfig::default());
    validate_upstream_policy(0, &group).expect("active circuit must validate");
    group
        .circuit_breaker
        .as_mut()
        .expect("circuit")
        .minimum_requests = 101;
    assert!(
        validate_upstream_policy(0, &group)
            .expect_err("sample bounds must fail")
            .to_string()
            .contains("unsafe")
    );
}
