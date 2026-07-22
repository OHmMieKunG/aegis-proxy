#[test]
fn activates_only_complete_bounded_trusted_proxy_policy() {
    let mut config = base_config();
    config.trusted_proxies.cidrs = vec!["127.0.0.1/32".parse().expect("CIDR")];
    config.trusted_proxies.trusted_hops = 1;
    validate(&config).expect("complete trusted proxy policy");

    config.trusted_proxies.trusted_hops = 0;
    assert!(validate(&config).is_err());
    config.trusted_proxies.trusted_hops = 1;
    config
        .trusted_proxies
        .cidrs
        .push("127.0.0.1/32".parse().expect("CIDR"));
    assert!(validate(&config).is_err());
}

#[test]
fn rejects_empty_security_header_middleware() {
    let mut config = base_config();
    config.middlewares.insert(
        "headers".into(),
        MiddlewareConfig::SecurityHeaders {
            hsts: None,
            content_security_policy: None,
            override_existing: false,
            acknowledge_hsts_risk: false,
        },
    );
    assert!(validate(&config).is_err());
}

#[test]
fn validates_safe_redirect_and_hsts_policies() {
    let redirect = MiddlewareConfig::Redirect {
        location: "/maintenance".into(),
        status: 307,
        preserve_query: true,
    };
    validate_middleware("redirect", &redirect).expect("safe redirect");
    let unsafe_redirect = MiddlewareConfig::Redirect {
        location: "//attacker.test".into(),
        status: 307,
        preserve_query: false,
    };
    assert!(validate_middleware("redirect", &unsafe_redirect).is_err());

    let hsts = MiddlewareConfig::SecurityHeaders {
        hsts: Some("max-age=31536000; includeSubDomains".into()),
        content_security_policy: None,
        override_existing: false,
        acknowledge_hsts_risk: false,
    };
    assert!(validate_middleware("headers", &hsts).is_err());
    let acknowledged = MiddlewareConfig::SecurityHeaders {
        hsts: Some("max-age=31536000; includeSubDomains".into()),
        content_security_policy: None,
        override_existing: false,
        acknowledge_hsts_risk: true,
    };
    validate_middleware("headers", &acknowledged).expect("acknowledged HSTS");
}

#[test]
fn redirect_is_an_exclusive_terminal_action() {
    let mut config = base_config();
    config.middlewares.insert(
        "redirect".into(),
        MiddlewareConfig::Redirect {
            location: "/maintenance".into(),
            status: 307,
            preserve_query: false,
        },
    );
    config.routes.push(RouteConfig {
        id: "redirect".into(),
        listeners: vec!["public".into()],
        hosts: vec![],
        paths: vec![],
        path_prefixes: vec![],
        methods: vec![],
        headers: vec![],
        default: true,
        priority: 0,
        middlewares: vec!["redirect".into()],
        upstream_group: None,
    });
    validate(&config).expect("redirect terminal");
    config.routes[0].middlewares.clear();
    assert!(validate(&config).is_err());
}

#[test]
fn bounds_ip_policy_cidrs_and_rejects_duplicates() {
    let allowed: IpNet = "127.0.0.0/8".parse().expect("CIDR");
    let policy = MiddlewareConfig::IpPolicy {
        allow: vec![allowed],
        deny: vec![],
    };
    validate_middleware("local", &policy).expect("bounded IP policy");
    let duplicate = MiddlewareConfig::IpPolicy {
        allow: vec![allowed],
        deny: vec![allowed],
    };
    assert!(validate_middleware("local", &duplicate).is_err());

    let mut config = base_config();
    add_http_upstream(&mut config);
    config.middlewares.insert("local".into(), policy);
    let mut route = test_route();
    route.middlewares = vec!["local".into()];
    config.routes.push(route);
    validate(&config).expect("route IP policy");

    config.middlewares.insert(
        "other".into(),
        MiddlewareConfig::IpPolicy {
            allow: vec![],
            deny: vec!["192.0.2.0/24".parse().expect("CIDR")],
        },
    );
    config.routes[0].middlewares.push("other".into());
    assert!(validate(&config).is_err());
}

#[test]
fn bounds_rate_limit_state_and_activates_one_per_route() {
    let mut config = base_config();
    add_http_upstream(&mut config);
    config.middlewares.insert(
        "edge".into(),
        MiddlewareConfig::RateLimit {
            key: RateLimitKey::ClientIp,
            requests_per_second: 10,
            burst: 20,
            max_keys: 100,
            idle_secs: 60,
        },
    );
    let mut route = test_route();
    route.middlewares = vec!["edge".into()];
    config.routes.push(route);
    validate(&config).expect("bounded rate limit");

    let Some(MiddlewareConfig::RateLimit { max_keys, .. }) = config.middlewares.get_mut("edge")
    else {
        panic!("rate limiter");
    };
    *max_keys = 0;
    assert!(validate(&config).is_err());

    let mut principal = base_config();
    add_http_upstream(&mut principal);
    principal.middlewares.insert(
        "principal".into(),
        MiddlewareConfig::RateLimit {
            key: RateLimitKey::Principal,
            requests_per_second: 10,
            burst: 20,
            max_keys: 100,
            idle_secs: 60,
        },
    );
    let mut route = test_route();
    route.middlewares = vec!["principal".into()];
    principal.routes.push(route);
    assert!(validate(&principal).is_err());
}

#[test]
fn bounds_route_and_client_in_flight_capacity() {
    let policy = MiddlewareConfig::InFlightLimit {
        max_requests: 100,
        max_per_client: 10,
        status: 503,
    };
    validate_middleware("inflight", &policy).expect("bounded in-flight policy");
    assert!(
        validate_middleware(
            "inflight",
            &MiddlewareConfig::InFlightLimit {
                max_requests: 10,
                max_per_client: 11,
                status: 503,
            },
        )
        .is_err()
    );

    let mut config = base_config();
    add_http_upstream(&mut config);
    config.middlewares.insert("inflight".into(), policy);
    let mut route = test_route();
    route.middlewares = vec!["inflight".into()];
    config.routes.push(route);
    validate(&config).expect("route in-flight policy");
    config.middlewares.insert(
        "second".into(),
        MiddlewareConfig::InFlightLimit {
            max_requests: 1,
            max_per_client: 1,
            status: 429,
        },
    );
    config.routes[0].middlewares.push("second".into());
    assert!(validate(&config).is_err());
}

#[test]
fn validates_exact_cors_policy() {
    let policy = MiddlewareConfig::Cors {
        origins: vec!["https://app.example.test".into()],
        methods: vec!["GET".into(), "POST".into()],
        headers: vec!["content-type".into()],
        allow_credentials: true,
        max_age_secs: 600,
    };
    validate_middleware("cors", &policy).expect("exact CORS policy");

    let wildcard_credentials = MiddlewareConfig::Cors {
        origins: vec!["*".into()],
        methods: vec!["GET".into()],
        headers: vec![],
        allow_credentials: true,
        max_age_secs: 0,
    };
    assert!(validate_middleware("cors", &wildcard_credentials).is_err());

    let mut config = base_config();
    add_http_upstream(&mut config);
    config.middlewares.insert("cors".into(), policy);
    let mut route = test_route();
    route.middlewares = vec!["cors".into()];
    config.routes.push(route);
    validate(&config).expect("route CORS policy");
}

#[test]
fn validates_basic_auth_secret_refs_and_requires_https() {
    let policy = MiddlewareConfig::BasicAuth {
        realm: "Private Area".into(),
        users: BTreeMap::from([("alice".into(), "env://ALICE_HASH".into())]),
        max_concurrent_verifications: 8,
        timeout_secs: 5,
    };
    validate_middleware("basic", &policy).expect("Basic auth policy");
    let inline = MiddlewareConfig::BasicAuth {
        realm: "Private Area".into(),
        users: BTreeMap::from([("alice".into(), "$argon2id$inline".into())]),
        max_concurrent_verifications: 8,
        timeout_secs: 5,
    };
    assert!(validate_middleware("basic", &inline).is_err());

    let mut config = base_config();
    add_http_upstream(&mut config);
    config.middlewares.insert("basic".into(), policy);
    let mut route = test_route();
    route.middlewares = vec!["basic".into()];
    config.routes.push(route);
    assert!(validate(&config).is_err());
}

#[test]
fn validates_forward_auth_header_contract_and_requires_https() {
    let policy = MiddlewareConfig::ForwardAuth {
        upstream_group: "auth".into(),
        path: "/outpost.goauthentik.io/auth/traefik".into(),
        request_headers: vec!["authorization".into(), "cookie".into()],
        response_headers: vec!["x-authentik-username".into(), "x-authentik-email".into()],
        principal_header: "x-authentik-username".into(),
        redirect_hosts: vec!["auth.example.test".into()],
        timeout_secs: 3,
    };
    validate_middleware("forward", &policy).expect("ForwardAuth policy");
    let spoofable = MiddlewareConfig::ForwardAuth {
        upstream_group: "auth".into(),
        path: "/auth".into(),
        request_headers: vec!["x-authentik-username".into()],
        response_headers: vec!["x-authentik-username".into()],
        principal_header: "x-authentik-username".into(),
        redirect_hosts: vec![],
        timeout_secs: 3,
    };
    assert!(validate_middleware("forward", &spoofable).is_err());

    let mut config = base_config();
    add_http_upstream(&mut config);
    config.middlewares.insert("forward".into(), policy);
    let mut route = test_route();
    route.middlewares = vec!["forward".into()];
    config.routes.push(route);
    assert!(validate(&config).is_err());
}

#[test]
fn validates_bounded_canonical_rewrites() {
    let rewrite = MiddlewareConfig::Rewrite {
        from_prefix: Some("/api".into()),
        to: "/internal".into(),
    };
    validate_middleware("rewrite", &rewrite).expect("canonical rewrite");
    assert!(
        validate_middleware(
            "rewrite",
            &MiddlewareConfig::Rewrite {
                from_prefix: Some("/api/../admin".into()),
                to: "/internal".into(),
            },
        )
        .is_err()
    );
    assert!(
        validate_middleware(
            "rewrite",
            &MiddlewareConfig::Rewrite {
                from_prefix: None,
                to: "/fixed?leak=query".into(),
            },
        )
        .is_err()
    );
}

#[test]
fn rejects_protected_or_ambiguous_header_mutations() {
    let valid = MiddlewareConfig::HeaderMutation {
        request_set: BTreeMap::from([("x-environment".into(), "production".into())]),
        request_add: BTreeMap::new(),
        request_remove: vec!["x-legacy".into()],
        response_set: BTreeMap::new(),
        response_add: BTreeMap::new(),
        response_remove: vec![],
    };
    validate_middleware("headers", &valid).expect("header mutations");
    let protected = MiddlewareConfig::HeaderMutation {
        request_set: BTreeMap::from([("x-forwarded-for".into(), "127.0.0.1".into())]),
        request_add: BTreeMap::new(),
        request_remove: vec![],
        response_set: BTreeMap::new(),
        response_add: BTreeMap::new(),
        response_remove: vec![],
    };
    assert!(validate_middleware("headers", &protected).is_err());
    let ambiguous = MiddlewareConfig::HeaderMutation {
        request_set: BTreeMap::from([("x-environment".into(), "production".into())]),
        request_add: BTreeMap::new(),
        request_remove: vec!["x-environment".into()],
        response_set: BTreeMap::new(),
        response_add: BTreeMap::new(),
        response_remove: vec![],
    };
    assert!(validate_middleware("headers", &ambiguous).is_err());
}

#[test]
fn maintenance_is_one_explicit_terminal_with_matching_auth_mode() {
    let mut config = base_config();
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
    let mut route = test_route();
    route.middlewares = vec!["maintenance".into()];
    route.upstream_group = None;
    config.routes.push(route);
    validate(&config).expect("public maintenance route");

    let Some(MiddlewareConfig::Maintenance { authenticated, .. }) =
        config.middlewares.get_mut("maintenance")
    else {
        panic!("maintenance middleware");
    };
    *authenticated = true;
    assert!(validate(&config).is_err());
}

#[test]
fn custom_errors_are_bounded_unique_upstream_statuses() {
    validate_middleware(
        "errors",
        &MiddlewareConfig::CustomError {
            statuses: vec![502, 503, 504],
            body: "service unavailable".into(),
            content_type: "text/plain; charset=utf-8".into(),
        },
    )
    .expect("custom upstream errors");
    assert!(
        validate_middleware(
            "errors",
            &MiddlewareConfig::CustomError {
                statuses: vec![401, 502, 502],
                body: "unsafe".into(),
                content_type: "text/plain; charset=utf-8".into(),
            },
        )
        .is_err()
    );
}

#[test]
fn compression_policy_is_bounded_and_unambiguous() {
    let valid = MiddlewareConfig::Compression {
        encodings: vec![CompressionEncoding::Brotli, CompressionEncoding::Gzip],
        content_types: vec!["application/json".into(), "text/plain".into()],
        min_bytes: 1_024,
        max_concurrent: 8,
        allow_authenticated: false,
    };
    validate_middleware("compress", &valid).expect("bounded compression policy");

    let duplicate = MiddlewareConfig::Compression {
        encodings: vec![CompressionEncoding::Gzip, CompressionEncoding::Gzip],
        content_types: vec!["text/plain".into()],
        min_bytes: 1_024,
        max_concurrent: 8,
        allow_authenticated: false,
    };
    assert!(validate_middleware("compress", &duplicate).is_err());

    let parameterized = MiddlewareConfig::Compression {
        encodings: vec![CompressionEncoding::Gzip],
        content_types: vec!["text/plain; charset=utf-8".into()],
        min_bytes: 1_024,
        max_concurrent: 8,
        allow_authenticated: false,
    };
    assert!(validate_middleware("compress", &parameterized).is_err());

    let mut config = base_config();
    for index in 0..9 {
        config
            .middlewares
            .insert(format!("compress-{index}"), valid.clone());
    }
    assert!(validate(&config).is_err());
}
