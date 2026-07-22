use super::*;

fn base_config() -> Config {
    Config {
        schema_version: 1,
        runtime: RuntimeConfig::default(),
        limits: LimitsConfig::default(),
        listeners: vec![ListenerConfig {
            id: "public".into(),
            bind: "127.0.0.1:8080".parse().expect("test address"),
            protocol: "http".into(),
            certificates: vec![],
        }],
        tls: TlsConfig::default(),
        certificates: vec![],
        acme: AcmeConfig::default(),
        trusted_proxies: TrustedProxyConfig::default(),
        upstream_groups: vec![],
        providers: vec![],
        middlewares: BTreeMap::new(),
        routes: vec![],
        admin: AdminConfig::default(),
        observability: ObservabilityConfig::default(),
    }
}

#[test]
fn rejects_duplicate_listener_bind() {
    let mut config = base_config();
    config.listeners.push(ListenerConfig {
        id: "other".into(),
        bind: config.listeners[0].bind,
        protocol: "http".into(),
        certificates: vec![],
    });
    assert!(validate(&config).is_err());
}

#[test]
fn rejects_unsafe_resource_limits() {
    let mut config = base_config();
    config.limits.max_header_bytes = 1024;
    assert!(validate(&config).is_err());
    config.limits.max_header_bytes = LimitsConfig::default().max_header_bytes;
    config.limits.max_request_target = 512;
    assert!(validate(&config).is_err());
    config.limits.max_request_target = LimitsConfig::default().max_request_target;
    config.limits.max_dns_lookups = 0;
    assert!(validate(&config).is_err());
    config.limits.max_dns_lookups = LimitsConfig::default().max_dns_lookups;
    config.limits.tcp_idle_timeout_secs = config.limits.tcp_connection_lifetime_secs + 1;
    assert!(validate(&config).is_err());
}

#[test]
fn rejects_unknown_fields() {
    let source = r#"
            schema_version = 1
            unexpected = true

            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"
        "#;
    assert!(toml::from_str::<Config>(source).is_err());
}

#[test]
fn egress_policy_requires_explicit_private_network() {
    let loopback: IpAddr = "127.0.0.1".parse().expect("IP");
    assert!(validate_egress_ip(loopback, &[], &[]).is_err());
    let allowed = ["127.0.0.1/32".parse().expect("CIDR")];
    assert!(validate_egress_ip(loopback, &allowed, &[]).is_ok());
    assert!(validate_egress_ip(loopback, &allowed, &allowed).is_err());
    let metadata: IpAddr = "169.254.169.254".parse().expect("IP");
    assert!(validate_egress_ip(metadata, &["169.254.0.0/16".parse().expect("CIDR")], &[]).is_err());
}

#[test]
fn rejects_inline_certificate_secrets() {
    let mut config = base_config();
    config.certificates.push(CertificateConfig {
        id: "site".into(),
        hosts: vec!["example.test".into()],
        certificate_chain: "-----BEGIN CERTIFICATE-----".into(),
        private_key: "env://TLS_KEY".into(),
    });
    assert!(validate(&config).is_err());
}

#[test]
fn rejects_unsafe_certificate_wildcards() {
    let mut config = base_config();
    config.certificates.push(CertificateConfig {
        id: "site".into(),
        hosts: vec!["*.*.example.test".into()],
        certificate_chain: "env://TLS_CERT".into(),
        private_key: "env://TLS_KEY".into(),
    });
    assert!(validate(&config).is_err());
}

#[test]
fn requires_known_certificate_on_https_listener() {
    let mut config = base_config();
    config.listeners[0].protocol = "https".into();
    config.listeners[0].certificates = vec!["missing".into()];
    let error = validate(&config).expect_err("unknown certificate must fail");
    assert!(error.to_string().contains("listeners[0].certificates[0]"));
}

fn acme_config(challenge: AcmeChallenge, host: &str) -> Config {
    let mut config = base_config();
    config.tls.identity = Some("env://STATE_IDENTITY".into());
    config.tls.state_encryption_recipients =
        vec![age::x25519::Identity::generate().to_public().to_string()];
    config.acme.issuers.push(AcmeIssuerConfig {
        id: "pebble".into(),
        directory_url: "https://127.0.0.1:14000/dir".parse().expect("URL"),
        environment: AcmeEnvironment::Staging,
        account_email: Some("ops@example.test".into()),
        terms_of_service_agreed: true,
        ca_bundle: Some("file:///pebble-ca.pem".into()),
        external_account: None,
        max_concurrent_orders: 2,
    });
    config.acme.certificates.push(AcmeCertificateConfig {
        id: "managed".into(),
        hosts: vec![host.into()],
        issuer: "pebble".into(),
        challenge,
        challenge_listener: Some("public".into()),
        dns_provider: None,
        profile: None,
        renew_before_days: 30,
    });
    config
}

#[test]
fn accepts_acme_after_all_policy_checks() {
    let config = acme_config(AcmeChallenge::Http01, "example.test");
    let mut certificate_ids = HashSet::new();
    let mut certificate_hosts = HashSet::new();
    validate_acme(&config, &mut certificate_ids, &mut certificate_hosts)
        .expect("valid ACME policy");
    validate(&config).expect("wired scheduler accepts valid ACME policy");
}

#[test]
fn validates_acme_renewal_owner_identifier() {
    let mut config = acme_config(AcmeChallenge::Http01, "example.test");
    config.acme.renewal_owner = Some("node-a".into());
    validate(&config).expect("valid renewal owner");

    config.acme.renewal_owner = Some("Node A".into());
    let error = validate(&config).expect_err("invalid renewal owner must fail");
    assert!(error.to_string().contains("invalid identifier"));
}

#[test]
fn rejects_unsafe_acme_challenge_combinations() {
    let wildcard = acme_config(AcmeChallenge::Http01, "*.example.test");
    assert!(validate(&wildcard).is_err());

    let mut dns = acme_config(AcmeChallenge::Dns01, "*.example.test");
    dns.acme.certificates[0].challenge_listener = None;
    dns.acme.certificates[0].dns_provider = Some("missing".into());
    let error = validate(&dns).expect_err("unknown DNS provider must fail");
    assert!(error.to_string().contains("unknown DNS provider"));

    let mut insecure = acme_config(AcmeChallenge::Http01, "example.test");
    insecure.acme.issuers[0].environment = AcmeEnvironment::Production;
    insecure.acme.issuers[0].directory_url = "http://127.0.0.1:14000/dir".parse().expect("URL");
    let error = validate(&insecure).expect_err("production plaintext directory must fail");
    assert!(error.to_string().contains("must use HTTPS"));

    let mut terms = acme_config(AcmeChallenge::Http01, "example.test");
    terms.acme.issuers[0].terms_of_service_agreed = false;
    let error = validate(&terms).expect_err("implicit terms agreement must fail");
    assert!(
        error
            .to_string()
            .contains("explicit terms_of_service_agreed")
    );
}

#[test]
fn rejects_unknown_nested_acme_fields() {
    let source = r#"
            schema_version = 1

            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"

            [[acme.issuers]]
            id = "pebble"
            directory_url = "https://127.0.0.1:14000/dir"
            environment = "staging"
            surprise = true
        "#;
    assert!(toml::from_str::<Config>(source).is_err());

    let provider = r#"
            schema_version = 1

            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"

            [[acme.dns_providers]]
            kind = "cloudflare"
            id = "dns"
            zone_id = "0123456789abcdef0123456789abcdef"
            api_token = "env://DNS_TOKEN"
            surprise = true
        "#;
    assert!(toml::from_str::<Config>(provider).is_err());
}

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
