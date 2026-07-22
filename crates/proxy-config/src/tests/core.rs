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
