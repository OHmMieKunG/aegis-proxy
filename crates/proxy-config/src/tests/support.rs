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
