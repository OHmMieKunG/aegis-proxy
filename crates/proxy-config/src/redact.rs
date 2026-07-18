//! Redacted configuration export.

use crate::Config;

const REDACTED: &str = "<redacted-secret-reference>";

/// Clone a configuration while removing every secret reference.
#[must_use]
pub fn redacted(config: &Config) -> Config {
    let mut output = config.clone();
    if output.admin.audit_key.is_some() {
        output.admin.audit_key = Some(REDACTED.into());
    }
    if output.tls.identity.is_some() {
        output.tls.identity = Some(REDACTED.into());
    }
    for certificate in &mut output.certificates {
        certificate.certificate_chain = REDACTED.into();
        certificate.private_key = REDACTED.into();
    }
    for issuer in &mut output.acme.issuers {
        if issuer.ca_bundle.is_some() {
            issuer.ca_bundle = Some(REDACTED.into());
        }
        if let Some(external) = &mut issuer.external_account {
            external.hmac_key = REDACTED.into();
        }
    }
    for provider in &mut output.acme.dns_providers {
        match provider {
            crate::AcmeDnsProviderConfig::Cloudflare { api_token, .. } => {
                *api_token = REDACTED.into();
            }
        }
    }
    for endpoint in output
        .upstream_groups
        .iter_mut()
        .flat_map(|group| group.endpoints.iter_mut())
    {
        if endpoint.ca_bundle.is_some() {
            endpoint.ca_bundle = Some(REDACTED.into());
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        AcmeConfig, AcmeDnsProviderConfig, AcmeEnvironment, AcmeExternalAccountConfig,
        AcmeIssuerConfig, AdminConfig, CertificateConfig, Config, EndpointConfig, LimitsConfig,
        ListenerConfig, ObservabilityConfig, RuntimeConfig, TlsConfig, TrustedProxyConfig,
        UpstreamGroupConfig,
    };

    use super::*;

    #[test]
    fn export_contains_no_secret_reference_canaries() {
        let config = Config {
            schema_version: 1,
            runtime: RuntimeConfig::default(),
            limits: LimitsConfig::default(),
            listeners: vec![ListenerConfig {
                id: "public".into(),
                bind: "127.0.0.1:443".parse().expect("address"),
                protocol: "https".into(),
                certificates: vec!["site".into()],
            }],
            tls: TlsConfig {
                identity: Some("env://CANARY_IDENTITY".into()),
                ..TlsConfig::default()
            },
            certificates: vec![CertificateConfig {
                id: "site".into(),
                hosts: vec!["example.test".into()],
                certificate_chain: "file:///CANARY_CHAIN".into(),
                private_key: "file:///CANARY_KEY".into(),
            }],
            acme: AcmeConfig {
                max_concurrent_orders: 4,
                issuers: vec![AcmeIssuerConfig {
                    id: "test-ca".into(),
                    directory_url: "https://acme.test/directory".parse().expect("URL"),
                    environment: AcmeEnvironment::Staging,
                    account_email: None,
                    terms_of_service_agreed: true,
                    ca_bundle: Some("file:///CANARY_ACME_CA".into()),
                    external_account: Some(AcmeExternalAccountConfig {
                        key_id: "key-id".into(),
                        hmac_key: "env://CANARY_EAB".into(),
                    }),
                    max_concurrent_orders: 2,
                }],
                certificates: vec![],
                dns_providers: vec![AcmeDnsProviderConfig::Cloudflare {
                    id: "cloudflare".into(),
                    zone_id: "0123456789abcdef0123456789abcdef".into(),
                    api_token: "env://CANARY_DNS".into(),
                }],
            },
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![UpstreamGroupConfig {
                id: "app".into(),
                allowed_cidrs: vec![],
                endpoints: vec![EndpointConfig {
                    id: "app-1".into(),
                    url: "https://192.0.2.1:443".parse().expect("URL"),
                    weight: 1,
                    server_name: Some("upstream.test".into()),
                    ca_bundle: Some("file:///CANARY_CA".into()),
                }],
                ..UpstreamGroupConfig::default()
            }],
            middlewares: BTreeMap::new(),
            routes: vec![],
            admin: AdminConfig {
                audit_key: Some("env://CANARY_AUDIT".into()),
                ..AdminConfig::default()
            },
            observability: ObservabilityConfig::default(),
        };
        let serialized = toml::to_string(&redacted(&config)).expect("serialize redacted config");
        assert!(!serialized.contains("CANARY"));
        assert_eq!(serialized.matches(REDACTED).count(), 8);
    }
}
