//! Bounded DNS provider configuration and endpoint normalization.

use std::{collections::BTreeSet, net::IpAddr};

use serde::{Deserialize, Serialize};

use super::{ProviderError, ProviderScheme, dns_endpoint_id, endpoint};
use crate::EndpointConfig;

/// Trusted A/AAAA provider policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsProviderConfig {
    /// Stable provider ID.
    pub id: String,
    /// Explicit activation; defaults false.
    #[serde(default)]
    pub enabled: bool,
    /// Sole upstream group whose endpoints may be replaced.
    pub upstream_group: String,
    /// Canonical configured A/AAAA name.
    pub hostname: String,
    /// Fixed destination port.
    pub port: u16,
    /// Fixed transport scheme.
    pub scheme: ProviderScheme,
    /// Trusted TLS server name required for HTTPS.
    pub server_name: Option<String>,
    /// Trusted custom CA secret reference for HTTPS.
    pub ca_bundle: Option<String>,
    /// Weight assigned to each answer.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Refresh interval.
    #[serde(default = "default_refresh_secs")]
    pub refresh_secs: u64,
    /// Maximum last-valid age before static fallback.
    #[serde(default = "default_stale_after_secs")]
    pub stale_after_secs: u64,
    /// Maximum raw A/AAAA answers.
    #[serde(default = "default_max_answers")]
    pub max_answers: usize,
}

/// Normalize bounded DNS answers through trusted provider template.
pub fn endpoints(
    provider: &DnsProviderConfig,
    addresses: impl IntoIterator<Item = IpAddr>,
) -> Result<Vec<EndpointConfig>, ProviderError> {
    let addresses: BTreeSet<_> = addresses.into_iter().collect();
    if addresses.is_empty() || addresses.len() > provider.max_answers {
        return Err(ProviderError::Limit);
    }
    addresses
        .into_iter()
        .map(|address| {
            endpoint(
                dns_endpoint_id(address),
                std::net::SocketAddr::new(address, provider.port),
                provider.weight,
                provider.scheme,
                provider.server_name.as_deref(),
                provider.ca_bundle.as_deref(),
            )
        })
        .collect()
}

const fn default_weight() -> u32 {
    1
}

const fn default_refresh_secs() -> u64 {
    30
}

const fn default_stale_after_secs() -> u64 {
    300
}

const fn default_max_answers() -> usize {
    16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_deduplicated_sorted_and_use_fixed_policy() {
        let provider = DnsProviderConfig {
            id: "nodes".into(),
            enabled: true,
            upstream_group: "app".into(),
            hostname: "nodes.example.test".into(),
            port: 8443,
            scheme: ProviderScheme::Https,
            server_name: Some("nodes.example.test".into()),
            ca_bundle: None,
            weight: 2,
            refresh_secs: 10,
            stale_after_secs: 30,
            max_answers: 2,
        };
        let endpoints = endpoints(
            &provider,
            [
                "192.0.2.2".parse().expect("IP"),
                "192.0.2.1".parse().expect("IP"),
                "192.0.2.2".parse().expect("IP"),
            ],
        )
        .expect("endpoints");
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].url.as_str(), "https://192.0.2.1:8443/");
        assert_eq!(
            endpoints[0].server_name.as_deref(),
            Some("nodes.example.test")
        );
    }
}
