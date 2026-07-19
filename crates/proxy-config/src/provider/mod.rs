//! Strict service-discovery provider contracts.

pub mod dns;
pub mod file;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::EndpointConfig;

pub use dns::DnsProviderConfig;
pub use file::{FileEndpoint, FileProviderConfig, FileProviderDocument};

/// Maximum service-discovery providers in one configuration.
pub const MAX_PROVIDERS: usize = 64;

/// Provider document or endpoint normalization failure.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// Provider input exceeded its hard byte or object limit.
    #[error("provider input exceeds configured bounds")]
    Limit,
    /// Provider input did not match its strict schema.
    #[error("provider input is invalid")]
    Invalid,
    /// Provider document identifies another configured provider.
    #[error("provider document identity does not match configuration")]
    Identity,
}

/// Approved provider transport template.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderScheme {
    /// Plain HTTP upstream.
    Http,
    /// Verified HTTPS upstream.
    Https,
    /// Raw TCP upstream.
    Tcp,
}

impl ProviderScheme {
    /// Return URL scheme text.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Tcp => "tcp",
        }
    }
}

/// Compile-time provider kinds supported by schema v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderConfig {
    /// Strict local file endpoint provider.
    File(FileProviderConfig),
    /// Bounded A/AAAA endpoint provider.
    Dns(DnsProviderConfig),
}

impl ProviderConfig {
    /// Stable configured provider ID.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::File(provider) => &provider.id,
            Self::Dns(provider) => &provider.id,
        }
    }

    /// Whether provider is explicitly activated.
    #[must_use]
    pub fn enabled(&self) -> bool {
        match self {
            Self::File(provider) => provider.enabled,
            Self::Dns(provider) => provider.enabled,
        }
    }

    /// Sole configured upstream namespace owned by provider.
    #[must_use]
    pub fn upstream_group(&self) -> &str {
        match self {
            Self::File(provider) => &provider.upstream_group,
            Self::Dns(provider) => &provider.upstream_group,
        }
    }

    /// Provider refresh period.
    #[must_use]
    pub fn refresh_secs(&self) -> u64 {
        match self {
            Self::File(provider) => provider.refresh_secs,
            Self::Dns(provider) => provider.refresh_secs,
        }
    }

    /// Maximum age of last valid provider result.
    #[must_use]
    pub fn stale_after_secs(&self) -> u64 {
        match self {
            Self::File(provider) => provider.stale_after_secs,
            Self::Dns(provider) => provider.stale_after_secs,
        }
    }

    /// Stable kind label.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Dns(_) => "dns",
        }
    }
}

fn endpoint(
    id: String,
    address: std::net::SocketAddr,
    weight: u32,
    scheme: ProviderScheme,
    server_name: Option<&str>,
    ca_bundle: Option<&str>,
) -> Result<EndpointConfig, ProviderError> {
    let url = Url::parse(&format!("{}://{address}", scheme.as_str()))
        .map_err(|_| ProviderError::Invalid)?;
    Ok(EndpointConfig {
        id,
        url,
        weight,
        server_name: server_name.map(str::to_owned),
        ca_bundle: ca_bundle.map(str::to_owned),
    })
}

fn dns_endpoint_id(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => format!("v4-{}", hex(&address.octets())),
        IpAddr::V6(address) => format!("v6-{}", hex(&address.octets())),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_endpoint_ids_are_stable_and_bounded() {
        assert_eq!(
            dns_endpoint_id("192.0.2.1".parse().expect("IP")),
            "v4-c0000201"
        );
        assert_eq!(
            dns_endpoint_id("2001:db8::1".parse().expect("IP")),
            "v6-20010db8000000000000000000000001"
        );
    }
}
