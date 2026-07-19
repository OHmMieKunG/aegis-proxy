//! Strict file-provider document and normalization.

use std::{io::Read as _, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};

use super::{ProviderError, ProviderScheme, endpoint};
use crate::EndpointConfig;

/// Maximum bytes read from one provider file.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

/// Local file provider policy declared in trusted base configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileProviderConfig {
    /// Stable provider ID.
    pub id: String,
    /// Explicit activation; defaults false.
    #[serde(default)]
    pub enabled: bool,
    /// Sole upstream group whose endpoints may be replaced.
    pub upstream_group: String,
    /// Absolute provider document path.
    pub path: String,
    /// Fixed transport scheme.
    pub scheme: ProviderScheme,
    /// Trusted TLS server name required for HTTPS.
    pub server_name: Option<String>,
    /// Trusted custom CA secret reference for HTTPS.
    pub ca_bundle: Option<String>,
    /// Refresh interval.
    #[serde(default = "default_refresh_secs")]
    pub refresh_secs: u64,
    /// Stable-file debounce period.
    #[serde(default = "default_debounce_millis")]
    pub debounce_millis: u64,
    /// Maximum last-valid age before static fallback.
    #[serde(default = "default_stale_after_secs")]
    pub stale_after_secs: u64,
    /// Maximum endpoints accepted from document.
    #[serde(default = "default_max_endpoints")]
    pub max_endpoints: usize,
}

/// Strict provider file document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileProviderDocument {
    /// Provider document schema version.
    pub schema_version: u32,
    /// Must equal configured provider ID.
    pub provider_id: String,
    /// Complete replacement endpoint set.
    pub endpoints: Vec<FileEndpoint>,
}

/// Untrusted endpoint record. Transport/TLS policy comes from base config.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileEndpoint {
    /// Stable endpoint ID within target group.
    pub id: String,
    /// Literal IP and explicit port; DNS names are not accepted here.
    pub address: SocketAddr,
    /// Balancer weight.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// Read and strictly parse one bounded provider document.
pub fn load(path: &Path) -> Result<(Vec<u8>, FileProviderDocument), ProviderError> {
    let source = std::fs::symlink_metadata(path).map_err(|_| ProviderError::Invalid)?;
    if !source.file_type().is_file() || source.len() > MAX_FILE_BYTES as u64 {
        return Err(ProviderError::Invalid);
    }
    let file = std::fs::File::open(path).map_err(|_| ProviderError::Invalid)?;
    if !file
        .metadata()
        .map_err(|_| ProviderError::Invalid)?
        .is_file()
    {
        return Err(ProviderError::Invalid);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(source.len())
            .unwrap_or(MAX_FILE_BYTES)
            .min(MAX_FILE_BYTES),
    );
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::Invalid)?;
    parse(&bytes).map(|document| (bytes, document))
}

/// Strictly parse bounded provider bytes.
pub fn parse(bytes: &[u8]) -> Result<FileProviderDocument, ProviderError> {
    if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
        return Err(ProviderError::Limit);
    }
    let input = std::str::from_utf8(bytes).map_err(|_| ProviderError::Invalid)?;
    toml::from_str(input).map_err(|_| ProviderError::Invalid)
}

/// Normalize untrusted file records through trusted provider template.
pub fn endpoints(
    provider: &FileProviderConfig,
    document: &FileProviderDocument,
) -> Result<Vec<EndpointConfig>, ProviderError> {
    if document.schema_version != 1 || document.provider_id != provider.id {
        return Err(ProviderError::Identity);
    }
    if document.endpoints.is_empty() || document.endpoints.len() > provider.max_endpoints {
        return Err(ProviderError::Limit);
    }
    document
        .endpoints
        .iter()
        .map(|record| {
            endpoint(
                record.id.clone(),
                record.address,
                record.weight,
                provider.scheme,
                provider.server_name.as_deref(),
                provider.ca_bundle.as_deref(),
            )
        })
        .collect()
}

const fn default_refresh_secs() -> u64 {
    5
}

const fn default_debounce_millis() -> u64 {
    250
}

const fn default_stale_after_secs() -> u64 {
    300
}

const fn default_max_endpoints() -> usize {
    64
}

const fn default_weight() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> FileProviderConfig {
        FileProviderConfig {
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
            max_endpoints: 2,
        }
    }

    #[test]
    fn strict_document_is_bounded_and_cannot_set_transport_policy() {
        let document = parse(
            br#"
                schema_version = 1
                provider_id = "nodes"
                [[endpoints]]
                id = "node-a"
                address = "192.0.2.10:8080"
            "#,
        )
        .expect("document");
        let endpoints = endpoints(&provider(), &document).expect("endpoints");
        assert_eq!(endpoints[0].url.as_str(), "http://192.0.2.10:8080/");
        assert!(
            parse(
                br#"schema_version=1
                provider_id="nodes"
                secret="canary"
                endpoints=[]"#
            )
            .is_err()
        );
    }
}
