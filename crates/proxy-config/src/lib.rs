#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Strict, bounded configuration types and validation.

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::Path,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Maximum configuration bytes accepted by the offline parser.
pub const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;

/// Root configuration document.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Supported schema version.
    pub schema_version: u32,
    /// Runtime settings.
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// Resource limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Public/admin listeners.
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    /// Trusted forwarding peers.
    #[serde(default)]
    pub trusted_proxies: TrustedProxyConfig,
    /// Upstream groups.
    #[serde(default)]
    pub upstream_groups: Vec<UpstreamGroupConfig>,
    /// Middleware definitions.
    #[serde(default)]
    pub middlewares: HashMap<String, MiddlewareConfig>,
    /// Routes.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// Administrative settings.
    #[serde(default)]
    pub admin: AdminConfig,
}

/// Runtime settings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    /// State directory.
    pub state_dir: String,
    /// Graceful drain duration in seconds.
    pub shutdown_grace_secs: u64,
    /// Poll interval in seconds.
    pub config_poll_secs: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            state_dir: "./state".into(),
            shutdown_grace_secs: 30,
            config_poll_secs: 1,
        }
    }
}

/// Resource limits.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum accepted connections.
    pub max_connections: usize,
    /// Maximum header bytes.
    pub max_header_bytes: usize,
    /// Maximum header count.
    pub max_headers: usize,
    /// Maximum request body bytes.
    pub max_request_body: usize,
    /// Request header timeout seconds.
    pub request_header_timeout_secs: u64,
    /// Upstream response header timeout seconds.
    pub response_header_timeout_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 4096,
            max_header_bytes: 32 * 1024,
            max_headers: 100,
            max_request_body: 32 * 1024 * 1024,
            request_header_timeout_secs: 10,
            response_header_timeout_secs: 30,
        }
    }
}

/// A network listener.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Stable identifier.
    pub id: String,
    /// Bind address.
    pub bind: SocketAddr,
    /// `http`, `https`, or `tcp`.
    pub protocol: String,
}

/// Trusted reverse proxies.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustedProxyConfig {
    /// Explicit trusted networks.
    pub cidrs: Vec<IpNet>,
    /// Maximum trusted hops.
    pub trusted_hops: usize,
}

/// Upstream group.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamGroupConfig {
    /// Stable identifier.
    pub id: String,
    /// Balancing algorithm.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Explicit egress allowlist.
    #[serde(default)]
    pub allowed_cidrs: Vec<IpNet>,
    /// Endpoints.
    pub endpoints: Vec<EndpointConfig>,
}

fn default_algorithm() -> String {
    "round_robin".into()
}

/// Upstream endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    /// Stable identifier.
    pub id: String,
    /// Absolute HTTP URL.
    pub url: Url,
    /// Relative selection weight.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Optional upstream TLS SNI/Host name.
    #[serde(default)]
    pub server_name: Option<String>,
}

fn default_weight() -> u32 {
    1
}

/// Middleware definition.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MiddlewareConfig {
    /// Security response headers.
    SecurityHeaders {
        /// HSTS value.
        hsts: Option<String>,
        /// Content-Security-Policy value.
        content_security_policy: Option<String>,
    },
    /// Edge request rate limit.
    RateLimit {
        /// Sustained request rate.
        requests_per_second: u64,
        /// Burst capacity.
        burst: u64,
    },
    /// Fixed redirect.
    Redirect {
        /// Destination URL.
        location: String,
        /// HTTP redirect status.
        status: u16,
    },
}

/// HTTP route.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Stable identifier.
    pub id: String,
    /// Listener IDs.
    pub listeners: Vec<String>,
    /// Exact or wildcard hosts.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Segment-aware path prefixes.
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    /// Allowed methods.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Exact header predicates.
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
    /// Explicit priority.
    #[serde(default)]
    pub priority: i32,
    /// Middleware IDs.
    #[serde(default)]
    pub middlewares: Vec<String>,
    /// Upstream group terminal action.
    pub upstream_group: Option<String>,
}

/// Exact request-header predicate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    /// Header name.
    pub name: String,
    /// Exact value.
    pub value: String,
}

/// Administrative settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Unix socket path. Not bound by the Phase 1 server yet.
    pub unix_socket: Option<String>,
}

/// Configuration error.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File read failure.
    #[error("could not read configuration: {0}")]
    Io(#[from] std::io::Error),
    /// Parse failure.
    #[error("configuration parse failed: {0}")]
    Parse(#[from] toml::de::Error),
    /// Validation failure.
    #[error("configuration is invalid: {0}")]
    Invalid(String),
}

/// Parse and validate a bounded configuration file.
pub fn load_file(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let bytes = fs::read(path)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid(format!(
            "configuration exceeds {MAX_CONFIG_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ConfigError::Invalid("configuration must be UTF-8".into()))?;
    let config: Config = toml::from_str(text)?;
    validate(&config)?;
    Ok(config)
}

/// Validate schema relationships and security-sensitive defaults.
pub fn validate(config: &Config) -> Result<(), ConfigError> {
    if config.schema_version != 1 {
        return Err(ConfigError::Invalid(format!(
            "unsupported schema_version {}",
            config.schema_version
        )));
    }
    if config.listeners.is_empty() {
        return Err(ConfigError::Invalid(
            "at least one listener is required".into(),
        ));
    }
    if config.limits.max_connections == 0 || config.limits.max_connections > 1_000_000 {
        return Err(ConfigError::Invalid(
            "limits.max_connections is outside 1..=1000000".into(),
        ));
    }
    if config.limits.max_header_bytes < 8 * 1024 || config.limits.max_header_bytes > 1024 * 1024 {
        return Err(ConfigError::Invalid(
            "limits.max_header_bytes is outside 8192..=1048576".into(),
        ));
    }
    if config.limits.max_headers == 0 || config.limits.max_headers > 1024 {
        return Err(ConfigError::Invalid(
            "limits.max_headers is outside 1..=1024".into(),
        ));
    }
    if config.limits.max_request_body == 0 || config.limits.max_request_body > 1024 * 1024 * 1024 {
        return Err(ConfigError::Invalid(
            "limits.max_request_body is outside 1..=1073741824".into(),
        ));
    }
    if config.limits.request_header_timeout_secs == 0
        || config.limits.request_header_timeout_secs > 300
        || config.limits.response_header_timeout_secs == 0
        || config.limits.response_header_timeout_secs > 3600
    {
        return Err(ConfigError::Invalid(
            "configured timeouts are outside safe bounds".into(),
        ));
    }
    let mut ids = HashSet::new();
    let mut binds = HashSet::new();
    for listener in &config.listeners {
        valid_id(&listener.id)?;
        if !ids.insert(format!("listener:{}", listener.id)) {
            return Err(ConfigError::Invalid(format!(
                "duplicate listener id {}",
                listener.id
            )));
        }
        if !binds.insert(listener.bind) {
            return Err(ConfigError::Invalid(format!(
                "duplicate listener bind {}",
                listener.bind
            )));
        }
        if !matches!(listener.protocol.as_str(), "http" | "https" | "tcp") {
            return Err(ConfigError::Invalid(format!(
                "unsupported listener protocol {}",
                listener.protocol
            )));
        }
    }
    let mut groups = HashSet::new();
    for group in &config.upstream_groups {
        valid_id(&group.id)?;
        if !groups.insert(group.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate upstream group {}",
                group.id
            )));
        }
        if group.endpoints.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "upstream group {} has no endpoints",
                group.id
            )));
        }
        if group.algorithm != "round_robin" {
            return Err(ConfigError::Invalid(format!(
                "unsupported upstream algorithm {}",
                group.algorithm
            )));
        }
        let mut endpoint_ids = HashSet::new();
        for endpoint in &group.endpoints {
            valid_id(&endpoint.id)?;
            if !endpoint_ids.insert(endpoint.id.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate endpoint id {} in group {}",
                    endpoint.id, group.id
                )));
            }
            if endpoint.weight == 0 {
                return Err(ConfigError::Invalid(format!(
                    "endpoint {} has zero weight",
                    endpoint.id
                )));
            }
            if !matches!(endpoint.url.scheme(), "http" | "https")
                || endpoint.url.host_str().is_none()
            {
                return Err(ConfigError::Invalid(format!(
                    "endpoint {} URL must be absolute http(s)",
                    endpoint.id
                )));
            }
        }
    }
    let listener_ids: HashSet<&str> = config.listeners.iter().map(|l| l.id.as_str()).collect();
    let group_ids: HashSet<&str> = config
        .upstream_groups
        .iter()
        .map(|g| g.id.as_str())
        .collect();
    let mut route_ids = HashSet::new();
    for route in &config.routes {
        valid_id(&route.id)?;
        if !route_ids.insert(route.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate route id {}",
                route.id
            )));
        }
        if route.listeners.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "route {} has no listeners",
                route.id
            )));
        }
        if route.upstream_group.is_none() {
            return Err(ConfigError::Invalid(format!(
                "route {} has no upstream_group",
                route.id
            )));
        }
        if !group_ids.contains(route.upstream_group.as_deref().unwrap_or_default()) {
            return Err(ConfigError::Invalid(format!(
                "route {} references unknown upstream",
                route.id
            )));
        }
        for listener in &route.listeners {
            if !listener_ids.contains(listener.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "route {} references unknown listener {}",
                    route.id, listener
                )));
            }
        }
        for middleware in &route.middlewares {
            if !config.middlewares.contains_key(middleware) {
                return Err(ConfigError::Invalid(format!(
                    "route {} references unknown middleware {}",
                    route.id, middleware
                )));
            }
        }
    }
    Ok(())
}

fn valid_id(value: &str) -> Result<(), ConfigError> {
    let bytes = value.as_bytes();
    let valid = bytes.first().is_some_and(u8::is_ascii_lowercase)
        && value.len() <= 63
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        });
    if !valid {
        return Err(ConfigError::Invalid(format!(
            "invalid identifier {value:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
            }],
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![],
            middlewares: HashMap::new(),
            routes: vec![],
            admin: AdminConfig::default(),
        }
    }

    #[test]
    fn rejects_duplicate_listener_bind() {
        let mut config = base_config();
        config.listeners.push(ListenerConfig {
            id: "other".into(),
            bind: config.listeners[0].bind,
            protocol: "http".into(),
        });
        assert!(validate(&config).is_err());
    }

    #[test]
    fn rejects_unsafe_resource_limits() {
        let mut config = base_config();
        config.limits.max_header_bytes = 1024;
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
}
