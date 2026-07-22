#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Strict, bounded configuration types and validation.

mod conflict;
pub mod provider;
mod redact;
pub mod revision;
mod schema;
mod validation_acme;
mod validation_middleware;
mod validation_platform;
mod validation_routing;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
};

use aegisproxy_secrets::{SecretRef, validate_age_recipient};
use http::{HeaderName, HeaderValue, Method, Uri};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub use schema::*;
#[cfg(test)]
use schema::{default_drain_timeout_secs, default_upstream_max_in_flight};
use validation_acme::validate_acme;
use validation_middleware::validate_middleware;
pub use validation_platform::estimated_metric_series;
use validation_platform::{validate_admin, validate_observability, validate_providers};
use validation_routing::{
    valid_certificate_host, valid_id, valid_upstream_host, validate_route_matchers,
    validate_tcp_route, validate_unique_strings, validate_upstream_policy,
};
pub use validation_routing::{validate_egress_ip, validate_exact_host, validate_upstream_hostname};

/// Maximum configuration bytes accepted by the offline parser.
pub const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
/// Maximum estimated OpenMetrics series for one active configuration.
pub const MAX_METRIC_SERIES: usize = 100_000;

const MAX_LISTENERS: usize = 128;
const MAX_ROUTES: usize = 4_096;
const MAX_UPSTREAM_GROUPS: usize = 1_024;
const MAX_ENDPOINTS_PER_GROUP: usize = 256;
const MAX_TOTAL_ENDPOINTS: usize = 4_096;
const MAX_MIDDLEWARES: usize = 1_024;
const MAX_TRUSTED_PROXY_CIDRS: usize = 256;
const MAX_MIDDLEWARE_CIDRS: usize = 256;
const MAX_ROUTE_LISTENERS: usize = 32;
const MAX_ROUTE_HOSTS: usize = 64;
const MAX_ROUTE_EXACT_PATHS: usize = 64;
const MAX_ROUTE_PATHS: usize = 64;
const MAX_ROUTE_METHODS: usize = 32;
const MAX_ROUTE_HEADERS: usize = 32;
const MAX_ROUTE_MIDDLEWARES: usize = 64;
const MAX_HEADER_NAME_BYTES: usize = 128;
const MAX_HEADER_VALUE_BYTES: usize = 1_024;
const MAX_PATH_BYTES: usize = 2_048;
const MAX_ACME_ISSUERS: usize = 32;
const MAX_ACME_CERTIFICATES: usize = 1024;
const MAX_ACME_DNS_PROVIDERS: usize = 32;

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

pub use redact::redacted;

/// Parse and validate a bounded configuration file.
pub fn load_file(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let bytes = fs::read(path)?;
    load_bytes(&bytes)
}

/// Parse and validate bounded configuration bytes.
pub fn load_bytes(bytes: &[u8]) -> Result<Config, ConfigError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid(format!(
            "configuration exceeds {MAX_CONFIG_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(bytes)
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
    if config.listeners.is_empty() || config.listeners.len() > MAX_LISTENERS {
        return Err(ConfigError::Invalid(format!(
            "listeners must contain 1..={MAX_LISTENERS} entries"
        )));
    }
    if config.routes.len() > MAX_ROUTES {
        return Err(ConfigError::Invalid(format!(
            "route count exceeds {MAX_ROUTES}"
        )));
    }
    if config.runtime.state_dir.is_empty() || config.runtime.state_dir.len() > 4_096 {
        return Err(ConfigError::Invalid(
            "runtime.state_dir must contain 1..=4096 bytes".into(),
        ));
    }
    if config.runtime.shutdown_grace_secs == 0
        || config.runtime.shutdown_grace_secs > 3_600
        || config.runtime.config_poll_secs == 0
        || config.runtime.config_poll_secs > 300
    {
        return Err(ConfigError::Invalid(
            "runtime shutdown/config polling durations are outside safe bounds".into(),
        ));
    }
    validate_admin(&config.admin)?;
    validate_observability(config)?;
    if config.upstream_groups.len() > MAX_UPSTREAM_GROUPS {
        return Err(ConfigError::Invalid(format!(
            "upstream_groups exceeds {MAX_UPSTREAM_GROUPS} entries"
        )));
    }
    if config.middlewares.len() > MAX_MIDDLEWARES {
        return Err(ConfigError::Invalid(format!(
            "middlewares exceeds {MAX_MIDDLEWARES} entries"
        )));
    }
    let mut compression_slots = 0_usize;
    let mut in_flight_slots = 0_usize;
    for (id, middleware) in &config.middlewares {
        valid_id(id)?;
        validate_middleware(id, middleware)?;
        if let MiddlewareConfig::Compression { max_concurrent, .. } = middleware {
            compression_slots = compression_slots
                .checked_add(*max_concurrent)
                .ok_or_else(|| ConfigError::Invalid("compression capacity overflow".into()))?;
            if compression_slots > 64 {
                return Err(ConfigError::Invalid(
                    "aggregate compression concurrency exceeds 64".into(),
                ));
            }
        }
        if let MiddlewareConfig::InFlightLimit { max_requests, .. } = middleware {
            in_flight_slots = in_flight_slots
                .checked_add(*max_requests)
                .ok_or_else(|| ConfigError::Invalid("in-flight capacity overflow".into()))?;
            if in_flight_slots > 100_000 {
                return Err(ConfigError::Invalid(
                    "aggregate route in-flight capacity exceeds 100000".into(),
                ));
            }
        }
    }
    if config.trusted_proxies.cidrs.len() > MAX_TRUSTED_PROXY_CIDRS
        || config.trusted_proxies.trusted_hops > 32
    {
        return Err(ConfigError::Invalid(
            "trusted_proxies exceeds configured CIDR or hop bounds".into(),
        ));
    }
    if config.trusted_proxies.cidrs.is_empty() != (config.trusted_proxies.trusted_hops == 0) {
        return Err(ConfigError::Invalid(
            "trusted_proxies cidrs and trusted_hops must be configured together".into(),
        ));
    }
    let mut trusted_cidrs = HashSet::new();
    for cidr in &config.trusted_proxies.cidrs {
        if !trusted_cidrs.insert(cidr) {
            return Err(ConfigError::Invalid(
                "trusted_proxies contains a duplicate CIDR".into(),
            ));
        }
    }
    if !matches!(config.tls.minimum_version.as_str(), "1.2" | "1.3") {
        return Err(ConfigError::Invalid(
            "tls.minimum_version must be 1.2 or 1.3".into(),
        ));
    }
    if config.tls.max_handshakes == 0
        || config.tls.max_handshakes > 100_000
        || config.tls.handshake_timeout_secs == 0
        || config.tls.handshake_timeout_secs > 300
    {
        return Err(ConfigError::Invalid(
            "TLS handshake limits are outside safe bounds".into(),
        ));
    }
    if let Some(identity) = config.tls.identity.as_deref() {
        SecretRef::parse(identity).map_err(|_| {
            ConfigError::Invalid("tls.identity has an invalid secret reference".into())
        })?;
    }
    if config.certificates.len() > 1024 {
        return Err(ConfigError::Invalid(
            "certificate count exceeds 1024".into(),
        ));
    }
    let mut certificate_ids = HashSet::new();
    let mut certificate_hosts = HashSet::new();
    for certificate in &config.certificates {
        valid_id(&certificate.id)?;
        if !certificate_ids.insert(certificate.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate certificate id {}",
                certificate.id
            )));
        }
        if certificate.hosts.is_empty() || certificate.hosts.len() > 64 {
            return Err(ConfigError::Invalid(format!(
                "certificate {} must contain 1..=64 hosts",
                certificate.id
            )));
        }
        for host in &certificate.hosts {
            valid_certificate_host(host)?;
            if !certificate_hosts.insert(host.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "certificate host {host} is assigned more than once"
                )));
            }
        }
        SecretRef::parse(&certificate.certificate_chain).map_err(|_| {
            ConfigError::Invalid(format!(
                "certificate {} has an invalid chain secret reference",
                certificate.id
            ))
        })?;
        SecretRef::parse(&certificate.private_key).map_err(|_| {
            ConfigError::Invalid(format!(
                "certificate {} has an invalid key secret reference",
                certificate.id
            ))
        })?;
    }
    if !config.certificates.is_empty() && config.tls.identity.is_none() {
        return Err(ConfigError::Invalid(
            "tls.identity is required for encrypted private keys".into(),
        ));
    }
    validate_acme(config, &mut certificate_ids, &mut certificate_hosts)?;
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
    if config.limits.max_request_target < 1_024 || config.limits.max_request_target > 64 * 1024 {
        return Err(ConfigError::Invalid(
            "limits.max_request_target is outside 1024..=65536".into(),
        ));
    }
    if config.limits.max_http2_streams == 0 || config.limits.max_http2_streams > 10_000 {
        return Err(ConfigError::Invalid(
            "limits.max_http2_streams is outside 1..=10000".into(),
        ));
    }
    if config.limits.max_health_checks == 0 || config.limits.max_health_checks > 4_096 {
        return Err(ConfigError::Invalid(
            "limits.max_health_checks is outside 1..=4096".into(),
        ));
    }
    if config.limits.max_dns_lookups == 0 || config.limits.max_dns_lookups > 4_096 {
        return Err(ConfigError::Invalid(
            "limits.max_dns_lookups is outside 1..=4096".into(),
        ));
    }
    if config.limits.tcp_connect_timeout_secs == 0
        || config.limits.tcp_connect_timeout_secs > 300
        || config.limits.tcp_idle_timeout_secs == 0
        || config.limits.tcp_idle_timeout_secs > 86_400
        || config.limits.tcp_connection_lifetime_secs == 0
        || config.limits.tcp_connection_lifetime_secs > 604_800
        || config.limits.tcp_idle_timeout_secs > config.limits.tcp_connection_lifetime_secs
    {
        return Err(ConfigError::Invalid(
            "configured TCP timeouts are outside safe bounds".into(),
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
    for (listener_index, listener) in config.listeners.iter().enumerate() {
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
        if !matches!(
            listener.protocol.as_str(),
            "http" | "https" | "tcp" | "tls_passthrough"
        ) {
            return Err(ConfigError::Invalid(format!(
                "unsupported listener protocol {}",
                listener.protocol
            )));
        }
        if listener.protocol == "https" {
            if listener.certificates.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "HTTPS listener {} has no certificates",
                    listener.id
                )));
            }
            let mut listener_certificates = HashSet::new();
            for (certificate_index, certificate) in listener.certificates.iter().enumerate() {
                if !listener_certificates.insert(certificate.as_str()) {
                    return Err(ConfigError::Invalid(format!(
                        "listeners[{listener_index}].certificates[{certificate_index}] duplicates certificate {certificate}"
                    )));
                }
                if !certificate_ids.contains(certificate.as_str()) {
                    return Err(ConfigError::Invalid(format!(
                        "listeners[{listener_index}].certificates[{certificate_index}] references unknown certificate {certificate}"
                    )));
                }
            }
        } else if !listener.certificates.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "non-HTTPS listener {} cannot reference certificates",
                listener.id
            )));
        }
    }
    let mut groups = HashSet::new();
    let mut group_is_tcp = HashMap::new();
    let mut total_endpoints = 0_usize;
    let mut total_upstream_in_flight = 0_usize;
    for (group_index, group) in config.upstream_groups.iter().enumerate() {
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
        if group.endpoints.len() > MAX_ENDPOINTS_PER_GROUP {
            return Err(ConfigError::Invalid(format!(
                "upstream_groups[{group_index}].endpoints exceeds {MAX_ENDPOINTS_PER_GROUP} entries"
            )));
        }
        total_endpoints += group.endpoints.len();
        if total_endpoints > MAX_TOTAL_ENDPOINTS {
            return Err(ConfigError::Invalid(format!(
                "total upstream endpoint count exceeds {MAX_TOTAL_ENDPOINTS}"
            )));
        }
        if group.allowed_cidrs.len() > 256 {
            return Err(ConfigError::Invalid(format!(
                "upstream_groups[{group_index}].allowed_cidrs exceeds 256 entries"
            )));
        }
        if group.denied_cidrs.len() > 256 {
            return Err(ConfigError::Invalid(format!(
                "upstream_groups[{group_index}].denied_cidrs exceeds 256 entries"
            )));
        }
        validate_upstream_policy(group_index, group)?;
        total_upstream_in_flight = total_upstream_in_flight
            .checked_add(group.max_in_flight)
            .ok_or_else(|| ConfigError::Invalid("upstream in-flight capacity overflow".into()))?;
        if total_upstream_in_flight > 100_000 {
            return Err(ConfigError::Invalid(
                "aggregate upstream in-flight capacity exceeds 100000".into(),
            ));
        }
        let mut endpoint_ids = HashSet::new();
        let mut total_weight = 0_u64;
        for (endpoint_index, endpoint) in group.endpoints.iter().enumerate() {
            valid_id(&endpoint.id)?;
            if !endpoint_ids.insert(endpoint.id.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate endpoint id {} in group {}",
                    endpoint.id, group.id
                )));
            }
            if endpoint.weight == 0 || endpoint.weight > 10_000 {
                return Err(ConfigError::Invalid(format!(
                    "upstream_groups[{group_index}].endpoints[{endpoint_index}].weight is outside 1..=10000"
                )));
            }
            total_weight += u64::from(endpoint.weight);
            if total_weight > 1_000_000 {
                return Err(ConfigError::Invalid(format!(
                    "upstream_groups[{group_index}] total endpoint weight exceeds 1000000"
                )));
            }
            if !matches!(endpoint.url.scheme(), "http" | "https" | "tcp")
                || endpoint.url.host_str().is_none()
                || endpoint.url.port().is_none()
            {
                return Err(ConfigError::Invalid(format!(
                    "endpoint {} URL must be absolute http(s) or tcp with an explicit port",
                    endpoint.id
                )));
            }
            if endpoint.url.as_str().len() > 2_048
                || !endpoint.url.username().is_empty()
                || endpoint.url.password().is_some()
                || endpoint.url.query().is_some()
                || endpoint.url.fragment().is_some()
            {
                return Err(ConfigError::Invalid(format!(
                    "upstream_groups[{group_index}].endpoints[{endpoint_index}].url must be bounded and contain no credentials, query, or fragment"
                )));
            }
            match (endpoint.url.scheme(), endpoint.server_name.as_deref()) {
                ("https", Some(server_name)) if !server_name.starts_with("*.") => {
                    valid_certificate_host(server_name)?;
                }
                ("https", _) => {
                    return Err(ConfigError::Invalid(format!(
                        "HTTPS endpoint {} requires an exact server_name",
                        endpoint.id
                    )));
                }
                ("http", Some(_)) => {
                    return Err(ConfigError::Invalid(format!(
                        "HTTP endpoint {} cannot set server_name",
                        endpoint.id
                    )));
                }
                ("tcp", Some(_)) => {
                    return Err(ConfigError::Invalid(format!(
                        "TCP endpoint {} cannot set server_name",
                        endpoint.id
                    )));
                }
                _ => {}
            }
            match (endpoint.url.scheme(), endpoint.ca_bundle.as_deref()) {
                ("https", Some(reference)) => {
                    SecretRef::parse(reference).map_err(|error| {
                        ConfigError::Invalid(format!(
                            "endpoint {} has invalid CA bundle reference: {error}",
                            endpoint.id
                        ))
                    })?;
                }
                ("http", Some(_)) => {
                    return Err(ConfigError::Invalid(format!(
                        "HTTP endpoint {} cannot set ca_bundle",
                        endpoint.id
                    )));
                }
                ("tcp", Some(_)) => {
                    return Err(ConfigError::Invalid(format!(
                        "TCP endpoint {} cannot set ca_bundle",
                        endpoint.id
                    )));
                }
                _ => {}
            }
            let host = endpoint.url.host_str().unwrap_or_default();
            if let Ok(ip) = host.parse::<IpAddr>() {
                validate_egress_ip(ip, &group.allowed_cidrs, &group.denied_cidrs).map_err(
                    |reason| {
                        ConfigError::Invalid(format!(
                            "endpoint {} is not allowed: {reason}",
                            endpoint.id
                        ))
                    },
                )?;
            } else {
                valid_upstream_host(host).map_err(|reason| {
                    ConfigError::Invalid(format!(
                        "endpoint {} has invalid DNS name: {reason}",
                        endpoint.id
                    ))
                })?;
            }
        }
        let is_tcp = group
            .endpoints
            .first()
            .is_some_and(|endpoint| endpoint.url.scheme() == "tcp");
        if group
            .endpoints
            .iter()
            .any(|endpoint| (endpoint.url.scheme() == "tcp") != is_tcp)
        {
            return Err(ConfigError::Invalid(format!(
                "upstream_groups[{group_index}] mixes HTTP-family and TCP endpoints"
            )));
        }
        if is_tcp
            && group
                .health
                .as_ref()
                .is_some_and(|health| health.kind == HealthCheckKind::Http)
        {
            return Err(ConfigError::Invalid(format!(
                "upstream_groups[{group_index}].health must use kind = \"tcp\" for TCP endpoints"
            )));
        }
        if is_tcp && group.retry != RetryConfig::default() {
            return Err(ConfigError::Invalid(format!(
                "upstream_groups[{group_index}].retry is unsupported for raw TCP endpoints"
            )));
        }
        group_is_tcp.insert(group.id.as_str(), is_tcp);
    }
    validate_providers(config)?;
    let listener_ids: HashSet<&str> = config.listeners.iter().map(|l| l.id.as_str()).collect();
    let listener_protocols: HashMap<&str, &str> = config
        .listeners
        .iter()
        .map(|listener| (listener.id.as_str(), listener.protocol.as_str()))
        .collect();
    let group_ids: HashSet<&str> = config
        .upstream_groups
        .iter()
        .map(|g| g.id.as_str())
        .collect();
    let mut route_ids = HashSet::new();
    for (route_index, route) in config.routes.iter().enumerate() {
        valid_id(&route.id)?;
        if !route_ids.insert(route.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate route id {}",
                route.id
            )));
        }
        if route.listeners.is_empty() || route.listeners.len() > MAX_ROUTE_LISTENERS {
            return Err(ConfigError::Invalid(format!(
                "route {} listeners must contain 1..={MAX_ROUTE_LISTENERS} entries",
                route.id,
            )));
        }
        validate_unique_strings(&route.id, "listener", &route.listeners)?;
        if route.hosts.len() > MAX_ROUTE_HOSTS
            || route.paths.len() > MAX_ROUTE_EXACT_PATHS
            || route.path_prefixes.len() > MAX_ROUTE_PATHS
            || route.methods.len() > MAX_ROUTE_METHODS
            || route.headers.len() > MAX_ROUTE_HEADERS
            || route.middlewares.len() > MAX_ROUTE_MIDDLEWARES
        {
            return Err(ConfigError::Invalid(format!(
                "route {} exceeds a matcher or middleware count limit",
                route.id
            )));
        }
        validate_route_matchers(route)?;
        if route
            .upstream_group
            .as_deref()
            .is_some_and(|group| !group_ids.contains(group))
        {
            return Err(ConfigError::Invalid(format!(
                "routes[{route_index}].upstream_group references unknown upstream"
            )));
        }
        for (listener_index, listener) in route.listeners.iter().enumerate() {
            if !listener_ids.contains(listener.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "routes[{route_index}].listeners[{listener_index}] references unknown listener {listener}"
                )));
            }
        }
        let mut route_protocol = None;
        for listener in &route.listeners {
            let protocol = listener_protocols
                .get(listener.as_str())
                .copied()
                .unwrap_or_default();
            let family = match protocol {
                "http" | "https" => "http",
                "tcp" => "tcp",
                "tls_passthrough" => "tls_passthrough",
                _ => unreachable!("listener protocol was validated"),
            };
            if route_protocol.is_some_and(|selected| selected != family) {
                return Err(ConfigError::Invalid(format!(
                    "route {} mixes incompatible listener protocols",
                    route.id
                )));
            }
            route_protocol = Some(family);
        }
        let upstream_is_tcp = route
            .upstream_group
            .as_deref()
            .and_then(|group| group_is_tcp.get(group))
            .copied()
            .unwrap_or(false);
        match route_protocol {
            Some("http") if route.upstream_group.is_some() && upstream_is_tcp => {
                return Err(ConfigError::Invalid(format!(
                    "route {} uses a TCP upstream on an HTTP-family listener",
                    route.id
                )));
            }
            Some("tcp") | Some("tls_passthrough") if route.upstream_group.is_none() => {
                return Err(ConfigError::Invalid(format!(
                    "route {} requires a TCP upstream",
                    route.id
                )));
            }
            Some("tcp") | Some("tls_passthrough") if !upstream_is_tcp => {
                return Err(ConfigError::Invalid(format!(
                    "route {} uses an HTTP-family upstream on a TCP-family listener",
                    route.id
                )));
            }
            Some("tcp") => validate_tcp_route(route, false)?,
            Some("tls_passthrough") => validate_tcp_route(route, true)?,
            _ => {}
        }
        validate_unique_strings(&route.id, "middleware", &route.middlewares)?;
        let mut redirects = 0_usize;
        let mut security_headers = 0_usize;
        let mut ip_policies = 0_usize;
        let mut edge_rate_limits = 0_usize;
        let mut principal_rate_limits = 0_usize;
        let mut in_flight_limits = 0_usize;
        let mut cors_policies = 0_usize;
        let mut authentication = 0_usize;
        let mut rewrites = 0_usize;
        let mut header_mutations = 0_usize;
        let mut request_header_mutations = false;
        let mut maintenance = 0_usize;
        let mut authenticated_maintenance = false;
        let mut custom_errors = 0_usize;
        let mut compression = 0_usize;
        for middleware in &route.middlewares {
            let Some(definition) = config.middlewares.get(middleware) else {
                return Err(ConfigError::Invalid(format!(
                    "route {} references unknown middleware {}",
                    route.id, middleware
                )));
            };
            match definition {
                MiddlewareConfig::Redirect { .. } => redirects += 1,
                MiddlewareConfig::SecurityHeaders { hsts, .. } => {
                    security_headers += 1;
                    if hsts.is_some()
                        && route.listeners.iter().any(|listener| {
                            listener_protocols.get(listener.as_str()).copied() != Some("https")
                        })
                    {
                        return Err(ConfigError::Invalid(format!(
                            "route {} applies HSTS to a non-HTTPS listener",
                            route.id
                        )));
                    }
                }
                MiddlewareConfig::RateLimit { key, .. } => match key {
                    RateLimitKey::ClientIp => edge_rate_limits += 1,
                    RateLimitKey::Principal => principal_rate_limits += 1,
                },
                MiddlewareConfig::InFlightLimit { .. } => in_flight_limits += 1,
                MiddlewareConfig::IpPolicy { .. } => ip_policies += 1,
                MiddlewareConfig::Cors { .. } => cors_policies += 1,
                MiddlewareConfig::BasicAuth { .. } => {
                    authentication += 1;
                    if route.listeners.iter().any(|listener| {
                        listener_protocols.get(listener.as_str()).copied() != Some("https")
                    }) {
                        return Err(ConfigError::Invalid(format!(
                            "route {} applies Basic authentication to a non-HTTPS listener",
                            route.id
                        )));
                    }
                }
                MiddlewareConfig::ForwardAuth { upstream_group, .. } => {
                    authentication += 1;
                    if route.listeners.iter().any(|listener| {
                        listener_protocols.get(listener.as_str()).copied() != Some("https")
                    }) {
                        return Err(ConfigError::Invalid(format!(
                            "route {} applies ForwardAuth to a non-HTTPS listener",
                            route.id
                        )));
                    }
                    let Some(group) = config
                        .upstream_groups
                        .iter()
                        .find(|group| group.id == *upstream_group)
                    else {
                        return Err(ConfigError::Invalid(format!(
                            "route {} ForwardAuth references unknown upstream group {}",
                            route.id, upstream_group
                        )));
                    };
                    if group
                        .endpoints
                        .iter()
                        .any(|endpoint| endpoint.url.scheme() == "tcp")
                    {
                        return Err(ConfigError::Invalid(format!(
                            "route {} ForwardAuth requires an HTTP-family upstream group",
                            route.id
                        )));
                    }
                }
                MiddlewareConfig::Rewrite { .. } => rewrites += 1,
                MiddlewareConfig::HeaderMutation {
                    request_set,
                    request_add,
                    request_remove,
                    ..
                } => {
                    header_mutations += 1;
                    request_header_mutations = !request_set.is_empty()
                        || !request_add.is_empty()
                        || !request_remove.is_empty();
                }
                MiddlewareConfig::Maintenance { authenticated, .. } => {
                    maintenance += 1;
                    authenticated_maintenance = *authenticated;
                }
                MiddlewareConfig::CustomError { .. } => custom_errors += 1,
                MiddlewareConfig::Compression { .. } => compression += 1,
            }
        }
        if redirects > 1
            || security_headers > 1
            || ip_policies > 1
            || edge_rate_limits > 1
            || principal_rate_limits > 1
            || in_flight_limits > 1
            || cors_policies > 1
            || authentication > 1
            || rewrites > 1
            || header_mutations > 1
            || maintenance > 1
            || custom_errors > 1
            || compression > 1
        {
            return Err(ConfigError::Invalid(format!(
                "route {} contains an ambiguous duplicate middleware stage",
                route.id
            )));
        }
        if !matches!(
            (route.upstream_group.is_some(), redirects, maintenance),
            (true, 0, 0) | (false, 1, 0) | (false, 0, 1)
        ) {
            return Err(ConfigError::Invalid(format!(
                "route {} must select exactly one proxy, redirect, or maintenance terminal action",
                route.id
            )));
        }
        if (redirects == 1 || maintenance == 1) && route_protocol != Some("http") {
            return Err(ConfigError::Invalid(format!(
                "route {} uses an HTTP terminal outside an HTTP-family listener",
                route.id
            )));
        }
        if redirects == 1 && authentication != 0 {
            return Err(ConfigError::Invalid(format!(
                "route {} cannot authenticate a public redirect stage",
                route.id
            )));
        }
        if principal_rate_limits != 0 && authentication != 1 {
            return Err(ConfigError::Invalid(format!(
                "route {} principal rate limit requires exactly one authentication stage",
                route.id
            )));
        }
        if redirects == 1 && rewrites != 0 {
            return Err(ConfigError::Invalid(format!(
                "route {} cannot rewrite a terminal redirect",
                route.id
            )));
        }
        if redirects == 1 && header_mutations != 0 {
            return Err(ConfigError::Invalid(format!(
                "route {} cannot mutate a terminal redirect request",
                route.id
            )));
        }
        if maintenance == 1 && rewrites != 0 {
            return Err(ConfigError::Invalid(format!(
                "route {} cannot rewrite a terminal maintenance response",
                route.id
            )));
        }
        if maintenance == 1 && (request_header_mutations || cors_policies != 0) {
            return Err(ConfigError::Invalid(format!(
                "route {} applies an unused request or CORS transform to maintenance",
                route.id
            )));
        }
        if maintenance == 1 && authenticated_maintenance != (authentication == 1) {
            return Err(ConfigError::Invalid(format!(
                "route {} maintenance authentication mode does not match its auth middleware",
                route.id
            )));
        }
        if custom_errors != 0 && route.upstream_group.is_none() {
            return Err(ConfigError::Invalid(format!(
                "route {} applies custom upstream errors without proxying",
                route.id
            )));
        }
        if compression != 0 && route.upstream_group.is_none() {
            return Err(ConfigError::Invalid(format!(
                "route {} applies compression without proxying",
                route.id
            )));
        }
    }
    conflict::validate_route_conflicts(&config.routes)?;
    for listener in &config.listeners {
        let route_count = config
            .routes
            .iter()
            .filter(|route| route.listeners.contains(&listener.id))
            .count();
        match listener.protocol.as_str() {
            "tcp" if route_count != 1 => {
                return Err(ConfigError::Invalid(format!(
                    "plain TCP listener {} requires exactly one default route",
                    listener.id
                )));
            }
            "tls_passthrough" if route_count == 0 => {
                return Err(ConfigError::Invalid(format!(
                    "TLS passthrough listener {} requires at least one SNI or default route",
                    listener.id
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
