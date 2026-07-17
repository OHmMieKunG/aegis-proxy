#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Strict, bounded configuration types and validation.

mod conflict;
mod redact;
pub mod revision;

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

/// Maximum configuration bytes accepted by the offline parser.
pub const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;

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
const MAX_HEADER_VALUE_BYTES: usize = 1_024;
const MAX_PATH_BYTES: usize = 2_048;
const MAX_ACME_ISSUERS: usize = 32;
const MAX_ACME_CERTIFICATES: usize = 1024;
const MAX_ACME_DNS_PROVIDERS: usize = 32;

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
    /// Global TLS policy.
    #[serde(default)]
    pub tls: TlsConfig,
    /// Bring-your-own certificate identities.
    #[serde(default)]
    pub certificates: Vec<CertificateConfig>,
    /// Automated certificate-management policy.
    #[serde(default)]
    pub acme: AcmeConfig,
    /// Trusted forwarding peers.
    #[serde(default)]
    pub trusted_proxies: TrustedProxyConfig,
    /// Upstream groups.
    #[serde(default)]
    pub upstream_groups: Vec<UpstreamGroupConfig>,
    /// Middleware definitions.
    #[serde(default)]
    pub middlewares: BTreeMap<String, MiddlewareConfig>,
    /// Routes.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// Administrative settings.
    #[serde(default)]
    pub admin: AdminConfig,
}

/// Runtime settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum accepted connections.
    pub max_connections: usize,
    /// Maximum header bytes.
    pub max_header_bytes: usize,
    /// Maximum header count.
    pub max_headers: usize,
    /// Maximum request-target bytes, including query.
    pub max_request_target: usize,
    /// Maximum concurrent HTTP/2 streams per connection.
    pub max_http2_streams: u32,
    /// Maximum concurrent active upstream health probes.
    pub max_health_checks: usize,
    /// Maximum concurrent upstream DNS lookups.
    pub max_dns_lookups: usize,
    /// Maximum raw upstream TCP connect time in seconds.
    pub tcp_connect_timeout_secs: u64,
    /// Maximum raw TCP inactivity in seconds.
    pub tcp_idle_timeout_secs: u64,
    /// Maximum raw TCP connection lifetime in seconds.
    pub tcp_connection_lifetime_secs: u64,
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
            max_request_target: 8 * 1024,
            max_http2_streams: 128,
            max_health_checks: 64,
            max_dns_lookups: 32,
            tcp_connect_timeout_secs: 5,
            tcp_idle_timeout_secs: 300,
            tcp_connection_lifetime_secs: 86_400,
            max_request_body: 32 * 1024 * 1024,
            request_header_timeout_secs: 10,
            response_header_timeout_secs: 30,
        }
    }
}

/// A network listener.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Stable identifier.
    pub id: String,
    /// Bind address.
    pub bind: SocketAddr,
    /// `http`, `https`, `tcp`, or `tls_passthrough`.
    pub protocol: String,
    /// Certificate identities available on an HTTPS listener.
    #[serde(default)]
    pub certificates: Vec<String>,
}

/// Global TLS policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Minimum accepted TLS version: `1.2` or `1.3`.
    pub minimum_version: String,
    /// Maximum concurrent handshakes.
    pub max_handshakes: usize,
    /// Handshake timeout in seconds.
    pub handshake_timeout_secs: u64,
    /// Secret reference containing one or more age X25519 decryption identities.
    pub identity: Option<String>,
    /// Public age X25519 recipients used for new encrypted state.
    pub state_encryption_recipients: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            minimum_version: "1.2".into(),
            max_handshakes: 256,
            handshake_timeout_secs: 10,
            identity: None,
            state_encryption_recipients: Vec::new(),
        }
    }
}

/// Bring-your-own certificate and private-key references.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateConfig {
    /// Stable identity.
    pub id: String,
    /// Exact or single-label wildcard DNS names served by this identity.
    pub hosts: Vec<String>,
    /// PEM certificate-chain secret reference.
    pub certificate_chain: String,
    /// Age-encrypted PEM private-key envelope reference.
    pub private_key: String,
}

/// Strict ACME issuers, managed certificates, and DNS adapters.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeConfig {
    /// Global bound across all issuers.
    pub max_concurrent_orders: usize,
    /// Explicit CA directory/account policies.
    pub issuers: Vec<AcmeIssuerConfig>,
    /// Certificates owned by ACME automation.
    pub certificates: Vec<AcmeCertificateConfig>,
    /// Approved DNS-01 providers.
    pub dns_providers: Vec<AcmeDnsProviderConfig>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            max_concurrent_orders: 4,
            issuers: Vec::new(),
            certificates: Vec::new(),
            dns_providers: Vec::new(),
        }
    }
}

/// One explicitly classified ACME directory/account.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeIssuerConfig {
    /// Stable issuer ID.
    pub id: String,
    /// Exact ACME directory URL.
    pub directory_url: Url,
    /// Operator-selected CA environment classification.
    pub environment: AcmeEnvironment,
    /// Optional account contact email.
    pub account_email: Option<String>,
    /// Explicit operator acceptance required before creating an account.
    pub terms_of_service_agreed: bool,
    /// Optional explicit private/test CA bundle.
    pub ca_bundle: Option<String>,
    /// Optional external-account binding.
    pub external_account: Option<AcmeExternalAccountConfig>,
    /// Per-issuer order concurrency bound.
    #[serde(default = "default_issuer_order_limit")]
    pub max_concurrent_orders: usize,
}

/// Explicit CA environment; it is never inferred from the directory URL.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeEnvironment {
    /// Real publicly trusted or organizational production issuance.
    Production,
    /// Test/staging issuance that must never replace production material.
    Staging,
}

/// External account binding references.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeExternalAccountConfig {
    /// CA-provided external account key ID.
    pub key_id: String,
    /// Secret reference containing raw or provider-documented HMAC bytes.
    pub hmac_key: String,
}

/// One managed certificate order and renewal policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeCertificateConfig {
    /// Stable certificate ID shared with listener references.
    pub id: String,
    /// Exact or single-label wildcard DNS identifiers.
    pub hosts: Vec<String>,
    /// Issuer ID.
    pub issuer: String,
    /// Challenge type selected without automatic fallback.
    pub challenge: AcmeChallenge,
    /// Listener that exclusively serves HTTP-01 or TLS-ALPN-01 state.
    pub challenge_listener: Option<String>,
    /// DNS provider ID required only for DNS-01.
    pub dns_provider: Option<String>,
    /// Optional ACME certificate profile name.
    pub profile: Option<String>,
    /// Fallback renewal window when ARI is unavailable.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u16,
}

/// Supported ACME ownership challenges.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AcmeChallenge {
    /// HTTP token response on an explicitly configured HTTP listener.
    #[serde(rename = "http-01")]
    Http01,
    /// DNS TXT record through an approved provider.
    #[serde(rename = "dns-01")]
    Dns01,
    /// Ephemeral `acme-tls/1` certificate on an HTTPS listener.
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// Compile-time reviewed DNS-01 provider configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcmeDnsProviderConfig {
    /// Cloudflare v4 API using a zone-scoped token.
    Cloudflare {
        /// Stable provider ID.
        id: String,
        /// Explicit Cloudflare zone ID; discovery is not used.
        zone_id: String,
        /// Secret reference containing a narrowly scoped API token.
        api_token: String,
    },
}

impl AcmeDnsProviderConfig {
    fn id(&self) -> &str {
        match self {
            Self::Cloudflare { id, .. } => id,
        }
    }
}

fn default_issuer_order_limit() -> usize {
    2
}

fn default_renew_before_days() -> u16 {
    30
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamGroupConfig {
    /// Stable identifier.
    pub id: String,
    /// Balancing algorithm.
    #[serde(default)]
    pub algorithm: BalancingAlgorithm,
    /// Explicit egress allowlist.
    #[serde(default)]
    pub allowed_cidrs: Vec<IpNet>,
    /// Explicit egress denylist. Denies override allows.
    #[serde(default)]
    pub denied_cidrs: Vec<IpNet>,
    /// DNS resolution policy for configured endpoint names.
    #[serde(default)]
    pub dns: DnsConfig,
    /// Optional active health-check policy.
    #[serde(default)]
    pub health: Option<HealthCheckConfig>,
    /// Passive failure classification and hysteresis.
    #[serde(default)]
    pub passive_health: PassiveHealthConfig,
    /// Retry attempt budget.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Optional group circuit-breaker policy.
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    /// Maximum time removed endpoints may drain existing work.
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
    /// Endpoints.
    pub endpoints: Vec<EndpointConfig>,
}

impl Default for UpstreamGroupConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            algorithm: BalancingAlgorithm::default(),
            allowed_cidrs: Vec::new(),
            denied_cidrs: Vec::new(),
            dns: DnsConfig::default(),
            health: None,
            passive_health: PassiveHealthConfig::default(),
            retry: RetryConfig::default(),
            circuit_breaker: None,
            drain_timeout_secs: default_drain_timeout_secs(),
            endpoints: Vec::new(),
        }
    }
}

/// Supported endpoint-selection algorithms.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BalancingAlgorithm {
    /// Equal-share rotating selection.
    #[default]
    RoundRobin,
    /// Smooth weighted round robin.
    SmoothWeightedRoundRobin,
    /// Pseudo-random eligible endpoint.
    Random,
    /// Select the less busy of two pseudo-random candidates.
    PowerOfTwo,
}

/// DNS bounds for configured endpoint names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Maximum accepted A/AAAA or SRV answers per lookup.
    pub max_answers: usize,
    /// Maximum lookup duration.
    pub lookup_timeout_secs: u64,
    /// Minimum refresh TTL applied to an answer.
    pub min_ttl_secs: u64,
    /// Maximum refresh TTL applied to an answer.
    pub max_ttl_secs: u64,
    /// Maximum time a last allowed answer may remain after refresh failure.
    pub stale_timeout_secs: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            max_answers: 16,
            lookup_timeout_secs: 3,
            min_ttl_secs: 5,
            max_ttl_secs: 300,
            stale_timeout_secs: 300,
        }
    }
}

/// Active upstream health-check policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Probe protocol.
    pub kind: HealthCheckKind,
    /// HTTP method for HTTP probes.
    pub method: String,
    /// Canonical HTTP path for HTTP probes.
    pub path: String,
    /// Accepted HTTP status codes.
    pub expected_statuses: Vec<u16>,
    /// Time between probes.
    pub interval_secs: u64,
    /// Per-probe deadline.
    pub timeout_secs: u64,
    /// Consecutive failures required for unhealthy state.
    pub unhealthy_threshold: u32,
    /// Consecutive successes required for healthy state.
    pub healthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            kind: HealthCheckKind::Http,
            method: "GET".into(),
            path: "/".into(),
            expected_statuses: vec![200],
            interval_secs: 10,
            timeout_secs: 2,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }
}

/// Active health-check protocol.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckKind {
    /// HTTP request probe.
    #[default]
    Http,
    /// TCP connection probe.
    Tcp,
}

/// Passive endpoint-health policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PassiveHealthConfig {
    /// Classified failures required inside the rolling window.
    pub failure_threshold: u32,
    /// Consecutive successes required for recovery.
    pub healthy_threshold: u32,
    /// Rolling failure-window duration.
    pub window_secs: u64,
    /// Maximum observations retained per endpoint.
    pub max_samples: usize,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            healthy_threshold: 2,
            window_secs: 30,
            max_samples: 64,
        }
    }
}

/// Upstream retry budget.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetryConfig {
    /// Total attempts, including the first request.
    pub max_attempts: u32,
    /// Total wall-clock attempt budget.
    pub total_timeout_secs: u64,
    /// Maximum replayable request body bytes.
    pub replay_body_bytes: usize,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            total_timeout_secs: 30,
            replay_body_bytes: 0,
        }
    }
}

/// Group circuit-breaker policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Bounded rolling sample count.
    pub sample_size: usize,
    /// Minimum observations before opening is possible.
    pub minimum_requests: usize,
    /// Failure percentage that opens the circuit.
    pub failure_percent: u8,
    /// Open-state duration before half-open probes.
    pub open_secs: u64,
    /// Concurrent half-open probe budget.
    pub half_open_requests: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            sample_size: 100,
            minimum_requests: 20,
            failure_percent: 50,
            open_secs: 10,
            half_open_requests: 1,
        }
    }
}

fn default_drain_timeout_secs() -> u64 {
    30
}

/// Upstream endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    /// Stable identifier.
    pub id: String,
    /// Absolute HTTP(S) or raw TCP URL.
    pub url: Url,
    /// Relative selection weight.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Optional upstream TLS SNI/Host name.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Optional PEM CA-bundle secret reference. When set, it replaces public roots.
    #[serde(default)]
    pub ca_bundle: Option<String>,
}

fn default_weight() -> u32 {
    1
}

/// Middleware definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MiddlewareConfig {
    /// Security response headers.
    SecurityHeaders {
        /// HSTS value.
        hsts: Option<String>,
        /// Content-Security-Policy value.
        content_security_policy: Option<String>,
        /// Replace an upstream value instead of preserving it.
        #[serde(default)]
        override_existing: bool,
        /// Explicit acknowledgement for HSTS subdomain/preload persistence.
        #[serde(default)]
        acknowledge_hsts_risk: bool,
    },
    /// Edge request rate limit.
    RateLimit {
        /// Sustained request rate.
        requests_per_second: u64,
        /// Burst capacity.
        burst: u64,
        /// Maximum simultaneously tracked client keys.
        #[serde(default = "default_rate_limit_keys")]
        max_keys: usize,
        /// Seconds after which an idle key may be evicted.
        #[serde(default = "default_rate_limit_idle_secs")]
        idle_secs: u64,
    },
    /// Trusted-client IP policy. Deny entries take precedence.
    IpPolicy {
        /// Optional allowlist; empty means any address not denied.
        #[serde(default)]
        allow: Vec<IpNet>,
        /// Explicit denylist.
        #[serde(default)]
        deny: Vec<IpNet>,
    },
    /// Fixed redirect.
    Redirect {
        /// Destination URL.
        location: String,
        /// HTTP redirect status.
        status: u16,
        /// Append the original query when the fixed target has no query.
        #[serde(default)]
        preserve_query: bool,
    },
}

fn default_rate_limit_keys() -> usize {
    10_000
}

fn default_rate_limit_idle_secs() -> u64 {
    300
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
    /// Canonical exact paths.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Segment-aware path prefixes.
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    /// Allowed methods.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Exact header predicates.
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
    /// Explicit catch-all route. Match predicates must be empty.
    #[serde(default)]
    pub default: bool,
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
    /// Exact value. Omit to match header presence only.
    #[serde(default)]
    pub value: Option<String>,
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
    for (id, middleware) in &config.middlewares {
        valid_id(id)?;
        validate_middleware(id, middleware)?;
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
        let mut rate_limits = 0_usize;
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
                MiddlewareConfig::RateLimit { .. } => rate_limits += 1,
                MiddlewareConfig::IpPolicy { .. } => ip_policies += 1,
            }
        }
        if redirects > 1 || security_headers > 1 || ip_policies > 1 || rate_limits > 1 {
            return Err(ConfigError::Invalid(format!(
                "route {} contains an ambiguous duplicate middleware stage",
                route.id
            )));
        }
        if (route.upstream_group.is_some(), redirects) != (true, 0)
            && (route.upstream_group.is_some(), redirects) != (false, 1)
        {
            return Err(ConfigError::Invalid(format!(
                "route {} must select exactly one proxy or redirect terminal action",
                route.id
            )));
        }
        if redirects == 1 && route_protocol != Some("http") {
            return Err(ConfigError::Invalid(format!(
                "route {} uses redirect outside an HTTP-family listener",
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

fn validate_middleware(id: &str, middleware: &MiddlewareConfig) -> Result<(), ConfigError> {
    match middleware {
        MiddlewareConfig::SecurityHeaders {
            hsts,
            content_security_policy,
            acknowledge_hsts_risk,
            ..
        } => {
            if hsts.is_none() && content_security_policy.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} has no security headers"
                )));
            }
            if let Some(value) = hsts {
                validate_header_value(id, "hsts", value)?;
                let mut max_age = None;
                let mut persistent = false;
                for directive in value.split(';').map(str::trim) {
                    if let Some(value) = directive
                        .to_ascii_lowercase()
                        .strip_prefix("max-age=")
                        .map(str::to_owned)
                    {
                        if max_age.replace(value).is_some() {
                            return Err(ConfigError::Invalid(format!(
                                "middleware {id} repeats HSTS max-age"
                            )));
                        }
                    } else if directive.eq_ignore_ascii_case("includesubdomains")
                        || directive.eq_ignore_ascii_case("preload")
                    {
                        persistent = true;
                    } else {
                        return Err(ConfigError::Invalid(format!(
                            "middleware {id} contains an unsupported HSTS directive"
                        )));
                    }
                }
                if max_age
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|seconds| *seconds <= 63_072_000)
                    .is_none()
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} HSTS requires max-age within 0..=63072000"
                    )));
                }
                if persistent && !acknowledge_hsts_risk {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} must acknowledge HSTS subdomain/preload risk"
                    )));
                }
            }
            if let Some(value) = content_security_policy {
                validate_header_value(id, "content_security_policy", value)?;
            }
        }
        MiddlewareConfig::RateLimit {
            requests_per_second,
            burst,
            max_keys,
            idle_secs,
        } => {
            if !(1..=1_000_000).contains(requests_per_second)
                || !(1..=1_000_000).contains(burst)
                || !(1..=100_000).contains(max_keys)
                || !(1..=86_400).contains(idle_secs)
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} rate limit is outside safe bounds"
                )));
            }
        }
        MiddlewareConfig::IpPolicy { allow, deny } => {
            if allow.len() > MAX_MIDDLEWARE_CIDRS
                || deny.len() > MAX_MIDDLEWARE_CIDRS
                || (allow.is_empty() && deny.is_empty())
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} IP policy is empty or exceeds CIDR bounds"
                )));
            }
            let mut cidrs = HashSet::new();
            if allow.iter().chain(deny).any(|cidr| !cidrs.insert(cidr)) {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} IP policy contains duplicate CIDRs"
                )));
            }
        }
        MiddlewareConfig::Redirect {
            location,
            status,
            preserve_query,
        } => {
            if !matches!(*status, 301 | 302 | 303 | 307 | 308) {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} has an invalid redirect status"
                )));
            }
            validate_header_value(id, "location", location)?;
            if let Ok(url) = Url::parse(location) {
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                    || (*preserve_query && url.query().is_some())
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an unsafe absolute redirect"
                    )));
                }
            } else {
                let uri = location.parse::<Uri>().map_err(|_| {
                    ConfigError::Invalid(format!(
                        "middleware {id} has an invalid relative redirect"
                    ))
                })?;
                if !uri.path().starts_with('/')
                    || uri.path().starts_with("//")
                    || uri.scheme().is_some()
                    || uri.authority().is_some()
                    || (*preserve_query && uri.query().is_some())
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an unsafe relative redirect"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_header_value(id: &str, field: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > MAX_HEADER_VALUE_BYTES
        || HeaderValue::from_str(value).is_err()
    {
        return Err(ConfigError::Invalid(format!(
            "middleware {id} has an invalid {field} header value"
        )));
    }
    Ok(())
}

fn validate_acme<'a>(
    config: &'a Config,
    certificate_ids: &mut HashSet<&'a str>,
    certificate_hosts: &mut HashSet<&'a str>,
) -> Result<(), ConfigError> {
    let acme = &config.acme;
    if acme.max_concurrent_orders == 0 || acme.max_concurrent_orders > 32 {
        return Err(ConfigError::Invalid(
            "acme.max_concurrent_orders is outside 1..=32".into(),
        ));
    }
    if acme.issuers.len() > MAX_ACME_ISSUERS
        || acme.certificates.len() > MAX_ACME_CERTIFICATES
        || acme.dns_providers.len() > MAX_ACME_DNS_PROVIDERS
        || config.certificates.len() + acme.certificates.len() > MAX_ACME_CERTIFICATES
    {
        return Err(ConfigError::Invalid(
            "ACME issuer, certificate, or DNS provider count exceeds its bound".into(),
        ));
    }

    let mut issuer_ids = HashSet::new();
    for issuer in &acme.issuers {
        valid_id(&issuer.id)?;
        if !issuer_ids.insert(issuer.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate ACME issuer id {}",
                issuer.id
            )));
        }
        validate_acme_directory(issuer)?;
        if let Some(email) = issuer.account_email.as_deref()
            && (email.is_empty()
                || email.len() > 254
                || !email.is_ascii()
                || email.chars().any(char::is_control)
                || email.matches('@').count() != 1)
        {
            return Err(ConfigError::Invalid(format!(
                "ACME issuer {} has an invalid account_email",
                issuer.id
            )));
        }
        if let Some(ca_bundle) = issuer.ca_bundle.as_deref() {
            SecretRef::parse(ca_bundle).map_err(|_| {
                ConfigError::Invalid(format!(
                    "ACME issuer {} has an invalid ca_bundle secret reference",
                    issuer.id
                ))
            })?;
        }
        if let Some(external) = &issuer.external_account {
            if external.key_id.is_empty()
                || external.key_id.len() > 256
                || external.key_id.chars().any(char::is_control)
            {
                return Err(ConfigError::Invalid(format!(
                    "ACME issuer {} has an invalid external account key ID",
                    issuer.id
                )));
            }
            SecretRef::parse(&external.hmac_key).map_err(|_| {
                ConfigError::Invalid(format!(
                    "ACME issuer {} has an invalid external account HMAC secret reference",
                    issuer.id
                ))
            })?;
        }
        if issuer.max_concurrent_orders == 0
            || issuer.max_concurrent_orders > acme.max_concurrent_orders
        {
            return Err(ConfigError::Invalid(format!(
                "ACME issuer {} order limit exceeds the global bound",
                issuer.id
            )));
        }
    }

    let mut provider_ids = HashSet::new();
    for provider in &acme.dns_providers {
        valid_id(provider.id())?;
        if !provider_ids.insert(provider.id()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate ACME DNS provider id {}",
                provider.id()
            )));
        }
        match provider {
            AcmeDnsProviderConfig::Cloudflare {
                id,
                zone_id,
                api_token,
            } => {
                if zone_id.len() != 32
                    || !zone_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                {
                    return Err(ConfigError::Invalid(format!(
                        "ACME DNS provider {id} has an invalid Cloudflare zone_id"
                    )));
                }
                SecretRef::parse(api_token).map_err(|_| {
                    ConfigError::Invalid(format!(
                        "ACME DNS provider {id} has an invalid api_token secret reference"
                    ))
                })?;
            }
        }
    }

    for certificate in &acme.certificates {
        valid_id(&certificate.id)?;
        if !certificate_ids.insert(certificate.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate certificate id {}",
                certificate.id
            )));
        }
        if certificate.hosts.is_empty() || certificate.hosts.len() > 64 {
            return Err(ConfigError::Invalid(format!(
                "ACME certificate {} must contain 1..=64 hosts",
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
            if host.starts_with("*.") && certificate.challenge != AcmeChallenge::Dns01 {
                return Err(ConfigError::Invalid(format!(
                    "ACME wildcard {host} requires dns-01"
                )));
            }
        }
        if !issuer_ids.contains(certificate.issuer.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "ACME certificate {} references unknown issuer {}",
                certificate.id, certificate.issuer
            )));
        }
        if acme
            .issuers
            .iter()
            .find(|issuer| issuer.id == certificate.issuer)
            .is_some_and(|issuer| !issuer.terms_of_service_agreed)
        {
            return Err(ConfigError::Invalid(format!(
                "ACME issuer {} requires explicit terms_of_service_agreed = true",
                certificate.issuer
            )));
        }
        validate_acme_challenge(config, certificate, &provider_ids)?;
        if let Some(profile) = certificate.profile.as_deref()
            && (profile.is_empty()
                || profile.len() > 64
                || !profile
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        {
            return Err(ConfigError::Invalid(format!(
                "ACME certificate {} has an invalid profile",
                certificate.id
            )));
        }
        if !(1..=90).contains(&certificate.renew_before_days) {
            return Err(ConfigError::Invalid(format!(
                "ACME certificate {} renew_before_days is outside 1..=90",
                certificate.id
            )));
        }
    }

    if !acme.certificates.is_empty() {
        if config.tls.identity.is_none() {
            return Err(ConfigError::Invalid(
                "tls.identity is required for encrypted ACME state".into(),
            ));
        }
        if config.tls.state_encryption_recipients.is_empty()
            || config.tls.state_encryption_recipients.len() > 8
        {
            return Err(ConfigError::Invalid(
                "tls.state_encryption_recipients must contain 1..=8 recipients for ACME".into(),
            ));
        }
        for recipient in &config.tls.state_encryption_recipients {
            validate_age_recipient(recipient).map_err(|_| {
                ConfigError::Invalid("tls.state_encryption_recipients is invalid".into())
            })?;
        }
    }
    Ok(())
}

fn validate_acme_directory(issuer: &AcmeIssuerConfig) -> Result<(), ConfigError> {
    let url = &issuer.directory_url;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(ConfigError::Invalid(format!(
            "ACME issuer {} directory_url contains forbidden URL components",
            issuer.id
        )));
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    let valid_transport = url.scheme() == "https"
        || issuer.environment == AcmeEnvironment::Staging && url.scheme() == "http" && loopback;
    if !valid_transport {
        return Err(ConfigError::Invalid(format!(
            "ACME issuer {} directory_url must use HTTPS; staging permits loopback HTTP only",
            issuer.id
        )));
    }
    Ok(())
}

fn validate_acme_challenge(
    config: &Config,
    certificate: &AcmeCertificateConfig,
    provider_ids: &HashSet<&str>,
) -> Result<(), ConfigError> {
    match certificate.challenge {
        AcmeChallenge::Dns01 => {
            if certificate.challenge_listener.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "ACME certificate {} dns-01 cannot set challenge_listener",
                    certificate.id
                )));
            }
            let provider = certificate.dns_provider.as_deref().ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "ACME certificate {} dns-01 requires dns_provider",
                    certificate.id
                ))
            })?;
            if !provider_ids.contains(provider) {
                return Err(ConfigError::Invalid(format!(
                    "ACME certificate {} references unknown DNS provider {provider}",
                    certificate.id
                )));
            }
        }
        AcmeChallenge::Http01 | AcmeChallenge::TlsAlpn01 => {
            if certificate.dns_provider.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "ACME certificate {} non-DNS challenge cannot set dns_provider",
                    certificate.id
                )));
            }
            let listener_id = certificate.challenge_listener.as_deref().ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "ACME certificate {} requires challenge_listener",
                    certificate.id
                ))
            })?;
            let listener = config
                .listeners
                .iter()
                .find(|listener| listener.id == listener_id)
                .ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "ACME certificate {} references unknown challenge listener {listener_id}",
                        certificate.id
                    ))
                })?;
            let expected = if certificate.challenge == AcmeChallenge::Http01 {
                "http"
            } else {
                "https"
            };
            if listener.protocol != expected {
                return Err(ConfigError::Invalid(format!(
                    "ACME certificate {} challenge listener must use {expected}",
                    certificate.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_tcp_route(route: &RouteConfig, tls_passthrough: bool) -> Result<(), ConfigError> {
    if !route.paths.is_empty()
        || !route.path_prefixes.is_empty()
        || !route.methods.is_empty()
        || !route.headers.is_empty()
        || !route.middlewares.is_empty()
        || route.priority != 0
    {
        return Err(ConfigError::Invalid(format!(
            "TCP-family route {} cannot use HTTP matchers, middleware, or priority",
            route.id
        )));
    }
    if tls_passthrough {
        if !route.default && route.hosts.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "TLS passthrough route {} requires an SNI host or default = true",
                route.id
            )));
        }
    } else if !route.default || !route.hosts.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "plain TCP route {} must be an explicit default route",
            route.id
        )));
    }
    Ok(())
}

fn validate_upstream_policy(
    group_index: usize,
    group: &UpstreamGroupConfig,
) -> Result<(), ConfigError> {
    let field = |name: &str| format!("upstream_groups[{group_index}].{name}");
    if group.dns.max_answers == 0
        || group.dns.max_answers > 64
        || group.dns.lookup_timeout_secs == 0
        || group.dns.lookup_timeout_secs > 30
        || group.dns.min_ttl_secs == 0
        || group.dns.min_ttl_secs > group.dns.max_ttl_secs
        || group.dns.max_ttl_secs > 86_400
        || group.dns.stale_timeout_secs > 3_600
    {
        return Err(ConfigError::Invalid(format!(
            "{} contains an unsafe answer, timeout, TTL, or stale bound",
            field("dns")
        )));
    }
    if group.drain_timeout_secs == 0 || group.drain_timeout_secs > 3_600 {
        return Err(ConfigError::Invalid(format!(
            "{} is outside 1..=3600",
            field("drain_timeout_secs")
        )));
    }
    let passive = &group.passive_health;
    if passive.failure_threshold == 0
        || passive.failure_threshold > 100
        || passive.healthy_threshold == 0
        || passive.healthy_threshold > 100
        || passive.window_secs == 0
        || passive.window_secs > 3_600
        || passive.max_samples == 0
        || passive.max_samples > 1_024
        || passive.failure_threshold as usize > passive.max_samples
    {
        return Err(ConfigError::Invalid(format!(
            "{} contains an unsafe threshold, window, or sample bound",
            field("passive_health")
        )));
    }
    let retry = &group.retry;
    if retry.max_attempts == 0
        || retry.max_attempts > 5
        || retry.total_timeout_secs == 0
        || retry.total_timeout_secs > 300
        || retry.replay_body_bytes > 1024 * 1024
    {
        return Err(ConfigError::Invalid(format!(
            "{} contains an unsafe attempt, time, or replay-body bound",
            field("retry")
        )));
    }
    if let Some(health) = &group.health {
        if health.interval_secs == 0
            || health.interval_secs > 3_600
            || health.timeout_secs == 0
            || health.timeout_secs >= health.interval_secs
            || health.unhealthy_threshold == 0
            || health.unhealthy_threshold > 100
            || health.healthy_threshold == 0
            || health.healthy_threshold > 100
        {
            return Err(ConfigError::Invalid(format!(
                "{} contains an unsafe interval, timeout, or threshold",
                field("health")
            )));
        }
        match health.kind {
            HealthCheckKind::Http => {
                let method = Method::from_bytes(health.method.as_bytes()).map_err(|_| {
                    ConfigError::Invalid(format!("{}.method is invalid", field("health")))
                })?;
                if !matches!(method, Method::GET | Method::HEAD) {
                    return Err(ConfigError::Invalid(format!(
                        "{}.method must be GET or HEAD",
                        field("health")
                    )));
                }
                validate_path(
                    &format!("upstream group {} health", group.id),
                    &health.path,
                    false,
                )?;
                if health.expected_statuses.is_empty()
                    || health.expected_statuses.len() > 32
                    || health
                        .expected_statuses
                        .iter()
                        .any(|status| !(100..=599).contains(status))
                    || health
                        .expected_statuses
                        .iter()
                        .collect::<HashSet<_>>()
                        .len()
                        != health.expected_statuses.len()
                {
                    return Err(ConfigError::Invalid(format!(
                        "{}.expected_statuses must contain 1..=32 unique HTTP statuses",
                        field("health")
                    )));
                }
            }
            HealthCheckKind::Tcp => {
                if health.method != "GET" || health.path != "/" || health.expected_statuses != [200]
                {
                    return Err(ConfigError::Invalid(format!(
                        "{} TCP probes cannot configure HTTP fields",
                        field("health")
                    )));
                }
            }
        }
    }
    if let Some(circuit) = &group.circuit_breaker {
        if circuit.sample_size == 0
            || circuit.sample_size > 10_000
            || circuit.minimum_requests == 0
            || circuit.minimum_requests > circuit.sample_size
            || circuit.failure_percent == 0
            || circuit.failure_percent > 100
            || circuit.open_secs == 0
            || circuit.open_secs > 3_600
            || circuit.half_open_requests == 0
            || circuit.half_open_requests > 100
        {
            return Err(ConfigError::Invalid(format!(
                "{} contains an unsafe sample, threshold, or half-open bound",
                field("circuit_breaker")
            )));
        }
    }
    Ok(())
}

fn validate_route_matchers(route: &RouteConfig) -> Result<(), ConfigError> {
    if route.default {
        if !route.hosts.is_empty()
            || !route.paths.is_empty()
            || !route.path_prefixes.is_empty()
            || !route.methods.is_empty()
            || !route.headers.is_empty()
            || route.priority != 0
        {
            return Err(ConfigError::Invalid(format!(
                "route {} is default and cannot contain matchers or a nonzero priority",
                route.id
            )));
        }
        return Ok(());
    }

    if route.hosts.is_empty()
        && route.paths.is_empty()
        && route.methods.is_empty()
        && route.headers.is_empty()
        && (route.path_prefixes.is_empty()
            || route.path_prefixes.iter().any(|prefix| prefix == "/"))
    {
        return Err(ConfigError::Invalid(format!(
            "route {} is a catch-all and must set default = true",
            route.id
        )));
    }

    let mut hosts = HashSet::new();
    for host in &route.hosts {
        valid_certificate_host(host).map_err(|_| {
            ConfigError::Invalid(format!("route {} has invalid host {host:?}", route.id))
        })?;
        if !hosts.insert(host.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate host {host:?}",
                route.id
            )));
        }
    }

    let mut exact_paths = HashSet::new();
    for path in &route.paths {
        validate_path(&route.id, path, false)?;
        if !exact_paths.insert(path.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate exact path {path:?}",
                route.id
            )));
        }
    }

    let mut paths = HashSet::new();
    for prefix in &route.path_prefixes {
        validate_path(&route.id, prefix, true)?;
        if !paths.insert(prefix.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate path prefix {prefix:?}",
                route.id
            )));
        }
    }

    let mut methods = HashSet::new();
    for method in &route.methods {
        let parsed = Method::from_bytes(method.as_bytes()).map_err(|_| {
            ConfigError::Invalid(format!("route {} has invalid method {method:?}", route.id))
        })?;
        if parsed.as_str() != method
            || method.bytes().any(|byte| byte.is_ascii_lowercase())
            || parsed == Method::CONNECT
        {
            return Err(ConfigError::Invalid(format!(
                "route {} method {method:?} is not canonical or supported",
                route.id
            )));
        }
        if !methods.insert(method.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate method {method:?}",
                route.id
            )));
        }
    }

    let mut headers = HashSet::new();
    for predicate in &route.headers {
        let name = HeaderName::from_bytes(predicate.name.as_bytes()).map_err(|_| {
            ConfigError::Invalid(format!(
                "route {} has invalid header name {:?}",
                route.id, predicate.name
            ))
        })?;
        if let Some(value) = &predicate.value {
            if value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(ConfigError::Invalid(format!(
                    "route {} header {} value exceeds {MAX_HEADER_VALUE_BYTES} bytes",
                    route.id, predicate.name
                )));
            }
            HeaderValue::try_from(value.as_str()).map_err(|_| {
                ConfigError::Invalid(format!(
                    "route {} header {} has an invalid value",
                    route.id, predicate.name
                ))
            })?;
        }
        if name.as_str() != predicate.name || prohibited_route_header(&name) {
            return Err(ConfigError::Invalid(format!(
                "route {} header {:?} is not canonical or routable",
                route.id, predicate.name
            )));
        }
        if !headers.insert(name) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate header predicate {:?}",
                route.id, predicate.name
            )));
        }
    }
    Ok(())
}

fn validate_path(route_id: &str, path: &str, prefix: bool) -> Result<(), ConfigError> {
    let valid = !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path.is_ascii()
        && path.starts_with('/')
        && !path.contains('%')
        && !path.contains('\\')
        && !path.contains('?')
        && !path.contains('#')
        && !path.contains("//")
        && (!prefix || path == "/" || !path.ends_with('/'))
        && !path.split('/').any(|segment| matches!(segment, "." | ".."));
    if !valid {
        return Err(ConfigError::Invalid(format!(
            "route {route_id} has non-canonical path {path:?}"
        )));
    }
    Ok(())
}

fn prohibited_route_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "content-length"
            | "host"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn validate_unique_strings(
    route_id: &str,
    field: &str,
    values: &[String],
) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {route_id} contains duplicate {field} reference {value:?}"
            )));
        }
    }
    Ok(())
}

/// Validate one resolved upstream address against the configured egress policy.
pub fn validate_egress_ip(
    ip: IpAddr,
    allowed: &[IpNet],
    denied: &[IpNet],
) -> Result<(), &'static str> {
    if ip.is_unspecified() || ip.is_multicast() {
        return Err("unspecified and multicast addresses are forbidden");
    }
    let link_local = match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    };
    if link_local {
        return Err("link-local addresses are forbidden");
    }
    if denied.iter().any(|network| network.contains(&ip)) {
        return Err("address is explicitly denied");
    }
    let private = match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00 || ip.is_loopback(),
    };
    if private && !allowed.iter().any(|network| network.contains(&ip)) {
        return Err("private or loopback address requires allowed_cidrs");
    }
    Ok(())
}

fn valid_upstream_host(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 253 || value != value.to_ascii_lowercase() {
        return Err("name must be bounded lowercase ASCII");
    }
    if value.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err("name contains an invalid DNS label");
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

fn valid_certificate_host(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.to_ascii_lowercase()
        || value.ends_with('.')
        || value.contains(':')
    {
        return Err(ConfigError::Invalid(format!(
            "invalid certificate host {value:?}"
        )));
    }
    let name = value.strip_prefix("*.").unwrap_or(value);
    if value.contains('*') && !value.starts_with("*.") || name.split('.').count() < 2 {
        return Err(ConfigError::Invalid(format!(
            "invalid certificate wildcard {value:?}"
        )));
    }
    if name.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err(ConfigError::Invalid(format!(
            "invalid certificate host {value:?}"
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
                certificates: vec![],
            }],
            tls: TlsConfig::default(),
            certificates: vec![],
            acme: AcmeConfig::default(),
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![],
            middlewares: BTreeMap::new(),
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
        assert!(
            validate_egress_ip(metadata, &["169.254.0.0/16".parse().expect("CIDR")], &[]).is_err()
        );
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
}
