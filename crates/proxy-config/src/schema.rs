use super::*;

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
    /// Public data-plane listeners.
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
    /// Explicit bounded service-discovery providers.
    #[serde(default)]
    pub providers: Vec<provider::ProviderConfig>,
    /// Middleware definitions.
    #[serde(default)]
    pub middlewares: BTreeMap<String, MiddlewareConfig>,
    /// Routes.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// Administrative settings.
    #[serde(default)]
    pub admin: AdminConfig,
    /// Logs, metrics, and optional trace export.
    #[serde(default)]
    pub observability: ObservabilityConfig,
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
    /// Unique fleet node allowed to create accounts and renew certificates.
    pub renewal_owner: Option<String>,
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
            renewal_owner: None,
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
    pub(crate) fn id(&self) -> &str {
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
    /// Maximum concurrent requests or raw connections for the group.
    #[serde(default = "default_upstream_max_in_flight")]
    pub max_in_flight: usize,
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
            max_in_flight: default_upstream_max_in_flight(),
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
    /// Maximum accepted A/AAAA answers per lookup.
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

pub(crate) fn default_drain_timeout_secs() -> u64 {
    30
}

pub(crate) fn default_upstream_max_in_flight() -> usize {
    1_024
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
        /// Trusted key source and fixed pipeline stage.
        #[serde(default)]
        key: RateLimitKey,
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
    /// Non-queuing route and trusted-client in-flight request limit.
    InFlightLimit {
        /// Maximum concurrent requests across all clients.
        max_requests: usize,
        /// Maximum concurrent requests for one trusted client address.
        max_per_client: usize,
        /// Rejection status: `429` or `503`.
        #[serde(default = "default_in_flight_status")]
        status: u16,
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
    /// Exact-origin CORS policy.
    Cors {
        /// Exact canonical origins, or a single `*` without credentials.
        origins: Vec<String>,
        /// Allowed request methods.
        methods: Vec<String>,
        /// Allowed non-simple request headers.
        #[serde(default)]
        headers: Vec<String>,
        /// Emit `Access-Control-Allow-Credentials: true`.
        #[serde(default)]
        allow_credentials: bool,
        /// Bounded preflight cache duration.
        #[serde(default)]
        max_age_secs: u64,
    },
    /// TLS-only HTTP Basic authentication backed by Argon2id hashes.
    BasicAuth {
        /// Bounded challenge realm.
        realm: String,
        /// Username to Argon2id PHC secret reference.
        users: BTreeMap<String, String>,
        /// Maximum simultaneous password verifications.
        #[serde(default = "default_auth_verifications")]
        max_concurrent_verifications: usize,
        /// Verification deadline in seconds.
        #[serde(default = "default_auth_timeout_secs")]
        timeout_secs: u64,
    },
    /// Fail-closed authentication subrequest to a configured HTTP upstream.
    ForwardAuth {
        /// Existing HTTP-family upstream group used only for authentication.
        upstream_group: String,
        /// Canonical authentication endpoint path.
        path: String,
        /// Client headers explicitly copied to the authentication request.
        #[serde(default)]
        request_headers: Vec<String>,
        /// Authentication response headers copied to the application request.
        response_headers: Vec<String>,
        /// Required response header used as the bounded principal identifier.
        principal_header: String,
        /// Exact hosts allowed in authentication redirects. Relative redirects remain allowed.
        #[serde(default)]
        redirect_hosts: Vec<String>,
        /// Complete authentication subrequest deadline in seconds.
        #[serde(default = "default_forward_auth_timeout_secs")]
        timeout_secs: u64,
    },
    /// Post-authentication path rewrite. Query parameters are preserved.
    Rewrite {
        /// Optional segment-aware prefix to replace. Omit for an exact replacement.
        #[serde(default)]
        from_prefix: Option<String>,
        /// Canonical replacement path or prefix.
        to: String,
    },
    /// Typed request and response header mutations.
    HeaderMutation {
        /// Replace request headers.
        #[serde(default)]
        request_set: BTreeMap<String, String>,
        /// Append request header values.
        #[serde(default)]
        request_add: BTreeMap<String, Vec<String>>,
        /// Remove request headers.
        #[serde(default)]
        request_remove: Vec<String>,
        /// Replace response headers.
        #[serde(default)]
        response_set: BTreeMap<String, String>,
        /// Append response header values.
        #[serde(default)]
        response_add: BTreeMap<String, Vec<String>>,
        /// Remove response headers.
        #[serde(default)]
        response_remove: Vec<String>,
    },
    /// Fixed terminal maintenance response.
    Maintenance {
        /// HTTP status, limited to 200 or 503.
        #[serde(default = "default_maintenance_status")]
        status: u16,
        /// Bounded static response body.
        body: String,
        /// `text/plain; charset=utf-8` or `text/html; charset=utf-8`.
        #[serde(default = "default_maintenance_content_type")]
        content_type: String,
        /// Optional Retry-After delta seconds.
        #[serde(default)]
        retry_after_secs: Option<u64>,
        /// Run authentication before returning maintenance content.
        #[serde(default)]
        authenticated: bool,
    },
    /// Static replacement for selected upstream 5xx responses.
    CustomError {
        /// Exact upstream response statuses to replace.
        statuses: Vec<u16>,
        /// Bounded static response body with no request interpolation.
        body: String,
        /// `text/plain; charset=utf-8` or `text/html; charset=utf-8`.
        #[serde(default = "default_maintenance_content_type")]
        content_type: String,
    },
    /// Streaming response compression with conservative exclusions.
    Compression {
        /// Preference-ordered enabled encodings.
        encodings: Vec<CompressionEncoding>,
        /// Allowed exact media types, excluding parameters.
        content_types: Vec<String>,
        /// Minimum declared response size.
        #[serde(default = "default_compression_min_bytes")]
        min_bytes: usize,
        /// Maximum concurrent encoders for this policy.
        #[serde(default = "default_compression_concurrency")]
        max_concurrent: usize,
        /// Explicitly permit compression after authentication.
        #[serde(default)]
        allow_authenticated: bool,
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

/// Trusted rate-limit key source.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    /// Immediate/trusted-chain client address at stage 5.
    #[default]
    ClientIp,
    /// Authenticated principal at stage 9.
    Principal,
}

/// Supported response content encodings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionEncoding {
    /// RFC 9110 gzip content coding.
    Gzip,
    /// RFC 7932 Brotli content coding.
    Brotli,
}

fn default_rate_limit_keys() -> usize {
    10_000
}

fn default_rate_limit_idle_secs() -> u64 {
    300
}

fn default_in_flight_status() -> u16 {
    503
}

fn default_auth_verifications() -> usize {
    8
}

fn default_auth_timeout_secs() -> u64 {
    5
}

fn default_forward_auth_timeout_secs() -> u64 {
    3
}

fn default_maintenance_status() -> u16 {
    503
}

fn default_maintenance_content_type() -> String {
    "text/plain; charset=utf-8".into()
}

fn default_compression_min_bytes() -> usize {
    1_024
}

fn default_compression_concurrency() -> usize {
    4
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Absolute Unix socket path. Omit to use `<state_dir>/admin/admin.sock`.
    pub unix_socket: Option<String>,
    /// Optional peer-UID allowlist. Empty relies on socket filesystem access.
    pub allowed_uids: Vec<u32>,
    /// Secret reference for the durable audit HMAC key.
    pub audit_key: Option<String>,
    /// Maximum JSON or TOML request body bytes.
    pub max_body_bytes: usize,
    /// Maximum concurrent administrative requests.
    pub max_in_flight: usize,
    /// Maximum concurrent Argon2 token verifications.
    pub max_auth_in_flight: usize,
    /// Per-request deadline in seconds.
    pub request_timeout_secs: u64,
    /// Per-principal request rate.
    pub requests_per_second: u32,
    /// Per-principal request burst.
    pub burst: u32,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            unix_socket: None,
            allowed_uids: Vec::new(),
            audit_key: None,
            max_body_bytes: 1024 * 1024,
            max_in_flight: 16,
            max_auth_in_flight: 4,
            request_timeout_secs: 10,
            requests_per_second: 20,
            burst: 40,
        }
    }
}

/// Bounded process telemetry policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// Emit structured access events.
    pub access_log: bool,
    /// Access events retained per million completed requests.
    pub access_log_sample_per_million: u32,
    /// Expose OpenMetrics on the private administrative socket.
    pub metrics: bool,
    /// Optional OTLP/HTTP protobuf trace exporter.
    pub otlp_traces: Option<OtlpTraceConfig>,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            access_log: true,
            access_log_sample_per_million: 1_000_000,
            metrics: true,
            otlp_traces: None,
        }
    }
}

/// Bounded OTLP trace-export configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpTraceConfig {
    /// Full OTLP/HTTP protobuf traces endpoint.
    pub endpoint: Url,
    /// Locally sampled root traces per million requests.
    pub sample_per_million: u32,
    /// Maximum queued spans waiting for export.
    pub max_queue_size: usize,
    /// Maximum spans in one export batch.
    pub max_export_batch_size: usize,
    /// Export attempt timeout in seconds.
    pub export_timeout_secs: u64,
}
