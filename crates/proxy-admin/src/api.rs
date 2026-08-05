//! Versioned high-level administration contracts.

use std::{collections::BTreeSet, fmt, net::IpAddr, path::Path, str::FromStr};

use aegisproxy_config::{
    MAX_PATH_BYTES, normalize_exact_host, provider::ProviderScheme, valid_route_path,
    validate_exact_host, validate_upstream_hostname,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Current high-level administration contract version.
pub const API_VERSION: &str = "v1";

const MAX_OBJECT_ID_BYTES: usize = 64;
const MAX_DOMAIN_BYTES: usize = 253;
/// Maximum exact domains accepted by one typed Proxy Host.
pub const MAX_PROXY_HOST_DOMAINS: usize = 32;
const MAX_PROXY_HOST_DOMAIN_BYTES: usize = MAX_PROXY_HOST_DOMAINS * MAX_DOMAIN_BYTES;
/// Maximum custom locations accepted by one typed Proxy Host.
pub const MAX_PROXY_HOST_LOCATIONS: usize = 16;
const MAX_PROXY_HOST_LOCATION_BYTES: usize =
    MAX_PROXY_HOST_LOCATIONS * (MAX_OBJECT_ID_BYTES + MAX_PATH_BYTES + MAX_FORWARD_HOST_BYTES);
const MAX_FORWARD_HOST_BYTES: usize = 253;
const MAX_ACCESS_POLICY_SHARES: usize = 128;
const MAX_ACCESS_POLICY_MIDDLEWARES: usize = 64;
const MAX_CERTIFICATE_SHARES: usize = 128;
const MAX_SNI_HOSTS: usize = 64;

/// Exact supported high-level administration contract version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiVersion;

impl Serialize for ApiVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(API_VERSION)
    }
}

impl<'de> Deserialize<'de> for ApiVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == API_VERSION {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(ContractError::UnsupportedVersion))
        }
    }
}

/// Stable control-plane object identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ObjectId(String);

impl ObjectId {
    /// Return identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ObjectId").field(&self.0).finish()
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ObjectId {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > MAX_OBJECT_ID_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
            || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        {
            return Err(ContractError::InvalidObjectId);
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for ObjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Common immutable identity and ownership fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectMetadata {
    /// Stable object identifier.
    pub id: ObjectId,
    /// Stable owner principal or tenant identifier.
    pub owner_id: ObjectId,
}

/// Versioned high-level API object envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiObject<T> {
    /// Exact contract version; currently `v1`.
    pub api_version: ApiVersion,
    /// Stable object metadata.
    pub metadata: ObjectMetadata,
    /// Typed object-specific desired state.
    pub spec: T,
}

/// Reference to a stored access-policy object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AccessPolicyRef(ObjectId);

impl AccessPolicyRef {
    /// Return referenced object ID.
    #[must_use]
    pub fn id(&self) -> &ObjectId {
        &self.0
    }
}

/// Reference to one existing canonical middleware definition.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MiddlewareRef(String);

impl MiddlewareRef {
    /// Return referenced middleware ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for MiddlewareRef {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > 63
            || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(ContractError::InvalidMiddlewareReference);
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for MiddlewareRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Secret-free ownership binding for an existing canonical access-policy pipeline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicySpec {
    /// Whether references to this policy may compile.
    pub enabled: bool,
    /// Other owners explicitly allowed to reference this policy.
    #[serde(default)]
    pub shared_with: Vec<ObjectId>,
    /// Existing canonical access-control middleware definitions.
    pub middlewares: Vec<MiddlewareRef>,
}

/// Reference to an existing canonical certificate identity.
pub type CertificateRef = ObjectId;

/// Secret-free ownership binding for an existing certificate identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateSpec {
    /// Whether automatic HTTPS may select this certificate.
    pub enabled: bool,
    /// Other owners explicitly allowed to use this certificate.
    #[serde(default)]
    pub shared_with: Vec<ObjectId>,
    /// Existing configured certificate identity; never key material.
    pub certificate_ref: CertificateRef,
}

impl CertificateSpec {
    /// Validate bounded ownership shape.
    pub fn validate_shape(&self, owner_id: &ObjectId) -> Result<(), ContractError> {
        if self.shared_with.len() > MAX_CERTIFICATE_SHARES {
            return Err(ContractError::InvalidCertificate);
        }
        let shared = self
            .shared_with
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if shared.len() != self.shared_with.len() || shared.contains(owner_id) {
            return Err(ContractError::InvalidCertificate);
        }
        Ok(())
    }
}

impl AccessPolicySpec {
    /// Validate bounded ownership and reference shape.
    pub fn validate_shape(&self, owner_id: &ObjectId) -> Result<(), ContractError> {
        if self.shared_with.len() > MAX_ACCESS_POLICY_SHARES
            || self.middlewares.is_empty()
            || self.middlewares.len() > MAX_ACCESS_POLICY_MIDDLEWARES
        {
            return Err(ContractError::InvalidAccessPolicy);
        }
        let shared = self
            .shared_with
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let middlewares = self
            .middlewares
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if shared.len() != self.shared_with.len()
            || shared.contains(owner_id)
            || middlewares.len() != self.middlewares.len()
        {
            return Err(ContractError::InvalidAccessPolicy);
        }
        Ok(())
    }
}

/// Forward protocol exposed by common Proxy Host workflow.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProtocol {
    /// Cleartext HTTP upstream.
    Http,
    /// Verified TLS HTTP upstream.
    Https,
}

/// Desired automatic-HTTPS behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticHttps {
    /// Keep host HTTP-only.
    Disabled,
    /// Request managed HTTPS through approved certificate automation.
    Managed,
}

/// Common user-facing Proxy Host desired state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProxyHostSpec {
    /// Ordered canonical public DNS names. The first is the display/primary domain.
    pub domains: Vec<DomainName>,
    /// Configured forward host name or IP address.
    pub forward_host: String,
    /// Configured forward TCP port.
    pub forward_port: u16,
    /// HTTP transport to forward destination.
    pub forward_protocol: ForwardProtocol,
    /// Managed certificate and redirect preference.
    pub automatic_https: AutomaticHttps,
    /// Optional stored access-policy reference.
    pub access_policy_ref: Option<AccessPolicyRef>,
    /// Ordered bounded custom routes; order is display-only.
    pub locations: Vec<ProxyLocation>,
    /// Whether object contributes to active configuration.
    pub enabled: bool,
}

/// Supported custom-location path matcher.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyLocationMatch {
    /// Match only the exact canonical request path.
    Exact,
    /// Match the canonical path and descendants on a segment boundary.
    Prefix,
}

/// Embedded typed custom location owned and activated with its Proxy Host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyLocation {
    /// Stable identity independent of path and display order.
    pub id: ObjectId,
    /// Exact or segment-aware prefix matcher.
    pub match_kind: ProxyLocationMatch,
    /// Canonical case-sensitive request path.
    pub path: String,
    /// Explicit location upstream host or IP address.
    pub forward_host: String,
    /// Explicit location upstream TCP port.
    pub forward_port: u16,
    /// Explicit location upstream transport.
    pub forward_protocol: ForwardProtocol,
    /// Optional policy override; absent inherits the parent policy.
    pub access_policy_ref: Option<AccessPolicyRef>,
    /// Whether this location contributes runtime routes.
    pub enabled: bool,
}

impl ProxyLocation {
    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.path == "/"
            || !valid_route_path(&self.path, self.match_kind == ProxyLocationMatch::Prefix)
        {
            return Err(ContractError::InvalidProxyLocation);
        }
        if self.forward_host.is_empty()
            || self.forward_host.len() > MAX_FORWARD_HOST_BYTES
            || (self.forward_host.parse::<IpAddr>().is_err()
                && validate_upstream_hostname(&self.forward_host).is_err())
            || self.forward_port == 0
        {
            return Err(ContractError::InvalidProxyLocation);
        }
        Ok(())
    }
}

/// One normalized exact DNS name used by a typed Proxy Host.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DomainName(String);

impl DomainName {
    /// Return the canonical lowercase ASCII name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for DomainName {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let domain = normalize_exact_host(value).map_err(|_| ContractError::InvalidDomain)?;
        if domain.len() > MAX_DOMAIN_BYTES {
            return Err(ContractError::InvalidDomain);
        }
        Ok(Self(domain))
    }
}

impl<'de> Deserialize<'de> for DomainName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyHostSpecInput {
    domain: Option<String>,
    domains: Option<Vec<String>>,
    forward_host: String,
    forward_port: u16,
    forward_protocol: ForwardProtocol,
    automatic_https: AutomaticHttps,
    access_policy_ref: Option<AccessPolicyRef>,
    #[serde(default)]
    locations: Vec<ProxyLocation>,
    enabled: bool,
}

impl<'de> Deserialize<'de> for ProxyHostSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = ProxyHostSpecInput::deserialize(deserializer)?;
        let raw_domains = match (input.domain, input.domains) {
            (Some(domain), None) => vec![domain],
            (None, Some(domains)) => domains,
            _ => return Err(serde::de::Error::custom(ContractError::InvalidDomain)),
        };
        if raw_domains.is_empty()
            || raw_domains.len() > MAX_PROXY_HOST_DOMAINS
            || raw_domains.iter().map(String::len).sum::<usize>() > MAX_PROXY_HOST_DOMAIN_BYTES
        {
            return Err(serde::de::Error::custom(ContractError::InvalidDomain));
        }
        let domains = raw_domains
            .into_iter()
            .map(|domain| domain.parse())
            .collect::<Result<Vec<DomainName>, ContractError>>()
            .map_err(serde::de::Error::custom)?;
        let spec = Self {
            domains,
            forward_host: input.forward_host,
            forward_port: input.forward_port,
            forward_protocol: input.forward_protocol,
            automatic_https: input.automatic_https,
            access_policy_ref: input.access_policy_ref,
            locations: input.locations,
            enabled: input.enabled,
        };
        spec.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(spec)
    }
}

/// Raw stream-listener protocol exposed by the typed control plane.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamProtocol {
    /// Plain TCP with one default route.
    Tcp,
    /// TLS ClientHello SNI passthrough using exact host names.
    TlsPassthrough,
}

/// Strict typed Stream Host desired state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHostSpec {
    /// Port bound on the unique public HTTP listener's IP.
    pub listen_port: u16,
    /// Plain TCP or exact-SNI TLS passthrough.
    pub protocol: StreamProtocol,
    /// Configured forward host name or IP address.
    pub forward_host: String,
    /// Configured forward TCP port.
    pub forward_port: u16,
    /// Exact canonical ASCII SNI names; TLS passthrough only.
    #[serde(default)]
    pub sni_hosts: Vec<String>,
    /// Whether this object contributes runtime resources.
    pub enabled: bool,
}

impl StreamHostSpec {
    /// Validate the strict transport contract before canonical compilation.
    pub fn validate_shape(&self) -> Result<(), ContractError> {
        if self.listen_port == 0
            || self.forward_port == 0
            || self.forward_host.is_empty()
            || self.forward_host.len() > MAX_FORWARD_HOST_BYTES
            || (self.forward_host.parse::<IpAddr>().is_err()
                && validate_upstream_hostname(&self.forward_host).is_err())
            || self.sni_hosts.len() > MAX_SNI_HOSTS
        {
            return Err(ContractError::InvalidStreamHost);
        }
        match self.protocol {
            StreamProtocol::Tcp if !self.sni_hosts.is_empty() => {
                return Err(ContractError::InvalidStreamHost);
            }
            StreamProtocol::TlsPassthrough if self.sni_hosts.is_empty() => {
                return Err(ContractError::InvalidStreamHost);
            }
            _ => {}
        }
        let hosts = self
            .sni_hosts
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if hosts.len() != self.sni_hosts.len()
            || self.sni_hosts.iter().any(|host| {
                host.is_empty()
                    || host.len() > MAX_DOMAIN_BYTES
                    || !host.is_ascii()
                    || host.contains('*')
                    || host.ends_with('.')
                    || host.parse::<IpAddr>().is_ok()
                    || validate_exact_host(host).is_err()
            })
        {
            return Err(ContractError::InvalidStreamHost);
        }
        Ok(())
    }
}

/// Strict file or DNS A/AAAA discovery desired state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiscoverySourceSpec {
    /// Bounded local file endpoint source.
    File {
        /// Explicit activation.
        enabled: bool,
        /// Existing upstream group owned by this source.
        upstream_group: ObjectId,
        /// Absolute bounded provider document path.
        path: String,
        /// Fixed endpoint transport.
        scheme: ProviderScheme,
        /// Exact HTTPS server name.
        server_name: Option<String>,
        /// Refresh interval.
        refresh_secs: u64,
        /// Stable-file debounce period.
        debounce_millis: u64,
        /// Maximum last-valid age.
        stale_after_secs: u64,
        /// Maximum accepted endpoints.
        max_endpoints: usize,
    },
    /// Bounded DNS A/AAAA endpoint source.
    Dns {
        /// Explicit activation.
        enabled: bool,
        /// Existing upstream group owned by this source.
        upstream_group: ObjectId,
        /// Canonical A/AAAA hostname.
        hostname: String,
        /// Fixed destination port.
        port: u16,
        /// Fixed endpoint transport.
        scheme: ProviderScheme,
        /// Exact HTTPS server name.
        server_name: Option<String>,
        /// Weight assigned to each answer.
        weight: u32,
        /// Refresh interval.
        refresh_secs: u64,
        /// Maximum last-valid age.
        stale_after_secs: u64,
        /// Maximum accepted A/AAAA answers.
        max_answers: usize,
    },
}

impl DiscoverySourceSpec {
    /// Validate fields that do not require canonical configuration context.
    pub fn validate_shape(&self) -> Result<(), ContractError> {
        let (refresh, stale, scheme, server_name) = match self {
            Self::File {
                path,
                scheme,
                server_name,
                refresh_secs,
                debounce_millis,
                stale_after_secs,
                max_endpoints,
                ..
            } => {
                let path_value = Path::new(path);
                if path.is_empty()
                    || path.len() > 4_096
                    || !path_value.is_absolute()
                    || path_value.file_name().is_none()
                    || path.contains(['$', '~'])
                    || path.bytes().any(|byte| byte.is_ascii_control())
                    || path_value
                        .components()
                        .any(|component| component == std::path::Component::ParentDir)
                    || !(50..=5_000).contains(debounce_millis)
                    || !(1..=256).contains(max_endpoints)
                {
                    return Err(ContractError::InvalidDiscoverySource);
                }
                (*refresh_secs, *stale_after_secs, *scheme, server_name)
            }
            Self::Dns {
                hostname,
                port,
                scheme,
                server_name,
                weight,
                refresh_secs,
                stale_after_secs,
                max_answers,
                ..
            } => {
                if hostname.parse::<IpAddr>().is_ok()
                    || validate_upstream_hostname(hostname).is_err()
                    || *port == 0
                    || !(1..=10_000).contains(weight)
                    || !(1..=64).contains(max_answers)
                {
                    return Err(ContractError::InvalidDiscoverySource);
                }
                (*refresh_secs, *stale_after_secs, *scheme, server_name)
            }
        };
        if !(1..=300).contains(&refresh)
            || stale < refresh
            || stale > 86_400
            || match scheme {
                ProviderScheme::Https => server_name.as_deref().is_none_or(|name| {
                    name.starts_with("*.") || validate_exact_host(name).is_err()
                }),
                ProviderScheme::Http | ProviderScheme::Tcp => server_name.is_some(),
            }
        {
            return Err(ContractError::InvalidDiscoverySource);
        }
        Ok(())
    }
}

impl ProxyHostSpec {
    /// Return the first user-visible domain used in bounded summaries.
    #[must_use]
    pub fn primary_domain(&self) -> Option<&DomainName> {
        self.domains.first()
    }

    /// Validate only the bounded normalized domain collection.
    pub fn validate_domains(&self) -> Result<(), ContractError> {
        let domains = self.domains.iter().collect::<BTreeSet<_>>();
        if self.domains.is_empty()
            || self.domains.len() > MAX_PROXY_HOST_DOMAINS
            || domains.len() != self.domains.len()
            || self
                .domains
                .iter()
                .map(|domain| domain.as_str().len())
                .sum::<usize>()
                > MAX_PROXY_HOST_DOMAIN_BYTES
            || self.domains.iter().any(|domain| {
                domain.as_str().len() > MAX_DOMAIN_BYTES
                    || validate_exact_host(domain.as_str()).is_err()
            })
        {
            return Err(ContractError::InvalidDomain);
        }
        Ok(())
    }

    /// Validate bounded contract shape before canonical configuration compilation.
    pub fn validate_shape(&self) -> Result<(), ContractError> {
        self.validate_domains()?;
        let location_ids = self
            .locations
            .iter()
            .map(|location| &location.id)
            .collect::<BTreeSet<_>>();
        let location_paths = self
            .locations
            .iter()
            .map(|location| location.path.as_str())
            .collect::<BTreeSet<_>>();
        if self.locations.len() > MAX_PROXY_HOST_LOCATIONS
            || location_ids.len() != self.locations.len()
            || location_paths.len() != self.locations.len()
            || self
                .locations
                .iter()
                .map(|location| {
                    location.id.as_str().len() + location.path.len() + location.forward_host.len()
                })
                .sum::<usize>()
                > MAX_PROXY_HOST_LOCATION_BYTES
            || self
                .locations
                .iter()
                .any(|location| location.validate_shape().is_err())
        {
            return Err(ContractError::InvalidProxyLocation);
        }
        if self.forward_host.is_empty()
            || self.forward_host.len() > MAX_FORWARD_HOST_BYTES
            || (self.forward_host.parse::<IpAddr>().is_err()
                && validate_upstream_hostname(&self.forward_host).is_err())
        {
            return Err(ContractError::InvalidForwardHost);
        }
        if self.forward_port == 0 {
            return Err(ContractError::InvalidForwardPort);
        }
        Ok(())
    }
}

/// Stable high-level contract validation error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    /// Object ID is empty, too long, non-canonical, or begins with a non-letter.
    #[error("invalid object identifier")]
    InvalidObjectId,
    /// Contract version is unsupported.
    #[error("unsupported API version")]
    UnsupportedVersion,
    /// Domain field violates its structural bound.
    #[error("invalid proxy host domain")]
    InvalidDomain,
    /// Forward host field violates its structural bound.
    #[error("invalid forward host")]
    InvalidForwardHost,
    /// Forward port is zero.
    #[error("invalid forward port")]
    InvalidForwardPort,
    /// Embedded custom location violates its bounded typed contract.
    #[error("invalid proxy location")]
    InvalidProxyLocation,
    /// Access policy is empty, duplicated, self-shared, or exceeds a fixed bound.
    #[error("invalid access policy")]
    InvalidAccessPolicy,
    /// Middleware reference is malformed or non-canonical.
    #[error("invalid middleware reference")]
    InvalidMiddlewareReference,
    /// Certificate ownership is duplicated, self-shared, or exceeds its fixed bound.
    #[error("invalid certificate ownership")]
    InvalidCertificate,
    /// Stream Host transport, host, port, or SNI shape is invalid.
    #[error("invalid stream host")]
    InvalidStreamHost,
    /// Discovery Source variant or bounded provider field is invalid.
    #[error("invalid discovery source")]
    InvalidDiscoverySource,
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT: &str = r#"{
        "api_version":"v1",
        "metadata":{"id":"proxy-home","owner_id":"admin"},
        "spec":{
            "domain":"home.example.test",
            "forward_host":"10.0.0.8",
            "forward_port":8080,
            "forward_protocol":"http",
            "automatic_https":"managed",
            "access_policy_ref":"private-lan",
            "enabled":true
        }
    }"#;

    #[test]
    fn proxy_host_contract_is_versioned_strict_and_round_trips() {
        let object: ApiObject<ProxyHostSpec> = serde_json::from_str(OBJECT).expect("valid object");
        assert_eq!(object.api_version, ApiVersion);
        object.spec.validate_shape().expect("valid shape");
        assert_eq!(object.metadata.id.as_str(), "proxy-home");
        assert_eq!(
            object
                .spec
                .access_policy_ref
                .as_ref()
                .map(AccessPolicyRef::id)
                .map(ObjectId::as_str),
            Some("private-lan")
        );
        let encoded = serde_json::to_string(&object).expect("serialize object");
        assert!(encoded.contains("\"domains\":[\"home.example.test\"]"));
        assert!(!encoded.contains("\"domain\":"));
        let decoded: ApiObject<ProxyHostSpec> =
            serde_json::from_str(&encoded).expect("round trip object");
        assert_eq!(decoded, object);
    }

    #[test]
    fn contract_rejects_unknown_fields_versions_and_bad_ids() {
        let unknown = OBJECT.replace("\"enabled\":true", "\"enabled\":true,\"raw\":{}");
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&unknown).is_err());

        let future = OBJECT.replace("\"v1\"", "\"v2\"");
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&future).is_err());

        let bad_id = OBJECT.replace("proxy-home", "../proxy-home");
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&bad_id).is_err());

        let unsupported_protocol = OBJECT.replace("\"http\"", "\"ftp\"");
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&unsupported_protocol).is_err());
    }

    #[test]
    fn proxy_host_contract_contains_no_secret_or_bypass_field() {
        let object: serde_json::Value = serde_json::from_str(OBJECT).expect("valid JSON");
        let encoded = serde_json::to_string(&object).expect("serialize JSON");
        for forbidden in [
            "secret",
            "password",
            "private_key",
            "raw_config",
            "insecure_skip_verify",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn proxy_host_shape_requires_canonical_domain_and_upstream() {
        let mut object: ApiObject<ProxyHostSpec> =
            serde_json::from_str(OBJECT).expect("valid object");
        for domain in ["*.example.test", "127.0.0.1"] {
            assert!(domain.parse::<DomainName>().is_err());
        }
        assert_eq!(
            "Example.test."
                .parse::<DomainName>()
                .expect("normalized")
                .as_str(),
            "example.test"
        );
        object.spec.domains = vec!["example.test".parse().expect("domain")];
        object.spec.forward_host = "bad_host".into();
        assert_eq!(
            object.spec.validate_shape(),
            Err(ContractError::InvalidForwardHost)
        );
    }

    #[test]
    fn proxy_host_domains_normalize_and_remain_bounded_and_unambiguous() {
        let plural = OBJECT.replace(
            "\"domain\":\"home.example.test\"",
            "\"domains\":[\"Example.COM.\",\"täst.example\"]",
        );
        let object: ApiObject<ProxyHostSpec> =
            serde_json::from_str(&plural).expect("plural domains");
        assert_eq!(
            object
                .spec
                .domains
                .iter()
                .map(DomainName::as_str)
                .collect::<Vec<_>>(),
            ["example.com", "xn--tst-qla.example"]
        );

        let duplicate = OBJECT.replace(
            "\"domain\":\"home.example.test\"",
            "\"domains\":[\"Example.COM\",\"example.com.\"]",
        );
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&duplicate).is_err());
        let idna_duplicate = OBJECT.replace(
            "\"domain\":\"home.example.test\"",
            "\"domains\":[\"täst.example\",\"xn--tst-qla.example\"]",
        );
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&idna_duplicate).is_err());
        for invalid in [
            "https://example.test",
            "example.test:443",
            "example.test/path",
            "user@example.test",
            " bad.example.test",
            "*.example.test",
            "127.0.0.1",
        ] {
            let value = OBJECT.replace("home.example.test", invalid);
            assert!(
                serde_json::from_str::<ApiObject<ProxyHostSpec>>(&value).is_err(),
                "accepted {invalid:?}"
            );
        }
        let ambiguous = OBJECT.replace(
            "\"domain\":\"home.example.test\"",
            "\"domain\":\"home.example.test\",\"domains\":[\"other.example.test\"]",
        );
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&ambiguous).is_err());
        let oversized = OBJECT.replace(
            "\"domain\":\"home.example.test\"",
            &format!(
                "\"domains\":{}",
                serde_json::to_string(&vec!["a.example.test"; MAX_PROXY_HOST_DOMAINS + 1])
                    .expect("domains")
            ),
        );
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&oversized).is_err());
    }

    #[test]
    fn proxy_locations_are_bounded_strict_and_use_canonical_paths() {
        let with_locations = OBJECT.replace(
            "\"access_policy_ref\":\"private-lan\"",
            r#""access_policy_ref":"private-lan","locations":[
                {"id":"loc-api","match_kind":"prefix","path":"/api","forward_host":"api.internal","forward_port":9000,"forward_protocol":"http","access_policy_ref":null,"enabled":true},
                {"id":"loc-health","match_kind":"exact","path":"/health/","forward_host":"127.0.0.1","forward_port":9001,"forward_protocol":"https","access_policy_ref":"private-lan","enabled":false}
            ]"#,
        );
        let object: ApiObject<ProxyHostSpec> =
            serde_json::from_str(&with_locations).expect("valid locations");
        assert_eq!(object.spec.locations.len(), 2);
        assert_eq!(object.spec.locations[0].path, "/api");
        assert_eq!(
            object.spec.locations[1].match_kind,
            ProxyLocationMatch::Exact
        );

        for invalid in [
            "",
            "api",
            "/",
            "/api/",
            "/api//v1",
            "/api/../v1",
            "/api?x=1",
            "/api#x",
            "/api v1",
            "/%61pi",
            "https://host/api",
        ] {
            let value = with_locations.replace("\"/api\"", &format!("\"{invalid}\""));
            assert!(
                serde_json::from_str::<ApiObject<ProxyHostSpec>>(&value).is_err(),
                "accepted {invalid:?}"
            );
        }
        let duplicate_path = with_locations.replace("\"/health/\"", "\"/api\"");
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&duplicate_path).is_err());
        let duplicate_id = with_locations.replace("loc-health", "loc-api");
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&duplicate_id).is_err());
        let unknown = with_locations.replace("\"enabled\":false", "\"enabled\":false,\"raw\":true");
        assert!(serde_json::from_str::<ApiObject<ProxyHostSpec>>(&unknown).is_err());

        let mut too_many = object.clone();
        too_many.spec.locations = (0..=MAX_PROXY_HOST_LOCATIONS)
            .map(|index| {
                let mut location = object.spec.locations[0].clone();
                location.id = format!("loc-{index}").parse().expect("location ID");
                location.path = format!("/path-{index}");
                location
            })
            .collect();
        assert_eq!(
            too_many.spec.validate_shape(),
            Err(ContractError::InvalidProxyLocation)
        );

        let mut excessive_path = object;
        excessive_path.spec.locations[0].path =
            format!("/{}", "a".repeat(aegisproxy_config::MAX_PATH_BYTES));
        assert_eq!(
            excessive_path.spec.validate_shape(),
            Err(ContractError::InvalidProxyLocation)
        );
    }

    #[test]
    fn access_policy_contract_is_strict_bounded_and_secret_free() {
        let source = serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "private-lan", "owner_id": "alice"},
            "spec": {
                "enabled": true,
                "shared_with": ["bob"],
                "middlewares": ["edge-ip", "edge-rate"]
            }
        });
        let object: ApiObject<AccessPolicySpec> =
            serde_json::from_value(source.clone()).expect("access policy");
        object
            .spec
            .validate_shape(&object.metadata.owner_id)
            .expect("valid shape");
        let encoded = serde_json::to_string(&object).expect("policy JSON");
        for forbidden in ["secret", "password", "private_key", "raw_config"] {
            assert!(!encoded.contains(forbidden));
        }

        let mut invalid = source.clone();
        invalid["spec"]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ApiObject<AccessPolicySpec>>(invalid).is_err());
        let mut invalid = source.clone();
        invalid["spec"]["middlewares"] = serde_json::json!(["Bad"]);
        assert!(serde_json::from_value::<ApiObject<AccessPolicySpec>>(invalid).is_err());

        let mut duplicate: ApiObject<AccessPolicySpec> =
            serde_json::from_value(source).expect("access policy");
        duplicate
            .spec
            .shared_with
            .push("bob".parse().expect("owner"));
        assert_eq!(
            duplicate.spec.validate_shape(&duplicate.metadata.owner_id),
            Err(ContractError::InvalidAccessPolicy)
        );
        duplicate.spec.shared_with = vec![duplicate.metadata.owner_id.clone()];
        assert_eq!(
            duplicate.spec.validate_shape(&duplicate.metadata.owner_id),
            Err(ContractError::InvalidAccessPolicy)
        );
    }

    #[test]
    fn access_policy_contract_enforces_exact_collection_and_reference_bounds() {
        let owner: ObjectId = "alice".parse().expect("owner");
        let mut spec = AccessPolicySpec {
            enabled: true,
            shared_with: Vec::new(),
            middlewares: Vec::new(),
        };
        assert_eq!(
            spec.validate_shape(&owner),
            Err(ContractError::InvalidAccessPolicy)
        );

        spec.middlewares = (0..MAX_ACCESS_POLICY_MIDDLEWARES)
            .map(|index| format!("m{index}").parse().expect("middleware"))
            .collect();
        spec.shared_with = (0..MAX_ACCESS_POLICY_SHARES)
            .map(|index| format!("o{index}").parse().expect("shared owner"))
            .collect();
        spec.validate_shape(&owner).expect("exact bounds");

        spec.middlewares
            .push("overflow".parse().expect("middleware"));
        assert_eq!(
            spec.validate_shape(&owner),
            Err(ContractError::InvalidAccessPolicy)
        );
        spec.middlewares.pop();
        spec.shared_with
            .push("overflow".parse().expect("shared owner"));
        assert_eq!(
            spec.validate_shape(&owner),
            Err(ContractError::InvalidAccessPolicy)
        );
        spec.shared_with.pop();
        spec.middlewares[1] = spec.middlewares[0].clone();
        assert_eq!(
            spec.validate_shape(&owner),
            Err(ContractError::InvalidAccessPolicy)
        );

        let maximum = format!("m{}", "a".repeat(62));
        assert_eq!(maximum.len(), 63);
        assert!(maximum.parse::<MiddlewareRef>().is_ok());
        assert_eq!(
            format!("{maximum}a").parse::<MiddlewareRef>(),
            Err(ContractError::InvalidMiddlewareReference)
        );
    }

    #[test]
    fn certificate_contract_is_strict_bounded_and_secret_free() {
        let source = serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "public-site", "owner_id": "alice"},
            "spec": {
                "enabled": true,
                "shared_with": ["bob"],
                "certificate_ref": "managed-public"
            }
        });
        let object: ApiObject<CertificateSpec> =
            serde_json::from_value(source.clone()).expect("certificate");
        object
            .spec
            .validate_shape(&object.metadata.owner_id)
            .expect("valid ownership");
        let encoded = serde_json::to_string(&object).expect("certificate JSON");
        for forbidden in ["secret", "password", "private_key", "certificate_chain"] {
            assert!(!encoded.contains(forbidden));
        }
        let mut invalid = source;
        invalid["spec"]["private_key"] = serde_json::json!("file:///secret.pem");
        assert!(serde_json::from_value::<ApiObject<CertificateSpec>>(invalid).is_err());
    }

    #[test]
    fn stream_host_contract_rejects_wildcards_and_protocol_mismatch() {
        let source = serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "database", "owner_id": "alice"},
            "spec": {
                "listen_port": 5432,
                "protocol": "tls_passthrough",
                "forward_host": "10.0.0.8",
                "forward_port": 5432,
                "sni_hosts": ["db.example.test"],
                "enabled": true
            }
        });
        let mut object: ApiObject<StreamHostSpec> =
            serde_json::from_value(source).expect("stream host");
        object.spec.validate_shape().expect("valid stream host");
        object.spec.sni_hosts = vec!["*.example.test".into()];
        assert_eq!(
            object.spec.validate_shape(),
            Err(ContractError::InvalidStreamHost)
        );
        object.spec.protocol = StreamProtocol::Tcp;
        object.spec.sni_hosts = vec!["db.example.test".into()];
        assert_eq!(
            object.spec.validate_shape(),
            Err(ContractError::InvalidStreamHost)
        );
    }

    #[test]
    fn discovery_contract_is_strict_bounded_and_credential_free() {
        let source = serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "nodes", "owner_id": "alice"},
            "spec": {
                "kind": "dns",
                "enabled": true,
                "upstream_group": "app",
                "hostname": "nodes.example.test",
                "port": 8443,
                "scheme": "https",
                "server_name": "nodes.example.test",
                "weight": 1,
                "refresh_secs": 30,
                "stale_after_secs": 300,
                "max_answers": 16
            }
        });
        let object: ApiObject<DiscoverySourceSpec> =
            serde_json::from_value(source.clone()).expect("discovery source");
        object.spec.validate_shape().expect("valid source");
        let encoded = serde_json::to_string(&object).expect("source JSON");
        for forbidden in ["credential", "password", "token", "ca_bundle"] {
            assert!(!encoded.contains(forbidden));
        }
        let mut unsupported = source;
        unsupported["spec"]["kind"] = serde_json::json!("docker");
        assert!(serde_json::from_value::<ApiObject<DiscoverySourceSpec>>(unsupported).is_err());
    }
}
