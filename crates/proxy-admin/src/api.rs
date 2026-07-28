//! Versioned high-level administration contracts.

use std::{fmt, net::IpAddr, str::FromStr};

use aegisproxy_config::{validate_exact_host, validate_upstream_hostname};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Current high-level administration contract version.
pub const API_VERSION: &str = "v1";

const MAX_OBJECT_ID_BYTES: usize = 64;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_FORWARD_HOST_BYTES: usize = 253;
const MAX_ACCESS_POLICY_SHARES: usize = 128;
const MAX_ACCESS_POLICY_MIDDLEWARES: usize = 64;
const MAX_CERTIFICATE_SHARES: usize = 128;

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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyHostSpec {
    /// Canonical public DNS name.
    pub domain: String,
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
    /// Whether object contributes to active configuration.
    pub enabled: bool,
}

impl ProxyHostSpec {
    /// Validate bounded contract shape before canonical configuration compilation.
    pub fn validate_shape(&self) -> Result<(), ContractError> {
        if self.domain.is_empty()
            || self.domain.len() > MAX_DOMAIN_BYTES
            || !self.domain.is_ascii()
            || self.domain.ends_with('.')
            || self.domain.contains('*')
            || self.domain.parse::<IpAddr>().is_ok()
            || validate_exact_host(&self.domain).is_err()
        {
            return Err(ContractError::InvalidDomain);
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
    /// Access policy is empty, duplicated, self-shared, or exceeds a fixed bound.
    #[error("invalid access policy")]
    InvalidAccessPolicy,
    /// Middleware reference is malformed or non-canonical.
    #[error("invalid middleware reference")]
    InvalidMiddlewareReference,
    /// Certificate ownership is duplicated, self-shared, or exceeds its fixed bound.
    #[error("invalid certificate ownership")]
    InvalidCertificate,
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
        for domain in [
            "Example.test",
            "example.test.",
            "*.example.test",
            "127.0.0.1",
        ] {
            object.spec.domain = domain.into();
            assert_eq!(
                object.spec.validate_shape(),
                Err(ContractError::InvalidDomain)
            );
        }
        object.spec.domain = "example.test".into();
        object.spec.forward_host = "bad_host".into();
        assert_eq!(
            object.spec.validate_shape(),
            Err(ContractError::InvalidForwardHost)
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
}
