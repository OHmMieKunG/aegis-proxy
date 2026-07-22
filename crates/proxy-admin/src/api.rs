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
}
