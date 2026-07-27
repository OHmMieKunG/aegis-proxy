//! Secret-free typed ownership metadata for canonical access-policy middleware.

use std::{collections::BTreeSet, fmt};

use aegisproxy_config::{Config, MiddlewareConfig, RateLimitKey, validate};
use thiserror::Error;

use crate::{AccessPolicySpec, ApiObject, ContractError, ObjectId};

/// Validated metadata allowed to influence Proxy Host access-policy resolution.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessPolicyMetadata {
    owner_id: ObjectId,
    shared_with: BTreeSet<ObjectId>,
    enabled: bool,
    middleware_ids: Vec<String>,
}

impl fmt::Debug for AccessPolicyMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessPolicyMetadata")
            .field("enabled", &self.enabled)
            .field("shared_owner_count", &self.shared_with.len())
            .field("middleware_count", &self.middleware_ids.len())
            .finish()
    }
}

impl AccessPolicyMetadata {
    /// Return policy owner.
    #[must_use]
    pub const fn owner_id(&self) -> &ObjectId {
        &self.owner_id
    }

    /// Return owners explicitly allowed to reference the policy.
    #[must_use]
    pub const fn shared_with(&self) -> &BTreeSet<ObjectId> {
        &self.shared_with
    }

    /// Return whether references may compile.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn permits(&self, owner_id: &ObjectId) -> bool {
        &self.owner_id == owner_id || self.shared_with.contains(owner_id)
    }

    /// Return canonical middleware IDs in stable order.
    #[must_use]
    pub fn middleware_ids(&self) -> &[String] {
        &self.middleware_ids
    }
}

/// Stable fail-closed access-policy metadata compilation error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AccessPolicyCompileError {
    /// Typed ownership or middleware-reference shape is invalid.
    #[error("access policy contract is invalid")]
    InvalidContract,
    /// Canonical configuration is not semantically valid.
    #[error("access policy configuration is invalid")]
    InvalidConfiguration,
    /// Referenced middleware does not exist.
    #[error("access policy middleware is unavailable")]
    MissingMiddleware,
    /// Referenced middleware is not an access-control stage.
    #[error("access policy middleware is incompatible")]
    IncompatibleMiddleware,
}

/// Compile one secret-free typed policy into immutable Proxy Host resolution metadata.
pub fn compile_access_policy_metadata(
    object: &ApiObject<AccessPolicySpec>,
    config: &Config,
) -> Result<AccessPolicyMetadata, AccessPolicyCompileError> {
    object
        .spec
        .validate_shape(&object.metadata.owner_id)
        .map_err(|_error: ContractError| AccessPolicyCompileError::InvalidContract)?;
    validate(config).map_err(|_| AccessPolicyCompileError::InvalidConfiguration)?;

    let mut middleware_ids = Vec::with_capacity(object.spec.middlewares.len());
    let mut ip_policies = 0_usize;
    let mut edge_rate_limits = 0_usize;
    let mut principal_rate_limits = 0_usize;
    let mut in_flight_limits = 0_usize;
    let mut authentication = 0_usize;
    for reference in &object.spec.middlewares {
        let middleware = config
            .middlewares
            .get(reference.as_str())
            .ok_or(AccessPolicyCompileError::MissingMiddleware)?;
        match middleware {
            MiddlewareConfig::IpPolicy { .. } => ip_policies += 1,
            MiddlewareConfig::RateLimit { key, .. } => match key {
                RateLimitKey::ClientIp => edge_rate_limits += 1,
                RateLimitKey::Principal => principal_rate_limits += 1,
            },
            MiddlewareConfig::InFlightLimit { .. } => in_flight_limits += 1,
            MiddlewareConfig::BasicAuth { .. } | MiddlewareConfig::ForwardAuth { .. } => {
                authentication += 1;
            }
            _ => return Err(AccessPolicyCompileError::IncompatibleMiddleware),
        }
        middleware_ids.push(reference.as_str().to_owned());
    }
    if ip_policies > 1
        || edge_rate_limits > 1
        || principal_rate_limits > 1
        || in_flight_limits > 1
        || authentication > 1
        || (principal_rate_limits == 1 && authentication != 1)
    {
        return Err(AccessPolicyCompileError::IncompatibleMiddleware);
    }
    middleware_ids.sort_unstable();

    Ok(AccessPolicyMetadata {
        owner_id: object.metadata.owner_id.clone(),
        shared_with: object.spec.shared_with.iter().cloned().collect(),
        enabled: object.spec.enabled,
        middleware_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(middlewares: &[&str]) -> ApiObject<AccessPolicySpec> {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "private-lan", "owner_id": "alice"},
            "spec": {
                "enabled": true,
                "shared_with": ["bob"],
                "middlewares": middlewares
            }
        }))
        .expect("access policy")
    }

    fn config() -> Config {
        aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/phase7.toml"))
            .expect("middleware config")
    }

    #[test]
    fn compiles_canonical_secret_free_ownership_metadata() {
        let mut config = config();
        let MiddlewareConfig::BasicAuth { users, .. } = config
            .middlewares
            .get_mut("basic")
            .expect("Basic auth middleware")
        else {
            panic!("expected Basic auth middleware");
        };
        users.insert("canary".into(), "env://ACCESS_POLICY_SECRET_CANARY".into());
        let object = policy(&["edge-rate", "basic", "edge-ip"]);
        let metadata = compile_access_policy_metadata(&object, &config).expect("compiled metadata");

        assert!(metadata.permits(&"alice".parse().expect("owner")));
        assert!(metadata.permits(&"bob".parse().expect("shared owner")));
        assert!(!metadata.permits(&"charlie".parse().expect("other owner")));
        assert_eq!(metadata.middleware_ids(), ["basic", "edge-ip", "edge-rate"]);
        let debug = format!("{metadata:?}");
        assert!(!debug.contains("ACCESS_POLICY_SECRET_CANARY"));
        assert!(!debug.contains("env://"));
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("bob"));
        assert!(
            !serde_json::to_string(&object)
                .expect("policy JSON")
                .contains("ACCESS_POLICY_SECRET_CANARY")
        );
        for error in [
            AccessPolicyCompileError::InvalidContract,
            AccessPolicyCompileError::InvalidConfiguration,
            AccessPolicyCompileError::MissingMiddleware,
            AccessPolicyCompileError::IncompatibleMiddleware,
        ] {
            assert!(!error.to_string().contains("ACCESS_POLICY_SECRET_CANARY"));
        }
    }

    #[test]
    fn canonicalizes_input_order_and_accepts_each_access_stage() {
        let config = config();
        let first = policy(&["edge-rate", "edge-ip", "route-cap"]);
        let mut second = policy(&["route-cap", "edge-ip", "edge-rate"]);
        second.spec.shared_with = vec![
            "carol".parse().expect("owner"),
            "bob".parse().expect("owner"),
        ];
        let mut first = first;
        first.spec.shared_with = vec![
            "bob".parse().expect("owner"),
            "carol".parse().expect("owner"),
        ];
        assert_eq!(
            compile_access_policy_metadata(&first, &config).expect("first"),
            compile_access_policy_metadata(&second, &config).expect("second")
        );

        for middlewares in [
            &["route-cap"][..],
            &["authentik"][..],
            &["basic", "principal-rate"][..],
        ] {
            compile_access_policy_metadata(&policy(middlewares), &config)
                .expect("compatible access stage");
        }
    }

    #[test]
    fn rejects_missing_incompatible_and_invalid_policy_bindings() {
        let config = config();
        assert_eq!(
            compile_access_policy_metadata(&policy(&["missing"]), &config),
            Err(AccessPolicyCompileError::MissingMiddleware)
        );
        assert_eq!(
            compile_access_policy_metadata(&policy(&["cors"]), &config),
            Err(AccessPolicyCompileError::IncompatibleMiddleware)
        );
        assert_eq!(
            compile_access_policy_metadata(&policy(&["basic", "authentik"]), &config),
            Err(AccessPolicyCompileError::IncompatibleMiddleware)
        );
        assert_eq!(
            compile_access_policy_metadata(&policy(&["principal-rate"]), &config),
            Err(AccessPolicyCompileError::IncompatibleMiddleware)
        );

        let mut invalid = policy(&["edge-ip"]);
        invalid
            .spec
            .shared_with
            .push("alice".parse().expect("owner"));
        assert_eq!(
            compile_access_policy_metadata(&invalid, &config),
            Err(AccessPolicyCompileError::InvalidContract)
        );

        let mut invalid_config = config;
        invalid_config.schema_version = 2;
        assert_eq!(
            compile_access_policy_metadata(&policy(&["edge-ip"]), &invalid_config),
            Err(AccessPolicyCompileError::InvalidConfiguration)
        );
    }
}
