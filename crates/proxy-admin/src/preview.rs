//! Safe side-effect-free views of compiled high-level candidates.

use std::fmt;

use aegisproxy_config::{Config, redacted, revision::content_hash, validate};
use aegisproxy_core::{RouteIndex, hot_reload_compatible};
use serde::Serialize;
use thiserror::Error;

use crate::{
    API_VERSION, AccessPolicyRef, AutomaticHttps, ForwardProtocol, ObjectId, ProxyHostCandidate,
    compile::namespace,
};

/// Candidate activation requirement derived without touching runtime state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateActivation {
    /// Candidate can use existing listener bindings.
    HotReload,
    /// Candidate changes a restart-only setting or listener binding.
    RestartRequired,
}

/// Deterministic canonical resources generated for one enabled Proxy Host.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratedProxyHostPreview {
    /// Generated route ID.
    pub route_id: String,
    /// Selected listener ID.
    pub listener_id: String,
    /// Generated upstream-group ID.
    pub upstream_group_id: String,
    /// Generated endpoint ID.
    pub endpoint_id: String,
}

/// Typed human-readable candidate summary safe for later API exposure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProxyHostPreviewSummary {
    /// High-level contract version.
    pub api_version: &'static str,
    /// Stable object ID.
    pub object_id: ObjectId,
    /// Stable owner ID.
    pub owner_id: ObjectId,
    /// Exact public domain.
    pub domain: String,
    /// Configured forward host or IP address.
    pub forward_host: String,
    /// Configured forward port.
    pub forward_port: u16,
    /// Configured upstream protocol.
    pub forward_protocol: ForwardProtocol,
    /// Desired automatic-HTTPS behavior.
    pub automatic_https: AutomaticHttps,
    /// Opaque access-policy reference.
    pub access_policy_ref: Option<AccessPolicyRef>,
    /// Whether canonical runtime resources are present.
    pub enabled: bool,
    /// Generated resources; absent for disabled objects.
    pub generated: Option<GeneratedProxyHostPreview>,
    /// Canonical candidate SHA-256 content hash.
    pub candidate_hash: String,
    /// Active route fingerprint for comparison only.
    pub active_route_fingerprint: String,
    /// Candidate route fingerprint for comparison only.
    pub candidate_route_fingerprint: String,
    /// Whether activation needs listener restart.
    pub activation: CandidateActivation,
}

/// Safe preview plus fully redacted canonical candidate.
#[derive(Clone, Serialize)]
pub struct ProxyHostCandidatePreview {
    /// Typed bounded summary.
    pub summary: ProxyHostPreviewSummary,
    /// Canonical configuration with every secret reference replaced.
    pub redacted_config: Config,
}

impl fmt::Debug for ProxyHostCandidatePreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyHostCandidatePreview")
            .field("summary", &self.summary)
            .field("route_count", &self.redacted_config.routes.len())
            .field(
                "upstream_group_count",
                &self.redacted_config.upstream_groups.len(),
            )
            .finish()
    }
}

/// Stable fail-closed preview error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProxyHostPreviewError {
    /// Active input is not a valid canonical configuration.
    #[error("active configuration is invalid")]
    InvalidActiveConfiguration,
    /// Compiled candidate is not valid or internally coherent.
    #[error("proxy host candidate is invalid")]
    InvalidCandidate,
}

/// Revalidate and preview one compiled candidate without persistence or activation.
pub fn preview_proxy_host_candidate(
    candidate: &ProxyHostCandidate,
    active: &Config,
) -> Result<ProxyHostCandidatePreview, ProxyHostPreviewError> {
    validate(active).map_err(|_| ProxyHostPreviewError::InvalidActiveConfiguration)?;
    let candidate_hash =
        content_hash(candidate.config()).map_err(|_| ProxyHostPreviewError::InvalidCandidate)?;
    let object = candidate.object();
    let generated = generated_resources(candidate)?;
    let activation = if hot_reload_compatible(active, candidate.config()) {
        CandidateActivation::HotReload
    } else {
        CandidateActivation::RestartRequired
    };
    Ok(ProxyHostCandidatePreview {
        summary: ProxyHostPreviewSummary {
            api_version: API_VERSION,
            object_id: object.metadata.id.clone(),
            owner_id: object.metadata.owner_id.clone(),
            domain: object.spec.domain.clone(),
            forward_host: object.spec.forward_host.clone(),
            forward_port: object.spec.forward_port,
            forward_protocol: object.spec.forward_protocol,
            automatic_https: object.spec.automatic_https,
            access_policy_ref: object.spec.access_policy_ref.clone(),
            enabled: object.spec.enabled,
            generated,
            candidate_hash,
            active_route_fingerprint: route_fingerprint(active),
            candidate_route_fingerprint: route_fingerprint(candidate.config()),
            activation,
        },
        redacted_config: redacted(candidate.config()),
    })
}

fn generated_resources(
    candidate: &ProxyHostCandidate,
) -> Result<Option<GeneratedProxyHostPreview>, ProxyHostPreviewError> {
    let object = candidate.object();
    if !object.spec.enabled {
        return Ok(None);
    }
    let namespace = namespace(&object.metadata.owner_id, &object.metadata.id);
    let route_id = format!("{namespace}-route");
    let upstream_group_id = format!("{namespace}-upstream");
    let endpoint_id = format!("{namespace}-endpoint");
    let route = candidate
        .config()
        .routes
        .iter()
        .find(|route| route.id == route_id)
        .ok_or(ProxyHostPreviewError::InvalidCandidate)?;
    if route.listeners.len() != 1 || route.upstream_group.as_deref() != Some(&upstream_group_id) {
        return Err(ProxyHostPreviewError::InvalidCandidate);
    }
    let group = candidate
        .config()
        .upstream_groups
        .iter()
        .find(|group| group.id == upstream_group_id)
        .ok_or(ProxyHostPreviewError::InvalidCandidate)?;
    if !group
        .endpoints
        .iter()
        .any(|endpoint| endpoint.id == endpoint_id)
    {
        return Err(ProxyHostPreviewError::InvalidCandidate);
    }
    Ok(Some(GeneratedProxyHostPreview {
        route_id,
        listener_id: route.listeners[0].clone(),
        upstream_group_id,
        endpoint_id,
    }))
}

fn route_fingerprint(config: &Config) -> String {
    format!("{:016x}", RouteIndex::compile(config).fingerprint())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{ApiObject, CompileContext, ProxyHostSpec, compile_proxy_host};

    fn base_config() -> Config {
        let mut config =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("valid base config");
        config.admin.audit_key = Some("env://PREVIEW_SECRET_CANARY".into());
        validate(&config).expect("valid secret-reference config");
        config
    }

    fn object(enabled: bool) -> ApiObject<ProxyHostSpec> {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "proxy-preview", "owner_id": "alice"},
            "spec": {
                "domain": "preview.example.test",
                "forward_host": "127.0.0.1",
                "forward_port": 9001,
                "forward_protocol": "http",
                "automatic_https": "disabled",
                "access_policy_ref": null,
                "enabled": enabled
            }
        }))
        .expect("typed object")
    }

    fn candidate(config: &Config, enabled: bool) -> ProxyHostCandidate {
        let owner = "alice".parse().expect("owner ID");
        let policies = BTreeMap::new();
        let objects = BTreeSet::new();
        let domains = BTreeMap::new();
        compile_proxy_host(
            &object(enabled),
            &CompileContext {
                base_config: config,
                owner_id: &owner,
                http_listener_id: "public",
                upstream_template_id: "app",
                access_policies: &policies,
                claimed_objects: &objects,
                claimed_domains: &domains,
                managed_https: None,
            },
        )
        .expect("compiled candidate")
    }

    #[test]
    fn preview_is_deterministic_redacted_and_non_active() {
        let active = base_config();
        let candidate = candidate(&active, true);
        let first = preview_proxy_host_candidate(&candidate, &active).expect("preview");
        let second = preview_proxy_host_candidate(&candidate, &active).expect("preview");
        assert_eq!(
            serde_json::to_vec(&first).expect("serialize preview"),
            serde_json::to_vec(&second).expect("serialize preview")
        );
        assert_eq!(first.summary.activation, CandidateActivation::HotReload);
        assert_eq!(first.summary.api_version, "v1");
        assert!(first.summary.generated.is_some());
        assert_ne!(
            first.summary.active_route_fingerprint,
            first.summary.candidate_route_fingerprint
        );
        let encoded = serde_json::to_string(&first).expect("serialize preview");
        assert!(!encoded.contains("PREVIEW_SECRET_CANARY"));
        assert!(encoded.contains("<redacted-secret-reference>"));
        assert!(!format!("{first:?}").contains("env://"));
        assert_eq!(
            candidate.config().admin.audit_key.as_deref(),
            Some("env://PREVIEW_SECRET_CANARY")
        );
    }

    #[test]
    fn disabled_preview_has_no_generated_runtime_resources() {
        let active = base_config();
        let candidate = candidate(&active, false);
        let preview = preview_proxy_host_candidate(&candidate, &active).expect("preview");
        assert!(!preview.summary.enabled);
        assert!(preview.summary.generated.is_none());
        assert_eq!(
            preview.summary.active_route_fingerprint,
            preview.summary.candidate_route_fingerprint
        );
    }

    #[test]
    fn invalid_active_configuration_fails_closed() {
        let active = base_config();
        let candidate = candidate(&active, true);
        let mut invalid = active;
        invalid.schema_version = 2;
        assert_eq!(
            preview_proxy_host_candidate(&candidate, &invalid).expect_err("invalid active config"),
            ProxyHostPreviewError::InvalidActiveConfiguration
        );
    }

    #[test]
    fn restart_only_difference_is_reported_without_activation() {
        let active = base_config();
        let mut changed = active.clone();
        changed.listeners[0].bind = "127.0.0.1:8081".parse().expect("listener address");
        validate(&changed).expect("valid changed base");
        let candidate = candidate(&changed, true);
        let preview = preview_proxy_host_candidate(&candidate, &active).expect("preview");
        assert_eq!(
            preview.summary.activation,
            CandidateActivation::RestartRequired
        );
        assert_eq!(active.listeners[0].bind.to_string(), "127.0.0.1:8080");
    }
}
