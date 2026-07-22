//! Owner-scoped preparation of typed Proxy Host validation and preview results.

use std::collections::{BTreeMap, BTreeSet};

use aegisproxy_config::Config;
use serde::Serialize;
use thiserror::Error;

use crate::{
    ApiObject, AutomaticHttps, CompileContext, ContractError, ObjectId, ProxyHostCandidatePreview,
    ProxyHostClaims, ProxyHostCompileError, ProxyHostDiff, ProxyHostDiffError,
    ProxyHostPreviewError, ProxyHostSetCandidate, ProxyHostSetCompileContext, ProxyHostSpec,
    compile_proxy_host, compile_proxy_hosts, diff_proxy_host_previews,
    preview_proxy_host_candidate,
};

/// Fully validated, non-active Proxy Host preview and creation diff.
#[derive(Clone, Debug, Serialize)]
pub struct PreparedProxyHost {
    /// Safe typed and redacted candidate preview.
    pub preview: ProxyHostCandidatePreview,
    /// Typed creation diff; persisted current object state is not available yet.
    pub diff: ProxyHostDiff,
}

/// Fail-closed typed Proxy Host preparation error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProxyHostPreparationError {
    /// Request ownership differs from the authenticated owner.
    #[error("proxy host owner is unauthorized")]
    UnauthorizedOwner,
    /// Typed contract shape is invalid.
    #[error("proxy host contract is invalid")]
    InvalidContract,
    /// Active configuration does not identify exactly one safe HTTP listener.
    #[error("proxy host HTTP listener policy is unavailable")]
    HttpListenerUnavailable,
    /// Active configuration does not identify exactly one safe upstream template.
    #[error("proxy host upstream template policy is unavailable")]
    UpstreamTemplateUnavailable,
    /// Access-policy ownership metadata is not yet available to the endpoint.
    #[error("proxy host access policy is unavailable")]
    AccessPolicyUnavailable,
    /// Managed HTTPS has no single existing certificate/listener match.
    #[error("proxy host managed HTTPS policy is unavailable")]
    ManagedHttpsUnavailable,
    /// Canonical compilation failed.
    #[error("proxy host compilation failed")]
    Compile,
    /// Safe preview generation failed.
    #[error("proxy host preview failed")]
    Preview,
    /// Typed diff generation failed.
    #[error("proxy host diff failed")]
    Diff,
}

/// Compile, semantically validate, redact, and diff one owned object without activation.
pub fn prepare_proxy_host(
    object: &ApiObject<ProxyHostSpec>,
    active: &Config,
    authenticated_owner: &ObjectId,
) -> Result<PreparedProxyHost, ProxyHostPreparationError> {
    prepare_proxy_host_with_claims(
        object,
        active,
        authenticated_owner,
        &ProxyHostClaims::default(),
    )
}

pub(crate) fn prepare_proxy_host_with_claims(
    object: &ApiObject<ProxyHostSpec>,
    active: &Config,
    authenticated_owner: &ObjectId,
    claims: &ProxyHostClaims,
) -> Result<PreparedProxyHost, ProxyHostPreparationError> {
    if &object.metadata.owner_id != authenticated_owner {
        return Err(ProxyHostPreparationError::UnauthorizedOwner);
    }
    object.spec.validate_shape().map_err(map_contract_error)?;
    if object.spec.access_policy_ref.is_some() {
        return Err(ProxyHostPreparationError::AccessPolicyUnavailable);
    }
    if object.spec.automatic_https == AutomaticHttps::Managed {
        return Err(ProxyHostPreparationError::ManagedHttpsUnavailable);
    }

    let http_listener_id = single_http_listener(active)?;
    let upstream_template_id = single_http_upstream_template(active)?;
    let access_policies = BTreeMap::new();
    let context = CompileContext {
        base_config: active,
        owner_id: authenticated_owner,
        http_listener_id,
        upstream_template_id,
        access_policies: &access_policies,
        claimed_objects: &claims.objects,
        claimed_domains: &claims.domains,
        managed_https: None,
    };
    let candidate = compile_proxy_host(object, &context).map_err(map_compile_error)?;
    let preview = preview_proxy_host_candidate(&candidate, active)
        .map_err(|_error: ProxyHostPreviewError| ProxyHostPreparationError::Preview)?;
    let diff = diff_proxy_host_previews(None, &preview.summary)
        .map_err(|_error: ProxyHostDiffError| ProxyHostPreparationError::Diff)?;
    Ok(PreparedProxyHost { preview, diff })
}

pub(crate) fn prepare_proxy_host_set(
    current: &[ApiObject<ProxyHostSpec>],
    desired: &[ApiObject<ProxyHostSpec>],
    active: &Config,
) -> Result<ProxyHostSetCandidate, ProxyHostPreparationError> {
    let http_listener_id = single_http_listener(active)?;
    let upstream_template_id = single_http_upstream_template_for_set(active, current)?;
    let access_policies = BTreeMap::new();
    let managed_https = BTreeMap::new();
    compile_proxy_hosts(
        current,
        desired,
        &ProxyHostSetCompileContext {
            base_config: active,
            http_listener_id,
            upstream_template_id,
            access_policies: &access_policies,
            managed_https: &managed_https,
        },
    )
    .map_err(map_compile_error)
}

fn map_contract_error(_error: ContractError) -> ProxyHostPreparationError {
    ProxyHostPreparationError::InvalidContract
}

fn map_compile_error(error: ProxyHostCompileError) -> ProxyHostPreparationError {
    match error {
        ProxyHostCompileError::UnauthorizedOwner => ProxyHostPreparationError::UnauthorizedOwner,
        _ => ProxyHostPreparationError::Compile,
    }
}

fn single_http_listener(config: &Config) -> Result<&str, ProxyHostPreparationError> {
    let mut listeners = config
        .listeners
        .iter()
        .filter(|listener| listener.protocol == "http");
    let listener = listeners
        .next()
        .ok_or(ProxyHostPreparationError::HttpListenerUnavailable)?;
    if listeners.next().is_some() {
        return Err(ProxyHostPreparationError::HttpListenerUnavailable);
    }
    Ok(&listener.id)
}

fn single_http_upstream_template(config: &Config) -> Result<&str, ProxyHostPreparationError> {
    let mut groups = config.upstream_groups.iter().filter(|group| {
        !group.endpoints.is_empty()
            && group
                .endpoints
                .iter()
                .all(|endpoint| matches!(endpoint.url.scheme(), "http" | "https"))
    });
    let group = groups
        .next()
        .ok_or(ProxyHostPreparationError::UpstreamTemplateUnavailable)?;
    if groups.next().is_some() {
        return Err(ProxyHostPreparationError::UpstreamTemplateUnavailable);
    }
    Ok(&group.id)
}

fn single_http_upstream_template_for_set<'a>(
    config: &'a Config,
    current: &[ApiObject<ProxyHostSpec>],
) -> Result<&'a str, ProxyHostPreparationError> {
    let managed = current
        .iter()
        .map(crate::compile::managed_upstream_group_id)
        .collect::<BTreeSet<_>>();
    let mut groups = config.upstream_groups.iter().filter(|group| {
        !managed.contains(&group.id)
            && !group.endpoints.is_empty()
            && group
                .endpoints
                .iter()
                .all(|endpoint| matches!(endpoint.url.scheme(), "http" | "https"))
    });
    let group = groups
        .next()
        .ok_or(ProxyHostPreparationError::UpstreamTemplateUnavailable)?;
    if groups.next().is_some() {
        return Err(ProxyHostPreparationError::UpstreamTemplateUnavailable);
    }
    Ok(&group.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(owner: &str) -> ApiObject<ProxyHostSpec> {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "proxy-new", "owner_id": owner},
            "spec": {
                "domain": "new.example.test",
                "forward_host": "127.0.0.1",
                "forward_port": 9001,
                "forward_protocol": "http",
                "automatic_https": "disabled",
                "access_policy_ref": null,
                "enabled": true
            }
        }))
        .expect("typed object")
    }

    #[test]
    fn prepares_redacted_deterministic_creation_without_mutating_active() {
        let mut active =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("active config");
        active.admin.audit_key = Some("env://PREVIEW_SECRET_CANARY".into());
        let before = serde_json::to_vec(&active).expect("active serialization");
        let owner: ObjectId = "uid-1000".parse().expect("owner");
        let first = prepare_proxy_host(&object(owner.as_str()), &active, &owner).expect("prepare");
        let second = prepare_proxy_host(&object(owner.as_str()), &active, &owner).expect("prepare");
        assert_eq!(
            serde_json::to_vec(&first).expect("first JSON"),
            serde_json::to_vec(&second).expect("second JSON")
        );
        let output = serde_json::to_string(&first).expect("preview JSON");
        assert!(!output.contains("PREVIEW_SECRET_CANARY"));
        assert!(output.contains("<redacted-secret-reference>"));
        assert_eq!(first.diff.changes.len(), 8);
        assert_eq!(
            before,
            serde_json::to_vec(&active).expect("active unchanged")
        );
    }

    #[test]
    fn rejects_cross_owner_policy_and_ambiguous_templates() {
        let mut active =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("active config");
        let owner: ObjectId = "uid-1000".parse().expect("owner");
        assert_eq!(
            prepare_proxy_host(&object("uid-2000"), &active, &owner).expect_err("cross owner"),
            ProxyHostPreparationError::UnauthorizedOwner
        );

        let mut protected = object(owner.as_str());
        protected.spec.access_policy_ref =
            Some(serde_json::from_str("\"private\"").expect("policy ref"));
        assert_eq!(
            prepare_proxy_host(&protected, &active, &owner).expect_err("policy metadata absent"),
            ProxyHostPreparationError::AccessPolicyUnavailable
        );

        active
            .upstream_groups
            .push(active.upstream_groups[0].clone());
        assert_eq!(
            prepare_proxy_host(&object(owner.as_str()), &active, &owner)
                .expect_err("ambiguous template"),
            ProxyHostPreparationError::UpstreamTemplateUnavailable
        );
    }

    #[test]
    fn managed_https_fails_closed_without_owned_certificate_policy() {
        let active =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("active config");
        let owner: ObjectId = "uid-1000".parse().expect("owner");
        let mut value = object(owner.as_str());
        value.spec.automatic_https = AutomaticHttps::Managed;
        assert_eq!(
            prepare_proxy_host(&value, &active, &owner).expect_err("policy metadata absent"),
            ProxyHostPreparationError::ManagedHttpsUnavailable
        );
    }

    #[test]
    fn recompiles_after_managed_candidate_activation() {
        let base =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("active config");
        let current = vec![object("uid-1000")];
        let activated = prepare_proxy_host_set(&[], &current, &base).expect("initial candidate");
        let removed = prepare_proxy_host_set(&current, &[], activated.config())
            .expect("candidate after activation");

        assert_eq!(
            serde_json::to_vec(removed.config()).expect("removed candidate"),
            serde_json::to_vec(&base).expect("base candidate")
        );
    }
}
