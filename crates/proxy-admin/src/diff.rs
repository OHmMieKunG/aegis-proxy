//! Deterministic bounded field differences for typed Proxy Host previews.

use serde::Serialize;
use thiserror::Error;

use crate::{
    API_VERSION, AccessPolicyRef, AutomaticHttps, ForwardProtocol, GeneratedProxyHostPreview,
    ObjectId, ProxyHostPreviewSummary,
};

const MAX_CHANGES: usize = 8;

/// Stable typed Proxy Host field path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyHostField {
    /// Public domain.
    Domain,
    /// Forward host or IP address.
    ForwardHost,
    /// Forward TCP port.
    ForwardPort,
    /// Forward application protocol.
    ForwardProtocol,
    /// Automatic-HTTPS desired state.
    AutomaticHttps,
    /// Opaque access-policy reference.
    AccessPolicyRef,
    /// Enabled desired state.
    Enabled,
    /// Generated canonical runtime resources.
    GeneratedResources,
}

/// Typed field operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffOperation {
    /// Field or generated resources are introduced.
    Add,
    /// Existing typed value changes.
    Replace,
    /// Generated resources are removed.
    Remove,
}

/// Closed set of safe values used by Proxy Host field differences.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProxyHostDiffValue {
    /// Canonical domain.
    Domain(String),
    /// Canonical forward host or IP address.
    ForwardHost(String),
    /// Explicit forward port.
    ForwardPort(u16),
    /// Supported forward protocol.
    ForwardProtocol(ForwardProtocol),
    /// Automatic-HTTPS desired state.
    AutomaticHttps(AutomaticHttps),
    /// Optional opaque policy reference; no policy content is copied.
    AccessPolicyRef(Option<AccessPolicyRef>),
    /// Enabled desired state.
    Enabled(bool),
    /// Generated identifiers; no runtime or secret state is copied.
    GeneratedResources(GeneratedProxyHostPreview),
}

/// One ordered typed field change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProxyHostFieldChange {
    /// Changed field.
    pub field: ProxyHostField,
    /// Change operation.
    pub operation: DiffOperation,
    /// Prior typed value; absent for additions.
    pub before: Option<ProxyHostDiffValue>,
    /// Candidate typed value; absent for removals.
    pub after: Option<ProxyHostDiffValue>,
}

/// Bounded deterministic diff for one owner-scoped Proxy Host.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProxyHostDiff {
    /// High-level contract version.
    pub api_version: &'static str,
    /// Stable object ID.
    pub object_id: ObjectId,
    /// Stable owner ID.
    pub owner_id: ObjectId,
    /// Current canonical candidate hash, when object exists.
    pub current_hash: Option<String>,
    /// Proposed canonical candidate hash.
    pub candidate_hash: String,
    /// Ordered field changes, bounded by the closed field set.
    pub changes: Vec<ProxyHostFieldChange>,
}

/// Stable fail-closed typed-diff error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProxyHostDiffError {
    /// Current or candidate preview uses an unsupported contract version.
    #[error("unsupported proxy host preview version")]
    UnsupportedVersion,
    /// Current and candidate previews do not identify the same owned object.
    #[error("proxy host preview identity does not match")]
    IdentityMismatch,
    /// Internal field set exceeded its fixed bound.
    #[error("proxy host diff invariant failed")]
    InternalInvariant,
}

/// Compare current optional state with one compiled candidate preview.
pub fn diff_proxy_host_previews(
    current: Option<&ProxyHostPreviewSummary>,
    candidate: &ProxyHostPreviewSummary,
) -> Result<ProxyHostDiff, ProxyHostDiffError> {
    if candidate.api_version != API_VERSION
        || current.is_some_and(|current| current.api_version != API_VERSION)
    {
        return Err(ProxyHostDiffError::UnsupportedVersion);
    }
    if current.is_some_and(|current| {
        current.object_id != candidate.object_id || current.owner_id != candidate.owner_id
    }) {
        return Err(ProxyHostDiffError::IdentityMismatch);
    }

    let mut changes = Vec::with_capacity(MAX_CHANGES);
    match current {
        None => {
            for (field, value) in fields(candidate) {
                changes.push(ProxyHostFieldChange {
                    field,
                    operation: DiffOperation::Add,
                    before: None,
                    after: Some(value),
                });
            }
            if let Some(generated) = &candidate.generated {
                changes.push(ProxyHostFieldChange {
                    field: ProxyHostField::GeneratedResources,
                    operation: DiffOperation::Add,
                    before: None,
                    after: Some(ProxyHostDiffValue::GeneratedResources(generated.clone())),
                });
            }
        }
        Some(current) => {
            for ((field, before), (candidate_field, after)) in
                fields(current).into_iter().zip(fields(candidate))
            {
                if field != candidate_field {
                    return Err(ProxyHostDiffError::InternalInvariant);
                }
                if before != after {
                    changes.push(ProxyHostFieldChange {
                        field,
                        operation: DiffOperation::Replace,
                        before: Some(before),
                        after: Some(after),
                    });
                }
            }
            match (&current.generated, &candidate.generated) {
                (None, Some(after)) => changes.push(ProxyHostFieldChange {
                    field: ProxyHostField::GeneratedResources,
                    operation: DiffOperation::Add,
                    before: None,
                    after: Some(ProxyHostDiffValue::GeneratedResources(after.clone())),
                }),
                (Some(before), None) => changes.push(ProxyHostFieldChange {
                    field: ProxyHostField::GeneratedResources,
                    operation: DiffOperation::Remove,
                    before: Some(ProxyHostDiffValue::GeneratedResources(before.clone())),
                    after: None,
                }),
                (Some(before), Some(after)) if before != after => {
                    changes.push(ProxyHostFieldChange {
                        field: ProxyHostField::GeneratedResources,
                        operation: DiffOperation::Replace,
                        before: Some(ProxyHostDiffValue::GeneratedResources(before.clone())),
                        after: Some(ProxyHostDiffValue::GeneratedResources(after.clone())),
                    });
                }
                _ => {}
            }
        }
    }
    if changes.len() > MAX_CHANGES {
        return Err(ProxyHostDiffError::InternalInvariant);
    }
    Ok(ProxyHostDiff {
        api_version: API_VERSION,
        object_id: candidate.object_id.clone(),
        owner_id: candidate.owner_id.clone(),
        current_hash: current.map(|current| current.candidate_hash.clone()),
        candidate_hash: candidate.candidate_hash.clone(),
        changes,
    })
}

fn fields(summary: &ProxyHostPreviewSummary) -> [(ProxyHostField, ProxyHostDiffValue); 7] {
    [
        (
            ProxyHostField::Domain,
            ProxyHostDiffValue::Domain(summary.domain.clone()),
        ),
        (
            ProxyHostField::ForwardHost,
            ProxyHostDiffValue::ForwardHost(summary.forward_host.clone()),
        ),
        (
            ProxyHostField::ForwardPort,
            ProxyHostDiffValue::ForwardPort(summary.forward_port),
        ),
        (
            ProxyHostField::ForwardProtocol,
            ProxyHostDiffValue::ForwardProtocol(summary.forward_protocol),
        ),
        (
            ProxyHostField::AutomaticHttps,
            ProxyHostDiffValue::AutomaticHttps(summary.automatic_https),
        ),
        (
            ProxyHostField::AccessPolicyRef,
            ProxyHostDiffValue::AccessPolicyRef(summary.access_policy_ref.clone()),
        ),
        (
            ProxyHostField::Enabled,
            ProxyHostDiffValue::Enabled(summary.enabled),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CandidateActivation, GeneratedProxyHostPreview};

    fn summary(enabled: bool) -> ProxyHostPreviewSummary {
        ProxyHostPreviewSummary {
            api_version: "v1",
            object_id: "proxy-diff".parse().expect("object ID"),
            owner_id: "alice".parse().expect("owner ID"),
            domain: "diff.example.test".into(),
            forward_host: "127.0.0.1".into(),
            forward_port: 9000,
            forward_protocol: ForwardProtocol::Http,
            automatic_https: AutomaticHttps::Disabled,
            access_policy_ref: None,
            enabled,
            generated: enabled.then(|| GeneratedProxyHostPreview {
                route_id: "ph-test-route".into(),
                listener_id: "public".into(),
                upstream_group_id: "ph-test-upstream".into(),
                endpoint_id: "ph-test-endpoint".into(),
            }),
            candidate_hash: if enabled { "a" } else { "b" }.repeat(64),
            active_route_fingerprint: "0000000000000001".into(),
            candidate_route_fingerprint: "0000000000000002".into(),
            activation: CandidateActivation::HotReload,
        }
    }

    #[test]
    fn creation_diff_is_bounded_stable_and_typed() {
        let candidate = summary(true);
        let first = diff_proxy_host_previews(None, &candidate).expect("diff");
        let second = diff_proxy_host_previews(None, &candidate).expect("diff");
        assert_eq!(first, second);
        assert_eq!(first.changes.len(), MAX_CHANGES);
        assert_eq!(first.changes[0].field, ProxyHostField::Domain);
        assert_eq!(
            first.changes[MAX_CHANGES - 1].field,
            ProxyHostField::GeneratedResources
        );
        assert!(
            first
                .changes
                .iter()
                .all(|change| change.operation == DiffOperation::Add && change.before.is_none())
        );
    }

    #[test]
    fn unchanged_and_disabled_diffs_are_exact() {
        let current = summary(true);
        let unchanged = diff_proxy_host_previews(Some(&current), &current).expect("unchanged diff");
        assert!(unchanged.changes.is_empty());

        let disabled = summary(false);
        let diff = diff_proxy_host_previews(Some(&current), &disabled).expect("disabled diff");
        assert_eq!(diff.changes.len(), 2);
        assert_eq!(diff.changes[0].field, ProxyHostField::Enabled);
        assert_eq!(diff.changes[0].operation, DiffOperation::Replace);
        assert_eq!(
            diff.changes[1],
            ProxyHostFieldChange {
                field: ProxyHostField::GeneratedResources,
                operation: DiffOperation::Remove,
                before: current
                    .generated
                    .clone()
                    .map(ProxyHostDiffValue::GeneratedResources),
                after: None,
            }
        );
    }

    #[test]
    fn identity_mismatch_fails_closed_and_output_has_no_secret_field() {
        let current = summary(true);
        let mut candidate = summary(true);
        candidate.owner_id = "bob".parse().expect("owner ID");
        assert_eq!(
            diff_proxy_host_previews(Some(&current), &candidate).expect_err("owner mismatch"),
            ProxyHostDiffError::IdentityMismatch
        );

        candidate = summary(true);
        candidate.api_version = "v2";
        assert_eq!(
            diff_proxy_host_previews(Some(&current), &candidate).expect_err("version mismatch"),
            ProxyHostDiffError::UnsupportedVersion
        );

        let encoded = serde_json::to_string(
            &diff_proxy_host_previews(None, &current).expect("creation diff"),
        )
        .expect("serialize diff");
        for forbidden in ["password", "private_key", "api_token", "secret_ref"] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
