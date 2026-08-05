use super::*;

async fn access_policy_metadata(
    state: &AppState,
    config: Arc<Config>,
    policy_id: Option<ObjectId>,
) -> Result<BTreeMap<ObjectId, AccessPolicyMetadata>, ApiError> {
    let Some(policy_id) = policy_id else {
        return Ok(BTreeMap::new());
    };
    let store = Arc::clone(&state.access_policies);
    let lookup_id = policy_id.clone();
    match tokio::task::spawn_blocking(move || store.metadata_for(&config, &lookup_id)).await {
        Ok(Ok(metadata)) => Ok(metadata
            .map(|metadata| BTreeMap::from([(policy_id, metadata)]))
            .unwrap_or_default()),
        Ok(Err(AccessPolicyStoreError::RecoveryRequired)) => Err(ApiError::Unavailable),
        Ok(Err(AccessPolicyStoreError::Invalid)) => Err(ApiError::InvalidRequest),
        Ok(Err(_)) | Err(_) => Err(ApiError::Internal),
    }
}

pub(super) async fn access_policy_dependencies(
    state: &AppState,
    config: Arc<Config>,
    objects: &[ApiObject<ProxyHostSpec>],
) -> Result<
    (
        Vec<StoredAccessPolicy>,
        BTreeMap<ObjectId, AccessPolicyMetadata>,
    ),
    ApiError,
> {
    let ids = objects
        .iter()
        .flat_map(|object| {
            object
                .spec
                .access_policy_ref
                .iter()
                .chain(
                    object
                        .spec
                        .locations
                        .iter()
                        .filter_map(|location| location.access_policy_ref.as_ref()),
                )
                .map(|reference| reference.id().clone())
        })
        .collect::<BTreeSet<_>>();
    if ids.is_empty() {
        return Ok((Vec::new(), BTreeMap::new()));
    }
    let store = Arc::clone(&state.access_policies);
    match tokio::task::spawn_blocking(move || store.candidate_dependencies(&config, &ids)).await {
        Ok(Ok(dependencies)) => Ok(dependencies),
        Ok(Err(AccessPolicyStoreError::RecoveryRequired)) => Err(ApiError::Unavailable),
        Ok(Err(AccessPolicyStoreError::Invalid)) => Err(ApiError::InvalidRequest),
        Ok(Err(_)) | Err(_) => Err(ApiError::Internal),
    }
}

async fn certificate_metadata(
    state: &AppState,
    config: Arc<Config>,
    required: bool,
) -> Result<BTreeMap<ObjectId, crate::CertificateMetadata>, ApiError> {
    if !required {
        return Ok(BTreeMap::new());
    }
    let store = Arc::clone(&state.certificates);
    match tokio::task::spawn_blocking(move || store.metadata(&config)).await {
        Ok(Ok(metadata)) => Ok(metadata),
        Ok(Err(CertificateStoreError::RecoveryRequired)) => Err(ApiError::Unavailable),
        Ok(Err(CertificateStoreError::Invalid)) => Err(ApiError::InvalidRequest),
        Ok(Err(_)) | Err(_) => Err(ApiError::Internal),
    }
}

mod access_policies;
mod config;
mod health;
mod operations;
mod proxy_hosts;
mod runtime;

pub(super) use access_policies::*;
pub(super) use config::*;
pub(super) use health::*;
pub(super) use operations::*;
pub(super) use proxy_hosts::*;
pub(super) use runtime::*;
