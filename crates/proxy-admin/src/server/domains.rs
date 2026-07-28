use std::fmt::Debug;

use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use super::*;
use crate::typed_store::{StoredObject, TypedStoreError};

trait Domain {
    type Spec: Clone + Debug + DeserializeOwned + Eq + Serialize + Send + 'static;

    const NAME: &'static str;
    const READ: Action;
    const CREATE: Action;
    const UPDATE: Action;
    const DELETE: Action;

    fn list(state: &AppState, owner: &ObjectId) -> Vec<StoredObject<Self::Spec>>;
    fn get(state: &AppState, owner: &ObjectId, id: &ObjectId) -> Option<StoredObject<Self::Spec>>;
    fn all(state: &AppState) -> Result<Vec<StoredObject<Self::Spec>>, TypedStoreError>;
    fn create(
        state: &AppState,
        object: ApiObject<Self::Spec>,
    ) -> Result<StoredObject<Self::Spec>, TypedStoreError>;
    fn update(
        state: &AppState,
        object: ApiObject<Self::Spec>,
        generation: u64,
    ) -> Result<StoredObject<Self::Spec>, TypedStoreError>;
    fn delete(
        state: &AppState,
        owner: &ObjectId,
        id: &ObjectId,
        generation: u64,
    ) -> Result<StoredObject<Self::Spec>, TypedStoreError>;
    fn compile(base: &Config, desired: &[ApiObject<Self::Spec>]) -> Result<Config, ApiError>;
}

struct StreamDomain;

impl Domain for StreamDomain {
    type Spec = StreamHostSpec;

    const NAME: &'static str = "stream_host";
    const READ: Action = Action::ReadStreamHosts;
    const CREATE: Action = Action::CreateStreamHost;
    const UPDATE: Action = Action::UpdateStreamHost;
    const DELETE: Action = Action::DeleteStreamHost;

    fn list(state: &AppState, owner: &ObjectId) -> Vec<StoredStreamHost> {
        state.stream_hosts.list(owner)
    }

    fn get(state: &AppState, owner: &ObjectId, id: &ObjectId) -> Option<StoredStreamHost> {
        state.stream_hosts.get(owner, id)
    }

    fn all(state: &AppState) -> Result<Vec<StoredStreamHost>, TypedStoreError> {
        state.stream_hosts.all()
    }

    fn create(
        state: &AppState,
        object: ApiObject<StreamHostSpec>,
    ) -> Result<StoredStreamHost, TypedStoreError> {
        state.stream_hosts.create(object)
    }

    fn update(
        state: &AppState,
        object: ApiObject<StreamHostSpec>,
        generation: u64,
    ) -> Result<StoredStreamHost, TypedStoreError> {
        state.stream_hosts.update(object, generation)
    }

    fn delete(
        state: &AppState,
        owner: &ObjectId,
        id: &ObjectId,
        generation: u64,
    ) -> Result<StoredStreamHost, TypedStoreError> {
        state.stream_hosts.delete(owner, id, generation)
    }

    fn compile(base: &Config, desired: &[ApiObject<StreamHostSpec>]) -> Result<Config, ApiError> {
        crate::compile_stream_hosts(base, &[], desired).map_err(|_| ApiError::InvalidRequest)
    }
}

struct DiscoveryDomain;

impl Domain for DiscoveryDomain {
    type Spec = DiscoverySourceSpec;

    const NAME: &'static str = "discovery_source";
    const READ: Action = Action::ReadDiscoverySources;
    const CREATE: Action = Action::CreateDiscoverySource;
    const UPDATE: Action = Action::UpdateDiscoverySource;
    const DELETE: Action = Action::DeleteDiscoverySource;

    fn list(state: &AppState, owner: &ObjectId) -> Vec<StoredDiscoverySource> {
        state.discovery_sources.list(owner)
    }

    fn get(state: &AppState, owner: &ObjectId, id: &ObjectId) -> Option<StoredDiscoverySource> {
        state.discovery_sources.get(owner, id)
    }

    fn all(state: &AppState) -> Result<Vec<StoredDiscoverySource>, TypedStoreError> {
        state.discovery_sources.all()
    }

    fn create(
        state: &AppState,
        object: ApiObject<DiscoverySourceSpec>,
    ) -> Result<StoredDiscoverySource, TypedStoreError> {
        state.discovery_sources.create(object)
    }

    fn update(
        state: &AppState,
        object: ApiObject<DiscoverySourceSpec>,
        generation: u64,
    ) -> Result<StoredDiscoverySource, TypedStoreError> {
        state.discovery_sources.update(object, generation)
    }

    fn delete(
        state: &AppState,
        owner: &ObjectId,
        id: &ObjectId,
        generation: u64,
    ) -> Result<StoredDiscoverySource, TypedStoreError> {
        state.discovery_sources.delete(owner, id, generation)
    }

    fn compile(
        base: &Config,
        desired: &[ApiObject<DiscoverySourceSpec>],
    ) -> Result<Config, ApiError> {
        crate::compile_discovery_sources(base, &[], desired).map_err(|_| ApiError::InvalidRequest)
    }
}

#[derive(Debug, Serialize)]
struct DomainMutation<T> {
    object: StoredObject<T>,
    candidate: CandidateResponse,
}

#[derive(Debug, Serialize)]
pub(super) struct DomainValidation {
    valid: bool,
}

pub(super) async fn stream_hosts(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredStreamHost>>, ApiError> {
    list::<StreamDomain>(state, principal).await
}

pub(super) async fn stream_host(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<Response, ApiError> {
    get::<StreamDomain>(state, principal, id).await
}

pub(super) async fn create_stream_host(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    create::<StreamDomain>(state, request_id, headers, principal, body).await
}

pub(super) async fn update_stream_host(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    update::<StreamDomain>(state, request_id, headers, principal, id, body).await
}

pub(super) async fn delete_stream_host(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    delete::<StreamDomain>(state, request_id, headers, principal, id).await
}

pub(super) async fn validate_stream_host(
    State(state): State<AppState>,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<DomainValidation>, ApiError> {
    validate_domain::<StreamDomain>(state, principal, body).await
}

pub(super) async fn preview_stream_host(
    State(state): State<AppState>,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<PreviewResponse>, ApiError> {
    preview_domain::<StreamDomain>(state, principal, body).await
}

pub(super) async fn discovery_sources(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredDiscoverySource>>, ApiError> {
    list::<DiscoveryDomain>(state, principal).await
}

pub(super) async fn discovery_source(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<Response, ApiError> {
    get::<DiscoveryDomain>(state, principal, id).await
}

pub(super) async fn create_discovery_source(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    create::<DiscoveryDomain>(state, request_id, headers, principal, body).await
}

pub(super) async fn update_discovery_source(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    update::<DiscoveryDomain>(state, request_id, headers, principal, id, body).await
}

pub(super) async fn delete_discovery_source(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    delete::<DiscoveryDomain>(state, request_id, headers, principal, id).await
}

pub(super) async fn validate_discovery_source(
    State(state): State<AppState>,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<DomainValidation>, ApiError> {
    validate_domain::<DiscoveryDomain>(state, principal, body).await
}

pub(super) async fn preview_discovery_source(
    State(state): State<AppState>,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<PreviewResponse>, ApiError> {
    preview_domain::<DiscoveryDomain>(state, principal, body).await
}

async fn list<D: Domain>(
    state: AppState,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredObject<D::Spec>>>, ApiError> {
    authorize(&principal, D::READ)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    tokio::task::spawn_blocking(move || D::list(&state, &owner))
        .await
        .map(axum::Json)
        .map_err(|_| ApiError::Internal)
}

async fn get<D: Domain>(
    state: AppState,
    principal: Principal,
    id: String,
) -> Result<Response, ApiError> {
    authorize(&principal, D::READ)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let stored = tokio::task::spawn_blocking(move || D::get(&state, &owner, &id))
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    stored_response(stored, StatusCode::OK)
}

async fn create<D: Domain>(
    state: AppState,
    request_id: RequestId,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_domain_mutation(
        &state,
        &principal,
        &request_id,
        &current,
        D::CREATE,
        D::NAME,
    )
    .await?;
    let expected = checked_revision(&state, &headers, &current, &audit).await?;
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let object = parse_owned::<D>(&principal, &body, &audit).await?;
    let mut desired = all_objects::<D>(&state, &audit).await?;
    desired.push(object.clone());
    let candidate = create_candidate::<D>(&state, &principal, &audit, &expected, desired).await?;
    let state_for_store = state.clone();
    let stored =
        match tokio::task::spawn_blocking(move || D::create(&state_for_store, object)).await {
            Ok(Ok(stored)) => stored,
            Ok(Err(error)) => return Err(map_store_error(&audit, error).await),
            Err(_) => {
                return Err(audited_failure(&audit, "store_failed", ApiError::Unavailable).await);
            }
        };
    audit
        .record(AuditOutcome::Success, Some(candidate.id.clone()), None)
        .await?;
    mutation_response(stored, candidate, StatusCode::CREATED)
}

async fn update<D: Domain>(
    state: AppState,
    request_id: RequestId,
    headers: HeaderMap,
    principal: Principal,
    id: String,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit =
        begin_domain_mutation(&state, &principal, &request_id, &current, D::UPDATE, &id).await?;
    let expected = checked_revision(&state, &headers, &current, &audit).await?;
    let generation = checked_generation(&headers, &audit).await?;
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let object = parse_owned::<D>(&principal, &body, &audit).await?;
    if id.parse::<ObjectId>().ok().as_ref() != Some(&object.metadata.id) {
        return Err(audited_failure(&audit, "invalid_object_id", ApiError::InvalidRequest).await);
    }
    let owner = object.metadata.owner_id.clone();
    let object_id = object.metadata.id.clone();
    let state_for_lookup = state.clone();
    let existing =
        tokio::task::spawn_blocking(move || D::get(&state_for_lookup, &owner, &object_id))
            .await
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::NotFound)?;
    if existing.generation != generation {
        return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
    }
    let mut desired = all_objects::<D>(&state, &audit).await?;
    let Some(slot) = desired
        .iter_mut()
        .find(|stored| stored.metadata.id == object.metadata.id)
    else {
        return Err(audited_failure(&audit, "not_found", ApiError::NotFound).await);
    };
    *slot = object.clone();
    let candidate = create_candidate::<D>(&state, &principal, &audit, &expected, desired).await?;
    let state_for_store = state.clone();
    let stored =
        match tokio::task::spawn_blocking(move || D::update(&state_for_store, object, generation))
            .await
        {
            Ok(Ok(stored)) => stored,
            Ok(Err(error)) => return Err(map_store_error(&audit, error).await),
            Err(_) => {
                return Err(audited_failure(&audit, "store_failed", ApiError::Unavailable).await);
            }
        };
    audit
        .record(AuditOutcome::Success, Some(candidate.id.clone()), None)
        .await?;
    mutation_response(stored, candidate, StatusCode::OK)
}

async fn delete<D: Domain>(
    state: AppState,
    request_id: RequestId,
    headers: HeaderMap,
    principal: Principal,
    id: String,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit =
        begin_domain_mutation(&state, &principal, &request_id, &current, D::DELETE, &id).await?;
    let expected = checked_revision(&state, &headers, &current, &audit).await?;
    let generation = checked_generation(&headers, &audit).await?;
    let owner = principal.owner_id.clone().ok_or(ApiError::Forbidden)?;
    let object_id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let state_for_lookup = state.clone();
    let lookup_owner = owner.clone();
    let lookup_id = object_id.clone();
    let existing =
        tokio::task::spawn_blocking(move || D::get(&state_for_lookup, &lookup_owner, &lookup_id))
            .await
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::NotFound)?;
    if existing.generation != generation {
        return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
    }
    let mut desired = all_objects::<D>(&state, &audit).await?;
    let before = desired.len();
    desired.retain(|object| object.metadata.id != object_id);
    if desired.len() == before {
        return Err(audited_failure(&audit, "not_found", ApiError::NotFound).await);
    }
    let candidate = create_candidate::<D>(&state, &principal, &audit, &expected, desired).await?;
    let state_for_store = state.clone();
    let deleted = match tokio::task::spawn_blocking(move || {
        D::delete(&state_for_store, &owner, &object_id, generation)
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(error)) => return Err(map_store_error(&audit, error).await),
        Err(_) => {
            return Err(audited_failure(&audit, "store_failed", ApiError::Unavailable).await);
        }
    };
    audit
        .record(AuditOutcome::Success, Some(candidate.id.clone()), None)
        .await?;
    mutation_response(deleted, candidate, StatusCode::OK)
}

async fn validate_domain<D: Domain>(
    state: AppState,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<DomainValidation>, ApiError> {
    authorize(&principal, Action::ValidateConfig)?;
    compile_request::<D>(&state, &principal, &body)
        .await
        .map(|_| axum::Json(DomainValidation { valid: true }))
}

async fn preview_domain<D: Domain>(
    state: AppState,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<PreviewResponse>, ApiError> {
    authorize(&principal, Action::PreviewConfig)?;
    let candidate = compile_request::<D>(&state, &principal, &body).await?;
    let runtime = state.control.runtime();
    let active = runtime.config();
    let activation_class = if runtime.can_hot_reload(&candidate) {
        "hot_reload"
    } else {
        "restart_required"
    };
    Ok(axum::Json(PreviewResponse {
        active_revision: runtime.revision().to_string(),
        active_route_fingerprint: format!("{:016x}", RouteIndex::compile(&active).fingerprint()),
        candidate_route_fingerprint: format!(
            "{:016x}",
            RouteIndex::compile(&candidate).fingerprint()
        ),
        activation_class,
        config: aegisproxy_config::redacted(&candidate),
    }))
}

async fn compile_request<D: Domain>(
    state: &AppState,
    principal: &Principal,
    body: &[u8],
) -> Result<Config, ApiError> {
    let object =
        serde_json::from_slice::<ApiObject<D::Spec>>(body).map_err(|_| ApiError::InvalidRequest)?;
    if principal.owner_id.as_ref() != Some(&object.metadata.owner_id) {
        return Err(ApiError::Forbidden);
    }
    let mut desired = D::all(state)
        .map_err(|_| ApiError::Unavailable)?
        .into_iter()
        .map(|stored| stored.object)
        .collect::<Vec<_>>();
    if let Some(existing) = desired
        .iter_mut()
        .find(|existing| existing.metadata.id == object.metadata.id)
    {
        *existing = object;
    } else {
        desired.push(object);
    }
    D::compile(&state.control.runtime().config(), &desired)
}

async fn create_candidate<D: Domain>(
    state: &AppState,
    principal: &Principal,
    audit: &MutationAudit,
    expected: &str,
    mut desired: Vec<ApiObject<D::Spec>>,
) -> Result<CandidateResponse, ApiError> {
    desired.sort_by(|left, right| {
        (&left.metadata.owner_id, &left.metadata.id)
            .cmp(&(&right.metadata.owner_id, &right.metadata.id))
    });
    let active = state.control.runtime().config();
    let desired_for_compile = desired.clone();
    let (config, binding_hash) = tokio::task::spawn_blocking(move || {
        let config = D::compile(&active, &desired_for_compile)?;
        let mut digest = Sha256::new();
        digest.update(D::NAME.as_bytes());
        digest.update([0]);
        digest.update(serde_json::to_vec(&desired_for_compile).map_err(|_| ApiError::Internal)?);
        Ok::<_, ApiError>((config, format!("{:x}", digest.finalize())))
    })
    .await
    .map_err(|_| ApiError::Internal)??;
    if state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(audit, "revision_conflict", ApiError::Conflict).await);
    }
    let store = state.control.revisions();
    let source = format!("typed:{}:{}", D::NAME, principal.actor_id);
    let metadata = match tokio::task::spawn_blocking(move || {
        store.create_bound_candidate(&config, &source, &binding_hash)
    })
    .await
    {
        Ok(Ok(metadata)) => metadata,
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(audit, "revision_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    Ok(CandidateResponse {
        id: metadata.id,
        hash: metadata.hash,
        sequence: metadata.sequence,
    })
}

async fn all_objects<D: Domain>(
    state: &AppState,
    audit: &MutationAudit,
) -> Result<Vec<ApiObject<D::Spec>>, ApiError> {
    match D::all(state) {
        Ok(stored) => Ok(stored.into_iter().map(|stored| stored.object).collect()),
        Err(_) => Err(audited_failure(audit, "store_failed", ApiError::Unavailable).await),
    }
}

async fn parse_owned<D: Domain>(
    principal: &Principal,
    body: &[u8],
    audit: &MutationAudit,
) -> Result<ApiObject<D::Spec>, ApiError> {
    let object = match serde_json::from_slice::<ApiObject<D::Spec>>(body) {
        Ok(object) => object,
        Err(_) => {
            return Err(audited_failure(audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    if principal.owner_id.as_ref() != Some(&object.metadata.owner_id) {
        return Err(audited_failure(audit, "owner_denied", ApiError::Forbidden).await);
    }
    Ok(object)
}

async fn begin_domain_mutation(
    state: &AppState,
    principal: &Principal,
    request_id: &RequestId,
    current: &str,
    permission: Action,
    resource: &str,
) -> Result<MutationAudit, ApiError> {
    begin_mutation(
        state,
        principal,
        request_id,
        Some(current.into()),
        MutationSpec {
            permission,
            action: resource,
            resource_id: resource,
            new_revision: None,
        },
    )
    .await
}

async fn checked_revision(
    state: &AppState,
    headers: &HeaderMap,
    current: &str,
    audit: &MutationAudit,
) -> Result<String, ApiError> {
    let expected = match expected_revision(headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(audit, "invalid_if_match", error).await),
    };
    if current != expected || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(audit, "revision_conflict", ApiError::Conflict).await);
    }
    Ok(expected)
}

async fn checked_generation(headers: &HeaderMap, audit: &MutationAudit) -> Result<u64, ApiError> {
    match expected_object_generation(headers) {
        Ok(generation) => Ok(generation),
        Err(error) => Err(audited_failure(audit, "invalid_generation", error).await),
    }
}

async fn map_store_error(audit: &MutationAudit, error: TypedStoreError) -> ApiError {
    match error {
        TypedStoreError::Conflict => {
            audited_failure(audit, "object_conflict", ApiError::ObjectConflict).await
        }
        TypedStoreError::Invalid => {
            audited_failure(audit, "invalid_object", ApiError::InvalidRequest).await
        }
        TypedStoreError::Indeterminate(_) | TypedStoreError::RecoveryRequired => {
            audited_failure(audit, "recovery_required", ApiError::Unavailable).await
        }
        _ => audited_failure(audit, "store_failed", ApiError::Unavailable).await,
    }
}

fn stored_response<T: Serialize>(
    stored: StoredObject<T>,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let generation = stored.generation.to_string();
    let mut response = (status, axum::Json(stored)).into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}

fn mutation_response<T: Serialize>(
    object: StoredObject<T>,
    candidate: CandidateResponse,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let generation = object.generation.to_string();
    let mut response = (status, axum::Json(DomainMutation { object, candidate })).into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}
