use super::*;
use crate::{ApiVersion, ObjectMetadata};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    #[serde(rename = "api_version")]
    _api_version: ApiVersion,
    metadata: ObjectMetadata,
    spec: CredentialRequestSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequestSpec {
    label: String,
    enabled: bool,
    expires_unix_secs: Option<u64>,
    value: Option<String>,
}

pub(super) async fn credentials(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredCredential>>, ApiError> {
    authorize(&principal, Action::ReadCredentials)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let store = Arc::clone(&state.credentials);
    tokio::task::spawn_blocking(move || store.list(&owner))
        .await
        .map(axum::Json)
        .map_err(|_| ApiError::Internal)
}

pub(super) async fn credential(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<Response, ApiError> {
    authorize(&principal, Action::ReadCredentials)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let store = Arc::clone(&state.credentials);
    let stored = tokio::task::spawn_blocking(move || store.get(&owner, &id))
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    credential_response(stored, StatusCode::OK)
}

pub(super) async fn create_credential(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_credential_mutation(
        &state,
        &principal,
        &request_id,
        &current,
        Action::CreateCredential,
        "credential_create",
        "credential",
    )
    .await?;
    checked_credential_revision(&state, &headers, &current, &audit).await?;
    let request = parse_credential(&headers, &principal, &body, &audit, true).await?;
    let value = Zeroizing::new(request.spec.value.expect("required").into_bytes());
    let store = Arc::clone(&state.credentials);
    let stored = match tokio::task::spawn_blocking(move || {
        store.create(
            request.metadata,
            request.spec.label,
            request.spec.enabled,
            request.spec.expires_unix_secs,
            value,
        )
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(error)) => return Err(credential_error(&audit, error).await),
        Err(_) => {
            return Err(audited_failure(&audit, "store_failed", ApiError::Unavailable).await);
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    credential_response(stored, StatusCode::CREATED)
}

pub(super) async fn update_credential(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_credential_mutation(
        &state,
        &principal,
        &request_id,
        &current,
        Action::UpdateCredential,
        "credential_update",
        &id,
    )
    .await?;
    checked_credential_revision(&state, &headers, &current, &audit).await?;
    let generation = match expected_object_generation(&headers) {
        Ok(generation) => generation,
        Err(error) => return Err(audited_failure(&audit, "invalid_generation", error).await),
    };
    let request = parse_credential(&headers, &principal, &body, &audit, false).await?;
    let object_id = match id.parse::<ObjectId>() {
        Ok(id) => id,
        Err(_) => return Err(audited_failure(&audit, "not_found", ApiError::NotFound).await),
    };
    if object_id != request.metadata.id {
        return Err(audited_failure(&audit, "invalid_object_id", ApiError::InvalidRequest).await);
    }
    let owner = request.metadata.owner_id;
    let value = request
        .spec
        .value
        .map(String::into_bytes)
        .map(Zeroizing::new);
    let store = Arc::clone(&state.credentials);
    let stored = match tokio::task::spawn_blocking(move || {
        store.replace(
            &owner,
            &object_id,
            generation,
            CredentialReplacement {
                label: request.spec.label,
                enabled: request.spec.enabled,
                expires_unix_secs: request.spec.expires_unix_secs,
                plaintext: value,
            },
        )
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(error)) => return Err(credential_error(&audit, error).await),
        Err(_) => {
            return Err(audited_failure(&audit, "store_failed", ApiError::Unavailable).await);
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    credential_response(stored, StatusCode::OK)
}

pub(super) async fn revoke_credential(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_credential_mutation(
        &state,
        &principal,
        &request_id,
        &current,
        Action::RevokeCredential,
        "credential_revoke",
        &id,
    )
    .await?;
    checked_credential_revision(&state, &headers, &current, &audit).await?;
    let generation = match expected_object_generation(&headers) {
        Ok(generation) => generation,
        Err(error) => return Err(audited_failure(&audit, "invalid_generation", error).await),
    };
    let owner = match principal.owner_id {
        Some(owner) => owner,
        None => return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await),
    };
    let id = match id.parse::<ObjectId>() {
        Ok(id) => id,
        Err(_) => return Err(audited_failure(&audit, "not_found", ApiError::NotFound).await),
    };
    let store = Arc::clone(&state.credentials);
    let stored =
        match tokio::task::spawn_blocking(move || store.revoke(&owner, &id, generation)).await {
            Ok(Ok(stored)) => stored,
            Ok(Err(error)) => return Err(credential_error(&audit, error).await),
            Err(_) => {
                return Err(audited_failure(&audit, "store_failed", ApiError::Unavailable).await);
            }
        };
    audit.record(AuditOutcome::Success, None, None).await?;
    credential_response(stored, StatusCode::OK)
}

async fn begin_credential_mutation(
    state: &AppState,
    principal: &Principal,
    request_id: &RequestId,
    current: &str,
    permission: Action,
    action: &str,
    resource_id: &str,
) -> Result<MutationAudit, ApiError> {
    begin_mutation(
        state,
        principal,
        request_id,
        Some(current.into()),
        MutationSpec {
            permission,
            action,
            resource_id,
            new_revision: None,
        },
    )
    .await
}

async fn checked_credential_revision(
    state: &AppState,
    headers: &HeaderMap,
    current: &str,
    audit: &MutationAudit,
) -> Result<(), ApiError> {
    let expected = match expected_revision(headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(audit, "invalid_if_match", error).await),
    };
    if expected != current || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(audit, "revision_conflict", ApiError::Conflict).await);
    }
    Ok(())
}

async fn parse_credential(
    headers: &HeaderMap,
    principal: &Principal,
    body: &[u8],
    audit: &MutationAudit,
    require_value: bool,
) -> Result<CredentialRequest, ApiError> {
    if require_json(headers).is_err() {
        return Err(audited_failure(audit, "invalid_content_type", ApiError::InvalidRequest).await);
    }
    let request = match serde_json::from_slice::<CredentialRequest>(body) {
        Ok(request) => request,
        Err(_) => {
            return Err(audited_failure(audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    if principal.owner_id.as_ref() != Some(&request.metadata.owner_id) {
        return Err(audited_failure(audit, "owner_denied", ApiError::Forbidden).await);
    }
    if require_value && request.spec.value.is_none() {
        return Err(audited_failure(audit, "missing_value", ApiError::InvalidRequest).await);
    }
    Ok(request)
}

async fn credential_error(audit: &MutationAudit, error: CredentialStoreError) -> ApiError {
    match error {
        CredentialStoreError::Store(crate::typed_store::TypedStoreError::Conflict) => {
            audited_failure(audit, "object_conflict", ApiError::ObjectConflict).await
        }
        CredentialStoreError::Invalid | CredentialStoreError::Limit => {
            audited_failure(audit, "invalid_credential", ApiError::InvalidRequest).await
        }
        CredentialStoreError::Store(_) => {
            audited_failure(audit, "store_failed", ApiError::Unavailable).await
        }
    }
}

fn credential_response(stored: StoredCredential, status: StatusCode) -> Result<Response, ApiError> {
    let generation = stored.generation.to_string();
    let mut response = (status, axum::Json(stored)).into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}
