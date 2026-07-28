use super::super::*;

pub(in crate::server) async fn access_policies(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredAccessPolicy>>, ApiError> {
    authorize(&principal, Action::ReadAccessPolicies)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let store = Arc::clone(&state.access_policies);
    tokio::task::spawn_blocking(move || store.list(&owner))
        .await
        .map(axum::Json)
        .map_err(|_| ApiError::Internal)
}

pub(in crate::server) async fn access_policy(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<Response, ApiError> {
    authorize(&principal, Action::ReadAccessPolicies)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let object_id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let store = Arc::clone(&state.access_policies);
    let stored = tokio::task::spawn_blocking(move || store.get(&owner, &object_id))
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    let generation = stored.generation.to_string();
    let mut response = axum::Json(stored).into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}

pub(in crate::server) async fn create_access_policy(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current_revision = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current_revision.clone()),
        MutationSpec {
            permission: Action::CreateAccessPolicy,
            action: "access_policy_create",
            resource_id: "access_policy",
            new_revision: None,
        },
    )
    .await?;
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current_revision != expected || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let object = match serde_json::from_slice::<ApiObject<AccessPolicySpec>>(&body) {
        Ok(object) => object,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    if principal.owner_id.as_ref() != Some(&object.metadata.owner_id) {
        return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await);
    }
    let active = state.control.runtime().config();
    let validation_object = object.clone();
    match tokio::task::spawn_blocking(move || {
        crate::compile_access_policy_metadata(&validation_object, &active)
    })
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            return Err(
                audited_failure(&audit, "invalid_access_policy", ApiError::InvalidRequest).await,
            );
        }
        Err(_) => return Err(audited_failure(&audit, "compile_failed", ApiError::Internal).await),
    }
    if state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let store = Arc::clone(&state.access_policies);
    let stored = match tokio::task::spawn_blocking(move || store.create(object)).await {
        Ok(Ok(stored)) => stored,
        Ok(Err(AccessPolicyStoreError::Conflict)) => {
            return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
        }
        Ok(Err(AccessPolicyStoreError::Invalid)) => {
            return Err(
                audited_failure(&audit, "invalid_access_policy", ApiError::InvalidRequest).await,
            );
        }
        Ok(Err(
            AccessPolicyStoreError::Indeterminate(_) | AccessPolicyStoreError::RecoveryRequired,
        )) => {
            return Err(audited_failure(
                &audit,
                "access_policy_recovery_required",
                ApiError::Unavailable,
            )
            .await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(audited_failure(
                &audit,
                "access_policy_store_failed",
                ApiError::Unavailable,
            )
            .await);
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    let generation = stored.generation.to_string();
    let mut response = (StatusCode::CREATED, axum::Json(stored)).into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}

pub(in crate::server) async fn update_access_policy(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current_revision = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current_revision.clone()),
        MutationSpec {
            permission: Action::UpdateAccessPolicy,
            action: "access_policy_update",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    let expected_revision = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    let expected_generation = match expected_object_generation(&headers) {
        Ok(expected) => expected,
        Err(error) => {
            return Err(audited_failure(&audit, "invalid_generation", error).await);
        }
    };
    if current_revision != expected_revision
        || state.control.runtime().revision().as_ref() != expected_revision
    {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let object = match serde_json::from_slice::<ApiObject<AccessPolicySpec>>(&body) {
        Ok(object) => object,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    let object_id = match id.parse::<ObjectId>() {
        Ok(object_id) if object_id == object.metadata.id => object_id,
        _ => {
            return Err(
                audited_failure(&audit, "invalid_object_id", ApiError::InvalidRequest).await,
            );
        }
    };
    let owner = match principal.owner_id.as_ref() {
        Some(owner) if owner == &object.metadata.owner_id => owner.clone(),
        _ => return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await),
    };
    let store = Arc::clone(&state.access_policies);
    let lookup_id = object_id.clone();
    let existing = match tokio::task::spawn_blocking(move || store.get(&owner, &lookup_id)).await {
        Ok(Some(existing)) => existing,
        Ok(None) => {
            return Err(audited_failure(&audit, "object_not_found", ApiError::NotFound).await);
        }
        Err(_) => {
            return Err(audited_failure(&audit, "object_store_failed", ApiError::Internal).await);
        }
    };
    if existing.generation != expected_generation {
        return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
    }
    let active = state.control.runtime().config();
    let validation_object = object.clone();
    match tokio::task::spawn_blocking(move || {
        crate::compile_access_policy_metadata(&validation_object, &active)
    })
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            return Err(
                audited_failure(&audit, "invalid_access_policy", ApiError::InvalidRequest).await,
            );
        }
        Err(_) => return Err(audited_failure(&audit, "compile_failed", ApiError::Internal).await),
    }
    if state.control.runtime().revision().as_ref() != expected_revision {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let store = Arc::clone(&state.access_policies);
    let stored = match tokio::task::spawn_blocking(move || {
        store.update(object, expected_generation)
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(AccessPolicyStoreError::Conflict)) => {
            return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
        }
        Ok(Err(AccessPolicyStoreError::Invalid)) => {
            return Err(
                audited_failure(&audit, "invalid_access_policy", ApiError::InvalidRequest).await,
            );
        }
        Ok(Err(
            AccessPolicyStoreError::Indeterminate(_) | AccessPolicyStoreError::RecoveryRequired,
        )) => {
            return Err(audited_failure(
                &audit,
                "access_policy_recovery_required",
                ApiError::Unavailable,
            )
            .await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(audited_failure(
                &audit,
                "access_policy_store_failed",
                ApiError::Unavailable,
            )
            .await);
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    let generation = stored.generation.to_string();
    let mut response = axum::Json(stored).into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}

pub(in crate::server) async fn delete_access_policy(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    let current_revision = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current_revision.clone()),
        MutationSpec {
            permission: Action::DeleteAccessPolicy,
            action: "access_policy_delete",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    let expected_revision = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    let expected_generation = match expected_object_generation(&headers) {
        Ok(expected) => expected,
        Err(error) => {
            return Err(audited_failure(&audit, "invalid_generation", error).await);
        }
    };
    if current_revision != expected_revision
        || state.control.runtime().revision().as_ref() != expected_revision
    {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let object_id = match id.parse::<ObjectId>() {
        Ok(object_id) => object_id,
        Err(_) => {
            return Err(audited_failure(&audit, "object_not_found", ApiError::NotFound).await);
        }
    };
    let owner = match principal.owner_id {
        Some(owner) => owner,
        None => return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await),
    };
    let store = Arc::clone(&state.access_policies);
    let lookup_owner = owner.clone();
    let lookup_id = object_id.clone();
    let existing = match tokio::task::spawn_blocking(move || store.get(&lookup_owner, &lookup_id))
        .await
    {
        Ok(Some(existing)) => existing,
        Ok(None) => {
            return Err(audited_failure(&audit, "object_not_found", ApiError::NotFound).await);
        }
        Err(_) => {
            return Err(audited_failure(&audit, "object_store_failed", ApiError::Internal).await);
        }
    };
    if existing.generation != expected_generation {
        return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
    }
    let store = Arc::clone(&state.access_policies);
    let deleted = match tokio::task::spawn_blocking(move || {
        store.delete(&owner, &object_id, expected_generation)
    })
    .await
    {
        Ok(Ok(deleted)) => deleted,
        Ok(Err(AccessPolicyStoreError::Conflict)) => {
            return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
        }
        Ok(Err(
            AccessPolicyStoreError::Indeterminate(_) | AccessPolicyStoreError::RecoveryRequired,
        )) => {
            return Err(audited_failure(
                &audit,
                "access_policy_recovery_required",
                ApiError::Unavailable,
            )
            .await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(audited_failure(
                &audit,
                "access_policy_store_failed",
                ApiError::Unavailable,
            )
            .await);
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    Ok(axum::Json(deleted).into_response())
}
