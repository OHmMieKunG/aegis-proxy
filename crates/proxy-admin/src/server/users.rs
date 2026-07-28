use super::*;

pub(super) async fn users(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredUser>>, ApiError> {
    authorize(&principal, Action::ReadUsers)?;
    let store = Arc::clone(&state.users);
    tokio::task::spawn_blocking(move || store.all())
        .await
        .map_err(|_| ApiError::Internal)?
        .map(axum::Json)
        .map_err(|_| ApiError::Unavailable)
}

pub(super) async fn user(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<Response, ApiError> {
    authorize(&principal, Action::ReadUsers)?;
    let id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let store = Arc::clone(&state.users);
    let stored = tokio::task::spawn_blocking(move || store.get(&id))
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    user_response(stored, StatusCode::OK)
}

pub(super) async fn roles(principal: Principal) -> Result<axum::Json<[Role; 4]>, ApiError> {
    authorize(&principal, Action::ReadRoles)?;
    Ok(axum::Json([
        Role::Viewer,
        Role::Auditor,
        Role::Operator,
        Role::Admin,
    ]))
}

pub(super) async fn create_user(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    mutate_user(state, request_id, headers, principal, None, body).await
}

pub(super) async fn update_user(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    mutate_user(state, request_id, headers, principal, Some(id), body).await
}

async fn mutate_user(
    state: AppState,
    request_id: RequestId,
    headers: HeaderMap,
    principal: Principal,
    id: Option<String>,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let (permission, action, resource) = match id.as_deref() {
        Some(id) => (Action::UpdateUser, "user_update", id),
        None => (Action::CreateUser, "user_create", "user"),
    };
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission,
            action,
            resource_id: resource,
            new_revision: None,
        },
    )
    .await?;
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if expected != current || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let object = match serde_json::from_slice::<ApiObject<UserSpec>>(&body) {
        Ok(object) => object,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    let store = Arc::clone(&state.users);
    let (stored, status) = match id {
        None => match tokio::task::spawn_blocking(move || store.create(object)).await {
            Ok(Ok(stored)) => (stored, StatusCode::CREATED),
            Ok(Err(error)) => return Err(map_user_store_error(&audit, error).await),
            Err(_) => {
                return Err(audited_failure(&audit, "user_store_failed", ApiError::Internal).await);
            }
        },
        Some(id) => {
            let generation = match expected_object_generation(&headers) {
                Ok(generation) => generation,
                Err(error) => {
                    return Err(audited_failure(&audit, "invalid_generation", error).await);
                }
            };
            if id.parse::<ObjectId>().ok().as_ref() != Some(&object.metadata.id) {
                return Err(
                    audited_failure(&audit, "invalid_object_id", ApiError::InvalidRequest).await,
                );
            }
            let object_id = object.metadata.id.clone();
            let lookup = Arc::clone(&store);
            match tokio::task::spawn_blocking(move || lookup.get(&object_id)).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(
                        audited_failure(&audit, "user_not_found", ApiError::NotFound).await,
                    );
                }
                Err(_) => {
                    return Err(
                        audited_failure(&audit, "user_store_failed", ApiError::Internal).await,
                    );
                }
            }
            match tokio::task::spawn_blocking(move || store.update(object, generation)).await {
                Ok(Ok(stored)) => (stored, StatusCode::OK),
                Ok(Err(error)) => return Err(map_user_store_error(&audit, error).await),
                Err(_) => {
                    return Err(
                        audited_failure(&audit, "user_store_failed", ApiError::Internal).await,
                    );
                }
            }
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    user_response(stored, status)
}

async fn map_user_store_error(audit: &MutationAudit, error: UserStoreError) -> ApiError {
    let (code, error) = user_store_error_contract(&error);
    audited_failure(audit, code, error).await
}

pub(super) fn user_store_error_contract(error: &UserStoreError) -> (&'static str, ApiError) {
    match error {
        UserStoreError::Conflict => ("object_conflict", ApiError::ObjectConflict),
        UserStoreError::Invalid => ("invalid_user", ApiError::InvalidRequest),
        UserStoreError::Limit => ("user_store_limit", ApiError::Busy),
        UserStoreError::Io(_)
        | UserStoreError::Indeterminate(_)
        | UserStoreError::RecoveryRequired
        | UserStoreError::Locked => ("user_store_failed", ApiError::Unavailable),
    }
}

fn user_response(stored: StoredUser, status: StatusCode) -> Result<Response, ApiError> {
    let generation = stored.generation.to_string();
    let mut response = (status, axum::Json(stored)).into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}
