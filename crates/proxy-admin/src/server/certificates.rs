use super::*;

pub(super) async fn certificate_objects(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredCertificate>>, ApiError> {
    authorize(&principal, Action::ReadCertificateObjects)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let store = Arc::clone(&state.certificates);
    tokio::task::spawn_blocking(move || store.list(&owner))
        .await
        .map(axum::Json)
        .map_err(|_| ApiError::Internal)
}

pub(super) async fn certificate_object(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<Response, ApiError> {
    authorize(&principal, Action::ReadCertificateObjects)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let store = Arc::clone(&state.certificates);
    let stored = tokio::task::spawn_blocking(move || store.get(&owner, &id))
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    stored_response(stored, StatusCode::OK)
}

pub(super) async fn create_certificate(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::CreateCertificate,
            action: "certificate_create",
            resource_id: "certificate",
            new_revision: None,
        },
    )
    .await?;
    let expected = checked_revision(&state, &headers, &current, &audit).await?;
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let object = parse_owned_certificate(&principal, &body, &audit).await?;
    validate_certificate(&state, &object, &audit).await?;
    if state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let store = Arc::clone(&state.certificates);
    let stored = match tokio::task::spawn_blocking(move || store.create(object)).await {
        Ok(Ok(stored)) => stored,
        Ok(Err(CertificateStoreError::Conflict)) => {
            return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
        }
        Ok(Err(CertificateStoreError::Invalid)) => {
            return Err(
                audited_failure(&audit, "invalid_certificate", ApiError::InvalidRequest).await,
            );
        }
        Ok(Err(
            CertificateStoreError::Indeterminate(_) | CertificateStoreError::RecoveryRequired,
        )) => {
            return Err(audited_failure(
                &audit,
                "certificate_recovery_required",
                ApiError::Unavailable,
            )
            .await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "certificate_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    stored_response(stored, StatusCode::CREATED)
}

pub(super) async fn update_certificate(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::UpdateCertificate,
            action: "certificate_update",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    let expected_revision = checked_revision(&state, &headers, &current, &audit).await?;
    let expected_generation = match expected_object_generation(&headers) {
        Ok(generation) => generation,
        Err(error) => {
            return Err(audited_failure(&audit, "invalid_generation", error).await);
        }
    };
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let object = parse_owned_certificate(&principal, &body, &audit).await?;
    if id.parse::<ObjectId>().ok().as_ref() != Some(&object.metadata.id) {
        return Err(audited_failure(&audit, "invalid_object_id", ApiError::InvalidRequest).await);
    }
    validate_certificate(&state, &object, &audit).await?;
    if state.control.runtime().revision().as_ref() != expected_revision {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let store = Arc::clone(&state.certificates);
    let stored = match tokio::task::spawn_blocking(move || {
        store.update(object, expected_generation)
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(CertificateStoreError::Conflict)) => {
            return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
        }
        Ok(Err(CertificateStoreError::Invalid)) => {
            return Err(
                audited_failure(&audit, "invalid_certificate", ApiError::InvalidRequest).await,
            );
        }
        Ok(Err(
            CertificateStoreError::Indeterminate(_) | CertificateStoreError::RecoveryRequired,
        )) => {
            return Err(audited_failure(
                &audit,
                "certificate_recovery_required",
                ApiError::Unavailable,
            )
            .await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "certificate_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    stored_response(stored, StatusCode::OK)
}

pub(super) async fn delete_certificate(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::DeleteCertificate,
            action: "certificate_delete",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    checked_revision(&state, &headers, &current, &audit).await?;
    let expected_generation = match expected_object_generation(&headers) {
        Ok(generation) => generation,
        Err(error) => {
            return Err(audited_failure(&audit, "invalid_generation", error).await);
        }
    };
    let object_id = match id.parse::<ObjectId>() {
        Ok(id) => id,
        Err(_) => return Err(audited_failure(&audit, "not_found", ApiError::NotFound).await),
    };
    let owner = match principal.owner_id {
        Some(owner) => owner,
        None => return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await),
    };
    let store = Arc::clone(&state.certificates);
    let deleted = match tokio::task::spawn_blocking(move || {
        store.delete(&owner, &object_id, expected_generation)
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(CertificateStoreError::Conflict)) => {
            return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
        }
        Ok(Err(
            CertificateStoreError::Indeterminate(_) | CertificateStoreError::RecoveryRequired,
        )) => {
            return Err(audited_failure(
                &audit,
                "certificate_recovery_required",
                ApiError::Unavailable,
            )
            .await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "certificate_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    Ok(axum::Json(deleted).into_response())
}

pub(super) async fn renew_certificate_object(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<axum::Json<RenewalResponse>, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::RenewCertificate,
            action: "certificate_renew",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    checked_revision(&state, &headers, &current, &audit).await?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let object_id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let store = Arc::clone(&state.certificates);
    let stored = tokio::task::spawn_blocking(move || store.get(&owner, &object_id))
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    let certificate_id = stored.object.spec.certificate_ref.to_string();
    if !state
        .control
        .runtime()
        .config()
        .acme
        .certificates
        .iter()
        .any(|certificate| certificate.id == certificate_id)
    {
        return Err(audited_failure(&audit, "certificate_not_found", ApiError::NotFound).await);
    }
    if state
        .control
        .request_certificate_renewal(&certificate_id)
        .await
        .is_err()
    {
        return Err(audited_failure(&audit, "renewal_failed", ApiError::Unavailable).await);
    }
    audit.record(AuditOutcome::Success, None, None).await?;
    Ok(axum::Json(RenewalResponse { requested: true }))
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

async fn parse_owned_certificate(
    principal: &Principal,
    body: &[u8],
    audit: &MutationAudit,
) -> Result<ApiObject<CertificateSpec>, ApiError> {
    let object = match serde_json::from_slice::<ApiObject<CertificateSpec>>(body) {
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

async fn validate_certificate(
    state: &AppState,
    object: &ApiObject<CertificateSpec>,
    audit: &MutationAudit,
) -> Result<(), ApiError> {
    let active = state.control.runtime().config();
    let object = object.clone();
    match tokio::task::spawn_blocking(move || crate::compile_certificate_metadata(&object, &active))
        .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => {
            Err(audited_failure(audit, "invalid_certificate", ApiError::InvalidRequest).await)
        }
        Err(_) => Err(audited_failure(audit, "compile_failed", ApiError::Internal).await),
    }
}

fn stored_response(stored: StoredCertificate, status: StatusCode) -> Result<Response, ApiError> {
    let generation = stored.generation.to_string();
    let mut response = (status, axum::Json(stored)).into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}
