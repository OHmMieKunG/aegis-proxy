use super::super::*;

pub(in crate::server) async fn audit_records(
    State(state): State<AppState>,
    Query(page): Query<Page>,
    principal: Principal,
) -> Result<axum::Json<AuditPage>, ApiError> {
    authorize(&principal, Action::ReadAudit)?;
    let limit = page_limit(&page)?;
    let audit = state.audit.ok_or(ApiError::Unavailable)?;
    let mut items = tokio::task::spawn_blocking(move || audit.records())
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(|_| ApiError::Unavailable)?;
    if let Some(sequence) = page.after_sequence {
        items.retain(|item| item.sequence > sequence);
    }
    let next_sequence = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|item| item.sequence)
    } else {
        None
    };
    Ok(axum::Json(AuditPage {
        items,
        next_sequence,
    }))
}

pub(in crate::server) async fn list_tokens(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<crate::TokenMetadata>>, ApiError> {
    authorize(&principal, Action::ReadTokens)?;
    Ok(axum::Json(state.tokens.list()))
}

pub(in crate::server) async fn create_token(
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
            permission: Action::CreateToken,
            action: "token_create",
            resource_id: "token",
            new_revision: None,
        },
    )
    .await?;
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current != expected || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let request: TokenCreateRequest = parse_operation_json(&headers, &body, &audit).await?;
    let now = unix_time().ok_or(ApiError::Internal)?;
    if request.expires_unix_secs <= now
        || request.expires_unix_secs > now.saturating_add(MAX_TOKEN_LIFETIME_SECS)
    {
        return Err(audited_failure(&audit, "invalid_expiry", ApiError::InvalidRequest).await);
    }
    let users = Arc::clone(&state.users);
    let user_ref = request.user_ref;
    let user = match tokio::task::spawn_blocking(move || users.get(&user_ref)).await {
        Ok(Some(user)) if user.object.spec.enabled => user,
        Ok(_) => return Err(audited_failure(&audit, "user_not_found", ApiError::NotFound).await),
        Err(_) => {
            return Err(audited_failure(&audit, "user_store_failed", ApiError::Unavailable).await);
        }
    };
    let scopes = match crate::TokenScopes::new(user.object.spec.role, request.scopes) {
        Ok(scopes) => scopes,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_scopes", ApiError::InvalidRequest).await);
        }
    };
    let role = user.object.spec.role;
    let user_ref = user.object.metadata.id;
    let permit = match Arc::clone(&state.auth_permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(audited_failure(&audit, "capacity_exhausted", ApiError::Busy).await),
    };
    let store = Arc::clone(&state.tokens);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store.issue(role, user_ref, scopes, request.expires_unix_secs)
    })
    .await;
    let (metadata, issued) = match result {
        Ok(Ok(issued)) => issued,
        Ok(Err(_)) | Err(_) => {
            return Err(audited_failure(&audit, "token_store_failed", ApiError::Unavailable).await);
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    let plaintext = issued.into_plaintext();
    let body = serde_json::to_vec(&IssuedTokenBody {
        token: plaintext.as_str(),
        metadata: &metadata,
    })
    .map_err(|_| ApiError::Internal)?;
    let mut response = Response::new(axum::body::Body::from(body));
    *response.status_mut() = StatusCode::CREATED;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(response)
}

pub(in crate::server) async fn revoke_token(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<axum::Json<RevocationResponse>, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::RevokeToken,
            action: "token_revoke",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current != expected || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let store = Arc::clone(&state.tokens);
    let revoked = match tokio::task::spawn_blocking(move || store.revoke(&id)).await {
        Ok(Ok(revoked)) => revoked,
        Ok(Err(_)) | Err(_) => {
            return Err(audited_failure(&audit, "token_store_failed", ApiError::Unavailable).await);
        }
    };
    if !revoked {
        return Err(audited_failure(&audit, "token_not_found", ApiError::NotFound).await);
    }
    audit.record(AuditOutcome::Success, None, None).await?;
    Ok(axum::Json(RevocationResponse { revoked }))
}

pub(in crate::server) async fn renew_runtime_certificate(
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
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current != expected || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    if !state
        .control
        .runtime()
        .config()
        .acme
        .certificates
        .iter()
        .any(|certificate| certificate.id == id)
    {
        return Err(audited_failure(&audit, "certificate_not_found", ApiError::NotFound).await);
    }
    if state
        .control
        .request_certificate_renewal(&id)
        .await
        .is_err()
    {
        return Err(audited_failure(&audit, "renewal_failed", ApiError::Unavailable).await);
    }
    audit.record(AuditOutcome::Success, None, None).await?;
    Ok(axum::Json(RenewalResponse { requested: true }))
}

pub(in crate::server) async fn create_backup_archive(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<crate::BackupSummary>, ApiError> {
    let config = state.control.runtime().config();
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::CreateBackup,
            action: "backup_create",
            resource_id: "backup",
            new_revision: None,
        },
    )
    .await?;
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current != expected || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let request: BackupCreateRequest = parse_operation_json(&headers, &body, &audit).await?;
    let output = PathBuf::from(request.output);
    if !valid_api_path(&output) || config.tls.state_encryption_recipients.is_empty() {
        return Err(
            audited_failure(&audit, "invalid_backup_request", ApiError::InvalidRequest).await,
        );
    }
    let state_dir = PathBuf::from(&config.runtime.state_dir);
    let recipients = config.tls.state_encryption_recipients.clone();
    let summary = match tokio::task::spawn_blocking(move || {
        crate::create_backup(state_dir, output, &recipients)
    })
    .await
    {
        Ok(Ok(summary)) => summary,
        Ok(Err(_)) | Err(_) => {
            return Err(audited_failure(&audit, "backup_failed", ApiError::Unavailable).await);
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    Ok(axum::Json(summary))
}

pub(in crate::server) async fn validate_restore_archive(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<crate::BackupSummary>, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::ValidateRestore,
            action: "restore_validate",
            resource_id: "backup",
            new_revision: None,
        },
    )
    .await?;
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current != expected || state.control.runtime().revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let request: RestoreValidateRequest = parse_operation_json(&headers, &body, &audit).await?;
    let input = PathBuf::from(request.input);
    if !valid_api_path(&input) {
        return Err(
            audited_failure(&audit, "invalid_restore_request", ApiError::InvalidRequest).await,
        );
    }
    let summary = match tokio::task::spawn_blocking(move || {
        let identity = SecretRef::parse(&request.identity)
            .and_then(|reference| reference.resolve(4 * 1024))
            .map_err(|_| crate::BackupError::Encryption)?;
        crate::validate_backup(input, identity.as_ref())
    })
    .await
    {
        Ok(Ok(summary)) => summary,
        Ok(Err(_)) | Err(_) => {
            return Err(audited_failure(
                &audit,
                "restore_validation_failed",
                ApiError::InvalidRequest,
            )
            .await);
        }
    };
    audit.record(AuditOutcome::Success, None, None).await?;
    Ok(axum::Json(summary))
}

async fn parse_operation_json<T: serde::de::DeserializeOwned>(
    headers: &HeaderMap,
    body: &[u8],
    audit: &MutationAudit,
) -> Result<T, ApiError> {
    if require_json(headers).is_err() {
        return Err(audited_failure(audit, "invalid_content_type", ApiError::InvalidRequest).await);
    }
    match serde_json::from_slice(body) {
        Ok(request) => Ok(request),
        Err(_) => Err(audited_failure(audit, "invalid_json", ApiError::InvalidRequest).await),
    }
}
