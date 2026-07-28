use super::super::*;

pub(in crate::server) async fn create_candidate(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<(StatusCode, axum::Json<CandidateResponse>), ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::CreateCandidate,
            action: "config_candidate_create",
            resource_id: "config",
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
    if require_toml(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let config = match load_candidate(body).await {
        Ok(config) => config,
        Err(error) => return Err(audited_failure(&audit, "invalid_config", error).await),
    };
    let store = state.control.revisions();
    let source = format!("admin:{}:{}", principal.actor_type, principal.actor_id);
    let metadata =
        match tokio::task::spawn_blocking(move || store.create_candidate(&config, &source)).await {
            Ok(Ok(metadata)) => metadata,
            Ok(Err(RevisionError::InvalidConfig(_))) => {
                return Err(
                    audited_failure(&audit, "invalid_config", ApiError::InvalidRequest).await,
                );
            }
            Ok(Err(_)) | Err(_) => {
                return Err(
                    audited_failure(&audit, "storage_unavailable", ApiError::Unavailable).await,
                );
            }
        };
    audit
        .record(AuditOutcome::Success, Some(metadata.id.clone()), None)
        .await?;
    Ok((
        StatusCode::CREATED,
        axum::Json(CandidateResponse {
            id: metadata.id,
            hash: metadata.hash,
            sequence: metadata.sequence,
        }),
    ))
}

pub(in crate::server) async fn activate_candidate(
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
        Some(current),
        MutationSpec {
            permission: Action::ActivateConfig,
            action: "config_activate",
            resource_id: &id,
            new_revision: Some(id.clone()),
        },
    )
    .await?;
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    let store = state.control.revisions();
    let candidate_id = id.clone();
    match tokio::task::spawn_blocking(move || store.metadata(&candidate_id)).await {
        Ok(Ok(metadata)) if metadata.binding_hash.is_some() => {
            return Err(
                audited_failure(&audit, "typed_candidate", ApiError::CandidateConflict).await,
            );
        }
        Ok(Ok(_)) => {}
        Ok(Err(RevisionError::InvalidStored(_))) => {
            return Err(audited_failure(&audit, "candidate_not_found", ApiError::NotFound).await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "storage_unavailable", ApiError::Unavailable).await,
            );
        }
    }
    let result = match state
        .control
        .coordinator()
        .activate(&id, Some(&expected))
        .await
    {
        Ok(result) => result,
        Err(error) => {
            let (code, error) = activation_error(error);
            return Err(audited_failure(&audit, code, error).await);
        }
    };
    audit
        .record(AuditOutcome::Success, Some(result.active.clone()), None)
        .await?;
    let mut response = axum::Json(ActivationResponse {
        active: result.active.clone(),
        previous: result.previous,
    })
    .into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&result.active).ok_or(ApiError::Internal)?);
    Ok(response)
}

pub(in crate::server) async fn rollback_revision(
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
            permission: Action::RollbackConfig,
            action: "config_rollback",
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
    let store = state.control.revisions();
    let rollback_id = id.clone();
    let forward = match tokio::task::spawn_blocking(move || {
        if store.metadata(&rollback_id)?.binding_hash.is_some() {
            return Err(RevisionError::Conflict);
        }
        let config = store.load(&rollback_id)?;
        store.create_forward_revision(&config, &format!("rollback:{rollback_id}"))
    })
    .await
    {
        Ok(Ok(metadata)) => metadata,
        Ok(Err(RevisionError::InvalidStored(_))) => {
            return Err(audited_failure(&audit, "revision_not_found", ApiError::NotFound).await);
        }
        Ok(Err(RevisionError::Conflict)) => {
            return Err(
                audited_failure(&audit, "typed_revision", ApiError::CandidateConflict).await,
            );
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "storage_unavailable", ApiError::Unavailable).await,
            );
        }
    };
    let result = match state
        .control
        .coordinator()
        .activate(&forward.id, Some(&expected))
        .await
    {
        Ok(result) => result,
        Err(error) => {
            let (code, error) = activation_error(error);
            return Err(audited_failure(&audit, code, error).await);
        }
    };
    audit
        .record(AuditOutcome::Success, Some(result.active.clone()), None)
        .await?;
    let mut response = axum::Json(ActivationResponse {
        active: result.active.clone(),
        previous: result.previous,
    })
    .into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&result.active).ok_or(ApiError::Internal)?);
    Ok(response)
}

pub(in crate::server) async fn revisions(
    State(state): State<AppState>,
    Query(page): Query<Page>,
    principal: Principal,
) -> Result<axum::Json<RevisionPage>, ApiError> {
    authorize(&principal, Action::ReadRevisions)?;
    let limit = page_limit(&page)?;
    let store = state.control.revisions();
    let mut items = tokio::task::spawn_blocking(move || store.list())
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
    Ok(axum::Json(RevisionPage {
        items,
        next_sequence,
    }))
}

pub(in crate::server) async fn revision(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<axum::Json<RevisionResponse>, ApiError> {
    authorize(&principal, Action::ReadRevisions)?;
    let store = state.control.revisions();
    let result = tokio::task::spawn_blocking(move || {
        let metadata = store.list()?.into_iter().find(|item| item.id == id);
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        let config = store.load(&metadata.id)?;
        let active = store.active()?;
        let status = if active.as_ref().map(|pointer| pointer.active.id.as_str())
            == Some(metadata.id.as_str())
        {
            "active"
        } else if active
            .as_ref()
            .and_then(|pointer| pointer.previous.as_ref())
            .map(|target| target.id.as_str())
            == Some(metadata.id.as_str())
        {
            "previous"
        } else {
            "retained"
        };
        Ok::<_, aegisproxy_config::revision::RevisionError>(Some((metadata, config, status)))
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map_err(|_| ApiError::Unavailable)?
    .ok_or(ApiError::NotFound)?;
    Ok(axum::Json(RevisionResponse {
        metadata: result.0,
        config: aegisproxy_config::redacted(&result.1),
        status: result.2,
    }))
}
