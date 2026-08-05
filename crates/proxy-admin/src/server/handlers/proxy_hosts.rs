use super::super::*;
use super::{access_policy_metadata, certificate_metadata};

pub(in crate::server) async fn validate_proxy_host(
    State(state): State<AppState>,
    ValidateProxyHostPrincipal(principal): ValidateProxyHostPrincipal,
    payload: Result<Json<ApiObject<ProxyHostSpec>>, JsonRejection>,
) -> Result<axum::Json<ProxyHostValidationResponse>, ApiError> {
    let prepared = prepare_proxy_host_request(&state, &principal, payload).await?;
    Ok(axum::Json(ProxyHostValidationResponse {
        valid: true,
        summary: prepared.preview.summary,
    }))
}

pub(in crate::server) async fn proxy_hosts(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredProxyHost>>, ApiError> {
    authorize(&principal, Action::ReadProxyHosts)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let store = Arc::clone(&state.proxy_hosts);
    tokio::task::spawn_blocking(move || store.list(&owner))
        .await
        .map(axum::Json)
        .map_err(|_| ApiError::Internal)
}

pub(in crate::server) async fn proxy_host_application_state(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<ProxyHostApplicationState>, ApiError> {
    authorize(&principal, Action::ReadProxyHosts)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let active_revision = state.control.runtime().revision().to_string();
    let store = Arc::clone(&state.proxy_hosts);
    let revisions = state.control.revisions();
    let owner_for_load = owner.clone();
    let active_for_load = active_revision.clone();
    let (desired, drafts, active, active_state_known, recovery_required) =
        tokio::task::spawn_blocking(move || {
            let desired = store.list(&owner_for_load);
            let drafts = store.list_drafts(&owner_for_load);
            let metadata = revisions
                .metadata(&active_for_load)
                .map_err(|_| ProxyHostStoreError::Invalid)?;
            let active_state_known = metadata.binding_hash.is_some();
            let active = match metadata.binding_hash.as_deref() {
                Some(hash) => store
                    .load_candidate(&active_for_load, hash)?
                    .objects()
                    .iter()
                    .filter(|object| object.metadata.owner_id == owner_for_load)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };
            Ok::<_, ProxyHostStoreError>((
                desired,
                drafts,
                active,
                active_state_known,
                store.recovery_required(),
            ))
        })
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(|_| ApiError::Unavailable)?;
    let desired = desired
        .into_iter()
        .map(|stored| (stored.object.metadata.id.clone(), stored.object))
        .collect::<BTreeMap<_, _>>();
    let drafts = drafts
        .into_iter()
        .map(|stored| stored.object.metadata.id)
        .collect::<BTreeSet<_>>();
    let active = active
        .into_iter()
        .map(|object| (object.metadata.id.clone(), object))
        .collect::<BTreeMap<_, _>>();
    let ids = desired
        .keys()
        .chain(drafts.iter())
        .chain(active.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    Ok(axum::Json(ProxyHostApplicationState {
        active_revision,
        recovery_required,
        active_state_known,
        objects: ids
            .into_iter()
            .map(|object_id| ProxyHostApplicationEntry {
                desired: desired.contains_key(&object_id),
                draft: drafts.contains(&object_id),
                active: active.contains_key(&object_id),
                desired_matches_active: desired
                    .get(&object_id)
                    .is_some_and(|desired| active.get(&object_id) == Some(desired)),
                object_id,
            })
            .collect(),
    }))
}

pub(in crate::server) async fn proxy_host(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<Response, ApiError> {
    authorize(&principal, Action::ReadProxyHosts)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let object_id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let store = Arc::clone(&state.proxy_hosts);
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

pub(in crate::server) async fn proxy_host_drafts(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<StoredProxyHostDraft>>, ApiError> {
    authorize(&principal, Action::ReadProxyHosts)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let store = Arc::clone(&state.proxy_hosts);
    tokio::task::spawn_blocking(move || store.list_drafts(&owner))
        .await
        .map(axum::Json)
        .map_err(|_| ApiError::Internal)
}

pub(in crate::server) async fn proxy_host_draft(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<Response, ApiError> {
    authorize(&principal, Action::ReadProxyHosts)?;
    let owner = principal.owner_id.ok_or(ApiError::Forbidden)?;
    let object_id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let store = Arc::clone(&state.proxy_hosts);
    let stored = tokio::task::spawn_blocking(move || store.get_draft(&owner, &object_id))
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

async fn draft_store_result<T>(
    audit: &MutationAudit,
    result: Result<Result<T, ProxyHostStoreError>, tokio::task::JoinError>,
) -> Result<T, ApiError> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(ProxyHostStoreError::Conflict)) => {
            Err(audited_failure(audit, "draft_conflict", ApiError::ObjectConflict).await)
        }
        Ok(Err(ProxyHostStoreError::Indeterminate(_) | ProxyHostStoreError::RecoveryRequired)) => {
            Err(audited_failure(audit, "recovery_required", ApiError::RecoveryRequired).await)
        }
        Ok(Err(_)) | Err(_) => {
            Err(audited_failure(audit, "persistence_failed", ApiError::PersistenceFailed).await)
        }
    }
}

pub(in crate::server) async fn create_proxy_host_draft(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let editing_applied = headers.contains_key("x-aegis-object-generation");
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(state.control.runtime().revision().to_string()),
        MutationSpec {
            permission: if editing_applied {
                Action::UpdateProxyHost
            } else {
                Action::CreateProxyHost
            },
            action: "proxy_host_draft_create",
            resource_id: "proxy_host_draft",
            new_revision: None,
        },
    )
    .await?;
    if state.proxy_hosts.recovery_required() {
        return Err(audited_failure(&audit, "recovery_required", ApiError::RecoveryRequired).await);
    }
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let expected_applied_generation = match optional_object_generation(&headers) {
        Ok(generation) => generation,
        Err(error) => return Err(audited_failure(&audit, "invalid_generation", error).await),
    };
    let object = match serde_json::from_slice::<ApiObject<ProxyHostSpec>>(&body) {
        Ok(object) => object,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    if principal.owner_id.as_ref() != Some(&object.metadata.owner_id) {
        return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await);
    }
    let store = Arc::clone(&state.proxy_hosts);
    let stored = draft_store_result(
        &audit,
        tokio::task::spawn_blocking(move || {
            store.create_draft(object, expected_applied_generation)
        })
        .await,
    )
    .await?;
    audit
        .record(AuditOutcome::Success, None, None)
        .await
        .map_err(|_| ApiError::AuditFailedAfterSave)?;
    Ok((
        StatusCode::CREATED,
        axum::Json(ProxyHostDraftResponse { draft: stored }),
    )
        .into_response())
}

pub(in crate::server) async fn update_proxy_host_draft(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(state.control.runtime().revision().to_string()),
        MutationSpec {
            permission: Action::UpdateProxyHost,
            action: "proxy_host_draft_update",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    if state.proxy_hosts.recovery_required() {
        return Err(audited_failure(&audit, "recovery_required", ApiError::RecoveryRequired).await);
    }
    let expected_generation = match expected_draft_generation(&headers) {
        Ok(generation) => generation,
        Err(error) => return Err(audited_failure(&audit, "invalid_generation", error).await),
    };
    if require_json(&headers).is_err() {
        return Err(
            audited_failure(&audit, "invalid_content_type", ApiError::InvalidRequest).await,
        );
    }
    let object = match serde_json::from_slice::<ApiObject<ProxyHostSpec>>(&body) {
        Ok(object) => object,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    match id.parse::<ObjectId>() {
        Ok(object_id) if object_id == object.metadata.id => {}
        _ => {
            return Err(
                audited_failure(&audit, "invalid_object_id", ApiError::InvalidRequest).await,
            );
        }
    };
    if principal.owner_id.as_ref() != Some(&object.metadata.owner_id) {
        return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await);
    }
    let store = Arc::clone(&state.proxy_hosts);
    let stored = draft_store_result(
        &audit,
        tokio::task::spawn_blocking(move || store.update_draft(object, expected_generation)).await,
    )
    .await?;
    audit
        .record(AuditOutcome::Success, None, None)
        .await
        .map_err(|_| ApiError::AuditFailedAfterSave)?;
    Ok(axum::Json(ProxyHostDraftResponse { draft: stored }).into_response())
}

pub(in crate::server) async fn discard_proxy_host_draft(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(state.control.runtime().revision().to_string()),
        MutationSpec {
            permission: Action::UpdateProxyHost,
            action: "proxy_host_draft_discard",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    if state.proxy_hosts.recovery_required() {
        return Err(audited_failure(&audit, "recovery_required", ApiError::RecoveryRequired).await);
    }
    let expected_generation = match expected_draft_generation(&headers) {
        Ok(generation) => generation,
        Err(error) => return Err(audited_failure(&audit, "invalid_generation", error).await),
    };
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
    let store = Arc::clone(&state.proxy_hosts);
    let discarded = draft_store_result(
        &audit,
        tokio::task::spawn_blocking(move || {
            store.discard_draft(&owner, &object_id, expected_generation)
        })
        .await,
    )
    .await?;
    audit
        .record(AuditOutcome::Success, None, None)
        .await
        .map_err(|_| ApiError::AuditFailedAfterSave)?;
    Ok(axum::Json(ProxyHostDraftResponse { draft: discarded }).into_response())
}

async fn create_proxy_host_candidate_revision(
    state: &AppState,
    principal: &Principal,
    audit: &MutationAudit,
    expected_revision: &str,
    _current_objects: Vec<ApiObject<ProxyHostSpec>>,
    desired_objects: Vec<ApiObject<ProxyHostSpec>>,
) -> Result<RevisionMetadata, ApiError> {
    create_unified_candidate(
        state,
        principal,
        audit,
        expected_revision,
        DesiredOverride::ProxyHosts(desired_objects),
        "proxy-host",
    )
    .await
}

pub(in crate::server) async fn promote_proxy_host_draft(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    let object_id = id.parse::<ObjectId>().map_err(|_| ApiError::NotFound)?;
    let owner = principal.owner_id.clone().ok_or(ApiError::Forbidden)?;
    let store = Arc::clone(&state.proxy_hosts);
    let applied_exists = {
        let owner = owner.clone();
        let object_id = object_id.clone();
        tokio::task::spawn_blocking(move || store.get(&owner, &object_id).is_some())
            .await
            .map_err(|_| ApiError::Internal)?
    };
    let current_revision = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current_revision.clone()),
        MutationSpec {
            permission: if applied_exists {
                Action::UpdateProxyHost
            } else {
                Action::CreateProxyHost
            },
            action: "proxy_host_draft_promote",
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    if state.proxy_hosts.recovery_required() {
        return Err(audited_failure(&audit, "recovery_required", ApiError::RecoveryRequired).await);
    }
    let expected_revision = match expected_revision(&headers) {
        Ok(revision) => revision,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    let expected_draft_generation = match expected_draft_generation(&headers) {
        Ok(generation) => generation,
        Err(error) => return Err(audited_failure(&audit, "invalid_generation", error).await),
    };
    if current_revision != expected_revision
        || state.control.runtime().revision().as_ref() != expected_revision
    {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let snapshot = proxy_host_mutation_snapshot(&state, &audit).await?;
    let store = Arc::clone(&state.proxy_hosts);
    let draft = {
        let owner = owner.clone();
        let object_id = object_id.clone();
        match tokio::task::spawn_blocking(move || store.get_draft(&owner, &object_id)).await {
            Ok(Some(draft)) if draft.generation == expected_draft_generation => draft,
            Ok(_) => {
                return Err(
                    audited_failure(&audit, "draft_conflict", ApiError::ObjectConflict).await,
                );
            }
            Err(_) => {
                return Err(audited_failure(&audit, "draft_load_failed", ApiError::Internal).await);
            }
        }
    };
    let current_objects = snapshot
        .objects()
        .iter()
        .map(|stored| stored.object.clone())
        .collect::<Vec<_>>();
    let mut desired_objects = current_objects.clone();
    if let Some(index) = snapshot.objects().iter().position(|stored| {
        stored.object.metadata.owner_id == owner && stored.object.metadata.id == object_id
    }) {
        if Some(snapshot.objects()[index].generation) != draft.base_generation {
            return Err(audited_failure(&audit, "draft_conflict", ApiError::ObjectConflict).await);
        }
        desired_objects[index] = draft.object;
    } else {
        if draft.base_generation.is_some() {
            return Err(audited_failure(&audit, "draft_conflict", ApiError::ObjectConflict).await);
        }
        desired_objects.push(draft.object);
    }
    let metadata = create_proxy_host_candidate_revision(
        &state,
        &principal,
        &audit,
        &expected_revision,
        current_objects,
        desired_objects,
    )
    .await?;
    let store = Arc::clone(&state.proxy_hosts);
    let epoch = snapshot.epoch();
    let stored = match tokio::task::spawn_blocking(move || {
        store.promote_draft_if_epoch(&owner, &object_id, expected_draft_generation, epoch)
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(ProxyHostStoreError::Conflict)) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("draft_conflict"),
                )
                .await?;
            return Err(ApiError::ObjectConflict);
        }
        Ok(Err(ProxyHostStoreError::Indeterminate(_) | ProxyHostStoreError::RecoveryRequired)) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("recovery_required"),
                )
                .await?;
            return Err(ApiError::RecoveryRequired);
        }
        Ok(Err(_)) | Err(_) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("persistence_failed"),
                )
                .await?;
            return Err(ApiError::PersistenceFailed);
        }
    };
    record_save_success(&audit, metadata.id.clone()).await?;
    Ok(axum::Json(ProxyHostCreateResponse {
        object: stored,
        candidate: CandidateResponse {
            id: metadata.id,
            hash: metadata.hash,
            sequence: metadata.sequence,
        },
    })
    .into_response())
}

async fn proxy_host_mutation_snapshot(
    state: &AppState,
    audit: &MutationAudit,
) -> Result<ProxyHostSnapshot, ApiError> {
    let store = Arc::clone(&state.proxy_hosts);
    match tokio::task::spawn_blocking(move || store.mutation_snapshot()).await {
        Ok(Ok(snapshot)) => Ok(snapshot),
        Ok(Err(ProxyHostStoreError::Indeterminate(_) | ProxyHostStoreError::RecoveryRequired)) => {
            Err(audited_failure(audit, "recovery_required", ApiError::RecoveryRequired).await)
        }
        Ok(Err(_)) | Err(_) => {
            Err(audited_failure(audit, "object_store_failed", ApiError::Internal).await)
        }
    }
}

pub(in crate::server) async fn preview_typed_candidate(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    principal: Principal,
) -> Result<axum::Json<TypedPreviewResponse>, ApiError> {
    authorize(&principal, Action::PreviewConfig)?;
    let revisions = state.control.revisions();
    let store = Arc::clone(&state.proxy_hosts);
    let candidate_id = id;
    let active_id = state.control.runtime().revision().to_string();
    let (candidate, bound, current) = tokio::task::spawn_blocking(move || {
        let metadata = revisions.metadata(&candidate_id)?;
        let binding_hash = metadata
            .binding_hash
            .ok_or_else(|| RevisionError::InvalidStored("candidate is not typed".into()))?;
        let bound = store
            .load_candidate(&candidate_id, &binding_hash)
            .map_err(|_| RevisionError::InvalidStored("typed binding is invalid".into()))?;
        if bound.schema_version() != 2 {
            return Err(RevisionError::InvalidStored(
                "candidate is not unified".into(),
            ));
        }
        let current = revisions
            .metadata(&active_id)?
            .binding_hash
            .map(|hash| store.load_candidate(&active_id, &hash))
            .transpose()
            .map_err(|_| RevisionError::InvalidStored("active typed binding is invalid".into()))?;
        Ok::<_, RevisionError>((revisions.load(&candidate_id)?, bound, current))
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map_err(|error| match error {
        RevisionError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound
        }
        RevisionError::InvalidStored(_) => ApiError::CandidateConflict,
        _ => ApiError::Unavailable,
    })?;
    let runtime = state.control.runtime();
    let active = runtime.config();
    Ok(axum::Json(TypedPreviewResponse {
        active_revision: runtime.revision().to_string(),
        active_route_fingerprint: format!("{:016x}", RouteIndex::compile(&active).fingerprint()),
        candidate_route_fingerprint: format!(
            "{:016x}",
            RouteIndex::compile(&candidate).fingerprint()
        ),
        activation_class: if runtime.can_hot_reload(&candidate) {
            "hot_reload"
        } else {
            "restart_required"
        },
        changes: typed_candidate_changes(current.as_ref(), &bound),
        config: aegisproxy_config::redacted(&candidate),
    }))
}

pub(in crate::server) async fn create_proxy_host(
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
            permission: Action::CreateProxyHost,
            action: "proxy_host_create",
            resource_id: "proxy_host",
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
    let object = match serde_json::from_slice::<ApiObject<ProxyHostSpec>>(&body) {
        Ok(object) => object,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    if principal.owner_id.as_ref() != Some(&object.metadata.owner_id) {
        return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await);
    }
    let snapshot = proxy_host_mutation_snapshot(&state, &audit).await?;
    let current_objects = snapshot
        .objects()
        .iter()
        .map(|stored| stored.object.clone())
        .collect::<Vec<_>>();
    let mut desired_objects = current_objects.clone();
    desired_objects.push(object.clone());
    let metadata = create_proxy_host_candidate_revision(
        &state,
        &principal,
        &audit,
        &expected,
        current_objects,
        desired_objects,
    )
    .await?;
    let store = Arc::clone(&state.proxy_hosts);
    let epoch = snapshot.epoch();
    let stored = match tokio::task::spawn_blocking(move || store.create_if_epoch(object, epoch))
        .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(ProxyHostStoreError::Conflict)) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("object_conflict"),
                )
                .await?;
            return Err(ApiError::ObjectConflict);
        }
        Ok(Err(ProxyHostStoreError::Indeterminate(_) | ProxyHostStoreError::RecoveryRequired)) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("recovery_required"),
                )
                .await?;
            return Err(ApiError::RecoveryRequired);
        }
        Ok(Err(_)) | Err(_) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("persistence_failed"),
                )
                .await?;
            return Err(ApiError::PersistenceFailed);
        }
    };
    record_save_success(&audit, metadata.id.clone()).await?;
    let generation = stored.generation.to_string();
    let mut response = (
        StatusCode::CREATED,
        axum::Json(ProxyHostCreateResponse {
            object: stored,
            candidate: CandidateResponse {
                id: metadata.id,
                hash: metadata.hash,
                sequence: metadata.sequence,
            },
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}

pub(in crate::server) async fn update_proxy_host(
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
            permission: Action::UpdateProxyHost,
            action: "proxy_host_update",
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
    let object = match serde_json::from_slice::<ApiObject<ProxyHostSpec>>(&body) {
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
    let snapshot = proxy_host_mutation_snapshot(&state, &audit).await?;
    let current_objects = snapshot
        .objects()
        .iter()
        .map(|stored| stored.object.clone())
        .collect::<Vec<_>>();
    let Some(index) = snapshot.objects().iter().position(|stored| {
        stored.object.metadata.owner_id == owner && stored.object.metadata.id == object_id
    }) else {
        return Err(audited_failure(&audit, "object_not_found", ApiError::NotFound).await);
    };
    if snapshot.objects()[index].generation != expected_generation {
        return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
    }
    let mut desired_objects = current_objects.clone();
    desired_objects[index] = object.clone();
    let metadata = create_proxy_host_candidate_revision(
        &state,
        &principal,
        &audit,
        &expected_revision,
        current_objects,
        desired_objects,
    )
    .await?;
    let store = Arc::clone(&state.proxy_hosts);
    let epoch = snapshot.epoch();
    let stored = match tokio::task::spawn_blocking(move || {
        store.update_if_epoch(object, expected_generation, epoch)
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(ProxyHostStoreError::Conflict)) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("object_conflict"),
                )
                .await?;
            return Err(ApiError::ObjectConflict);
        }
        Ok(Err(ProxyHostStoreError::Indeterminate(_) | ProxyHostStoreError::RecoveryRequired)) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("recovery_required"),
                )
                .await?;
            return Err(ApiError::RecoveryRequired);
        }
        Ok(Err(_)) | Err(_) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("persistence_failed"),
                )
                .await?;
            return Err(ApiError::PersistenceFailed);
        }
    };
    record_save_success(&audit, metadata.id.clone()).await?;
    let generation = stored.generation.to_string();
    let mut response = axum::Json(ProxyHostCreateResponse {
        object: stored,
        candidate: CandidateResponse {
            id: metadata.id,
            hash: metadata.hash,
            sequence: metadata.sequence,
        },
    })
    .into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&generation).ok_or(ApiError::Internal)?);
    Ok(response)
}

pub(in crate::server) async fn delete_proxy_host(
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
            permission: Action::DeleteProxyHost,
            action: "proxy_host_delete",
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
    let owner = match principal.owner_id.as_ref() {
        Some(owner) => owner.clone(),
        None => return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await),
    };
    let snapshot = proxy_host_mutation_snapshot(&state, &audit).await?;
    let Some((index, target)) = snapshot.objects().iter().enumerate().find(|(_, stored)| {
        stored.object.metadata.owner_id == owner && stored.object.metadata.id == object_id
    }) else {
        return Err(audited_failure(&audit, "object_not_found", ApiError::NotFound).await);
    };
    if target.generation != expected_generation {
        return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
    }
    let current_objects = snapshot
        .objects()
        .iter()
        .map(|stored| stored.object.clone())
        .collect::<Vec<_>>();
    let mut desired_objects = current_objects.clone();
    desired_objects.remove(index);
    let metadata = create_proxy_host_candidate_revision(
        &state,
        &principal,
        &audit,
        &expected_revision,
        current_objects,
        desired_objects,
    )
    .await?;
    let store = Arc::clone(&state.proxy_hosts);
    let epoch = snapshot.epoch();
    let deleted = match tokio::task::spawn_blocking(move || {
        store.delete_if_epoch(&owner, &object_id, expected_generation, epoch)
    })
    .await
    {
        Ok(Ok(deleted)) => deleted,
        Ok(Err(ProxyHostStoreError::Conflict)) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("object_conflict"),
                )
                .await?;
            return Err(ApiError::ObjectConflict);
        }
        Ok(Err(ProxyHostStoreError::Indeterminate(_) | ProxyHostStoreError::RecoveryRequired)) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("recovery_required"),
                )
                .await?;
            return Err(ApiError::RecoveryRequired);
        }
        Ok(Err(_)) | Err(_) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("persistence_failed"),
                )
                .await?;
            return Err(ApiError::PersistenceFailed);
        }
    };
    record_save_success(&audit, metadata.id.clone()).await?;
    Ok(axum::Json(ProxyHostDeleteResponse {
        deleted,
        candidate: CandidateResponse {
            id: metadata.id,
            hash: metadata.hash,
            sequence: metadata.sequence,
        },
    })
    .into_response())
}

pub(in crate::server) async fn activate_proxy_host_candidate(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    activate_bound_candidate(state, request_id, id, headers, principal, true).await
}

pub(in crate::server) async fn activate_typed_candidate(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    activate_bound_candidate(state, request_id, id, headers, principal, false).await
}

async fn activate_bound_candidate(
    state: AppState,
    request_id: RequestId,
    id: String,
    headers: HeaderMap,
    principal: Principal,
    legacy: bool,
) -> Result<Response, ApiError> {
    let current_revision = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current_revision.clone()),
        MutationSpec {
            permission: if legacy {
                Action::ActivateProxyHost
            } else {
                Action::ActivateTypedCandidate
            },
            action: if legacy {
                "proxy_host_activate"
            } else {
                "typed_candidate_activate"
            },
            resource_id: &id,
            new_revision: Some(id.clone()),
        },
    )
    .await?;
    let expected_revision = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current_revision != expected_revision
        || state.control.runtime().revision().as_ref() != expected_revision
    {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    if id == current_revision {
        return Err(
            audited_failure(&audit, "candidate_conflict", ApiError::CandidateConflict).await,
        );
    }
    if principal.owner_id.is_none() {
        return Err(audited_failure(&audit, "owner_denied", ApiError::Forbidden).await);
    }
    let snapshot = proxy_host_mutation_snapshot(&state, &audit).await?;
    let objects = snapshot
        .objects()
        .iter()
        .map(|stored| stored.object.clone())
        .collect::<Vec<_>>();
    let active = state.control.runtime().config();
    let (access_policy_records, access_policies) =
        match access_policy_dependencies(&state, Arc::clone(&active), &objects).await {
            Ok(dependencies) => dependencies,
            Err(error) => {
                return Err(audited_failure(&audit, "access_policy_unavailable", error).await);
            }
        };
    let certificates = match certificate_metadata(
        &state,
        Arc::clone(&active),
        objects
            .iter()
            .any(|object| object.spec.automatic_https == crate::AutomaticHttps::Managed),
    )
    .await
    {
        Ok(certificates) => certificates,
        Err(error) => {
            return Err(audited_failure(&audit, "certificate_unavailable", error).await);
        }
    };
    let (expected_hash, objects) = match tokio::task::spawn_blocking(move || {
        let candidate = crate::proxy_host::prepare_proxy_host_set(
            &objects,
            &objects,
            &active,
            &access_policies,
            &certificates,
        )
        .map_err(|_| RevisionError::InvalidStored("typed candidate preparation failed".into()))?;
        Ok::<_, RevisionError>((content_hash(candidate.config())?, objects))
    })
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            return Err(
                audited_failure(&audit, "invalid_proxy_host", ApiError::InvalidRequest).await,
            );
        }
        Err(_) => {
            return Err(
                audited_failure(&audit, "compilation_failed", ApiError::CompilationFailed).await,
            );
        }
    };
    let revisions = state.control.revisions();
    let candidate_id = id.clone();
    let (candidate_hash, binding_hash) = match tokio::task::spawn_blocking(move || {
        let candidate = revisions.load(&candidate_id)?;
        let metadata = revisions.metadata(&candidate_id)?;
        Ok::<_, RevisionError>((content_hash(&candidate)?, metadata.binding_hash))
    })
    .await
    {
        Ok(Ok((hash, Some(binding_hash)))) => (hash, binding_hash),
        Ok(Ok((_, None))) => {
            return Err(
                audited_failure(&audit, "candidate_conflict", ApiError::CandidateConflict).await,
            );
        }
        Ok(Err(RevisionError::InvalidStored(_))) => {
            return Err(audited_failure(&audit, "candidate_not_found", ApiError::NotFound).await);
        }
        Ok(Err(RevisionError::Io(error))) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(audited_failure(&audit, "candidate_not_found", ApiError::NotFound).await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "revision_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    let store = Arc::clone(&state.proxy_hosts);
    let bound_id = id.clone();
    let bound =
        match tokio::task::spawn_blocking(move || store.load_candidate(&bound_id, &binding_hash))
            .await
        {
            Ok(Ok(bound)) => bound,
            Ok(Err(ProxyHostStoreError::Io(error)))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Err(audited_failure(
                    &audit,
                    "candidate_conflict",
                    ApiError::CandidateConflict,
                )
                .await);
            }
            Ok(Err(_)) | Err(_) => {
                return Err(audited_failure(
                    &audit,
                    "candidate_binding_failed",
                    ApiError::Unavailable,
                )
                .await);
            }
        };
    if !candidate_schema_matches_route(bound.schema_version(), legacy) {
        return Err(
            audited_failure(&audit, "candidate_conflict", ApiError::CandidateConflict).await,
        );
    }
    if legacy
        && (candidate_hash != expected_hash
            || bound.objects() != objects
            || bound.access_policies() != access_policy_records)
    {
        return Err(
            audited_failure(&audit, "candidate_conflict", ApiError::CandidateConflict).await,
        );
    }
    if !legacy {
        verify_unified_binding(&state, &bound, &audit).await?;
    }
    let current_epoch = proxy_host_mutation_snapshot(&state, &audit).await?.epoch();
    if current_epoch != snapshot.epoch() {
        return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
    }
    let result = match state
        .control
        .coordinator()
        .activate(&id, Some(&expected_revision))
        .await
    {
        Ok(result) => result,
        Err(error) => {
            let (code, error) = activation_error(error);
            return Err(audited_failure(&audit, code, error).await);
        }
    };
    record_activation_success(&audit, result.active.clone()).await?;
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

pub(in crate::server) async fn rollback_proxy_hosts(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    rollback_bound_revision(state, request_id, id, headers, principal, true).await
}

pub(in crate::server) async fn rollback_typed_revision(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Response, ApiError> {
    rollback_bound_revision(state, request_id, id, headers, principal, false).await
}

async fn rollback_bound_revision(
    state: AppState,
    request_id: RequestId,
    id: String,
    headers: HeaderMap,
    principal: Principal,
    legacy: bool,
) -> Result<Response, ApiError> {
    let current_revision = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current_revision.clone()),
        MutationSpec {
            permission: if legacy {
                Action::RollbackProxyHost
            } else {
                Action::RollbackTypedRevision
            },
            action: if legacy {
                "proxy_host_rollback"
            } else {
                "typed_revision_rollback"
            },
            resource_id: &id,
            new_revision: None,
        },
    )
    .await?;
    let expected_revision = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current_revision != expected_revision
        || state.control.runtime().revision().as_ref() != expected_revision
    {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    if id == current_revision || principal.owner_id.is_none() {
        return Err(
            audited_failure(&audit, "rollback_conflict", ApiError::CandidateConflict).await,
        );
    }

    let revisions = state.control.revisions();
    let target_id = id.clone();
    let binding_hash = match tokio::task::spawn_blocking(move || {
        let metadata = revisions.metadata(&target_id)?;
        revisions.load(&target_id)?;
        Ok::<_, RevisionError>(metadata.binding_hash)
    })
    .await
    {
        Ok(Ok(Some(hash))) => hash,
        Ok(Ok(None)) => {
            return Err(
                audited_failure(&audit, "rollback_conflict", ApiError::CandidateConflict).await,
            );
        }
        Ok(Err(RevisionError::InvalidStored(_))) => {
            return Err(audited_failure(&audit, "revision_not_found", ApiError::NotFound).await);
        }
        Ok(Err(RevisionError::Io(error))) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(audited_failure(&audit, "revision_not_found", ApiError::NotFound).await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "revision_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    let store = Arc::clone(&state.proxy_hosts);
    let target_id = id.clone();
    let target =
        match tokio::task::spawn_blocking(move || store.load_candidate(&target_id, &binding_hash))
            .await
        {
            Ok(Ok(target)) => target,
            Ok(Err(ProxyHostStoreError::Io(error)))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Err(audited_failure(
                    &audit,
                    "rollback_conflict",
                    ApiError::CandidateConflict,
                )
                .await);
            }
            Ok(Err(_)) | Err(_) => {
                return Err(audited_failure(
                    &audit,
                    "candidate_binding_failed",
                    ApiError::Unavailable,
                )
                .await);
            }
        };
    if target.schema_version() != if legacy { 1 } else { 2 } {
        return Err(
            audited_failure(&audit, "rollback_conflict", ApiError::CandidateConflict).await,
        );
    }
    if !legacy {
        return rollback_unified_snapshot(&state, &audit, &expected_revision, &id, target).await;
    }
    let current = proxy_host_mutation_snapshot(&state, &audit).await?;
    let current_objects = current
        .objects()
        .iter()
        .map(|stored| stored.object.clone())
        .collect::<Vec<_>>();
    let target_objects = target.objects().to_vec();
    let active = state.control.runtime().config();
    let (access_policy_records, access_policies) =
        match access_policy_dependencies(&state, Arc::clone(&active), &target_objects).await {
            Ok(dependencies) => dependencies,
            Err(error) => {
                return Err(audited_failure(&audit, "access_policy_unavailable", error).await);
            }
        };
    let certificates = match certificate_metadata(
        &state,
        Arc::clone(&active),
        target_objects
            .iter()
            .any(|object| object.spec.automatic_https == crate::AutomaticHttps::Managed),
    )
    .await
    {
        Ok(certificates) => certificates,
        Err(error) => {
            return Err(audited_failure(&audit, "certificate_unavailable", error).await);
        }
    };
    if target.access_policies() != access_policy_records {
        return Err(
            audited_failure(&audit, "rollback_conflict", ApiError::CandidateConflict).await,
        );
    }
    let (config, target_objects) = match tokio::task::spawn_blocking(move || {
        crate::proxy_host::prepare_proxy_host_set(
            &current_objects,
            &target_objects,
            &active,
            &access_policies,
            &certificates,
        )
        .map(|candidate| (candidate.config().clone(), candidate.objects().to_vec()))
    })
    .await
    {
        Ok(Ok(candidate)) => candidate,
        Ok(Err(_)) => {
            return Err(
                audited_failure(&audit, "invalid_proxy_host", ApiError::InvalidRequest).await,
            );
        }
        Err(_) => return Err(audited_failure(&audit, "compile_failed", ApiError::Internal).await),
    };
    let forward_binding = match ProxyHostStore::binding_hash_with_access_policies(
        &target_objects,
        &access_policy_records,
    ) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(
                audited_failure(&audit, "invalid_proxy_host", ApiError::InvalidRequest).await,
            );
        }
    };
    let revisions = state.control.revisions();
    let source = format!("rollback:proxy-host:{id}");
    let revision_binding = forward_binding.clone();
    let (forward, retained) = match tokio::task::spawn_blocking(move || {
        let metadata =
            revisions.create_bound_forward_revision(&config, &source, &revision_binding)?;
        Ok::<_, RevisionError>((metadata, revisions.list()?))
    })
    .await
    {
        Ok(Ok(metadata)) => metadata,
        Ok(Err(RevisionError::InvalidConfig(_))) => {
            return Err(
                audited_failure(&audit, "invalid_candidate", ApiError::InvalidRequest).await,
            );
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "revision_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    let store = Arc::clone(&state.proxy_hosts);
    let forward_id = forward.id.clone();
    let snapshot_binding = forward_binding;
    let bound_objects = target_objects.clone();
    let bound_access_policies = access_policy_records;
    match tokio::task::spawn_blocking(move || {
        store.reconcile_candidates(&retained)?;
        store.bind_candidate_with_access_policies(
            &forward_id,
            &snapshot_binding,
            &bound_objects,
            &bound_access_policies,
        )
    })
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "candidate_binding_failed", ApiError::Unavailable).await,
            );
        }
    }
    if state.control.runtime().revision().as_ref() != expected_revision {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    let store = Arc::clone(&state.proxy_hosts);
    let rollback_revision = forward.id.clone();
    let rollback_objects = target_objects;
    let expected_epoch = current.epoch();
    match tokio::task::spawn_blocking(move || {
        store.begin_rollback(&rollback_revision, &rollback_objects, expected_epoch)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(ProxyHostStoreError::Conflict)) => {
            return Err(audited_failure(&audit, "object_conflict", ApiError::ObjectConflict).await);
        }
        Ok(Err(ProxyHostStoreError::Indeterminate(_) | ProxyHostStoreError::RecoveryRequired)) => {
            return Err(
                audited_failure(&audit, "recovery_required", ApiError::RecoveryRequired).await,
            );
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(&audit, "object_store_failed", ApiError::Unavailable).await,
            );
        }
    }
    let result = match state
        .control
        .coordinator()
        .activate(&forward.id, Some(&expected_revision))
        .await
    {
        Ok(result) => result,
        Err(error) => {
            if matches!(error, ActivationError::RecoveryRequired) {
                return Err(audited_failure(
                    &audit,
                    "rollback_recovery_required",
                    ApiError::RecoveryRequired,
                )
                .await);
            }
            if matches!(error, ActivationError::RollbackFailed) {
                return Err(
                    audited_failure(&audit, "rollback_failed", ApiError::RollbackFailed).await,
                );
            }
            let store = Arc::clone(&state.proxy_hosts);
            let forward_id = forward.id.clone();
            let recovered =
                tokio::task::spawn_blocking(move || store.abort_rollback(&forward_id)).await;
            if !matches!(recovered, Ok(Ok(()))) {
                return Err(audited_failure(
                    &audit,
                    "rollback_recovery_failed",
                    ApiError::RollbackFailed,
                )
                .await);
            }
            let (code, error) = activation_error(error);
            return Err(audited_failure(&audit, code, error).await);
        }
    };
    let store = Arc::clone(&state.proxy_hosts);
    let forward_id = forward.id.clone();
    if !matches!(
        tokio::task::spawn_blocking(move || store.commit_rollback(&forward_id)).await,
        Ok(Ok(()))
    ) {
        return Err(
            audited_failure(&audit, "rollback_commit_failed", ApiError::RollbackFailed).await,
        );
    }
    record_activation_success(&audit, result.active.clone()).await?;
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

pub(in crate::server) async fn preview_proxy_host(
    State(state): State<AppState>,
    PreviewProxyHostPrincipal(principal): PreviewProxyHostPrincipal,
    payload: Result<Json<ApiObject<ProxyHostSpec>>, JsonRejection>,
) -> Result<axum::Json<PreparedProxyHost>, ApiError> {
    prepare_proxy_host_request(&state, &principal, payload)
        .await
        .map(axum::Json)
}

async fn prepare_proxy_host_request(
    state: &AppState,
    principal: &Principal,
    payload: Result<Json<ApiObject<ProxyHostSpec>>, JsonRejection>,
) -> Result<PreparedProxyHost, ApiError> {
    let object = payload.map_err(|_| ApiError::InvalidRequest)?.0;
    let owner = principal.owner_id.clone().ok_or(ApiError::Forbidden)?;
    let active = state.control.runtime().config();
    let policy_id = object
        .spec
        .access_policy_ref
        .as_ref()
        .map(|reference| reference.id().clone());
    let access_policies = access_policy_metadata(state, Arc::clone(&active), policy_id).await?;
    let certificates = certificate_metadata(
        state,
        Arc::clone(&active),
        object.spec.automatic_https == crate::AutomaticHttps::Managed,
    )
    .await?;
    let store = Arc::clone(&state.proxy_hosts);
    tokio::task::spawn_blocking(move || {
        let claims = store.claims();
        crate::proxy_host::prepare_proxy_host_with_claims(
            &object,
            &active,
            &owner,
            &claims,
            &access_policies,
            &certificates,
        )
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map_err(map_proxy_host_preparation_error)
}

fn map_proxy_host_preparation_error(error: ProxyHostPreparationError) -> ApiError {
    match error {
        ProxyHostPreparationError::UnauthorizedOwner => ApiError::Forbidden,
        ProxyHostPreparationError::Preview | ProxyHostPreparationError::Diff => ApiError::Internal,
        ProxyHostPreparationError::InvalidContract
        | ProxyHostPreparationError::HttpListenerUnavailable
        | ProxyHostPreparationError::UpstreamTemplateUnavailable
        | ProxyHostPreparationError::AccessPolicyUnavailable
        | ProxyHostPreparationError::ManagedHttpsUnavailable
        | ProxyHostPreparationError::Compile => ApiError::InvalidRequest,
        ProxyHostPreparationError::ManagedHttpsDomainsUnavailable => {
            ApiError::CertificateCoverageFailed
        }
    }
}
