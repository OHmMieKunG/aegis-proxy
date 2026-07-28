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
    let store = Arc::clone(&state.proxy_hosts);
    let snapshot = match tokio::task::spawn_blocking(move || store.snapshot()).await {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Err(audited_failure(&audit, "object_store_failed", ApiError::Internal).await);
        }
    };
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
    let stored =
        match tokio::task::spawn_blocking(move || store.create_if_epoch(object, epoch)).await {
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
            Ok(Err(_)) | Err(_) => {
                audit
                    .record(
                        AuditOutcome::Failed,
                        Some(metadata.id.clone()),
                        Some("object_store_failed"),
                    )
                    .await?;
                return Err(ApiError::Unavailable);
            }
        };
    audit
        .record(AuditOutcome::Success, Some(metadata.id.clone()), None)
        .await?;
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
    let store = Arc::clone(&state.proxy_hosts);
    let snapshot = match tokio::task::spawn_blocking(move || store.snapshot()).await {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Err(audited_failure(&audit, "object_store_failed", ApiError::Internal).await);
        }
    };
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
        Ok(Err(_)) | Err(_) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("object_store_failed"),
                )
                .await?;
            return Err(ApiError::Unavailable);
        }
    };
    audit
        .record(AuditOutcome::Success, Some(metadata.id.clone()), None)
        .await?;
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
    let store = Arc::clone(&state.proxy_hosts);
    let snapshot = match tokio::task::spawn_blocking(move || store.snapshot()).await {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Err(audited_failure(&audit, "object_store_failed", ApiError::Internal).await);
        }
    };
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
        Ok(Err(_)) | Err(_) => {
            audit
                .record(
                    AuditOutcome::Failed,
                    Some(metadata.id.clone()),
                    Some("object_store_failed"),
                )
                .await?;
            return Err(ApiError::Unavailable);
        }
    };
    audit
        .record(AuditOutcome::Success, Some(metadata.id.clone()), None)
        .await?;
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
    let store = Arc::clone(&state.proxy_hosts);
    let snapshot = match tokio::task::spawn_blocking(move || store.snapshot()).await {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Err(audited_failure(&audit, "object_store_failed", ApiError::Internal).await);
        }
    };
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
        Err(_) => return Err(audited_failure(&audit, "compile_failed", ApiError::Internal).await),
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
    let store = Arc::clone(&state.proxy_hosts);
    let current_epoch = match tokio::task::spawn_blocking(move || store.snapshot().epoch()).await {
        Ok(epoch) => epoch,
        Err(_) => {
            return Err(audited_failure(&audit, "object_store_failed", ApiError::Internal).await);
        }
    };
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
    let store = Arc::clone(&state.proxy_hosts);
    let current = match tokio::task::spawn_blocking(move || store.snapshot()).await {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Err(audited_failure(&audit, "object_store_failed", ApiError::Internal).await);
        }
    };
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
                    ApiError::Unavailable,
                )
                .await);
            }
            let store = Arc::clone(&state.proxy_hosts);
            let forward_id = forward.id.clone();
            let recovered =
                tokio::task::spawn_blocking(move || store.abort_rollback(&forward_id)).await;
            if !matches!(recovered, Ok(Ok(()))) {
                return Err(audited_failure(
                    &audit,
                    "rollback_recovery_failed",
                    ApiError::Unavailable,
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
        return Err(audited_failure(&audit, "rollback_commit_failed", ApiError::Unavailable).await);
    }
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
    }
}
