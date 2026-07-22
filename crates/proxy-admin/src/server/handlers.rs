use super::*;

pub(super) async fn live() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse { status: "live" })
}

pub(super) async fn ready(
    State(state): State<AppState>,
) -> (StatusCode, axum::Json<HealthResponse>) {
    if state.control.coordinator().administration_ready() && !state.control.runtime().is_draining()
    {
        (
            StatusCode::OK,
            axum::Json(HealthResponse { status: "ready" }),
        )
    } else {
        let status = if state.control.runtime().is_draining() {
            "draining"
        } else {
            "recovery_required"
        };
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(HealthResponse { status }),
        )
    }
}

pub(super) async fn metrics(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    authorize(&principal, Action::ReadStatus)?;
    if !state.control.runtime().config().observability.metrics {
        return Err(ApiError::NotFound);
    }
    let body = state
        .control
        .render_openmetrics()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let mut response = Response::new(axum::body::Body::from(body));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/openmetrics-text; version=1.0.0; charset=utf-8"),
    );
    Ok(response)
}

pub(super) async fn status(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    principal: Principal,
) -> Result<axum::Json<StatusResponse>, ApiError> {
    authorize(&principal, Action::ReadStatus)?;
    let runtime = state.control.runtime();
    let config = runtime.config();
    Ok(axum::Json(StatusResponse {
        request_id: request_id.0,
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started.elapsed().as_secs(),
        node_id: runtime.node_id().to_string(),
        fleet_generation: runtime.fleet_generation(),
        active_revision: runtime.revision().to_string(),
        active_hash: runtime.revision_hash().ok_or(ApiError::Internal)?,
        administration_ready: state.control.coordinator().administration_ready(),
        audit_ready: runtime.audit_ready(),
        draining: runtime.is_draining(),
        certificate_owner: runtime.certificate_owner(),
        managed_certificates: config.acme.certificates.len(),
        actor_type: principal.actor_type,
        actor_id: principal.actor_id,
    }))
}

pub(super) async fn health_details(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    principal: Principal,
) -> Result<axum::Json<HealthDetailsResponse>, ApiError> {
    authorize(&principal, Action::ReadStatus)?;
    let config = state.control.runtime().config();
    let mut stored: HashMap<_, _> = state
        .control
        .certificate_statuses()
        .await
        .map_err(|_| ApiError::Unavailable)?
        .into_iter()
        .map(|certificate| (certificate.id.clone(), certificate))
        .collect();
    let now = unix_time()
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(ApiError::Internal)?;
    let mut certificates = config
        .certificates
        .iter()
        .map(|certificate| certificate.id.clone())
        .chain(
            config
                .acme
                .certificates
                .iter()
                .map(|certificate| certificate.id.clone()),
        )
        .map(|id| {
            let status = stored.remove(&id);
            CertificateWindow {
                id,
                not_before_unix_secs: status.as_ref().map(|status| status.not_before_unix_secs),
                not_after_unix_secs: status.as_ref().map(|status| status.not_after_unix_secs),
                state: status.as_ref().map_or("missing", |status| {
                    if status.not_after_unix_secs <= now {
                        "expired"
                    } else if status.not_before_unix_secs > now {
                        "not_yet_valid"
                    } else {
                        "valid"
                    }
                }),
            }
        })
        .collect::<Vec<_>>();
    certificates.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    let draining = state.control.runtime().is_draining();
    let ready = state.control.coordinator().administration_ready() && !draining;
    Ok(axum::Json(HealthDetailsResponse {
        request_id: request_id.0,
        status: if ready {
            "ready"
        } else if draining {
            "draining"
        } else {
            "recovery_required"
        },
        active_revision: state.control.runtime().revision().to_string(),
        administration_ready: ready,
        audit_ready: state.control.runtime().audit_ready(),
        certificates,
    }))
}

pub(super) async fn drain_node(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<axum::Json<DrainResponse>, ApiError> {
    let runtime = state.control.runtime();
    let current = runtime.revision().to_string();
    let node_id = runtime.node_id().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::Drain,
            action: "node_drain",
            resource_id: &node_id,
            new_revision: None,
        },
    )
    .await?;
    let expected = match expected_revision(&headers) {
        Ok(expected) => expected,
        Err(error) => return Err(audited_failure(&audit, "invalid_if_match", error).await),
    };
    if current != expected || runtime.revision().as_ref() != expected {
        return Err(audited_failure(&audit, "revision_conflict", ApiError::Conflict).await);
    }
    runtime.begin_drain();
    audit.record(AuditOutcome::Success, None, None).await?;
    Ok(axum::Json(DrainResponse { draining: true }))
}

pub(super) async fn active_config(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    authorize(&principal, Action::ReadConfig)?;
    let revision = state.control.runtime().revision();
    let mut response = axum::Json(aegisproxy_config::redacted(
        &state.control.runtime().config(),
    ))
    .into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&revision).ok_or(ApiError::Internal)?);
    Ok(response)
}

pub(super) async fn validate_config(
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<ValidationResponse>, ApiError> {
    authorize(&principal, Action::ValidateConfig)?;
    require_toml(&headers)?;
    let config = load_candidate(body).await?;
    Ok(axum::Json(ValidationResponse {
        valid: true,
        route_fingerprint: format!("{:016x}", RouteIndex::compile(&config).fingerprint()),
        warnings: Vec::new(),
    }))
}

pub(super) async fn preview_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    principal: Principal,
    body: axum::body::Bytes,
) -> Result<axum::Json<PreviewResponse>, ApiError> {
    authorize(&principal, Action::PreviewConfig)?;
    require_toml(&headers)?;
    let candidate = load_candidate(body).await?;
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

pub(super) async fn validate_proxy_host(
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

pub(super) async fn proxy_hosts(
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

pub(super) async fn proxy_host(
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
    current_objects: Vec<ApiObject<ProxyHostSpec>>,
    desired_objects: Vec<ApiObject<ProxyHostSpec>>,
) -> Result<RevisionMetadata, ApiError> {
    let active = state.control.runtime().config();
    let (config, desired_objects) = match tokio::task::spawn_blocking(move || {
        crate::proxy_host::prepare_proxy_host_set(&current_objects, &desired_objects, &active)
            .map(|candidate| (candidate.config().clone(), candidate.objects().to_vec()))
    })
    .await
    {
        Ok(Ok(candidate)) => candidate,
        Ok(Err(_)) => {
            return Err(
                audited_failure(audit, "invalid_proxy_host", ApiError::InvalidRequest).await,
            );
        }
        Err(_) => return Err(audited_failure(audit, "compile_failed", ApiError::Internal).await),
    };
    if state.control.runtime().revision().as_ref() != expected_revision {
        return Err(audited_failure(audit, "revision_conflict", ApiError::Conflict).await);
    }
    let revisions = state.control.revisions();
    let binding_hash = match ProxyHostStore::binding_hash(&desired_objects) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(
                audited_failure(audit, "invalid_proxy_host", ApiError::InvalidRequest).await,
            );
        }
    };
    let source = format!(
        "admin:{}:{}:proxy-host",
        principal.actor_type, principal.actor_id
    );
    let revision_binding = binding_hash.clone();
    let metadata = match tokio::task::spawn_blocking(move || {
        revisions.create_bound_candidate(&config, &source, &revision_binding)
    })
    .await
    {
        Ok(Ok(metadata)) => metadata,
        Ok(Err(RevisionError::InvalidConfig(_))) => {
            return Err(
                audited_failure(audit, "invalid_candidate", ApiError::InvalidRequest).await,
            );
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(audit, "revision_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    let store = Arc::clone(&state.proxy_hosts);
    let candidate_id = metadata.id.clone();
    let snapshot_binding = binding_hash;
    match tokio::task::spawn_blocking(move || {
        store.bind_candidate(&candidate_id, &snapshot_binding, &desired_objects)
    })
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(audit, "candidate_binding_failed", ApiError::Unavailable).await,
            );
        }
    }
    if state.control.runtime().revision().as_ref() != expected_revision {
        audit
            .record(
                AuditOutcome::Failed,
                Some(metadata.id.clone()),
                Some("revision_conflict"),
            )
            .await?;
        return Err(ApiError::Conflict);
    }
    Ok(metadata)
}

pub(super) async fn create_proxy_host(
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

pub(super) async fn update_proxy_host(
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

pub(super) async fn delete_proxy_host(
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

pub(super) async fn activate_proxy_host_candidate(
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
            permission: Action::ActivateProxyHost,
            action: "proxy_host_activate",
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
    let (expected_hash, objects) = match tokio::task::spawn_blocking(move || {
        let candidate = crate::proxy_host::prepare_proxy_host_set(&objects, &objects, &active)
            .map_err(|_| {
                RevisionError::InvalidStored("typed candidate preparation failed".into())
            })?;
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
    if candidate_hash != expected_hash {
        return Err(
            audited_failure(&audit, "candidate_conflict", ApiError::CandidateConflict).await,
        );
    }
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
    if bound.objects() != objects {
        return Err(
            audited_failure(&audit, "candidate_conflict", ApiError::CandidateConflict).await,
        );
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

pub(super) async fn preview_proxy_host(
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
    let store = Arc::clone(&state.proxy_hosts);
    tokio::task::spawn_blocking(move || {
        let claims = store.claims();
        crate::proxy_host::prepare_proxy_host_with_claims(&object, &active, &owner, &claims)
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

pub(super) async fn create_candidate(
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

pub(super) async fn activate_candidate(
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

pub(super) async fn rollback_revision(
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
        let config = store.load(&rollback_id)?;
        store.create_forward_revision(&config, &format!("rollback:{rollback_id}"))
    })
    .await
    {
        Ok(Ok(metadata)) => metadata,
        Ok(Err(RevisionError::InvalidStored(_))) => {
            return Err(audited_failure(&audit, "revision_not_found", ApiError::NotFound).await);
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

pub(super) async fn revisions(
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

pub(super) async fn revision(
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

pub(super) async fn routes(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<RouteSummary>>, ApiError> {
    authorize(&principal, Action::ReadRoutes)?;
    let mut routes: Vec<_> = state
        .control
        .runtime()
        .config()
        .routes
        .iter()
        .map(|route| RouteSummary {
            id: route.id.clone(),
            listeners: route.listeners.clone(),
            hosts: route.hosts.clone(),
            paths: route.paths.clone(),
            path_prefixes: route.path_prefixes.clone(),
            methods: route.methods.clone(),
            default: route.default,
            priority: route.priority,
            middlewares: route.middlewares.clone(),
            upstream_group: route.upstream_group.clone(),
        })
        .collect();
    routes.sort_unstable_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(axum::Json(routes))
}

pub(super) async fn upstreams(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<UpstreamSummary>>, ApiError> {
    authorize(&principal, Action::ReadUpstreams)?;
    let mut groups: Vec<_> = state
        .control
        .runtime()
        .config()
        .upstream_groups
        .iter()
        .map(|group| UpstreamSummary {
            id: group.id.clone(),
            algorithm: group.algorithm,
            max_in_flight: group.max_in_flight,
            endpoints: group
                .endpoints
                .iter()
                .map(|endpoint| EndpointSummary {
                    id: endpoint.id.clone(),
                    transport: endpoint.url.scheme().to_owned(),
                    weight: endpoint.weight,
                    state: "configured",
                })
                .collect(),
        })
        .collect();
    groups.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(axum::Json(groups))
}

pub(super) async fn providers(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<ProviderSummary>>, ApiError> {
    authorize(&principal, Action::ReadUpstreams)?;
    Ok(axum::Json(
        state
            .control
            .provider_statuses()
            .into_iter()
            .map(provider_summary)
            .collect(),
    ))
}

pub(super) fn provider_summary(status: aegisproxy_core::ProviderStatus) -> ProviderSummary {
    ProviderSummary {
        id: status.id,
        kind: status.kind,
        state: status.state,
        source_hash: status.source_hash,
        last_success_unix_secs: status.last_success_unix_secs,
        stale_at_unix_secs: status.stale_at_unix_secs,
        endpoint_count: status.endpoint_count,
        error: status.error,
    }
}

pub(super) async fn certificates(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<CertificateSummary>>, ApiError> {
    authorize(&principal, Action::ReadCertificates)?;
    let config = state.control.runtime().config();
    let stored = state
        .control
        .certificate_statuses()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let mut stored: HashMap<_, _> = stored
        .into_iter()
        .map(|certificate| (certificate.id.clone(), certificate))
        .collect();
    let mut certificates = Vec::with_capacity(
        config
            .certificates
            .len()
            .saturating_add(config.acme.certificates.len()),
    );
    for certificate in &config.certificates {
        certificates.push(certificate_summary(
            certificate.id.clone(),
            certificate.hosts.clone(),
            "imported",
            None,
            stored.remove(&certificate.id),
        ));
    }
    for certificate in &config.acme.certificates {
        certificates.push(certificate_summary(
            certificate.id.clone(),
            certificate.hosts.clone(),
            "acme",
            Some(certificate.issuer.clone()),
            stored.remove(&certificate.id),
        ));
    }
    certificates.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(axum::Json(certificates))
}

fn certificate_summary(
    id: String,
    hosts: Vec<String>,
    source: &'static str,
    fallback_issuer: Option<String>,
    stored: Option<aegisproxy_core::CertificateStatus>,
) -> CertificateSummary {
    CertificateSummary {
        id,
        hosts,
        source,
        issuer: stored
            .as_ref()
            .map_or(fallback_issuer, |stored| Some(stored.issuer.clone())),
        generation: stored.as_ref().map(|stored| stored.generation.clone()),
        not_before_unix_secs: stored.as_ref().map(|stored| stored.not_before_unix_secs),
        not_after_unix_secs: stored.as_ref().map(|stored| stored.not_after_unix_secs),
        state: if stored.is_some() {
            "active"
        } else {
            "missing"
        },
    }
}

pub(super) async fn audit_records(
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

pub(super) async fn list_tokens(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<crate::TokenMetadata>>, ApiError> {
    authorize(&principal, Action::ManageIdentities)?;
    Ok(axum::Json(state.tokens.list()))
}

pub(super) async fn create_token(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    payload: Result<Json<TokenCreateRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let current = state.control.runtime().revision().to_string();
    let audit = begin_mutation(
        &state,
        &principal,
        &request_id,
        Some(current.clone()),
        MutationSpec {
            permission: Action::ManageIdentities,
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
    let request = match payload {
        Ok(Json(request)) => request,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
    let now = unix_time().ok_or(ApiError::Internal)?;
    if request.expires_unix_secs <= now
        || request.expires_unix_secs > now.saturating_add(MAX_TOKEN_LIFETIME_SECS)
    {
        return Err(audited_failure(&audit, "invalid_expiry", ApiError::InvalidRequest).await);
    }
    let scopes = match crate::TokenScopes::new(request.role, request.scopes) {
        Ok(scopes) => scopes,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_scopes", ApiError::InvalidRequest).await);
        }
    };
    let owner_id = match principal.owner_id.clone() {
        Some(owner_id) => owner_id,
        None => {
            return Err(audited_failure(&audit, "owner_unavailable", ApiError::Forbidden).await);
        }
    };
    let permit = match Arc::clone(&state.auth_permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(audited_failure(&audit, "capacity_exhausted", ApiError::Busy).await),
    };
    let store = Arc::clone(&state.tokens);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store.issue(request.role, owner_id, scopes, request.expires_unix_secs)
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

pub(super) async fn revoke_token(
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
            permission: Action::ManageIdentities,
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

pub(super) async fn renew_certificate(
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

pub(super) async fn create_backup_archive(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    payload: Result<Json<BackupCreateRequest>, JsonRejection>,
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
    let request = match payload {
        Ok(Json(request)) => request,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
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

pub(super) async fn validate_restore_archive(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    principal: Principal,
    payload: Result<Json<RestoreValidateRequest>, JsonRejection>,
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
    let request = match payload {
        Ok(Json(request)) => request,
        Err(_) => {
            return Err(audited_failure(&audit, "invalid_json", ApiError::InvalidRequest).await);
        }
    };
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
