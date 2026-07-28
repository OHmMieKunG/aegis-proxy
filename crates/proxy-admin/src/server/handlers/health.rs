use super::super::*;

pub(in crate::server) async fn live() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse { status: "live" })
}

pub(in crate::server) async fn ready(
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

pub(in crate::server) async fn metrics(
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

pub(in crate::server) async fn status(
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

pub(in crate::server) async fn health_details(
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

pub(in crate::server) async fn drain_node(
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

pub(in crate::server) async fn active_config(
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

pub(in crate::server) async fn validate_config(
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

pub(in crate::server) async fn preview_config(
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
