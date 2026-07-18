//! Private Unix-socket administrative HTTP service.

use std::{
    collections::HashMap,
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aegisproxy_config::{
    BalancingAlgorithm, Config,
    revision::{RevisionError, RevisionMetadata},
};
use aegisproxy_core::{ActivationError, ManagedControl, RouteIndex, RuntimeHandle};
use aegisproxy_secrets::SecretRef;
use axum::{
    Router,
    extract::{
        ConnectInfo, Extension, FromRequestParts, Json, Path as AxumPath, Query, Request, State,
        connect_info::Connected, rejection::JsonRejection,
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, ETAG, IF_MATCH},
        request::Parts,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::IncomingStream,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{net::UnixListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;

use crate::{Action, AuditEvent, AuditLog, AuditOutcome, Role, TokenStore};

const AUDIT_KEY_BYTES: usize = 64;
const REQUEST_ID_BYTES: usize = 16;
const MAX_RATE_LIMIT_KEYS: usize = 2_048;
const MAX_TOKEN_LIFETIME_SECS: u64 = 365 * 24 * 60 * 60;

/// Administrative service startup or listener failure.
#[derive(Debug, Error)]
pub enum AdminServerError {
    /// Private socket preparation or service failure.
    #[error("administrative socket failed: {0}")]
    Io(#[from] io::Error),
    /// Token metadata could not be loaded safely.
    #[error("administrative token store failed")]
    Token,
    /// Audit key or authenticated audit records could not be loaded safely.
    #[error("administrative audit store failed")]
    Audit,
    /// Blocking initialization task failed.
    #[error("administrative initialization task failed: {0}")]
    Initialization(String),
}

#[derive(Clone, Debug)]
struct AppState {
    control: ManagedControl,
    tokens: Arc<TokenStore>,
    audit: Option<Arc<AuditLog>>,
    allowed_uids: Arc<[u32]>,
    auth_permits: Arc<Semaphore>,
    request_permits: Arc<Semaphore>,
    rate_limiter: Arc<RateLimiter>,
    started: Instant,
    timeout: Duration,
}

#[derive(Clone, Debug)]
struct UnixPeer {
    uid: Option<u32>,
}

impl Connected<IncomingStream<'_, UnixListener>> for UnixPeer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream
                .io()
                .peer_cred()
                .ok()
                .map(|credentials| credentials.uid()),
        }
    }
}

#[derive(Clone, Debug)]
struct RequestId(String);

#[derive(Clone, Debug)]
struct Principal {
    actor_type: &'static str,
    actor_id: String,
    role: Role,
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let peer = parts.extensions.get::<ConnectInfo<UnixPeer>>().cloned();
        let authorization = authorization_header(&parts.headers);
        let state = state.clone();
        async move {
            let authorization = authorization?;
            let uid = peer
                .and_then(|ConnectInfo(peer)| peer.uid)
                .ok_or(ApiError::Unauthorized)?;
            if !state.allowed_uids.is_empty() && !state.allowed_uids.contains(&uid) {
                return Err(ApiError::Unauthorized);
            }
            let Some(authorization) = authorization else {
                let principal = Self {
                    actor_type: "unix_peer",
                    actor_id: uid.to_string(),
                    role: Role::Admin,
                };
                state.rate_limiter.check(&principal)?;
                return Ok(principal);
            };
            let token = authorization
                .strip_prefix("Bearer ")
                .filter(|token| {
                    !token.is_empty() && !token.bytes().any(|byte| byte.is_ascii_whitespace())
                })
                .ok_or(ApiError::Unauthorized)?
                .to_owned();
            let permit = Arc::clone(&state.auth_permits)
                .try_acquire_owned()
                .map_err(|_| ApiError::Busy)?;
            let tokens = Arc::clone(&state.tokens);
            let metadata = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                tokens.authenticate(&token, unix_time().unwrap_or(u64::MAX))
            })
            .await
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::Unauthorized)?;
            let principal = Self {
                actor_type: "api_token",
                actor_id: metadata.id,
                role: metadata.role,
            };
            state.rate_limiter.check(&principal)?;
            Ok(principal)
        }
    }
}

#[derive(Debug)]
struct RateLimiter {
    requests_per_second: f64,
    burst: f64,
    max_keys: usize,
    buckets: Mutex<HashMap<String, Bucket>>,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl RateLimiter {
    fn new(requests_per_second: u32, burst: u32) -> Self {
        Self {
            requests_per_second: f64::from(requests_per_second),
            burst: f64::from(burst),
            max_keys: MAX_RATE_LIMIT_KEYS,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, principal: &Principal) -> Result<(), ApiError> {
        self.check_at(principal, Instant::now())
    }

    fn check_at(&self, principal: &Principal, now: Instant) -> Result<(), ApiError> {
        let key = format!("{}:{}", principal.actor_type, principal.actor_id);
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bucket) = buckets.get_mut(&key) {
            let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * self.requests_per_second).min(self.burst);
            bucket.updated = now;
            if bucket.tokens < 1.0 {
                return Err(ApiError::RateLimited);
            }
            bucket.tokens -= 1.0;
            return Ok(());
        }
        if buckets.len() >= self.max_keys {
            return Err(ApiError::RateLimited);
        }
        buckets.insert(
            key,
            Bucket {
                tokens: self.burst - 1.0,
                updated: now,
            },
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum ApiError {
    Unauthorized,
    Forbidden,
    Busy,
    RateLimited,
    Timeout,
    InvalidRequest,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, _) = self.contract();
        let mut response = status.into_response();
        response
            .headers_mut()
            .insert("x-aegis-error-code", HeaderValue::from_static(code));
        response
    }
}

impl ApiError {
    fn contract(self) -> (StatusCode, &'static str, &'static str) {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Busy => (StatusCode::SERVICE_UNAVAILABLE, "capacity_exhausted"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Timeout => (StatusCode::GATEWAY_TIMEOUT, "request_timeout"),
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "revision_conflict"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let message = match self {
            Self::Unauthorized => "authentication required",
            Self::Forbidden => "operation is not permitted",
            Self::Busy => "administrative capacity is exhausted",
            Self::RateLimited => "administrative rate limit exceeded",
            Self::Timeout => "administrative request timed out",
            Self::InvalidRequest => "request is invalid",
            Self::NotFound => "resource was not found",
            Self::Conflict => "active revision changed",
            Self::Unavailable => "administrative dependency is unavailable",
            Self::Internal => "administrative request failed",
        };
        (status, code, message)
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: String,
    message: String,
    details: Vec<ErrorDetail>,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    path: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    request_id: String,
    version: &'static str,
    uptime_secs: u64,
    active_revision: String,
    administration_ready: bool,
    audit_ready: bool,
    actor_type: &'static str,
    actor_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after_sequence: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct RevisionPage {
    items: Vec<RevisionMetadata>,
    next_sequence: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RevisionResponse {
    metadata: RevisionMetadata,
    status: &'static str,
    config: Config,
}

#[derive(Debug, Serialize)]
struct RouteSummary {
    id: String,
    listeners: Vec<String>,
    hosts: Vec<String>,
    paths: Vec<String>,
    path_prefixes: Vec<String>,
    methods: Vec<String>,
    default: bool,
    priority: i32,
    middlewares: Vec<String>,
    upstream_group: Option<String>,
}

#[derive(Debug, Serialize)]
struct UpstreamSummary {
    id: String,
    algorithm: BalancingAlgorithm,
    max_in_flight: usize,
    endpoints: Vec<EndpointSummary>,
}

#[derive(Debug, Serialize)]
struct EndpointSummary {
    id: String,
    transport: String,
    weight: u32,
    state: &'static str,
}

#[derive(Debug, Serialize)]
struct CertificateSummary {
    id: String,
    hosts: Vec<String>,
    source: &'static str,
    issuer: Option<String>,
    generation: Option<String>,
    not_before_unix_secs: Option<i64>,
    not_after_unix_secs: Option<i64>,
    state: &'static str,
}

#[derive(Debug, Serialize)]
struct AuditPage {
    items: Vec<crate::AuditRecord>,
    next_sequence: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ValidationResponse {
    valid: bool,
    route_fingerprint: String,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PreviewResponse {
    active_revision: String,
    active_route_fingerprint: String,
    candidate_route_fingerprint: String,
    activation_class: &'static str,
    config: Config,
}

#[derive(Debug, Serialize)]
struct CandidateResponse {
    id: String,
    hash: String,
    sequence: u64,
}

#[derive(Debug, Serialize)]
struct ActivationResponse {
    active: String,
    previous: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenCreateRequest {
    role: Role,
    expires_unix_secs: u64,
}

#[derive(Debug, Serialize)]
struct IssuedTokenBody<'a> {
    token: &'a str,
    metadata: &'a crate::TokenMetadata,
}

#[derive(Debug, Serialize)]
struct RevocationResponse {
    revoked: bool,
}

#[derive(Debug, Serialize)]
struct RenewalResponse {
    requested: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCreateRequest {
    output: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreValidateRequest {
    input: String,
    identity: String,
}

#[derive(Debug)]
struct MutationAudit {
    log: Arc<AuditLog>,
    runtime: RuntimeHandle,
    actor_type: String,
    actor_id: String,
    action: String,
    resource_id: String,
    request_id: String,
    old_revision: Option<String>,
}

#[derive(Debug)]
struct MutationSpec<'a> {
    permission: Action,
    action: &'a str,
    resource_id: &'a str,
    new_revision: Option<String>,
}

/// Serve private administrative requests until process cancellation.
pub async fn serve(
    control: ManagedControl,
    shutdown: CancellationToken,
) -> Result<(), AdminServerError> {
    let config = control.runtime().config();
    let state_dir = PathBuf::from(&config.runtime.state_dir);
    let socket_path = config
        .admin
        .unix_socket
        .as_deref()
        .map_or_else(|| state_dir.join("admin/admin.sock"), PathBuf::from);
    let token_path = state_dir.join("admin/tokens.json");
    let tokens = tokio::task::spawn_blocking(move || TokenStore::open(token_path))
        .await
        .map_err(|error| AdminServerError::Initialization(error.to_string()))?
        .map_err(|_| AdminServerError::Token)?;
    let audit = match config.admin.audit_key.clone() {
        Some(reference) => {
            let audit_path = state_dir.join("audit/admin.jsonl");
            Some(
                tokio::task::spawn_blocking(move || {
                    let key = SecretRef::parse(&reference)
                        .and_then(|reference| reference.resolve(AUDIT_KEY_BYTES))
                        .map_err(|_| AdminServerError::Audit)?;
                    AuditLog::open(audit_path, key.as_ref().to_vec())
                        .map(Arc::new)
                        .map_err(|_| AdminServerError::Audit)
                })
                .await
                .map_err(|error| AdminServerError::Initialization(error.to_string()))??,
            )
        }
        None => None,
    };
    let socket_path_for_bind = socket_path.clone();
    let (listener, guard) =
        tokio::task::spawn_blocking(move || bind_private_socket(&socket_path_for_bind))
            .await
            .map_err(|error| AdminServerError::Initialization(error.to_string()))??;
    let state = AppState {
        control,
        tokens: Arc::new(tokens),
        audit,
        allowed_uids: Arc::from(config.admin.allowed_uids.clone()),
        auth_permits: Arc::new(Semaphore::new(config.admin.max_auth_in_flight)),
        request_permits: Arc::new(Semaphore::new(config.admin.max_in_flight)),
        rate_limiter: Arc::new(RateLimiter::new(
            config.admin.requests_per_second,
            config.admin.burst,
        )),
        started: Instant::now(),
        timeout: Duration::from_secs(config.admin.request_timeout_secs),
    };
    state
        .control
        .runtime()
        .set_audit_ready(state.audit.is_some());
    let app = Router::new()
        .route("/v1/live", get(live))
        .route("/v1/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/config/active", get(active_config))
        .route("/v1/config/validate", post(validate_config))
        .route("/v1/config/preview", post(preview_config))
        .route("/v1/config/candidates", post(create_candidate))
        .route(
            "/v1/config/candidates/{id}/activate",
            post(activate_candidate),
        )
        .route("/v1/config/revisions", get(revisions))
        .route("/v1/config/revisions/{id}", get(revision))
        .route(
            "/v1/config/revisions/{id}/rollback",
            post(rollback_revision),
        )
        .route("/v1/routes", get(routes))
        .route("/v1/upstreams", get(upstreams))
        .route("/v1/certificates", get(certificates))
        .route("/v1/certificates/{id}/renew", post(renew_certificate))
        .route("/v1/audit", get(audit_records))
        .route("/v1/tokens", get(list_tokens).post(create_token))
        .route("/v1/tokens/{id}/revoke", post(revoke_token))
        .route("/v1/backups", post(create_backup_archive))
        .route("/v1/restore/validate", post(validate_restore_archive))
        .layer(axum::extract::DefaultBodyLimit::max(
            config.admin.max_body_bytes,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), bound_request))
        .with_state(state);
    tracing::info!(path = %socket_path.display(), "private administration listener started");
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<UnixPeer>(),
    )
    .with_graceful_shutdown(shutdown.cancelled_owned())
    .await;
    drop(guard);
    result.map_err(AdminServerError::Io)
}

async fn bound_request(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request_id().unwrap_or_else(|| "request-id-unavailable".into());
    let _permit = match Arc::clone(&state.request_permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return error_contract(ApiError::Busy.into_response(), &request_id),
    };
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));
    let response = match tokio::time::timeout(state.timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::Timeout.into_response(),
    };
    let mut response = if response.status().is_client_error()
        || (response.status().is_server_error()
            && !response
                .headers()
                .get(CONTENT_TYPE)
                .is_some_and(|value| value.as_bytes().starts_with(b"application/json")))
    {
        error_contract(response, &request_id)
    } else {
        response
    };
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

fn error_contract(mut response: Response, request_id: &str) -> Response {
    let status = response.status();
    let tagged = response
        .headers_mut()
        .remove("x-aegis-error-code")
        .and_then(|value| value.to_str().ok().map(str::to_owned));
    let (code, message) = tagged.as_deref().map_or_else(
        || match status {
            StatusCode::NOT_FOUND => ("not_found", "resource was not found"),
            StatusCode::METHOD_NOT_ALLOWED => ("method_not_allowed", "method is not allowed"),
            StatusCode::PAYLOAD_TOO_LARGE => ("body_too_large", "request body is too large"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                ("invalid_content_type", "content type is not supported")
            }
            _ => ("request_failed", "request failed"),
        },
        |code| {
            let message = match code {
                "unauthorized" => "authentication required",
                "forbidden" => "operation is not permitted",
                "capacity_exhausted" => "administrative capacity is exhausted",
                "rate_limited" => "administrative rate limit exceeded",
                "request_timeout" => "administrative request timed out",
                "invalid_request" => "request is invalid",
                "not_found" => "resource was not found",
                "revision_conflict" => "active revision changed",
                "unavailable" => "administrative dependency is unavailable",
                _ => "administrative request failed",
            };
            (code, message)
        },
    );
    let body = serde_json::to_vec(&ErrorResponse {
        error: ErrorBody {
            code: code.to_owned(),
            message: message.to_owned(),
            details: Vec::new(),
            request_id: request_id.to_owned(),
        },
    })
    .unwrap_or_else(|_| b"{\"error\":{\"code\":\"internal_error\"}}".to_vec());
    let mut contract = Response::new(axum::body::Body::from(body));
    *contract.status_mut() = status;
    contract
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    contract
}

async fn live() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse { status: "live" })
}

async fn ready(State(state): State<AppState>) -> (StatusCode, axum::Json<HealthResponse>) {
    if state.control.coordinator().administration_ready() {
        (
            StatusCode::OK,
            axum::Json(HealthResponse { status: "ready" }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(HealthResponse {
                status: "recovery_required",
            }),
        )
    }
}

async fn metrics(
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

async fn status(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    principal: Principal,
) -> Result<axum::Json<StatusResponse>, ApiError> {
    authorize(&principal, Action::ReadStatus)?;
    Ok(axum::Json(StatusResponse {
        request_id: request_id.0,
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started.elapsed().as_secs(),
        active_revision: state.control.runtime().revision().to_string(),
        administration_ready: state.control.coordinator().administration_ready(),
        audit_ready: state.audit.is_some(),
        actor_type: principal.actor_type,
        actor_id: principal.actor_id,
    }))
}

async fn active_config(
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

async fn validate_config(
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

async fn preview_config(
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

async fn create_candidate(
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

async fn activate_candidate(
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

async fn rollback_revision(
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

async fn revisions(
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

async fn revision(
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

async fn routes(
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

async fn upstreams(
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

async fn certificates(
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

async fn audit_records(
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

async fn list_tokens(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<crate::TokenMetadata>>, ApiError> {
    authorize(&principal, Action::ManageIdentities)?;
    Ok(axum::Json(state.tokens.list()))
}

async fn create_token(
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
    let permit = match Arc::clone(&state.auth_permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(audited_failure(&audit, "capacity_exhausted", ApiError::Busy).await),
    };
    let store = Arc::clone(&state.tokens);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store.issue(request.role, request.expires_unix_secs)
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

async fn revoke_token(
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

async fn renew_certificate(
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

async fn create_backup_archive(
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

async fn validate_restore_archive(
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

fn page_limit(page: &Page) -> Result<usize, ApiError> {
    let limit = page.limit.unwrap_or(100);
    (1..=100)
        .contains(&limit)
        .then_some(limit)
        .ok_or(ApiError::InvalidRequest)
}

fn etag(revision: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("\"{revision}\"")).ok()
}

fn require_toml(headers: &HeaderMap) -> Result<(), ApiError> {
    let values: Vec<_> = headers.get_all(CONTENT_TYPE).iter().collect();
    match values.as_slice() {
        [value] if value.as_bytes() == b"application/toml" => Ok(()),
        _ => Err(ApiError::InvalidRequest),
    }
}

fn valid_api_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    path.is_absolute()
        && path.file_name().is_some()
        && value.len() <= 4_096
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && !path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
}

fn expected_revision(headers: &HeaderMap) -> Result<String, ApiError> {
    let values = headers
        .get_all(IF_MATCH)
        .iter()
        .map(HeaderValue::to_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::InvalidRequest)?;
    let [value] = values.as_slice() else {
        return Err(ApiError::InvalidRequest);
    };
    let revision = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| {
            (66..=96).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f' | b'-'))
        })
        .ok_or(ApiError::InvalidRequest)?;
    Ok(revision.to_owned())
}

async fn load_candidate(body: axum::body::Bytes) -> Result<Config, ApiError> {
    tokio::task::spawn_blocking(move || aegisproxy_config::load_bytes(&body))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(|_| ApiError::InvalidRequest)
}

async fn begin_mutation(
    state: &AppState,
    principal: &Principal,
    request_id: &RequestId,
    old_revision: Option<String>,
    spec: MutationSpec<'_>,
) -> Result<MutationAudit, ApiError> {
    let audit = MutationAudit {
        log: state.audit.clone().ok_or(ApiError::Unavailable)?,
        runtime: state.control.runtime(),
        actor_type: principal.actor_type.to_owned(),
        actor_id: principal.actor_id.clone(),
        action: spec.action.to_owned(),
        resource_id: spec.resource_id.to_owned(),
        request_id: request_id.0.clone(),
        old_revision,
    };
    if !principal.role.allows(spec.permission) {
        audit
            .record(
                AuditOutcome::Denied,
                spec.new_revision,
                Some("authorization_denied"),
            )
            .await?;
        return Err(ApiError::Forbidden);
    }
    audit
        .record(AuditOutcome::Intent, spec.new_revision, None)
        .await?;
    Ok(audit)
}

impl MutationAudit {
    async fn record(
        &self,
        outcome: AuditOutcome,
        new_revision: Option<String>,
        error_code: Option<&str>,
    ) -> Result<(), ApiError> {
        let log = Arc::clone(&self.log);
        let event = AuditEvent {
            actor_type: self.actor_type.clone(),
            actor_id: self.actor_id.clone(),
            action: self.action.clone(),
            resource_id: self.resource_id.clone(),
            request_id: self.request_id.clone(),
            old_revision: self.old_revision.clone(),
            new_revision,
            authorized: outcome != AuditOutcome::Denied,
            outcome,
            error_code: error_code.map(str::to_owned),
        };
        let result = tokio::task::spawn_blocking(move || log.append(event))
            .await
            .map_err(|_| ApiError::Internal)?
            .map(|_| ())
            .map_err(|_| ApiError::Unavailable);
        self.runtime.record_audit_operation(if result.is_ok() {
            match outcome {
                AuditOutcome::Intent => "intent",
                AuditOutcome::Success => "success",
                AuditOutcome::Denied => "denied",
                AuditOutcome::Failed => "failed",
            }
        } else {
            "unavailable"
        });
        if result.is_err() {
            self.runtime.set_audit_ready(false);
        }
        result
    }
}

async fn audited_failure(audit: &MutationAudit, code: &'static str, error: ApiError) -> ApiError {
    if audit
        .record(AuditOutcome::Failed, None, Some(code))
        .await
        .is_err()
    {
        ApiError::Unavailable
    } else {
        error
    }
}

fn activation_error(error: ActivationError) -> (&'static str, ApiError) {
    match error {
        ActivationError::Revision(RevisionError::Conflict) => {
            ("revision_conflict", ApiError::Conflict)
        }
        ActivationError::RestartRequired => ("restart_required", ApiError::Conflict),
        ActivationError::RecoveryRequired => ("recovery_required", ApiError::Unavailable),
        ActivationError::Revision(RevisionError::InvalidStored(_)) => {
            ("revision_not_found", ApiError::NotFound)
        }
        ActivationError::Revision(_)
        | ActivationError::Preparation(_)
        | ActivationError::Probation => ("activation_failed", ApiError::Unavailable),
    }
}

fn authorize(principal: &Principal, action: Action) -> Result<(), ApiError> {
    principal
        .role
        .allows(action)
        .then_some(())
        .ok_or(ApiError::Forbidden)
}

fn authorization_header(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let values = headers
        .get_all(AUTHORIZATION)
        .iter()
        .map(HeaderValue::to_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::Unauthorized)?;
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some((*value).to_owned())),
        _ => Err(ApiError::Unauthorized),
    }
}

fn request_id() -> Option<String> {
    let mut bytes = [0_u8; REQUEST_ID_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

fn unix_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn bind_private_socket(path: &Path) -> Result<(UnixListener, SocketGuard), io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_input("socket has no parent"))?;
    create_private_directory(parent)?;
    remove_stale_socket(path)?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    let metadata = fs::symlink_metadata(path)?;
    Ok((
        listener,
        SocketGuard {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    ))
}

fn create_private_directory(path: &Path) -> Result<(), io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o077 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrative socket parent is not a private directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        }
        Err(error) => Err(error),
    }
}

fn remove_stale_socket(path: &Path) -> Result<(), io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(invalid_input("administrative socket path is not a socket"));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "administrative socket is active",
        )),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(path),
        Err(error) => Err(error),
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(Debug)]
struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegisproxy-admin-{name}-{}-{}",
            std::process::id(),
            request_id().expect("request ID")
        ))
    }

    #[tokio::test]
    async fn socket_is_private_and_removed_only_by_its_guard() {
        let root = temporary_directory("socket");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let path = root.join("admin.sock");
        let (_listener, guard) = bind_private_socket(&path).expect("private socket");
        let mode = fs::symlink_metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o660);
        drop(guard);
        assert!(!path.exists());
        fs::remove_dir(root).expect("remove root");
    }

    #[tokio::test]
    async fn errors_use_stable_nested_contract_and_hide_internal_tag() {
        let response = error_contract(ApiError::Forbidden.into_response(), "request-123");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get("x-aegis-error-code").is_none());
        let body = axum::body::to_bytes(response.into_body(), 4_096)
            .await
            .expect("error body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("error JSON");
        assert_eq!(value["error"]["code"], "forbidden");
        assert_eq!(value["error"]["request_id"], "request-123");
        assert_eq!(value["error"]["details"], serde_json::json!([]));
    }

    #[test]
    fn checked_openapi_contains_every_private_route() {
        let openapi = include_str!("../../../config/schema/admin-openapi.yaml");
        for path in [
            "/metrics:",
            "/v1/live:",
            "/v1/ready:",
            "/v1/status:",
            "/v1/config/active:",
            "/v1/config/validate:",
            "/v1/config/preview:",
            "/v1/config/candidates:",
            "/v1/config/candidates/{id}/activate:",
            "/v1/config/revisions:",
            "/v1/config/revisions/{id}:",
            "/v1/config/revisions/{id}/rollback:",
            "/v1/routes:",
            "/v1/upstreams:",
            "/v1/certificates:",
            "/v1/certificates/{id}/renew:",
            "/v1/audit:",
            "/v1/tokens:",
            "/v1/tokens/{id}/revoke:",
            "/v1/backups:",
            "/v1/restore/validate:",
        ] {
            assert!(openapi.contains(path), "OpenAPI missing {path}");
        }
        assert!(!openapi.contains("0.0.0.0"));
        assert!(!openapi.contains("private_key"));
    }

    #[test]
    fn duplicate_or_non_text_authorization_never_downgrades_to_peer_auth() {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer first"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
        assert!(authorization_header(&headers).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(&[0xff]).expect("opaque header value"),
        );
        assert!(authorization_header(&headers).is_err());
    }

    #[test]
    fn principal_rate_limit_enforces_burst_refill_and_key_bound() {
        let start = Instant::now();
        let limiter = RateLimiter {
            requests_per_second: 2.0,
            burst: 2.0,
            max_keys: 1,
            buckets: Mutex::new(HashMap::new()),
        };
        let first = Principal {
            actor_type: "unix_peer",
            actor_id: "1000".into(),
            role: Role::Admin,
        };
        assert!(limiter.check_at(&first, start).is_ok());
        assert!(limiter.check_at(&first, start).is_ok());
        assert!(limiter.check_at(&first, start).is_err());
        assert!(
            limiter
                .check_at(&first, start + Duration::from_millis(500))
                .is_ok()
        );

        let second = Principal {
            actor_type: "api_token",
            actor_id: "second".into(),
            role: Role::Viewer,
        };
        assert!(limiter.check_at(&second, start).is_err());
    }

    #[test]
    fn pagination_and_etags_are_bounded() {
        assert_eq!(
            page_limit(&Page {
                after_sequence: None,
                limit: None,
            })
            .expect("default page"),
            100
        );
        assert!(
            page_limit(&Page {
                after_sequence: None,
                limit: Some(0),
            })
            .is_err()
        );
        assert!(
            page_limit(&Page {
                after_sequence: None,
                limit: Some(101),
            })
            .is_err()
        );
        assert_eq!(etag("0001-deadbeef").expect("ETag"), "\"0001-deadbeef\"");
        assert!(etag("bad\nrevision").is_none());
    }

    #[test]
    fn mutation_preconditions_are_exact_and_single_valued() {
        let revision = format!("{:020}-{}", 1, "a".repeat(64));
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/toml"));
        headers.insert(
            IF_MATCH,
            HeaderValue::from_str(&format!("\"{revision}\"")).expect("If-Match"),
        );
        assert!(require_toml(&headers).is_ok());
        assert_eq!(expected_revision(&headers).expect("revision"), revision);

        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/toml"));
        assert!(require_toml(&headers).is_err());
        headers.append(IF_MATCH, HeaderValue::from_static("\"duplicate\""));
        assert!(expected_revision(&headers).is_err());

        let mut weak = HeaderMap::new();
        weak.insert(
            IF_MATCH,
            HeaderValue::from_str(&format!("W/\"{revision}\"")).expect("weak ETag"),
        );
        assert!(expected_revision(&weak).is_err());
        assert!(valid_api_path(Path::new("/var/backups/aegis.age")));
        assert!(!valid_api_path(Path::new("relative.age")));
        assert!(!valid_api_path(Path::new("/var/backups/../escape.age")));
    }

    #[test]
    fn broad_socket_parent_is_rejected() {
        let root = temporary_directory("broad");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("broad root");
        let result = bind_private_socket(&root.join("admin.sock"));
        assert!(result.is_err());
        fs::remove_dir(root).expect("remove root");
    }
}
