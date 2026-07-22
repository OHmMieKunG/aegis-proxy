//! Private Unix-socket administrative HTTP service.

mod handlers;
mod support;

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

use crate::{
    Action, ApiObject, AuditEvent, AuditLog, AuditOutcome, ObjectId, PreparedProxyHost,
    ProxyHostPreparationError, ProxyHostPreviewSummary, ProxyHostSpec, ProxyHostStore,
    ProxyHostStoreError, Role, StoredProxyHost, TokenScopes, TokenStore,
};
use handlers::*;
use support::*;

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
    /// Typed Proxy Host desired state could not be loaded safely.
    #[error("administrative Proxy Host store failed")]
    ProxyHosts,
    /// Blocking initialization task failed.
    #[error("administrative initialization task failed: {0}")]
    Initialization(String),
}

#[derive(Clone, Debug)]
struct AppState {
    control: ManagedControl,
    tokens: Arc<TokenStore>,
    proxy_hosts: Arc<ProxyHostStore>,
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
    owner_id: Option<ObjectId>,
    token_scopes: Option<TokenScopes>,
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
                let owner_id = format!("uid-{uid}")
                    .parse()
                    .map_err(|_| ApiError::Internal)?;
                let principal = Self {
                    actor_type: "unix_peer",
                    actor_id: uid.to_string(),
                    role: Role::Admin,
                    owner_id: Some(owner_id),
                    token_scopes: None,
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
                owner_id: metadata.owner_id,
                token_scopes: Some(metadata.scopes),
            };
            state.rate_limiter.check(&principal)?;
            Ok(principal)
        }
    }
}

#[derive(Debug)]
struct ValidateProxyHostPrincipal(Principal);

impl FromRequestParts<AppState> for ValidateProxyHostPrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let principal = Principal::from_request_parts(parts, state).await?;
        authorize(&principal, Action::ValidateConfig)?;
        Ok(Self(principal))
    }
}

#[derive(Debug)]
struct PreviewProxyHostPrincipal(Principal);

impl FromRequestParts<AppState> for PreviewProxyHostPrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let principal = Principal::from_request_parts(parts, state).await?;
        authorize(&principal, Action::PreviewConfig)?;
        Ok(Self(principal))
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
    ObjectConflict,
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
            Self::ObjectConflict => (StatusCode::CONFLICT, "object_conflict"),
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
            Self::ObjectConflict => "object state changed",
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
    node_id: String,
    fleet_generation: u64,
    active_revision: String,
    active_hash: String,
    administration_ready: bool,
    audit_ready: bool,
    draining: bool,
    certificate_owner: bool,
    managed_certificates: usize,
    actor_type: &'static str,
    actor_id: String,
}

#[derive(Debug, Serialize)]
struct HealthDetailsResponse {
    request_id: String,
    status: &'static str,
    active_revision: String,
    administration_ready: bool,
    audit_ready: bool,
    certificates: Vec<CertificateWindow>,
}

#[derive(Debug, Serialize)]
struct CertificateWindow {
    id: String,
    not_before_unix_secs: Option<i64>,
    not_after_unix_secs: Option<i64>,
    state: &'static str,
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
struct ProviderSummary {
    id: String,
    kind: &'static str,
    state: &'static str,
    source_hash: Option<String>,
    last_success_unix_secs: Option<u64>,
    stale_at_unix_secs: Option<u64>,
    endpoint_count: usize,
    error: Option<&'static str>,
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
struct ProxyHostValidationResponse {
    valid: bool,
    summary: ProxyHostPreviewSummary,
}

#[derive(Debug, Serialize)]
struct CandidateResponse {
    id: String,
    hash: String,
    sequence: u64,
}

#[derive(Debug, Serialize)]
struct ProxyHostCreateResponse {
    object: StoredProxyHost,
    candidate: CandidateResponse,
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
    scopes: Vec<Action>,
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

#[derive(Debug, Serialize)]
struct DrainResponse {
    draining: bool,
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
    node_id: String,
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
    let proxy_host_path = state_dir.join("admin/proxy-hosts.json");
    let proxy_host_store =
        tokio::task::spawn_blocking(move || ProxyHostStore::open(proxy_host_path))
            .await
            .map_err(|error| AdminServerError::Initialization(error.to_string()))?
            .map_err(|_| AdminServerError::ProxyHosts)?;
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
        proxy_hosts: Arc::new(proxy_host_store),
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
        .route("/live", get(live))
        .route("/ready", get(ready))
        .route("/health/details", get(health_details))
        .route("/v1/live", get(live))
        .route("/v1/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/node/drain", post(drain_node))
        .route("/v1/config/active", get(active_config))
        .route("/v1/config/validate", post(validate_config))
        .route("/v1/config/preview", post(preview_config))
        .route("/v1/proxy-hosts", get(proxy_hosts).post(create_proxy_host))
        .route("/v1/proxy-hosts/{id}", get(proxy_host))
        .route("/v1/proxy-hosts/validate", post(validate_proxy_host))
        .route("/v1/proxy-hosts/preview", post(preview_proxy_host))
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
        .route("/v1/providers", get(providers))
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

#[cfg(test)]
mod tests;
