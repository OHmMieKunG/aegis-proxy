//! Private Unix-socket administrative HTTP service.

use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aegisproxy_core::ManagedControl;
use aegisproxy_secrets::SecretRef;
use axum::{
    Router,
    extract::{ConnectInfo, Extension, FromRequestParts, Request, State, connect_info::Connected},
    http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    serve::IncomingStream,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use thiserror::Error;
use tokio::{net::UnixListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;

use crate::{Action, AuditLog, Role, TokenStore};

const AUDIT_KEY_BYTES: usize = 64;
const REQUEST_ID_BYTES: usize = 16;

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
                return Ok(Self {
                    actor_type: "unix_peer",
                    actor_id: uid.to_string(),
                    role: Role::Admin,
                });
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
            Ok(Self {
                actor_type: "api_token",
                actor_id: metadata.id,
                role: metadata.role,
            })
        }
    }
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Forbidden,
    Busy,
    Timeout,
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Busy => (StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted"),
            Self::Timeout => (StatusCode::GATEWAY_TIMEOUT, "request_timeout"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (status, axum::Json(ErrorResponse { error: code })).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    request_id: String,
    active_revision: String,
    administration_ready: bool,
    audit_ready: bool,
    actor_type: &'static str,
    actor_id: String,
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
        timeout: Duration::from_secs(config.admin.request_timeout_secs),
    };
    let app = Router::new()
        .route("/v1/live", get(live))
        .route("/v1/ready", get(ready))
        .route("/v1/status", get(status))
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
) -> Result<Response, ApiError> {
    let _permit = Arc::clone(&state.request_permits)
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let request_id = request_id().ok_or(ApiError::Internal)?;
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));
    let mut response = tokio::time::timeout(state.timeout, next.run(request))
        .await
        .map_err(|_| ApiError::Timeout)?;
    let value = HeaderValue::from_str(&request_id).map_err(|_| ApiError::Internal)?;
    response.headers_mut().insert("x-request-id", value);
    Ok(response)
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

async fn status(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    principal: Principal,
) -> Result<axum::Json<StatusResponse>, ApiError> {
    authorize(&principal, Action::ReadStatus)?;
    Ok(axum::Json(StatusResponse {
        request_id: request_id.0,
        active_revision: state.control.runtime().revision().to_string(),
        administration_ready: state.control.coordinator().administration_ready(),
        audit_ready: state.audit.is_some(),
        actor_type: principal.actor_type,
        actor_id: principal.actor_id,
    }))
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
    fn broad_socket_parent_is_rejected() {
        let root = temporary_directory("broad");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("broad root");
        let result = bind_private_socket(&root.join("admin.sock"));
        assert!(result.is_err());
        fs::remove_dir(root).expect("remove root");
    }
}
