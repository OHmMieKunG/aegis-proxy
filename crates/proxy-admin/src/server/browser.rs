use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use aegisproxy_config::AdminWebConfig;
use axum::{
    extract::{Extension, Query, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, LOCATION, ORIGIN, SET_COOKIE,
        },
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::{
    ApiError, AppState, MutationAudit, MutationSpec, OidcBinding, OidcBindingStore, OidcError,
    OidcIdentity, OidcProvider, Principal, RequestId, audited_failure, begin_mutation,
    no_store_json, require_json, unix_time,
};
use crate::{Action, AuditOutcome, ObjectId, Role};

pub(super) const SESSION_COOKIE: &str = "__Host-aegis-session";
const CSRF_HEADER: &str = "x-aegis-csrf-token";
const FETCH_SITE_HEADER: &str = "sec-fetch-site";
const MAX_SESSIONS: usize = 1_024;
const IDLE_TTL_SECS: u64 = 15 * 60;
const ABSOLUTE_TTL_SECS: u64 = 60 * 60;
const ROTATION_SECS: u64 = 15 * 60;
const ROTATION_OVERLAP_SECS: u64 = 30;
const SESSION_SECRET_BYTES: usize = 32;
const MAX_CALLBACK_CODE_BYTES: usize = 2_048;

#[derive(Clone, Debug)]
pub(super) struct BrowserAuth {
    expected_host: String,
    origin: String,
    pub(super) oidc: OidcProvider,
    sessions: Arc<SessionStore>,
    bindings: Arc<OidcBindingStore>,
    binding_available: Arc<AtomicBool>,
}

impl BrowserAuth {
    pub(super) fn new(
        config: &AdminWebConfig,
        oidc_available: Arc<std::sync::atomic::AtomicBool>,
        bindings: OidcBindingStore,
    ) -> Option<Self> {
        let oidc = config.oidc.clone()?;
        Some(Self {
            expected_host: format!("localhost:{}", config.bind.port()),
            origin: config.origin.clone(),
            oidc: OidcProvider::new(oidc, &config.origin, oidc_available),
            sessions: Arc::new(SessionStore::new()),
            bindings: Arc::new(bindings),
            binding_available: Arc::new(AtomicBool::new(true)),
        })
    }

    pub(super) fn setup_required(&self) -> bool {
        self.bindings.is_empty()
    }

    pub(super) fn available(&self) -> bool {
        self.binding_available.load(Ordering::Acquire) && self.oidc.available()
    }

    fn mark_binding_unavailable(&self) {
        self.binding_available.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
struct SessionRecord {
    current_id: String,
    previous_id: Option<(String, u64)>,
    identity_id: ObjectId,
    owner_id: Option<ObjectId>,
    fingerprint: String,
    role: Role,
    csrf_token: String,
    created_unix_secs: u64,
    last_seen_unix_secs: u64,
    rotated_unix_secs: u64,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRecord")
            .field("current_id", &"[REDACTED]")
            .field(
                "previous_id",
                &self.previous_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field("identity_id", &self.identity_id)
            .field("owner_id", &self.owner_id)
            .field("role", &self.role)
            .field("csrf_token", &"[REDACTED]")
            .field("created_unix_secs", &self.created_unix_secs)
            .field("last_seen_unix_secs", &self.last_seen_unix_secs)
            .field("rotated_unix_secs", &self.rotated_unix_secs)
            .finish()
    }
}

struct SessionStore(Mutex<HashMap<String, SessionRecord>>);

impl fmt::Debug for SessionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionStore")
            .field(
                "entries",
                &self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len(),
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
pub(super) struct BrowserSession {
    pub(super) session_id: String,
    pub(super) identity_id: ObjectId,
    pub(super) owner_id: Option<ObjectId>,
    pub(super) role: Role,
    fingerprint: String,
    csrf_token: String,
    idle_expires_unix_secs: u64,
    absolute_expires_unix_secs: u64,
}

struct SessionAccess {
    session: BrowserSession,
    set_cookie: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginQuery {
    #[serde(default = "default_return_path")]
    return_to: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallbackQuery {
    code: String,
    state: String,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    session_state: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupRequest {
    setup_token: String,
}

#[derive(Debug, Serialize)]
struct SessionResponse<'a> {
    identity_id: &'a ObjectId,
    owner_id: &'a Option<ObjectId>,
    role: Role,
    permitted_actions: Vec<Action>,
    csrf_token: &'a str,
    idle_expires_unix_secs: u64,
    absolute_expires_unix_secs: u64,
}

impl SessionStore {
    fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    fn create(
        &self,
        identity: OidcIdentity,
        owner_id: Option<ObjectId>,
        now_unix_secs: u64,
    ) -> Result<BrowserSession, ApiError> {
        let current_id = random_secret()?;
        let csrf_token = random_secret()?;
        let mut sessions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retain_live(&mut sessions, now_unix_secs);
        if sessions.len() >= MAX_SESSIONS || sessions.contains_key(&current_id) {
            return Err(ApiError::Busy);
        }
        let OidcIdentity {
            identity_id,
            fingerprint,
            role,
        } = identity;
        let record = SessionRecord {
            current_id: current_id.clone(),
            previous_id: None,
            identity_id,
            owner_id,
            fingerprint,
            role,
            csrf_token,
            created_unix_secs: now_unix_secs,
            last_seen_unix_secs: now_unix_secs,
            rotated_unix_secs: now_unix_secs,
        };
        let session = session_snapshot(&record);
        sessions.insert(current_id, record);
        Ok(session)
    }

    fn access(&self, presented: &str, now_unix_secs: u64) -> Option<SessionAccess> {
        let mut sessions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retain_live(&mut sessions, now_unix_secs);
        let key = if sessions.contains_key(presented) {
            presented.to_owned()
        } else {
            sessions
                .iter()
                .find(|(_, record)| {
                    record
                        .previous_id
                        .as_ref()
                        .is_some_and(|(id, expires)| id == presented && now_unix_secs < *expires)
                })
                .map(|(key, _)| key.clone())?
        };
        let mut record = sessions.remove(&key)?;
        record
            .previous_id
            .take_if(|(_, expires)| now_unix_secs >= *expires);
        let mut set_cookie = presented != record.current_id;
        if now_unix_secs.saturating_sub(record.rotated_unix_secs) >= ROTATION_SECS {
            let replacement = random_secret().ok()?;
            record.previous_id = Some((
                record.current_id.clone(),
                now_unix_secs.saturating_add(ROTATION_OVERLAP_SECS),
            ));
            record.current_id = replacement;
            record.rotated_unix_secs = now_unix_secs;
            set_cookie = true;
        }
        record.last_seen_unix_secs = now_unix_secs;
        let session = session_snapshot(&record);
        sessions.insert(record.current_id.clone(), record);
        Some(SessionAccess {
            session,
            set_cookie,
        })
    }

    fn remove(&self, session_id: &str) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session_id);
    }

    fn replace(
        &self,
        prior_session_id: &str,
        identity: OidcIdentity,
        owner_id: ObjectId,
        now_unix_secs: u64,
    ) -> Result<BrowserSession, ApiError> {
        let current_id = random_secret()?;
        let csrf_token = random_secret()?;
        let mut sessions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retain_live(&mut sessions, now_unix_secs);
        let key = sessions
            .iter()
            .find(|(_, record)| {
                record.current_id == prior_session_id
                    || record
                        .previous_id
                        .as_ref()
                        .is_some_and(|(id, _)| id == prior_session_id)
            })
            .map(|(key, _)| key.clone())
            .ok_or(ApiError::Unauthorized)?;
        if sessions.contains_key(&current_id) {
            return Err(ApiError::Busy);
        }
        sessions.remove(&key);
        let record = SessionRecord {
            current_id: current_id.clone(),
            previous_id: None,
            identity_id: identity.identity_id,
            owner_id: Some(owner_id),
            fingerprint: identity.fingerprint,
            role: identity.role,
            csrf_token,
            created_unix_secs: now_unix_secs,
            last_seen_unix_secs: now_unix_secs,
            rotated_unix_secs: now_unix_secs,
        };
        let session = session_snapshot(&record);
        sessions.insert(current_id, record);
        Ok(session)
    }
}

fn retain_live(sessions: &mut HashMap<String, SessionRecord>, now_unix_secs: u64) {
    sessions.retain(|_, session| {
        now_unix_secs < session.created_unix_secs.saturating_add(ABSOLUTE_TTL_SECS)
            && now_unix_secs < session.last_seen_unix_secs.saturating_add(IDLE_TTL_SECS)
    });
}

fn session_snapshot(record: &SessionRecord) -> BrowserSession {
    let absolute_expires_unix_secs = record.created_unix_secs.saturating_add(ABSOLUTE_TTL_SECS);
    BrowserSession {
        session_id: record.current_id.clone(),
        identity_id: record.identity_id.clone(),
        owner_id: record.owner_id.clone(),
        role: record.role,
        fingerprint: record.fingerprint.clone(),
        csrf_token: record.csrf_token.clone(),
        idle_expires_unix_secs: record
            .last_seen_unix_secs
            .saturating_add(IDLE_TTL_SECS)
            .min(absolute_expires_unix_secs),
        absolute_expires_unix_secs,
    }
}

pub(super) async fn browser_boundary(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(browser) = state.browser.as_ref() else {
        return ApiError::Unavailable.into_response();
    };
    if !exact_header(request.headers(), HOST, &browser.expected_host)
        || request.headers().contains_key(AUTHORIZATION)
    {
        return browser_response(ApiError::Unauthorized.into_response(), request.uri().path());
    }
    let path = request.uri().path().to_owned();
    let public = matches!(
        path.as_str(),
        "/v1/auth/login" | "/v1/auth/callback" | "/v1/web/status"
    ) || is_ui_path(&path)
        || path.starts_with("/assets/");
    let session_route = matches!(
        path.as_str(),
        "/v1/session" | "/v1/session/setup" | "/v1/session/logout"
    );
    let mut access = None;
    if !public {
        let Some(session_id) = session_cookie(request.headers()) else {
            return browser_response(ApiError::Unauthorized.into_response(), &path);
        };
        let Some(found) = browser
            .sessions
            .access(&session_id, unix_time().unwrap_or(u64::MAX))
        else {
            return browser_response(ApiError::Unauthorized.into_response(), &path);
        };
        if let Some(owner_id) = found.session.owner_id.as_ref() {
            let valid_binding = browser
                .bindings
                .get(&found.session.fingerprint)
                .is_some_and(|binding| {
                    binding.user_id == found.session.identity_id && &binding.owner_id == owner_id
                });
            let valid_user = state
                .users
                .get(&found.session.identity_id)
                .is_some_and(|user| {
                    user.object.spec.enabled
                        && user.object.spec.role == found.session.role
                        && &user.object.metadata.owner_id == owner_id
                });
            let valid =
                browser.binding_available.load(Ordering::Acquire) && valid_binding && valid_user;
            if !valid {
                browser.sessions.remove(&found.session.session_id);
                return browser_response(ApiError::Unauthorized.into_response(), &path);
            }
        } else {
            let valid_provisional = found.session.role == Role::Admin
                && browser.bindings.get(&found.session.fingerprint).is_none();
            if !valid_provisional
                || (!browser.setup_required() && path.as_str() != "/v1/session/setup")
            {
                browser.sessions.remove(&found.session.session_id);
                return browser_response(ApiError::Unauthorized.into_response(), &path);
            }
            if !session_route {
                return browser_response(ApiError::Forbidden.into_response(), &path);
            }
        }
        if is_unsafe(request.method())
            && (!exact_header(request.headers(), ORIGIN, &browser.origin)
                || !exact_header(request.headers(), FETCH_SITE_HEADER, "same-origin")
                || !csrf_matches(request.headers(), &found.session.csrf_token))
        {
            return browser_response(ApiError::Forbidden.into_response(), &path);
        }
        request.extensions_mut().insert(found.session.clone());
        access = Some(found);
    }
    let mut response = next.run(request).await;
    if let Some(access) = access
        && access.set_cookie
        && !response.headers().contains_key(SET_COOKIE)
    {
        set_session_cookie(&mut response, &access.session.session_id);
    }
    browser_response(response, &path)
}

pub(super) async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let browser = state.browser.ok_or(ApiError::Unavailable)?;
    if !browser.binding_available.load(Ordering::Acquire) {
        return Err(ApiError::Unavailable);
    }
    let return_path = validate_return_path(query.return_to)?;
    let login = browser
        .oidc
        .login(return_path, unix_time().ok_or(ApiError::Unavailable)?)
        .await
        .map_err(map_oidc_error)?;
    redirect(&login.authorization_url)
}

pub(super) async fn callback(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let browser = state.browser.clone().ok_or(ApiError::Unavailable)?;
    if query.code.is_empty()
        || query.code.len() > MAX_CALLBACK_CODE_BYTES
        || query.state.is_empty()
        || query.state.len() > 512
        || query
            .session_state
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 512)
        || query
            .iss
            .as_deref()
            .is_some_and(|issuer| !browser.oidc.matches_issuer(issuer))
    {
        return Err(ApiError::InvalidRequest);
    }
    if !browser.binding_available.load(Ordering::Acquire) {
        return Err(ApiError::Unavailable);
    }
    let (identity, return_path) = browser
        .oidc
        .callback(
            query.code,
            &query.state,
            unix_time().ok_or(ApiError::Unavailable)?,
        )
        .await
        .map_err(map_oidc_error)?;
    let now = unix_time().ok_or(ApiError::Unavailable)?;
    let (identity, owner_id, destination) =
        resolve_callback_identity(&state, &browser, &request_id, identity, return_path).await?;
    let session = browser.sessions.create(identity, owner_id, now)?;
    let mut response = redirect(&destination)?;
    set_session_cookie(&mut response, &session.session_id);
    Ok(response)
}

pub(super) async fn setup(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(session): Extension<BrowserSession>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let browser = state.browser.clone().ok_or(ApiError::Unavailable)?;
    if !browser.setup_required() {
        return Err(ApiError::Conflict);
    }
    if session.owner_id.is_some() || session.role != Role::Admin {
        return Err(ApiError::Forbidden);
    }
    require_json(&headers)?;
    let request =
        serde_json::from_slice::<SetupRequest>(&body).map_err(|_| ApiError::InvalidRequest)?;
    let now = unix_time().ok_or(ApiError::Unavailable)?;
    let owner_id = state
        .web_setup_tokens
        .consume(&request.setup_token, now)
        .ok_or(ApiError::Conflict)?;
    let binding = OidcBinding {
        fingerprint: session.fingerprint.clone(),
        user_id: owner_id.clone(),
        owner_id: owner_id.clone(),
    };
    let audit = begin_oidc_mutation(
        &state,
        &session.principal(),
        &request_id,
        "oidc_setup_bind",
        owner_id.as_str(),
    )
    .await?;
    persist_binding(&state, &browser, &audit, binding.clone(), Role::Admin, true).await?;
    let identity = OidcIdentity {
        identity_id: binding.user_id,
        fingerprint: binding.fingerprint,
        role: Role::Admin,
    };
    let established = browser
        .sessions
        .replace(&session.session_id, identity, owner_id, now)?;
    let mut response = session_response(&established)?;
    set_session_cookie(&mut response, &established.session_id);
    Ok(response)
}

async fn resolve_callback_identity(
    state: &AppState,
    browser: &Arc<BrowserAuth>,
    request_id: &RequestId,
    mut identity: OidcIdentity,
    return_path: String,
) -> Result<(OidcIdentity, Option<ObjectId>, String), ApiError> {
    if browser.setup_required() {
        return (identity.role == Role::Admin)
            .then_some((identity, None, "/setup".into()))
            .ok_or(ApiError::Unauthorized);
    }
    if let Some(binding) = browser.bindings.get(&identity.fingerprint) {
        let Some(stored) = state.users.get(&binding.user_id) else {
            browser.mark_binding_unavailable();
            return Err(ApiError::Unavailable);
        };
        if stored.object.metadata.owner_id != binding.owner_id {
            browser.mark_binding_unavailable();
            return Err(ApiError::Unavailable);
        }
        if stored.object.spec.role != identity.role {
            let principal = oidc_system_principal(&identity);
            let audit = begin_oidc_mutation(
                state,
                &principal,
                request_id,
                "oidc_role_sync",
                binding.user_id.as_str(),
            )
            .await?;
            persist_binding(
                state,
                browser,
                &audit,
                binding.clone(),
                identity.role,
                false,
            )
            .await?;
        }
        let user = state
            .users
            .get(&binding.user_id)
            .ok_or(ApiError::Unavailable)?;
        if !user.object.spec.enabled
            || user.object.spec.role != identity.role
            || user.object.metadata.owner_id != binding.owner_id
        {
            return Err(ApiError::Unauthorized);
        }
        identity.identity_id = binding.user_id;
        return Ok((identity, Some(binding.owner_id), return_path));
    }

    if browser.bindings.user_is_bound(&identity.identity_id)
        || state.users.get(&identity.identity_id).is_some()
    {
        browser.mark_binding_unavailable();
        return Err(ApiError::Unavailable);
    }
    let binding = OidcBinding {
        fingerprint: identity.fingerprint.clone(),
        user_id: identity.identity_id.clone(),
        owner_id: identity.identity_id.clone(),
    };
    let principal = oidc_system_principal(&identity);
    let audit = begin_oidc_mutation(
        state,
        &principal,
        request_id,
        "oidc_identity_bind",
        binding.user_id.as_str(),
    )
    .await?;
    persist_binding(state, browser, &audit, binding.clone(), identity.role, true).await?;
    let user = state
        .users
        .get(&binding.user_id)
        .ok_or(ApiError::Unavailable)?;
    if !user.object.spec.enabled {
        return Err(ApiError::Unauthorized);
    }
    Ok((identity, Some(binding.owner_id), return_path))
}

fn oidc_system_principal(identity: &OidcIdentity) -> Principal {
    Principal {
        actor_type: "oidc_identity",
        actor_id: identity.identity_id.to_string(),
        role: Role::Admin,
        owner_id: Some(identity.identity_id.clone()),
        token_scopes: None,
    }
}

async fn begin_oidc_mutation(
    state: &AppState,
    principal: &Principal,
    request_id: &RequestId,
    action: &'static str,
    resource_id: &str,
) -> Result<MutationAudit, ApiError> {
    begin_mutation(
        state,
        principal,
        request_id,
        Some(state.control.runtime().revision().to_string()),
        MutationSpec {
            permission: Action::ManageIdentities,
            action,
            resource_id,
            new_revision: None,
        },
    )
    .await
}

async fn persist_binding(
    state: &AppState,
    browser: &Arc<BrowserAuth>,
    audit: &MutationAudit,
    binding: OidcBinding,
    role: Role,
    allow_user_create: bool,
) -> Result<(), ApiError> {
    let bindings = Arc::clone(&browser.bindings);
    let users = Arc::clone(&state.users);
    let result = tokio::task::spawn_blocking(move || {
        bindings.bind(binding, role, &users, allow_user_create)
    })
    .await
    .map_err(|_| ApiError::Internal)?;
    if result.is_err() {
        browser.mark_binding_unavailable();
        return Err(audited_failure(audit, "oidc_binding_failed", ApiError::Unavailable).await);
    }
    audit.record(AuditOutcome::Success, None, None).await
}

pub(super) async fn session(
    Extension(session): Extension<BrowserSession>,
) -> Result<Response, ApiError> {
    session_response(&session)
}

pub(super) async fn logout(
    State(state): State<AppState>,
    Extension(session): Extension<BrowserSession>,
) -> Response {
    if let Some(browser) = state.browser {
        browser.sessions.remove(&session.session_id);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "__Host-aegis-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict",
        ),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(super) async fn ui_asset(State(state): State<AppState>, uri: axum::http::Uri) -> Response {
    let path = uri.path();
    let (asset_path, cache) = if is_ui_path(path) {
        ("index.html", "no-store")
    } else if path.starts_with("/assets/") && hashed_asset(path) {
        (&path[1..], "public, max-age=31536000, immutable")
    } else {
        return ApiError::NotFound.into_response();
    };
    let Some(asset) = state.web_assets.and_then(|load| load(asset_path)) else {
        return ApiError::NotFound.into_response();
    };
    let mut response = Response::new(axum::body::Body::from(asset.bytes));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(cache));
    response
}

fn is_ui_path(path: &str) -> bool {
    matches!(
        path,
        "/" | "/setup"
            | "/proxy-hosts"
            | "/stream-hosts"
            | "/certificates"
            | "/access-policies"
            | "/users"
            | "/health"
            | "/logs"
            | "/revisions"
            | "/backups"
            | "/settings"
    )
}

fn hashed_asset(path: &str) -> bool {
    path.strip_prefix("/assets/")
        .filter(|name| !name.contains('/'))
        .is_some_and(|file_name| {
            file_name
                .rsplit_once('.')
                .and_then(|(stem, extension)| {
                    stem.split_once('-').map(|(_, hash)| (hash, extension))
                })
                .is_some_and(|(hash, extension)| {
                    hash.len() >= 8
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                        && matches!(extension, "js" | "css" | "svg" | "png" | "webp")
                })
        })
}

fn session_response(session: &BrowserSession) -> Result<Response, ApiError> {
    let permitted_actions = session
        .owner_id
        .as_ref()
        .map_or_else(Vec::new, |_| session.role.actions());
    let body = serde_json::to_vec(&SessionResponse {
        identity_id: &session.identity_id,
        owner_id: &session.owner_id,
        role: session.role,
        permitted_actions,
        csrf_token: &session.csrf_token,
        idle_expires_unix_secs: session.idle_expires_unix_secs,
        absolute_expires_unix_secs: session.absolute_expires_unix_secs,
    })
    .map_err(|_| ApiError::Internal)?;
    no_store_json(StatusCode::OK, body)
}

fn redirect(location: &str) -> Result<Response, ApiError> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(location).map_err(|_| ApiError::Internal)?,
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn default_return_path() -> String {
    "/".into()
}

fn validate_return_path(path: String) -> Result<String, ApiError> {
    if path.is_empty()
        || path.len() > 2_048
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.chars().any(char::is_control)
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(path)
}

fn exact_header(
    headers: &HeaderMap,
    name: impl axum::http::header::AsHeaderName,
    expected: &str,
) -> bool {
    let values: Vec<_> = headers.get_all(name).iter().collect();
    matches!(values.as_slice(), [value] if value.as_bytes() == expected.as_bytes())
}

fn csrf_matches(headers: &HeaderMap, expected: &str) -> bool {
    let values: Vec<_> = headers.get_all(CSRF_HEADER).iter().collect();
    matches!(
        values.as_slice(),
        [value]
            if value.as_bytes().len() == expected.len()
                && bool::from(value.as_bytes().ct_eq(expected.as_bytes()))
    )
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let values: Vec<_> = headers.get_all(COOKIE).iter().collect();
    let [value] = values.as_slice() else {
        return None;
    };
    let value = value.to_str().ok()?;
    let mut found = None;
    for cookie in value.split(';').map(str::trim) {
        let (name, value) = cookie.split_once('=')?;
        if name == SESSION_COOKIE {
            if found.is_some()
                || value.len() != 43
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return None;
            }
            found = Some(value.to_owned());
        }
    }
    found
}

fn is_unsafe(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD)
}

fn random_secret() -> Result<String, ApiError> {
    let mut bytes = [0_u8; SESSION_SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn set_session_cookie(response: &mut Response, session_id: &str) {
    let value = format!("{SESSION_COOKIE}={session_id}; Path=/; Secure; HttpOnly; SameSite=Strict");
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
}

fn browser_response(mut response: Response, path: &str) -> Response {
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
        ),
    );
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if matches!(
        path,
        "/v1/auth/login"
            | "/v1/auth/callback"
            | "/v1/session"
            | "/v1/session/setup"
            | "/v1/session/logout"
    ) {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

fn map_oidc_error(error: OidcError) -> ApiError {
    match error {
        OidcError::Unavailable => ApiError::Unavailable,
        OidcError::Capacity => ApiError::Busy,
        OidcError::Invalid => ApiError::Unauthorized,
    }
}

impl BrowserSession {
    pub(super) fn principal(&self) -> Principal {
        Principal {
            actor_type: "oidc_session",
            actor_id: self.identity_id.to_string(),
            role: self.role,
            owner_id: self.owner_id.clone(),
            token_scopes: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(role: Role) -> OidcIdentity {
        OidcIdentity {
            identity_id: "oidc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .expect("ID"),
            fingerprint: "a".repeat(64),
            role,
        }
    }

    #[test]
    fn sessions_expire_rotate_overlap_and_never_fixate() {
        let store = SessionStore::new();
        let first = store
            .create(identity(Role::Admin), None, 100)
            .expect("session");
        assert_eq!(first.session_id.len(), 43);
        assert!(store.access("attacker-fixed", 100).is_none());
        assert!(store.access(&first.session_id, 999).is_some());
        let rotated = store.access(&first.session_id, 1_000).expect("rotate");
        assert!(rotated.set_cookie);
        assert_ne!(rotated.session.session_id, first.session_id);
        assert!(store.access(&first.session_id, 1_029).is_some());
        assert!(store.access(&first.session_id, 1_030).is_none());
        assert!(store.access(&rotated.session.session_id, 3_700).is_none());

        let idle = store
            .create(identity(Role::Viewer), None, 5_000)
            .expect("idle");
        assert!(store.access(&idle.session_id, 5_900).is_none());
    }

    #[test]
    fn session_store_enforces_capacity() {
        let store = SessionStore::new();
        for index in 0..MAX_SESSIONS {
            let mut identity = identity(Role::Viewer);
            identity.fingerprint = format!("{index:064x}");
            store.create(identity, None, 100).expect("within capacity");
        }
        assert!(matches!(
            store.create(identity(Role::Viewer), None, 100),
            Err(ApiError::Busy)
        ));
    }

    #[test]
    fn cookies_and_return_paths_are_strict() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{SESSION_COOKIE}={}", "a".repeat(43))).expect("cookie"),
        );
        assert_eq!(session_cookie(&headers), Some("a".repeat(43)));
        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!("{SESSION_COOKIE}={}", "b".repeat(43))).expect("cookie"),
        );
        assert!(session_cookie(&headers).is_none());
        assert!(validate_return_path("/proxy-hosts".into()).is_ok());
        assert!(validate_return_path("//evil.test".into()).is_err());
        assert!(validate_return_path("https://evil.test".into()).is_err());
    }

    #[test]
    fn csrf_comparison_is_exact_and_single_valued() {
        let mut headers = HeaderMap::new();
        headers.insert(CSRF_HEADER, HeaderValue::from_static("token"));
        assert!(csrf_matches(&headers, "token"));
        assert!(!csrf_matches(&headers, "Token"));
        headers.append(CSRF_HEADER, HeaderValue::from_static("token"));
        assert!(!csrf_matches(&headers, "token"));
    }

    #[test]
    fn callback_accepts_standard_provider_parameters_only() {
        let query: CallbackQuery = serde_json::from_value(serde_json::json!({
            "code": "code",
            "state": "state",
            "iss": "https://issuer.example",
            "session_state": "session"
        }))
        .expect("standard callback");
        assert_eq!(query.iss.as_deref(), Some("https://issuer.example"));
        assert!(
            serde_json::from_value::<CallbackQuery>(serde_json::json!({
                "code": "code",
                "state": "state",
                "unexpected": "value"
            }))
            .is_err()
        );
    }

    #[test]
    fn cookie_contract_has_every_required_attribute_and_no_domain() {
        let mut response = StatusCode::OK.into_response();
        set_session_cookie(&mut response, &"a".repeat(43));
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .expect("cookie")
            .to_str()
            .expect("text");
        for attribute in [
            "__Host-aegis-session=",
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
        ] {
            assert!(cookie.contains(attribute));
        }
        assert!(!cookie.contains("Domain"));
    }

    #[test]
    fn spa_fallback_and_immutable_assets_are_closed_allowlists() {
        assert!(is_ui_path("/proxy-hosts"));
        assert!(!is_ui_path("/v1/status"));
        assert!(!is_ui_path("/auth/callback"));
        assert!(hashed_asset("/assets/index-D3ad_b33f.js"));
        assert!(!hashed_asset("/assets/index.js"));
        assert!(!hashed_asset("/v1/index-D3adbeef.js"));
    }
}
