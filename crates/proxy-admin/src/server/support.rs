use super::*;

pub(super) fn page_limit(page: &Page) -> Result<usize, ApiError> {
    let limit = page.limit.unwrap_or(100);
    (1..=100)
        .contains(&limit)
        .then_some(limit)
        .ok_or(ApiError::InvalidRequest)
}

pub(super) fn etag(revision: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("\"{revision}\"")).ok()
}

pub(super) fn require_toml(headers: &HeaderMap) -> Result<(), ApiError> {
    let values: Vec<_> = headers.get_all(CONTENT_TYPE).iter().collect();
    match values.as_slice() {
        [value] if value.as_bytes() == b"application/toml" => Ok(()),
        _ => Err(ApiError::InvalidRequest),
    }
}

pub(super) fn valid_api_path(path: &Path) -> bool {
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

pub(super) fn expected_revision(headers: &HeaderMap) -> Result<String, ApiError> {
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

pub(super) async fn load_candidate(body: axum::body::Bytes) -> Result<Config, ApiError> {
    tokio::task::spawn_blocking(move || aegisproxy_config::load_bytes(&body))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(|_| ApiError::InvalidRequest)
}

pub(super) async fn begin_mutation(
    state: &AppState,
    principal: &Principal,
    request_id: &RequestId,
    old_revision: Option<String>,
    spec: MutationSpec<'_>,
) -> Result<MutationAudit, ApiError> {
    let audit = MutationAudit {
        log: state.audit.clone().ok_or(ApiError::Unavailable)?,
        runtime: state.control.runtime(),
        node_id: state.control.runtime().node_id().to_string(),
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
    pub(super) async fn record(
        &self,
        outcome: AuditOutcome,
        new_revision: Option<String>,
        error_code: Option<&str>,
    ) -> Result<(), ApiError> {
        let log = Arc::clone(&self.log);
        let event = AuditEvent {
            node_id: self.node_id.clone(),
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

pub(super) async fn audited_failure(
    audit: &MutationAudit,
    code: &'static str,
    error: ApiError,
) -> ApiError {
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

pub(super) fn activation_error(error: ActivationError) -> (&'static str, ApiError) {
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

pub(super) fn authorize(principal: &Principal, action: Action) -> Result<(), ApiError> {
    (principal.role.allows(action)
        && principal
            .token_scopes
            .as_ref()
            .is_none_or(|scopes| scopes.allows(action)))
    .then_some(())
    .ok_or(ApiError::Forbidden)
}

pub(super) fn authorization_header(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
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

pub(super) fn request_id() -> Option<String> {
    let mut bytes = [0_u8; REQUEST_ID_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn unix_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

pub(super) fn bind_private_socket(path: &Path) -> Result<(UnixListener, SocketGuard), io::Error> {
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

pub(super) fn create_private_directory(path: &Path) -> Result<(), io::Error> {
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

pub(super) fn remove_stale_socket(path: &Path) -> Result<(), io::Error> {
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

pub(super) fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(Debug)]
pub(super) struct SocketGuard {
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
