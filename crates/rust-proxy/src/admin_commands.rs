use super::*;

pub(super) async fn run_admin(
    control: aegisproxy_core::ManagedControl,
    shutdown: CancellationToken,
) {
    if let Err(error) = aegisproxy_admin::serve(control, shutdown).await {
        tracing::error!(%error, "administrative service stopped");
    }
}

pub(super) async fn admin_request(
    admin: &AdminConnection,
    method: Method,
    path: &str,
    if_match: Option<String>,
    content_type: Option<&'static str>,
    body: Vec<u8>,
) -> Result<admin_client::AdminResponse, BoxError> {
    admin_request_with_generation(admin, method, path, if_match, None, content_type, body).await
}

async fn admin_request_with_generation(
    admin: &AdminConnection,
    method: Method,
    path: &str,
    if_match: Option<String>,
    object_generation: Option<u64>,
    content_type: Option<&'static str>,
    body: Vec<u8>,
) -> Result<admin_client::AdminResponse, BoxError> {
    let bearer = load_admin_token(admin.token_ref.clone()).await?;
    admin_client::request(
        &admin.socket,
        admin_client::AdminRequest {
            method,
            path: path.to_owned(),
            if_match,
            object_generation,
            content_type,
            bearer,
            body,
        },
    )
    .await
}

async fn load_admin_token(
    reference: Option<String>,
) -> Result<Option<Zeroizing<String>>, BoxError> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    tokio::task::spawn_blocking(move || {
        let secret = aegisproxy_secrets::SecretRef::parse(&reference)?.resolve(256)?;
        let value = std::str::from_utf8(secret.as_ref())?.trim_end_matches(['\r', '\n']);
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid API token").into());
        }
        Ok(Some(Zeroizing::new(value.to_owned())))
    })
    .await
    .map_err(|error| -> BoxError { Box::new(error) })?
}

pub(super) fn require_admin_success(
    response: &admin_client::AdminResponse,
) -> Result<(), BoxError> {
    if response.status.is_success() {
        return Ok(());
    }
    let body = String::from_utf8_lossy(&response.body);
    Err(AdminHttpError {
        status: response.status,
        body: body.into_owned(),
    }
    .into())
}

pub(super) async fn run_token_command(command: TokenCommand) -> Result<(), BoxError> {
    match command {
        TokenCommand::Create {
            admin,
            expect,
            user_ref,
            scope,
            ttl_secs,
        } => {
            if ttl_secs == 0 || ttl_secs > 365 * 24 * 60 * 60 {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid token TTL").into(),
                );
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let user_ref = user_ref.parse::<aegisproxy_admin::ObjectId>()?;
            let body = serde_json::to_vec(&TokenCreateBody {
                user_ref: user_ref.as_str(),
                scopes: scope.into_iter().map(CliScope::as_api_str).collect(),
                expires_unix_secs: now.saturating_add(ttl_secs),
            })?;
            let response = admin_request(
                &admin,
                Method::POST,
                "/v1/tokens",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
        TokenCommand::List { admin } => {
            let response =
                admin_request(&admin, Method::GET, "/v1/tokens", None, None, Vec::new()).await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
        TokenCommand::Revoke { admin, expect, id } => {
            let response = admin_request(
                &admin,
                Method::POST,
                &format!("/v1/tokens/{id}/revoke"),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
    }
    Ok(())
}

pub(super) async fn run_web_command(command: WebCommand) -> Result<(), BoxError> {
    let WebCommand::SetupToken { socket } = command;
    let response = admin_request(
        &AdminConnection {
            socket,
            token_ref: None,
        },
        Method::POST,
        "/v1/web/setup-token",
        None,
        None,
        Vec::new(),
    )
    .await?;
    require_admin_success(&response)?;
    io::stdout().lock().write_all(&response.body)?;
    writeln!(io::stdout().lock())?;
    Ok(())
}

pub(super) async fn run_proxy_host_command(command: ProxyHostCommand) -> Result<(), BoxError> {
    let response = match command {
        ProxyHostCommand::List { admin } => {
            admin_request(
                &admin,
                Method::GET,
                "/v1/proxy-hosts",
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        ProxyHostCommand::Get { admin, id } => {
            let id = id.parse::<aegisproxy_admin::ObjectId>()?;
            admin_request(
                &admin,
                Method::GET,
                &format!("/v1/proxy-hosts/{id}"),
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        ProxyHostCommand::Create {
            admin,
            expect,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                "/v1/proxy-hosts",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?
        }
        ProxyHostCommand::Update {
            admin,
            expect,
            generation,
            id,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request_with_generation(
                &admin,
                Method::PUT,
                &format!("/v1/proxy-hosts/{id}"),
                Some(expect),
                Some(generation),
                Some("application/json"),
                body,
            )
            .await?
        }
        ProxyHostCommand::Delete {
            admin,
            expect,
            generation,
            id,
        } => {
            admin_request_with_generation(
                &admin,
                Method::DELETE,
                &format!("/v1/proxy-hosts/{id}"),
                Some(expect),
                Some(generation),
                None,
                Vec::new(),
            )
            .await?
        }
        ProxyHostCommand::Activate {
            admin,
            expect,
            candidate,
        } => {
            admin_request(
                &admin,
                Method::POST,
                &format!("/v1/config/typed-candidates/{candidate}/activate"),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?
        }
        ProxyHostCommand::Rollback {
            admin,
            expect,
            revision,
        } => {
            admin_request(
                &admin,
                Method::POST,
                &format!("/v1/config/typed-revisions/{revision}/rollback"),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?
        }
        ProxyHostCommand::Validate { admin, file } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                "/v1/proxy-hosts/validate",
                None,
                Some("application/json"),
                body,
            )
            .await?
        }
        ProxyHostCommand::Preview { admin, file } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                "/v1/proxy-hosts/preview",
                None,
                Some("application/json"),
                body,
            )
            .await?
        }
    };
    require_admin_success(&response)?;
    io::stdout().lock().write_all(&response.body)?;
    writeln!(io::stdout().lock())?;
    Ok(())
}

pub(super) async fn run_owned_object_command(
    command: AccessPolicyCommand,
    resource: &str,
) -> Result<(), BoxError> {
    let response = match command {
        AccessPolicyCommand::List { admin } => {
            admin_request(
                &admin,
                Method::GET,
                &format!("/v1/{resource}"),
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        AccessPolicyCommand::Get { admin, id } => {
            let id = id.parse::<aegisproxy_admin::ObjectId>()?;
            admin_request(
                &admin,
                Method::GET,
                &format!("/v1/{resource}/{id}"),
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        AccessPolicyCommand::Create {
            admin,
            expect,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                &format!("/v1/{resource}"),
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?
        }
        AccessPolicyCommand::Update {
            admin,
            expect,
            generation,
            id,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request_with_generation(
                &admin,
                Method::PUT,
                &format!("/v1/{resource}/{id}"),
                Some(expect),
                Some(generation),
                Some("application/json"),
                body,
            )
            .await?
        }
        AccessPolicyCommand::Delete {
            admin,
            expect,
            generation,
            id,
        } => {
            admin_request_with_generation(
                &admin,
                Method::DELETE,
                &format!("/v1/{resource}/{id}"),
                Some(expect),
                Some(generation),
                None,
                Vec::new(),
            )
            .await?
        }
    };
    require_admin_success(&response)?;
    io::stdout().lock().write_all(&response.body)?;
    writeln!(io::stdout().lock())?;
    Ok(())
}

pub(super) async fn run_user_command(command: UserCommand) -> Result<(), BoxError> {
    let response = match command {
        UserCommand::List { admin } => {
            admin_request(&admin, Method::GET, "/v1/users", None, None, Vec::new()).await?
        }
        UserCommand::Get { admin, id } => {
            let id = id.parse::<aegisproxy_admin::ObjectId>()?;
            admin_request(
                &admin,
                Method::GET,
                &format!("/v1/users/{id}"),
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        UserCommand::Create {
            admin,
            expect,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                "/v1/users",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?
        }
        UserCommand::Update {
            admin,
            expect,
            generation,
            id,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request_with_generation(
                &admin,
                Method::PUT,
                &format!("/v1/users/{id}"),
                Some(expect),
                Some(generation),
                Some("application/json"),
                body,
            )
            .await?
        }
    };
    require_admin_success(&response)?;
    io::stdout().lock().write_all(&response.body)?;
    writeln!(io::stdout().lock())?;
    Ok(())
}

pub(super) async fn run_certificate_object_command(
    command: CertificateObjectCommand,
) -> Result<(), BoxError> {
    let response = match command {
        CertificateObjectCommand::List { admin } => {
            admin_request(
                &admin,
                Method::GET,
                "/v1/certificates",
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        CertificateObjectCommand::Get { admin, id } => {
            let id = id.parse::<aegisproxy_admin::ObjectId>()?;
            admin_request(
                &admin,
                Method::GET,
                &format!("/v1/certificates/{id}"),
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        CertificateObjectCommand::Create {
            admin,
            expect,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                "/v1/certificates",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?
        }
        CertificateObjectCommand::Update {
            admin,
            expect,
            generation,
            id,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request_with_generation(
                &admin,
                Method::PUT,
                &format!("/v1/certificates/{id}"),
                Some(expect),
                Some(generation),
                Some("application/json"),
                body,
            )
            .await?
        }
        CertificateObjectCommand::Delete {
            admin,
            expect,
            generation,
            id,
        } => {
            admin_request_with_generation(
                &admin,
                Method::DELETE,
                &format!("/v1/certificates/{id}"),
                Some(expect),
                Some(generation),
                None,
                Vec::new(),
            )
            .await?
        }
        CertificateObjectCommand::Renew { admin, expect, id } => {
            admin_request(
                &admin,
                Method::POST,
                &format!("/v1/certificates/{id}/renew"),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?
        }
    };
    require_admin_success(&response)?;
    io::stdout().lock().write_all(&response.body)?;
    writeln!(io::stdout().lock())?;
    Ok(())
}

pub(super) async fn run_typed_domain_command(
    command: TypedDomainCommand,
    collection: &str,
) -> Result<(), BoxError> {
    let response = match command {
        TypedDomainCommand::List { admin } => {
            admin_request(
                &admin,
                Method::GET,
                &format!("/v1/{collection}"),
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        TypedDomainCommand::Get { admin, id } => {
            let id = id.parse::<aegisproxy_admin::ObjectId>()?;
            admin_request(
                &admin,
                Method::GET,
                &format!("/v1/{collection}/{id}"),
                None,
                None,
                Vec::new(),
            )
            .await?
        }
        TypedDomainCommand::Create {
            admin,
            expect,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                &format!("/v1/{collection}"),
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?
        }
        TypedDomainCommand::Update {
            admin,
            expect,
            generation,
            id,
            file,
        } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request_with_generation(
                &admin,
                Method::PUT,
                &format!("/v1/{collection}/{id}"),
                Some(expect),
                Some(generation),
                Some("application/json"),
                body,
            )
            .await?
        }
        TypedDomainCommand::Delete {
            admin,
            expect,
            generation,
            id,
        } => {
            admin_request_with_generation(
                &admin,
                Method::DELETE,
                &format!("/v1/{collection}/{id}"),
                Some(expect),
                Some(generation),
                None,
                Vec::new(),
            )
            .await?
        }
        TypedDomainCommand::Validate { admin, file } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                &format!("/v1/{collection}/validate"),
                None,
                Some("application/json"),
                body,
            )
            .await?
        }
        TypedDomainCommand::Preview { admin, file } => {
            let body = read_bounded(file, aegisproxy_config::MAX_CONFIG_BYTES).await?;
            admin_request(
                &admin,
                Method::POST,
                &format!("/v1/{collection}/preview"),
                None,
                Some("application/json"),
                body,
            )
            .await?
        }
    };
    require_admin_success(&response)?;
    io::stdout().lock().write_all(&response.body)?;
    writeln!(io::stdout().lock())?;
    Ok(())
}

async fn read_bounded(path: PathBuf, maximum: usize) -> Result<Vec<u8>, BoxError> {
    tokio::task::spawn_blocking(move || {
        let metadata = std::fs::metadata(&path)?;
        if metadata.len() > maximum as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "input exceeds its size limit",
            ));
        }
        std::fs::read(path)
    })
    .await
    .map_err(|error| -> BoxError { Box::new(error) })?
    .map_err(|error| -> BoxError { Box::new(error) })
}

pub(super) async fn run_backup_command(command: BackupCommand) -> Result<(), BoxError> {
    match command {
        BackupCommand::Create {
            admin,
            expect,
            output,
        } => {
            let output = output.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "backup path is not UTF-8")
            })?;
            let body = serde_json::to_vec(&BackupCreateBody { output })?;
            let response = admin_request(
                &admin,
                Method::POST,
                "/v1/backups",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
        BackupCommand::Verify { input, identity } => {
            let summary = tokio::task::spawn_blocking(move || {
                let identity =
                    aegisproxy_secrets::SecretRef::parse(&identity)?.resolve(4 * 1024)?;
                aegisproxy_admin::validate_backup(input, identity.as_ref())
                    .map_err(|error| -> BoxError { Box::new(error) })
            })
            .await
            .map_err(|error| -> BoxError { Box::new(error) })??;
            writeln!(io::stdout().lock(), "{}", serde_json::to_string(&summary)?)?;
        }
    }
    Ok(())
}

pub(super) async fn run_restore_command(command: RestoreCommand) -> Result<(), BoxError> {
    match command {
        RestoreCommand::Validate {
            admin,
            expect,
            input,
            identity,
        } => {
            let input = input.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "backup path is not UTF-8")
            })?;
            let body = serde_json::to_vec(&RestoreValidateBody {
                input,
                identity: &identity,
            })?;
            let response = admin_request(
                &admin,
                Method::POST,
                "/v1/restore/validate",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
    }
    Ok(())
}

pub(super) async fn run_config_command(command: ConfigCommand) -> Result<(), BoxError> {
    match command {
        ConfigCommand::Revisions { state_dir } => {
            tokio::task::spawn_blocking(move || write_revisions(state_dir))
                .await
                .map_err(|error| -> BoxError { Box::new(error) })??;
        }
        ConfigCommand::Activate {
            admin,
            file,
            expect,
        } => {
            let config = load_config(file).await?;
            let body = toml::to_string_pretty(&config)?.into_bytes();
            let candidate = admin_request(
                &admin,
                Method::POST,
                "/v1/config/candidates",
                Some(expect.clone()),
                Some("application/toml"),
                body,
            )
            .await?;
            require_admin_success(&candidate)?;
            let candidate: CandidateResponse = serde_json::from_slice(&candidate.body)?;
            let activation = admin_request(
                &admin,
                Method::POST,
                &format!("/v1/config/candidates/{}/activate", candidate.id),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?;
            require_admin_success(&activation)?;
            io::stdout().lock().write_all(&activation.body)?;
            writeln!(io::stdout().lock())?;
        }
        ConfigCommand::Rollback {
            admin,
            revision,
            expect,
        } => {
            let response = admin_request(
                &admin,
                Method::POST,
                &format!("/v1/config/revisions/{revision}/rollback"),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
    }
    Ok(())
}

fn write_revisions(state_dir: PathBuf) -> Result<(), BoxError> {
    let store = aegisproxy_config::revision::RevisionStore::open(state_dir)?;
    let active = store.active()?;
    let active_id = active.as_ref().map(|pointer| pointer.active.id.as_str());
    let previous_id = active
        .as_ref()
        .and_then(|pointer| pointer.previous.as_ref())
        .map(|previous| previous.id.as_str());
    let mut output = io::stdout().lock();
    for revision in store.list()? {
        let status = if Some(revision.id.as_str()) == active_id {
            "active"
        } else if Some(revision.id.as_str()) == previous_id {
            "previous"
        } else {
            "retained"
        };
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}",
            revision.id, revision.hash, revision.created_unix_secs, revision.source, status
        )?;
    }
    Ok(())
}
