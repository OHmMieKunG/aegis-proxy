use super::*;
use crate::http::{ListenerContext, accept_loop};

/// Run configured public listeners until cancellation.
pub async fn run(config: Arc<Config>, shutdown: CancellationToken) -> Result<(), ProxyError> {
    let snapshot = RuntimeSnapshot::prepare(config, "startup", &shutdown).await?;
    let runtime = RuntimeHandle::new(Arc::clone(&snapshot));
    let listeners = bind_listeners(&snapshot.config).await?;
    serve_bound(runtime, snapshot, listeners, shutdown).await
}

/// Run a file-backed daemon with durable revisions and automatic safe reload.
pub async fn run_managed(
    config_path: PathBuf,
    shutdown: CancellationToken,
) -> Result<(), ProxyError> {
    run_managed_with_control(config_path, shutdown, |_, shutdown| async move {
        shutdown.cancelled().await;
    })
    .await
}

/// Run a file-backed daemon and start an isolated management service.
pub async fn run_managed_with_control<F, Fut>(
    config_path: PathBuf,
    shutdown: CancellationToken,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let config = tokio::task::spawn_blocking({
        let config_path = config_path.clone();
        move || aegisproxy_config::load_file(config_path)
    })
    .await
    .map_err(|error| ProxyError::Preparation(error.to_string()))??;
    run_managed_config_with_control(config_path, config, shutdown, start_control).await
}

/// Run an already validated file-backed configuration with an isolated management service.
pub async fn run_managed_config_with_control<F, Fut>(
    config_path: PathBuf,
    config: Config,
    shutdown: CancellationToken,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    run_managed_config_with_control_on_node(
        config_path,
        config,
        NodeIdentity::standalone(),
        shutdown,
        start_control,
    )
    .await
}

/// Run validated configuration with explicit node identity and isolated management.
pub async fn run_managed_config_with_control_on_node<F, Fut>(
    config_path: PathBuf,
    config: Config,
    identity: NodeIdentity,
    shutdown: CancellationToken,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    validate_node_policy(&config, &identity)?;
    let state_dir = PathBuf::from(&config.runtime.state_dir);
    let revisions = Arc::new(
        tokio::task::spawn_blocking(move || RevisionStore::open(state_dir))
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??,
    );
    let recovered = {
        let revisions = Arc::clone(&revisions);
        tokio::task::spawn_blocking(move || revisions.recover_incomplete())
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??
    };
    let candidate = {
        let revisions = Arc::clone(&revisions);
        let config = config.clone();
        tokio::task::spawn_blocking(move || revisions.create_candidate(&config, "file"))
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??
    };
    let (snapshot, listeners) = prepare_bound(config, candidate.id.clone(), &shutdown).await?;
    if recovered.as_ref().map(|pointer| pointer.active.id.as_str()) != Some(&candidate.id) {
        let revisions = Arc::clone(&revisions);
        let candidate_id = candidate.id.clone();
        let expected = recovered.map(|pointer| pointer.active.id);
        tokio::task::spawn_blocking(move || {
            revisions.begin_activation(&candidate_id, expected.as_deref())?;
            revisions.mark_probation(&candidate_id)?;
            revisions.commit_activation(&candidate_id)
        })
        .await
        .map_err(|error| ProxyError::Preparation(error.to_string()))??;
    }
    serve_managed(
        FileWatch::Enabled(config_path),
        revisions,
        snapshot,
        listeners,
        identity,
        shutdown,
        start_control,
    )
    .await
}

/// Run one pre-created typed revision with restart-only base configuration.
pub async fn run_managed_revision_with_control_on_node<F, Fut>(
    config: Config,
    revision_id: String,
    identity: NodeIdentity,
    shutdown: CancellationToken,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    run_managed_bound_revision(config, revision_id, identity, shutdown, None, start_control).await
}

/// Run one pre-created typed revision and bind provider revisions to its typed desired state.
pub async fn run_managed_bound_revision_with_control_on_node<F, Fut, B>(
    config: Config,
    revision_id: String,
    identity: NodeIdentity,
    shutdown: CancellationToken,
    bind_provider_candidate: B,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
    B: Fn(&str, &str, &str) -> Result<(), String> + Send + Sync + 'static,
{
    run_managed_bound_revision(
        config,
        revision_id,
        identity,
        shutdown,
        Some(Arc::new(bind_provider_candidate)),
        start_control,
    )
    .await
}

type ProviderCandidateBinder = Arc<dyn Fn(&str, &str, &str) -> Result<(), String> + Send + Sync>;

async fn run_managed_bound_revision<F, Fut>(
    config: Config,
    revision_id: String,
    identity: NodeIdentity,
    shutdown: CancellationToken,
    provider_candidate_binder: Option<ProviderCandidateBinder>,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    validate_node_policy(&config, &identity)?;
    let state_dir = PathBuf::from(&config.runtime.state_dir);
    let revisions = Arc::new(
        tokio::task::spawn_blocking(move || RevisionStore::open(state_dir))
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??,
    );
    let recovered = {
        let revisions = Arc::clone(&revisions);
        tokio::task::spawn_blocking(move || revisions.recover_incomplete())
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??
    };
    let candidate = {
        let revisions = Arc::clone(&revisions);
        let revision_id = revision_id.clone();
        let expected_hash = aegisproxy_config::revision::content_hash(&config)?;
        tokio::task::spawn_blocking(move || {
            let metadata = revisions.metadata(&revision_id)?;
            if metadata.binding_hash.is_none() || metadata.hash != expected_hash {
                return Err(RevisionError::InvalidStored(
                    "typed startup revision does not match configuration".into(),
                ));
            }
            revisions.load(&revision_id)?;
            Ok::<_, RevisionError>(metadata)
        })
        .await
        .map_err(|error| ProxyError::Preparation(error.to_string()))??
    };
    let (snapshot, listeners) = prepare_bound(config, candidate.id.clone(), &shutdown).await?;
    if recovered.as_ref().map(|pointer| pointer.active.id.as_str()) != Some(&candidate.id) {
        let revisions = Arc::clone(&revisions);
        let candidate_id = candidate.id.clone();
        let expected = recovered.map(|pointer| pointer.active.id);
        tokio::task::spawn_blocking(move || {
            revisions.begin_activation(&candidate_id, expected.as_deref())?;
            revisions.mark_probation(&candidate_id)?;
            revisions.commit_activation(&candidate_id)
        })
        .await
        .map_err(|error| ProxyError::Preparation(error.to_string()))??;
    }
    serve_managed(
        FileWatch::Disabled(provider_candidate_binder),
        revisions,
        snapshot,
        listeners,
        identity,
        shutdown,
        start_control,
    )
    .await
}

/// Explicitly start from the durable last-known-good revision.
///
/// Bootstrap does not load or overwrite the configured file. The watcher is
/// enabled after startup so a later valid edit can activate normally.
pub async fn run_last_known_good(
    config_path: PathBuf,
    state_dir: PathBuf,
    shutdown: CancellationToken,
) -> Result<(), ProxyError> {
    run_last_known_good_with_control(config_path, state_dir, shutdown, |_, shutdown| async move {
        shutdown.cancelled().await;
    })
    .await
}

/// Load the durable last-known-good configuration without starting listeners.
pub async fn load_last_known_good(state_dir: PathBuf) -> Result<Config, ProxyError> {
    tokio::task::spawn_blocking(move || {
        let revisions = RevisionStore::open(state_dir)?;
        let active = revisions.recover_incomplete()?.ok_or_else(|| {
            RevisionError::InvalidStored("no last-known-good revision is available".into())
        })?;
        revisions.load(&active.active.id)
    })
    .await
    .map_err(|error| ProxyError::Preparation(error.to_string()))?
    .map_err(ProxyError::Revision)
}

/// Start from last-known-good and start an isolated management service.
pub async fn run_last_known_good_with_control<F, Fut>(
    config_path: PathBuf,
    state_dir: PathBuf,
    shutdown: CancellationToken,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    run_last_known_good_with_control_on_node(
        config_path,
        state_dir,
        NodeIdentity::standalone(),
        shutdown,
        start_control,
    )
    .await
}

/// Start from last-known-good with explicit node identity and isolated management.
pub async fn run_last_known_good_with_control_on_node<F, Fut>(
    config_path: PathBuf,
    state_dir: PathBuf,
    identity: NodeIdentity,
    shutdown: CancellationToken,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let revisions = Arc::new(
        tokio::task::spawn_blocking(move || RevisionStore::open(state_dir))
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??,
    );
    let active = {
        let revisions = Arc::clone(&revisions);
        tokio::task::spawn_blocking(move || revisions.recover_incomplete())
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??
            .ok_or_else(|| {
                ProxyError::Preparation("no last-known-good revision is available".into())
            })?
    };
    let config = {
        let revisions = Arc::clone(&revisions);
        let revision = active.active.id.clone();
        tokio::task::spawn_blocking(move || revisions.load(&revision))
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??
    };
    validate_node_policy(&config, &identity)?;
    tracing::warn!(revision = %active.active.id, "explicit last-known-good recovery selected");
    let (snapshot, listeners) = prepare_bound(config, active.active.id, &shutdown).await?;
    serve_managed(
        FileWatch::Enabled(config_path),
        revisions,
        snapshot,
        listeners,
        identity,
        shutdown,
        start_control,
    )
    .await
}

async fn prepare_bound(
    config: Config,
    revision: String,
    shutdown: &CancellationToken,
) -> Result<(Arc<RuntimeSnapshot>, Vec<(ListenerConfig, TcpListener)>), ProxyError> {
    let snapshot = RuntimeSnapshot::prepare(Arc::new(config), revision, shutdown).await?;
    let listeners = bind_listeners(&snapshot.config).await?;
    Ok((snapshot, listeners))
}

enum FileWatch {
    Enabled(PathBuf),
    Disabled(Option<ProviderCandidateBinder>),
}

async fn serve_managed<F, Fut>(
    file_watch: FileWatch,
    revisions: Arc<RevisionStore>,
    snapshot: Arc<RuntimeSnapshot>,
    listeners: Vec<(ListenerConfig, TcpListener)>,
    identity: NodeIdentity,
    shutdown: CancellationToken,
    start_control: F,
) -> Result<(), ProxyError>
where
    F: FnOnce(ManagedControl, CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeHandle::new_with_identity(Arc::clone(&snapshot), identity);
    let coordinator = Arc::new(ActivationCoordinator::new(
        Arc::clone(&revisions),
        runtime.clone(),
        shutdown.clone(),
    ));
    let providers = Arc::new(provider::ProviderCoordinator::default());
    let provider_audit = ProviderAuditRegistry::default();
    let provider_task = tokio::spawn(
        ProviderLifecycle {
            file_watch,
            revisions: Arc::clone(&revisions),
            coordinator: Arc::clone(&coordinator),
            providers: Arc::clone(&providers),
            audit: provider_audit.clone(),
            runtime: runtime.clone(),
            initial_config: Arc::clone(&snapshot.config),
            initial_revision: snapshot.revision.to_string(),
            shutdown: shutdown.clone(),
        }
        .run(),
    );
    let control = tokio::spawn(start_control(
        ManagedControl {
            revisions,
            coordinator,
            runtime: runtime.clone(),
            providers: providers.registry(),
            provider_audit,
        },
        shutdown.clone(),
    ));
    let result = serve_bound(runtime, snapshot, listeners, shutdown).await;
    if let Err(error) = provider_task.await {
        tracing::error!(%error, "provider reconciliation task failed");
    }
    if let Err(error) = control.await {
        tracing::error!(%error, "management service task failed");
    }
    result
}

pub(crate) fn validate_node_policy(
    config: &Config,
    identity: &NodeIdentity,
) -> Result<(), ProxyError> {
    if identity.fleet_generation() > 0
        && !config.acme.certificates.is_empty()
        && config.acme.renewal_owner.is_none()
    {
        return Err(ProxyError::Preparation(
            "fleet ACME configuration requires acme.renewal_owner".into(),
        ));
    }
    Ok(())
}

async fn bind_listeners(config: &Config) -> Result<Vec<(ListenerConfig, TcpListener)>, ProxyError> {
    let mut listeners = Vec::with_capacity(config.listeners.len());
    for listener in &config.listeners {
        listeners.push((listener.clone(), TcpListener::bind(listener.bind).await?));
    }
    Ok(listeners)
}

async fn serve_bound(
    runtime: RuntimeHandle,
    snapshot: Arc<RuntimeSnapshot>,
    listeners: Vec<(ListenerConfig, TcpListener)>,
    shutdown: CancellationToken,
) -> Result<(), ProxyError> {
    let config = Arc::clone(&snapshot.config);
    drop(snapshot);
    let handshake_permits = Arc::new(Semaphore::new(config.tls.max_handshakes));
    let mut tasks = tokio::task::JoinSet::new();
    for (listener, tcp) in listeners {
        let listener_id = listener.id.clone();
        let runtime = runtime.clone();
        let shutdown = shutdown.clone();
        let limits = config.limits.clone();
        let handshake_permits = Arc::clone(&handshake_permits);
        tracing::info!(listener = %listener_id, bind = %listener.bind, protocol = %listener.protocol, "listener started");
        if matches!(listener.protocol.as_str(), "tcp" | "tls_passthrough") {
            let tls_passthrough = listener.protocol == "tls_passthrough";
            tasks.spawn(async move {
                tcp_accept_loop(
                    tcp,
                    TcpListenerContext {
                        listener_id,
                        tls_passthrough,
                        runtime,
                        limits,
                        handshake_permits,
                        shutdown,
                    },
                )
                .await
            });
        } else {
            tasks.spawn(async move {
                accept_loop(
                    tcp,
                    ListenerContext {
                        listener_id,
                        runtime,
                        limits,
                        handshake_permits,
                        shutdown,
                    },
                )
                .await
            });
        }
    }
    if tasks.is_empty() {
        return Err(ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no public listeners configured",
        )));
    }
    let acme_tasks = acme_manager::start(runtime.clone(), shutdown.clone());
    while tasks.join_next().await.is_some() {}
    shutdown.cancel();
    acme_tasks.wait().await;
    let snapshot = runtime.load();
    for pool in snapshot.upstream_pools.values() {
        let handles: Vec<_> = pool
            .endpoints()
            .iter()
            .filter_map(|endpoint| {
                pool.begin_drain(&endpoint.config().id)
                    .ok()
                    .map(|handle| (endpoint.config().id.clone(), handle))
            })
            .collect();
        for (endpoint_id, handle) in handles {
            if !handle.wait().await {
                tracing::warn!(endpoint = %endpoint_id, "upstream drain deadline reached");
            }
        }
    }
    snapshot.stop_background().await;
    Ok(())
}

struct ProviderLifecycle {
    file_watch: FileWatch,
    revisions: Arc<RevisionStore>,
    coordinator: Arc<ActivationCoordinator>,
    providers: Arc<provider::ProviderCoordinator>,
    audit: ProviderAuditRegistry,
    runtime: RuntimeHandle,
    initial_config: Arc<Config>,
    initial_revision: String,
    shutdown: CancellationToken,
}

impl ProviderLifecycle {
    async fn run(self) {
        let Self {
            file_watch,
            revisions,
            coordinator,
            providers,
            audit,
            runtime,
            initial_config,
            initial_revision,
            shutdown,
        } = self;
        let provider_candidate_binder = match &file_watch {
            FileWatch::Enabled(_) => None,
            FileWatch::Disabled(binder) => binder.clone(),
        };
        #[cfg(unix)]
        let mut sighup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
        let mut last_fingerprint = None;
        let mut last_error: Option<String> = None;
        let mode = match &file_watch {
            FileWatch::Enabled(_) => "file",
            FileWatch::Disabled(_) => "typed",
        };
        let mut attempt = 0_u64;
        let (mut typed_base, mut typed_base_revision, mut last_provider_revision) =
            if matches!(&file_watch, FileWatch::Disabled(_)) {
                match load_typed_provider_base(Arc::clone(&revisions), &initial_revision).await {
                    Ok(base) => base,
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "typed provider base rejected; last-known-good retained"
                        );
                        return;
                    }
                }
            } else {
                ((*initial_config).clone(), initial_revision, None)
            };
        tracing::info!(mode, "provider coordinator started");
        loop {
            let interval = Duration::from_secs(runtime.load().config.runtime.config_poll_secs);
            #[cfg(unix)]
            tokio::select! {
                _ = shutdown.cancelled() => break,
                () = tokio::time::sleep(interval) => {},
                () = receive_sighup(&mut sighup) => {},
            }
            #[cfg(not(unix))]
            tokio::select! {
                _ = shutdown.cancelled() => break,
                () = tokio::time::sleep(interval) => {},
            }
            let (base, hash, source, binding) = match &file_watch {
                FileWatch::Enabled(config_path) => {
                    let loaded = tokio::task::spawn_blocking({
                        let config_path = config_path.clone();
                        move || {
                            let bytes = std::fs::read(config_path).map_err(ConfigError::from)?;
                            let hash: [u8; 32] = Sha256::digest(&bytes).into();
                            Ok::<_, ConfigError>((hash, aegisproxy_config::load_bytes(&bytes)))
                        }
                    })
                    .await;
                    let (hash, parsed) = match loaded {
                        Ok(Ok(loaded)) => loaded,
                        Ok(Err(error)) => {
                            let message = error.to_string();
                            if last_error.as_deref() != Some(message.as_str()) {
                                tracing::error!(%error, "changed configuration rejected");
                                last_error = Some(message);
                            }
                            continue;
                        }
                        Err(error) => {
                            tracing::error!(%error, "configuration reload task failed");
                            continue;
                        }
                    };
                    let base = match parsed {
                        Ok(config) => config,
                        Err(error) => {
                            tracing::error!(%error, "changed configuration rejected");
                            continue;
                        }
                    };
                    (base, hash, "file+providers".to_owned(), None)
                }
                FileWatch::Disabled(_) => {
                    let active = runtime.revision().to_string();
                    if active != typed_base_revision
                        && last_provider_revision.as_deref() != Some(active.as_str())
                    {
                        match load_typed_provider_base(Arc::clone(&revisions), &active).await {
                            Ok((config, revision, provider_revision)) => {
                                typed_base = config;
                                typed_base_revision = revision;
                                last_provider_revision = provider_revision;
                                last_fingerprint = None;
                            }
                            Err(error) => {
                                tracing::error!(
                                    %error,
                                    revision = %active,
                                    "typed provider base rejected; last-known-good retained"
                                );
                                continue;
                            }
                        }
                    }
                    let binding = match typed_provider_binding(&revisions, &typed_base_revision) {
                        Ok(binding) => binding,
                        Err(error) => {
                            tracing::error!(
                                %error,
                                revision = %typed_base_revision,
                                "typed provider binding rejected; last-known-good retained"
                            );
                            continue;
                        }
                    };
                    (
                        typed_base.clone(),
                        Sha256::digest(typed_base_revision.as_bytes()).into(),
                        format!("{TYPED_PROVIDER_SOURCE_PREFIX}{typed_base_revision}"),
                        Some(binding),
                    )
                }
            };
            last_error = None;
            attempt = attempt.saturating_add(1);
            let request_id = format!("provider-{mode}-{attempt}");
            let resource_id = format!("provider/{mode}");
            let active_before = runtime.revision().to_string();
            let provider_audit_required = base.providers.iter().any(|provider| provider.enabled())
                || runtime
                    .config()
                    .providers
                    .iter()
                    .any(|provider| provider.enabled());
            let intent_audited = audit
                .record(ProviderAuditEvent {
                    action: "provider_reconciliation",
                    resource_id: resource_id.clone(),
                    request_id: request_id.clone(),
                    old_revision: Some(active_before.clone()),
                    new_revision: None,
                    outcome: ProviderAuditOutcome::Intent,
                    error_code: None,
                })
                .await;
            if provider_audit_required && !intent_audited {
                tracing::error!(mode, "provider audit unavailable; last-known-good retained");
                continue;
            }
            tracing::debug!(mode, "provider reconciliation attempted");
            let reconciled = providers.reconcile(base, hash).await;
            let statuses = providers.registry().statuses();
            let source_unresolved = statuses.iter().any(|status| {
                matches!(status.state, "pending" | "stale")
                    && status.last_success_unix_secs.is_none()
            });
            for status in &statuses {
                runtime.update_provider_status(status);
                match (status.state, status.error) {
                    (_, Some(error @ "invalid_result")) => tracing::warn!(
                        provider_kind = status.kind,
                        %error,
                        "provider validation or conflict rejected; last-known-good retained"
                    ),
                    ("stale", error) => tracing::warn!(
                        provider_kind = status.kind,
                        ?error,
                        "stale provider output rejected; last-known-good retained"
                    ),
                    (_, Some(error)) => tracing::warn!(
                        provider_kind = status.kind,
                        %error,
                        "provider fetch failed; last-known-good retained"
                    ),
                    _ => {}
                }
            }
            let provider_failure =
                statuses
                    .iter()
                    .find_map(|status| match (status.state, status.error) {
                        (_, Some("invalid_result")) => Some("provider_validation_rejected"),
                        ("stale", _) => Some("provider_stale_rejected"),
                        (_, Some(_)) => Some("provider_fetch_failed"),
                        _ => None,
                    });
            if let Some(error_code) = provider_failure
                && !audit
                    .record(ProviderAuditEvent {
                        action: "provider_reconciliation",
                        resource_id: resource_id.clone(),
                        request_id: request_id.clone(),
                        old_revision: Some(active_before.clone()),
                        new_revision: None,
                        outcome: ProviderAuditOutcome::Failed,
                        error_code: Some(error_code),
                    })
                    .await
            {
                tracing::error!(mode, "provider audit unavailable; last-known-good retained");
                continue;
            }
            if source_unresolved {
                if last_provider_revision.is_some() {
                    tracing::warn!(
                        "recovered provider state is not yet usable; last-known-good retained"
                    );
                } else {
                    tracing::debug!(
                        "provider state is not yet usable; active configuration unchanged"
                    );
                }
                continue;
            }
            if matches!(&file_watch, FileWatch::Disabled(_))
                && statuses.iter().all(|status| status.state == "disabled")
            {
                let _ = audit
                    .record(provider_skipped_event(
                        &resource_id,
                        &request_id,
                        &active_before,
                        "provider_disabled",
                    ))
                    .await;
                last_fingerprint = Some(reconciled.fingerprint);
                last_provider_revision = None;
                continue;
            }
            if last_fingerprint == Some(reconciled.fingerprint) {
                let _ = audit
                    .record(provider_skipped_event(
                        &resource_id,
                        &request_id,
                        &active_before,
                        "provider_no_change",
                    ))
                    .await;
                tracing::debug!(
                    mode,
                    "provider reconciliation succeeded with no configuration change"
                );
                continue;
            }
            let config = reconciled.config;
            let candidate = tokio::task::spawn_blocking({
                let revisions = Arc::clone(&revisions);
                let binding = binding.clone();
                move || match binding {
                    Some(binding) => {
                        revisions.create_bound_forward_revision(&config, &source, &binding)
                    }
                    None => revisions.create_candidate(&config, &source),
                }
            })
            .await;
            let candidate = match candidate {
                Ok(Ok(candidate)) => candidate,
                Ok(Err(error)) => {
                    let _ = audit
                        .record(ProviderAuditEvent {
                            action: "provider_candidate_create",
                            resource_id: resource_id.clone(),
                            request_id: request_id.clone(),
                            old_revision: Some(active_before.clone()),
                            new_revision: None,
                            outcome: ProviderAuditOutcome::Failed,
                            error_code: Some("candidate_persistence_failed"),
                        })
                        .await;
                    tracing::error!(
                        %error,
                        "provider candidate persistence failed; last-known-good retained"
                    );
                    continue;
                }
                Err(error) => {
                    let _ = audit
                        .record(ProviderAuditEvent {
                            action: "provider_candidate_create",
                            resource_id: resource_id.clone(),
                            request_id: request_id.clone(),
                            old_revision: Some(active_before.clone()),
                            new_revision: None,
                            outcome: ProviderAuditOutcome::Failed,
                            error_code: Some("candidate_task_failed"),
                        })
                        .await;
                    tracing::error!(
                        %error,
                        "provider candidate task failed; last-known-good retained"
                    );
                    continue;
                }
            };
            let candidate_audited = audit
                .record(ProviderAuditEvent {
                    action: "provider_candidate_create",
                    resource_id: candidate.id.clone(),
                    request_id: request_id.clone(),
                    old_revision: Some(active_before.clone()),
                    new_revision: Some(candidate.id.clone()),
                    outcome: ProviderAuditOutcome::Success,
                    error_code: None,
                })
                .await;
            if provider_audit_required && !candidate_audited {
                tracing::error!(mode, "provider audit unavailable; candidate not activated");
                continue;
            }
            if let Some(binding) = binding.as_deref() {
                let Some(binder) = provider_candidate_binder.as_ref() else {
                    let _ = audit
                        .record(provider_activation_failure_event(
                            &candidate.id,
                            &request_id,
                            &active_before,
                            "candidate_binding_unavailable",
                        ))
                        .await;
                    tracing::error!(
                        candidate = %candidate.id,
                        "provider candidate binder unavailable; last-known-good retained"
                    );
                    continue;
                };
                let bound = tokio::task::spawn_blocking({
                    let binder = Arc::clone(binder);
                    let source_revision = typed_base_revision.clone();
                    let target_revision = candidate.id.clone();
                    let binding = binding.to_owned();
                    move || binder(&source_revision, &target_revision, &binding)
                })
                .await;
                match bound {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let _ = audit
                            .record(provider_activation_failure_event(
                                &candidate.id,
                                &request_id,
                                &active_before,
                                "candidate_binding_failed",
                            ))
                            .await;
                        tracing::error!(
                            %error,
                            candidate = %candidate.id,
                            "provider candidate binding failed; last-known-good retained"
                        );
                        continue;
                    }
                    Err(error) => {
                        let _ = audit
                            .record(provider_activation_failure_event(
                                &candidate.id,
                                &request_id,
                                &active_before,
                                "candidate_binding_task_failed",
                            ))
                            .await;
                        tracing::error!(
                            %error,
                            candidate = %candidate.id,
                            "provider candidate binding task failed; last-known-good retained"
                        );
                        continue;
                    }
                }
            }
            let active = runtime.revision();
            if candidate.id.as_str() == active.as_ref() {
                let _ = audit
                    .record(provider_skipped_event(
                        &candidate.id,
                        &request_id,
                        &active_before,
                        "candidate_already_active",
                    ))
                    .await;
                last_fingerprint = Some(reconciled.fingerprint);
                last_provider_revision = Some(candidate.id);
                tracing::debug!(
                    mode,
                    "provider reconciliation succeeded with active configuration unchanged"
                );
                continue;
            }
            match coordinator.activate(&candidate.id, Some(&active)).await {
                Ok(result) => {
                    if !audit
                        .record(ProviderAuditEvent {
                            action: "provider_activate",
                            resource_id: result.active.clone(),
                            request_id: request_id.clone(),
                            old_revision: result.previous.clone(),
                            new_revision: Some(result.active.clone()),
                            outcome: ProviderAuditOutcome::Success,
                            error_code: None,
                        })
                        .await
                    {
                        tracing::error!(revision = %result.active, "provider activation succeeded but audit durability is unavailable");
                    }
                    last_fingerprint = Some(reconciled.fingerprint);
                    last_provider_revision = Some(result.active.clone());
                    tracing::info!(
                        revision = %result.active,
                        "provider reconciliation succeeded and configuration activated"
                    );
                }
                Err(error) => {
                    let _ = audit
                        .record(provider_activation_failure_event(
                            &candidate.id,
                            &request_id,
                            &active_before,
                            provider_activation_error_code(&error),
                        ))
                        .await;
                    if let Some((outcome, error_code)) = provider_rollback_outcome(&error) {
                        let _ = audit
                            .record(ProviderAuditEvent {
                                action: "provider_rollback",
                                resource_id: candidate.id.clone(),
                                request_id: request_id.clone(),
                                old_revision: Some(candidate.id.clone()),
                                new_revision: Some(active_before.clone()),
                                outcome,
                                error_code,
                            })
                            .await;
                    }
                    tracing::error!(
                        %error,
                        candidate = %candidate.id,
                        "provider activation failed; last-known-good retained"
                    )
                }
            }
        }
        tracing::info!(mode, "provider coordinator stopped");
    }
}

fn provider_skipped_event(
    resource_id: &str,
    request_id: &str,
    active_revision: &str,
    reason: &'static str,
) -> ProviderAuditEvent {
    ProviderAuditEvent {
        action: "provider_reconciliation_skip",
        resource_id: resource_id.to_owned(),
        request_id: request_id.to_owned(),
        old_revision: Some(active_revision.to_owned()),
        new_revision: Some(active_revision.to_owned()),
        outcome: ProviderAuditOutcome::Success,
        error_code: Some(reason),
    }
}

fn provider_activation_failure_event(
    candidate_id: &str,
    request_id: &str,
    active_revision: &str,
    error_code: &'static str,
) -> ProviderAuditEvent {
    ProviderAuditEvent {
        action: "provider_activate",
        resource_id: candidate_id.to_owned(),
        request_id: request_id.to_owned(),
        old_revision: Some(active_revision.to_owned()),
        new_revision: Some(candidate_id.to_owned()),
        outcome: ProviderAuditOutcome::Failed,
        error_code: Some(error_code),
    }
}

fn provider_activation_error_code(error: &ActivationError) -> &'static str {
    match error {
        ActivationError::Revision(RevisionError::Conflict) => "activation_conflict",
        ActivationError::RecoveryRequired => "recovery_required",
        ActivationError::RollbackFailed => "rollback_failed",
        ActivationError::RestartRequired => "restart_required",
        ActivationError::Probation => "probation_failed",
        ActivationError::Revision(_) | ActivationError::Preparation(_) => "activation_failed",
    }
}

fn provider_rollback_outcome(
    error: &ActivationError,
) -> Option<(ProviderAuditOutcome, Option<&'static str>)> {
    match error {
        ActivationError::Probation => Some((ProviderAuditOutcome::Success, None)),
        ActivationError::RollbackFailed => {
            Some((ProviderAuditOutcome::Failed, Some("rollback_failed")))
        }
        _ => None,
    }
}

fn typed_provider_binding(
    revisions: &RevisionStore,
    revision: &str,
) -> Result<String, RevisionError> {
    revisions
        .metadata(revision)?
        .binding_hash
        .ok_or_else(|| RevisionError::InvalidStored("typed provider base is unbound".into()))
}

async fn load_typed_provider_base(
    revisions: Arc<RevisionStore>,
    active: &str,
) -> Result<(Config, String, Option<String>), RevisionError> {
    let active = active.to_owned();
    tokio::task::spawn_blocking(move || {
        let metadata = revisions.metadata(&active)?;
        let (revision, provider_revision) =
            match metadata.source.strip_prefix(TYPED_PROVIDER_SOURCE_PREFIX) {
                Some(base) => (base.to_owned(), Some(active)),
                None => (active, None),
            };
        let binding = metadata.binding_hash.ok_or_else(|| {
            RevisionError::InvalidStored("active typed provider revision is unbound".into())
        })?;
        let base = revisions.metadata(&revision)?;
        if base.binding_hash.as_deref() != Some(binding.as_str()) {
            return Err(RevisionError::InvalidStored(
                "typed provider revision binding does not match its base".into(),
            ));
        }
        Ok((revisions.load(&revision)?, revision, provider_revision))
    })
    .await
    .map_err(|error| RevisionError::InvalidStored(error.to_string()))?
}

#[cfg(unix)]
async fn receive_sighup(signal: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(signal) = signal
        && signal.recv().await.is_some()
    {
        return;
    }
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod provider_audit_tests {
    use super::*;

    #[test]
    fn activation_failures_have_bounded_rollback_audit_outcomes() {
        assert_eq!(
            provider_activation_error_code(&ActivationError::Probation),
            "probation_failed"
        );
        assert_eq!(
            provider_rollback_outcome(&ActivationError::Probation),
            Some((ProviderAuditOutcome::Success, None))
        );
        assert_eq!(
            provider_rollback_outcome(&ActivationError::RollbackFailed),
            Some((ProviderAuditOutcome::Failed, Some("rollback_failed")))
        );
        assert_eq!(
            provider_rollback_outcome(&ActivationError::RestartRequired),
            None
        );
    }
}
