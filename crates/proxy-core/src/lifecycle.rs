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
        FileWatch::Disabled,
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
    Disabled,
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
    let watcher = match file_watch {
        FileWatch::Enabled(config_path) => Some(tokio::spawn(watch_config_file(
            config_path,
            Arc::clone(&revisions),
            Arc::clone(&coordinator),
            Arc::clone(&providers),
            runtime.clone(),
            shutdown.clone(),
        ))),
        FileWatch::Disabled => None,
    };
    let control = tokio::spawn(start_control(
        ManagedControl {
            revisions,
            coordinator,
            runtime: runtime.clone(),
            providers: providers.registry(),
        },
        shutdown.clone(),
    ));
    let result = serve_bound(runtime, snapshot, listeners, shutdown).await;
    if let Some(watcher) = watcher
        && let Err(error) = watcher.await
    {
        tracing::error!(%error, "configuration watcher task failed");
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

async fn watch_config_file(
    config_path: PathBuf,
    revisions: Arc<RevisionStore>,
    coordinator: Arc<ActivationCoordinator>,
    providers: Arc<provider::ProviderCoordinator>,
    runtime: RuntimeHandle,
    shutdown: CancellationToken,
) {
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    let mut last_fingerprint = None;
    let mut last_error: Option<String> = None;
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
        last_error = None;
        let reconciled = providers.reconcile(base, hash).await;
        for status in providers.registry().statuses() {
            runtime.update_provider_status(&status);
        }
        if last_fingerprint == Some(reconciled.fingerprint) {
            continue;
        }
        let config = reconciled.config;
        let candidate = tokio::task::spawn_blocking({
            let revisions = Arc::clone(&revisions);
            move || revisions.create_candidate(&config, "file+providers")
        })
        .await;
        let candidate = match candidate {
            Ok(Ok(candidate)) => candidate,
            Ok(Err(error)) => {
                tracing::error!(%error, "configuration candidate persistence failed");
                continue;
            }
            Err(error) => {
                tracing::error!(%error, "configuration candidate task failed");
                continue;
            }
        };
        last_fingerprint = Some(reconciled.fingerprint);
        let active = runtime.revision();
        if candidate.id.as_str() == active.as_ref() {
            continue;
        }
        match coordinator.activate(&candidate.id, Some(&active)).await {
            Ok(result) => tracing::info!(revision = %result.active, "configuration activated"),
            Err(error) => {
                tracing::error!(%error, candidate = %candidate.id, "configuration activation rejected")
            }
        }
    }
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
