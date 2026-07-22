#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Data-plane HTTP and TCP reverse-proxy runtime.

mod acme_manager;
mod middleware;
mod provider;
mod route;
mod runtime;
mod tcp;
mod telemetry;
mod upstream;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;

use std::{
    collections::HashMap,
    convert::Infallible,
    error::Error,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aegisproxy_config::{
    Config, ConfigError, EndpointConfig, HealthCheckConfig, HealthCheckKind, LimitsConfig,
    ListenerConfig,
    revision::{RevisionError, RevisionStore},
};
use aegisproxy_tls::{
    CertificateResolver, Identity, TlsAcceptor,
    acme::{HttpChallengeError, HttpChallengeRegistry},
    inspect_certificate, load_identity, load_stored_identity, tls_acceptor,
};
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::service::Service;
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{
        AUTHORIZATION, CONNECTION, HOST, HeaderValue, RETRY_AFTER, UPGRADE, WWW_AUTHENTICATE,
    },
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use opentelemetry::{
    global,
    propagation::{Extractor, Injector},
    trace::TraceContextExt as _,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use upstream::{
    DnsEndpoint, GuardedBody, PolicyResolver, UpstreamPool, prepare_dns, start_dns_refreshes,
};

use middleware::auth::{BasicAuthPolicies, ForwardOutcome, Outcome as AuthOutcome};
use middleware::compression::CompressionLimiters;
use middleware::limit::{InFlightLimiters, Outcome as InFlightOutcome};
use middleware::normalize::{normalize_forwarding_headers, rebuild_proxy_headers};
use middleware::rate::{Outcome as RateOutcome, RateLimiters};

pub use provider::{ProviderRegistry, ProviderStatus};
pub use route::RouteIndex;
use route::{PathError, canonical_host, canonicalize_request_path, request_host};
use runtime::RuntimeSnapshot;
pub use runtime::{
    ActivationCoordinator, ActivationError, ActivationResult, NodeIdentity, RuntimeHandle,
};
use tcp::{TcpListenerContext, accept_loop as tcp_accept_loop};

/// Boxed body error.
pub type BoxError = Box<dyn Error + Send + Sync>;
/// Boxed response body used by the server and upstream client.
pub type ResponseBody = BoxBody<bytes::Bytes, BoxError>;

struct HeaderExtractor<'a>(&'a hyper::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(hyper::header::HeaderName::as_str)
            .collect()
    }
}

struct HeaderInjector<'a>(&'a mut hyper::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        let Ok(name) = key.parse::<hyper::header::HeaderName>() else {
            return;
        };
        let Ok(value) = HeaderValue::from_str(&value) else {
            return;
        };
        self.0.insert(name, value);
    }
}
type UpstreamClient = Client<HttpsConnector<HttpConnector<PolicyResolver>>, ResponseBody>;
type UpstreamClients = Arc<HashMap<String, UpstreamClient>>;
type UpstreamPools = Arc<HashMap<String, Arc<UpstreamPool>>>;
type DnsEndpoints = Arc<HashMap<String, Arc<DnsEndpoint>>>;

struct TlsPreparation {
    acceptors: HashMap<String, TlsAcceptor>,
    resolvers: HashMap<String, CertificateResolver>,
    identities: HashMap<String, Identity>,
}

/// Proxy runtime error.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Invalid startup configuration.
    #[error("configuration failed validation: {0}")]
    Config(#[from] ConfigError),
    /// Listener bind failure.
    #[error("listener failed: {0}")]
    Io(#[from] std::io::Error),
    /// TLS identity or policy preparation failed.
    #[error("TLS preparation failed: {0}")]
    Tls(#[from] aegisproxy_tls::TlsError),
    /// A blocking preparation task failed unexpectedly.
    #[error("runtime preparation failed: {0}")]
    Preparation(String),
    /// Durable revision state failed.
    #[error("revision state failed: {0}")]
    Revision(#[from] RevisionError),
}

/// Handles exposed to an isolated management service.
#[derive(Clone, Debug)]
pub struct ManagedControl {
    revisions: Arc<RevisionStore>,
    coordinator: Arc<ActivationCoordinator>,
    runtime: RuntimeHandle,
    providers: ProviderRegistry,
}

/// Redacted public certificate-generation status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateStatus {
    /// Stable configured certificate ID.
    pub id: String,
    /// Validated covered host names.
    pub hosts: Vec<String>,
    /// Immutable stored generation ID.
    pub generation: String,
    /// Public issuer display name.
    pub issuer: String,
    /// Certificate validity start as Unix seconds.
    pub not_before_unix_secs: i64,
    /// Certificate validity end as Unix seconds.
    pub not_after_unix_secs: i64,
    /// Whether ACME automation owns this generation.
    pub managed: bool,
}

impl ManagedControl {
    /// Return the durable revision store.
    #[must_use]
    pub fn revisions(&self) -> Arc<RevisionStore> {
        Arc::clone(&self.revisions)
    }

    /// Return the transactional activation coordinator.
    #[must_use]
    pub fn coordinator(&self) -> Arc<ActivationCoordinator> {
        Arc::clone(&self.coordinator)
    }

    /// Return the current runtime handle.
    #[must_use]
    pub fn runtime(&self) -> RuntimeHandle {
        self.runtime.clone()
    }

    /// Return bounded redacted discovery-provider status.
    #[must_use]
    pub fn provider_statuses(&self) -> Vec<ProviderStatus> {
        self.providers.statuses()
    }

    /// Durably request renewal for one configured ACME certificate.
    pub async fn request_certificate_renewal(&self, id: &str) -> Result<(), ProxyError> {
        if !self.runtime.certificate_owner() {
            return Err(ProxyError::Preparation(
                "node does not own certificate renewal".into(),
            ));
        }
        let config = self.runtime.config();
        if !config
            .acme
            .certificates
            .iter()
            .any(|certificate| certificate.id == id)
        {
            return Err(ProxyError::Preparation(
                "certificate is not managed by active configuration".into(),
            ));
        }
        let state_dir = PathBuf::from(&config.runtime.state_dir);
        let certificate_id = id.to_owned();
        let renewal_id = certificate_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            aegisproxy_tls::acme::request_certificate_renewal(&state_dir, &renewal_id)
                .map_err(|_| ProxyError::Preparation("renewal request failed".into()))
        })
        .await
        .map_err(|error| ProxyError::Preparation(error.to_string()))?;
        self.runtime.record_certificate_renewal(
            &certificate_id,
            if result.is_ok() {
                "requested"
            } else {
                "failed"
            },
        );
        result
    }

    /// Load bounded public certificate-generation metadata off runtime workers.
    pub async fn certificate_statuses(&self) -> Result<Vec<CertificateStatus>, ProxyError> {
        let state_dir = PathBuf::from(&self.runtime.config().runtime.state_dir);
        tokio::task::spawn_blocking(move || {
            aegisproxy_tls::list_certificates(&state_dir)
                .map(|certificates| {
                    certificates
                        .into_iter()
                        .map(|certificate| CertificateStatus {
                            id: certificate.id,
                            hosts: certificate.hosts,
                            generation: certificate.generation,
                            issuer: certificate.issuer,
                            not_before_unix_secs: certificate.not_before_unix_secs,
                            not_after_unix_secs: certificate.not_after_unix_secs,
                            managed: certificate.managed.is_some(),
                        })
                        .collect()
                })
                .map_err(ProxyError::Tls)
        })
        .await
        .map_err(|error| ProxyError::Preparation(error.to_string()))?
    }

    /// Refresh certificate expiry gauges, then encode bounded OpenMetrics output.
    pub async fn render_openmetrics(&self) -> Result<String, ProxyError> {
        for status in self.certificate_statuses().await? {
            self.runtime
                .telemetry()
                .update_certificate_expiry(&status.id, status.not_after_unix_secs);
        }
        self.runtime
            .render_openmetrics()
            .map_err(|_| ProxyError::Preparation("metrics output exceeded its bound".into()))
    }
}

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
        config_path,
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
        config_path,
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

async fn serve_managed<F, Fut>(
    config_path: PathBuf,
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
    let watcher = tokio::spawn(watch_config_file(
        config_path,
        Arc::clone(&revisions),
        Arc::clone(&coordinator),
        Arc::clone(&providers),
        runtime.clone(),
        shutdown.clone(),
    ));
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
    if let Err(error) = watcher.await {
        tracing::error!(%error, "configuration watcher task failed");
    }
    if let Err(error) = control.await {
        tracing::error!(%error, "management service task failed");
    }
    result
}

fn validate_node_policy(config: &Config, identity: &NodeIdentity) -> Result<(), ProxyError> {
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

fn build_upstream_clients(config: &Config) -> Result<(UpstreamClients, DnsEndpoints), ProxyError> {
    let mut clients = HashMap::new();
    let mut dns_endpoints = HashMap::new();
    for group in &config.upstream_groups {
        for endpoint in &group.endpoints {
            let dns_endpoint = Arc::new(
                DnsEndpoint::new(endpoint, group)
                    .map_err(|error| ProxyError::Preparation(error.to_string()))?,
            );
            let key = endpoint_key(&group.id, &endpoint.id);
            if dns_endpoints
                .insert(key.clone(), Arc::clone(&dns_endpoint))
                .is_some()
            {
                return Err(ProxyError::Preparation(format!(
                    "duplicate DNS endpoint {}/{}",
                    group.id, endpoint.id
                )));
            }
            if endpoint.url.scheme() == "tcp" {
                continue;
            }
            let server_name = endpoint
                .server_name
                .as_deref()
                .map(|server_name| {
                    rustls::pki_types::ServerName::try_from(server_name.to_owned()).map_err(|_| {
                        ProxyError::Preparation(format!(
                            "endpoint {} has invalid server_name",
                            endpoint.id
                        ))
                    })
                })
                .transpose()?;
            let tls_config = aegisproxy_tls::client_config(endpoint.ca_bundle.as_deref())?;
            let mut http = HttpConnector::new_with_resolver(dns_endpoint.resolver());
            http.enforce_http(false);
            let connector = HttpsConnectorBuilder::new()
                .with_tls_config(tls_config)
                .https_or_http()
                .with_server_name_resolver(move |uri: &Uri| {
                    server_name.clone().map(Ok).unwrap_or_else(|| {
                        rustls::pki_types::ServerName::try_from(
                            uri.host().unwrap_or_default().to_owned(),
                        )
                    })
                })
                .enable_http1()
                .enable_http2()
                .wrap_connector(http);
            let client = Client::builder(TokioExecutor::new()).build(connector);
            if clients.insert(key, client).is_some() {
                return Err(ProxyError::Preparation(format!(
                    "duplicate upstream endpoint {}/{}",
                    group.id, endpoint.id
                )));
            }
        }
    }
    Ok((Arc::new(clients), Arc::new(dns_endpoints)))
}

fn build_upstream_pools(config: &Config) -> Result<UpstreamPools, ProxyError> {
    let mut pools = HashMap::new();
    for group in &config.upstream_groups {
        let pool = UpstreamPool::new(group)
            .map_err(|error| ProxyError::Preparation(format!("group {}: {error}", group.id)))?;
        if pools.insert(group.id.clone(), Arc::new(pool)).is_some() {
            return Err(ProxyError::Preparation(format!(
                "duplicate upstream group {}",
                group.id
            )));
        }
    }
    Ok(Arc::new(pools))
}

fn endpoint_key(group_id: &str, endpoint_id: &str) -> String {
    format!("{group_id}/{endpoint_id}")
}

fn start_active_health_checks(
    config: &Config,
    clients: &UpstreamClients,
    pools: &UpstreamPools,
    dns_endpoints: &DnsEndpoints,
    shutdown: &CancellationToken,
) -> Result<TaskTracker, ProxyError> {
    let tracker = TaskTracker::new();
    let permits = Arc::new(Semaphore::new(config.limits.max_health_checks));
    for group in &config.upstream_groups {
        let Some(policy) = &group.health else {
            continue;
        };
        let pool = pools.get(&group.id).ok_or_else(|| {
            ProxyError::Preparation(format!("health pool {} is missing", group.id))
        })?;
        for endpoint in pool.endpoints() {
            let client = if policy.kind == HealthCheckKind::Http {
                Some(
                    clients
                        .get(&endpoint_key(&group.id, &endpoint.config().id))
                        .cloned()
                        .ok_or_else(|| {
                            ProxyError::Preparation(format!(
                                "health client {}/{} is missing",
                                group.id,
                                endpoint.config().id
                            ))
                        })?,
                )
            } else {
                None
            };
            let dns_endpoint = dns_endpoints
                .get(&endpoint_key(&group.id, &endpoint.config().id))
                .cloned()
                .ok_or_else(|| {
                    ProxyError::Preparation(format!(
                        "DNS endpoint {}/{} is missing",
                        group.id,
                        endpoint.config().id
                    ))
                })?;
            let endpoint = Arc::clone(endpoint);
            let policy = policy.clone();
            let permits = Arc::clone(&permits);
            let shutdown = shutdown.clone();
            tracker.spawn(async move {
                loop {
                    let permit = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        result = permits.clone().acquire_owned() => match result {
                            Ok(permit) => permit,
                            Err(_) => break,
                        },
                    };
                    let healthy = active_health_probe(
                        client.as_ref(),
                        &dns_endpoint,
                        endpoint.config(),
                        &policy,
                    )
                    .await;
                    drop(permit);
                    if healthy {
                        endpoint
                            .health()
                            .record_active_success(policy.healthy_threshold);
                    } else {
                        endpoint
                            .health()
                            .record_active_failure(policy.unhealthy_threshold);
                    }
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        () = tokio::time::sleep(health_interval(&endpoint.config().id, &policy)) => {}
                    }
                }
            });
        }
    }
    tracker.close();
    Ok(tracker)
}

async fn active_health_probe(
    client: Option<&UpstreamClient>,
    dns_endpoint: &DnsEndpoint,
    endpoint: &EndpointConfig,
    policy: &HealthCheckConfig,
) -> bool {
    match policy.kind {
        HealthCheckKind::Tcp => {
            let Ok(addresses) = dns_endpoint.connection_addresses() else {
                return false;
            };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(policy.timeout_secs);
            for address in addresses {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return false;
                }
                if matches!(
                    tokio::time::timeout(remaining, TcpStream::connect(address)).await,
                    Ok(Ok(_))
                ) {
                    return true;
                }
            }
            false
        }
        HealthCheckKind::Http => {
            let Some(client) = client else {
                return false;
            };
            let Ok(method) = hyper::Method::from_bytes(policy.method.as_bytes()) else {
                return false;
            };
            let mut target = endpoint.url.clone();
            target.set_path(&policy.path);
            target.set_query(None);
            let Ok(uri) = target.as_str().parse::<Uri>() else {
                return false;
            };
            let Ok(mut request) = Request::builder()
                .method(method)
                .uri(uri)
                .body(full_body(b""))
            else {
                return false;
            };
            let Some(authority) = endpoint_authority(endpoint) else {
                return false;
            };
            request.headers_mut().insert(HOST, authority);
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(policy.timeout_secs),
                    client.request(request)
                )
                .await,
                Ok(Ok(response)) if policy.expected_statuses.contains(&response.status().as_u16())
            )
        }
    }
}

fn endpoint_authority(endpoint: &EndpointConfig) -> Option<HeaderValue> {
    let host = endpoint.url.host_str()?;
    let port = endpoint.url.port()?;
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    HeaderValue::from_str(&authority).ok()
}

fn health_interval(endpoint_id: &str, policy: &HealthCheckConfig) -> Duration {
    let hash = endpoint_id.bytes().fold(2_166_136_261_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(16_777_619)
    });
    let percent = 90 + hash % 21;
    Duration::from_millis(policy.interval_secs * 1_000 * percent / 100)
}

fn prepare_tls(
    config: &Config,
    tls_challenges: aegisproxy_tls::acme::TlsAlpnChallengeRegistry,
) -> Result<TlsPreparation, ProxyError> {
    let mut identities = HashMap::new();
    let decryption_identity = config.tls.identity.as_deref();
    for certificate in &config.certificates {
        let identity = load_identity(
            certificate.id.clone(),
            certificate.hosts.clone(),
            &certificate.certificate_chain,
            &certificate.private_key,
            decryption_identity.ok_or_else(|| {
                ProxyError::Preparation(
                    "tls.identity is required for encrypted private keys".into(),
                )
            })?,
        )?;
        identities.insert(certificate.id.as_str(), identity);
    }
    for certificate in &config.acme.certificates {
        let state_dir = Path::new(&config.runtime.state_dir);
        let certificate_dir = state_dir.join("certificates").join(&certificate.id);
        if !certificate_dir.exists() {
            continue;
        }
        let metadata = inspect_certificate(state_dir, &certificate.id)?;
        if metadata.hosts != certificate.hosts {
            return Err(ProxyError::Preparation(format!(
                "stored ACME certificate {} hosts do not match configuration",
                certificate.id
            )));
        }
        let expected_environment = match config
            .acme
            .issuers
            .iter()
            .find(|issuer| issuer.id == certificate.issuer)
            .map(|issuer| issuer.environment)
        {
            Some(aegisproxy_config::AcmeEnvironment::Production) => {
                aegisproxy_tls::ManagedCertificateEnvironment::Production
            }
            Some(aegisproxy_config::AcmeEnvironment::Staging) => {
                aegisproxy_tls::ManagedCertificateEnvironment::Staging
            }
            None => {
                return Err(ProxyError::Preparation(format!(
                    "ACME certificate {} references missing issuer",
                    certificate.id
                )));
            }
        };
        if !metadata.managed.as_ref().is_some_and(|provenance| {
            provenance.issuer_id == certificate.issuer
                && provenance.environment == expected_environment
                && provenance.profile == certificate.profile
        }) {
            return Err(ProxyError::Preparation(format!(
                "stored ACME certificate {} provenance does not match configuration",
                certificate.id
            )));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProxyError::Preparation("system clock predates Unix epoch".into()))?
            .as_secs();
        if metadata.not_after_unix_secs >= 0 && metadata.not_after_unix_secs as u64 <= now {
            continue;
        }
        let identity = load_stored_identity(
            state_dir,
            &certificate.id,
            decryption_identity.ok_or_else(|| {
                ProxyError::Preparation("tls.identity is required for managed certificates".into())
            })?,
        )?;
        identities.insert(certificate.id.as_str(), identity);
    }
    let mut acceptors = HashMap::new();
    let mut resolvers = HashMap::new();
    for listener in config
        .listeners
        .iter()
        .filter(|listener| listener.protocol == "https")
    {
        let selected: Result<Vec<Identity>, ProxyError> = listener
            .certificates
            .iter()
            .filter_map(|id| match identities.get(id.as_str()).cloned() {
                Some(identity) => Some(Ok(identity)),
                None if config
                    .acme
                    .certificates
                    .iter()
                    .any(|certificate| certificate.id == *id) =>
                {
                    None
                }
                None => Some(Err(ProxyError::Preparation(format!(
                    "listener {} references missing certificate {id}",
                    listener.id
                )))),
            })
            .collect();
        let resolver =
            CertificateResolver::with_acme_challenges(&selected?, tls_challenges.clone())?;
        acceptors.insert(
            listener.id.clone(),
            tls_acceptor(resolver.clone(), &config.tls.minimum_version)?,
        );
        resolvers.insert(listener.id.clone(), resolver);
    }
    Ok(TlsPreparation {
        acceptors,
        resolvers,
        identities: identities
            .into_iter()
            .map(|(id, identity)| (id.to_owned(), identity))
            .collect(),
    })
}

#[derive(Clone)]
struct ListenerContext {
    listener_id: String,
    runtime: RuntimeHandle,
    limits: LimitsConfig,
    handshake_permits: Arc<Semaphore>,
    shutdown: CancellationToken,
}

async fn accept_loop(listener: TcpListener, context: ListenerContext) {
    let ListenerContext {
        listener_id,
        runtime,
        limits,
        handshake_permits,
        shutdown,
    } = context;
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut connections = tokio::task::JoinSet::new();
    let upgrade_tasks = TaskTracker::new();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "connection task failed");
                }
                continue;
            }
            result = listener.accept() => result,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "connection limit reached");
            continue;
        };
        let snapshot = runtime.load();
        let tls_acceptor = snapshot.tls_acceptors.get(&listener_id).cloned();
        let handshake_timeout_secs = snapshot.config.tls.handshake_timeout_secs;
        let listener_protocol = snapshot
            .config
            .listeners
            .iter()
            .find(|listener| listener.id == listener_id)
            .map_or("unknown", |listener| listener.protocol.as_str());
        let connection_metric = runtime
            .telemetry()
            .connection_started(&listener_id, listener_protocol);
        drop(snapshot);
        let handshake_permit = if tls_acceptor.is_some() {
            let Ok(permit) = handshake_permits.clone().try_acquire_owned() else {
                runtime.telemetry().tls_handshake(&listener_id, "capacity");
                tracing::debug!(%peer, "TLS handshake limit reached");
                continue;
            };
            Some(permit)
        } else {
            None
        };
        let runtime = runtime.clone();
        let shutdown = shutdown.clone();
        let limits = limits.clone();
        let listener_id = listener_id.clone();
        let tls_acceptor = tls_acceptor.clone();
        let upgrade_tasks = upgrade_tasks.clone();
        let telemetry = runtime.telemetry();
        connections.spawn(async move {
            let _permit = permit;
            let _connection_metric = connection_metric;
            let connection = ConnectionContext {
                peer,
                listener_id,
                runtime,
                limits,
                shutdown,
                upgrade_tasks,
                tls_server_name: None,
            };
            let result = match tls_acceptor {
                Some(acceptor) => {
                    let accepted = tokio::time::timeout(
                        Duration::from_secs(handshake_timeout_secs),
                        acceptor.accept(stream),
                    )
                    .await;
                    drop(handshake_permit);
                    match accepted {
                        Ok(Ok(stream)) => {
                            telemetry.tls_handshake(&connection.listener_id, "success");
                            serve_tls_connection(stream, connection).await
                        }
                        Ok(Err(error)) => {
                            telemetry.tls_handshake(&connection.listener_id, "handshake_error");
                            Err(Box::new(error) as BoxError)
                        }
                        Err(_) => {
                            telemetry.tls_handshake(&connection.listener_id, "timeout");
                            Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "TLS handshake timed out",
                            )) as BoxError)
                        }
                    }
                }
                None => {
                    drop(handshake_permit);
                    serve_http1_connection(stream, connection)
                        .await
                        .map_err(|error| Box::new(error) as BoxError)
                }
            };
            if let Err(error) = result {
                tracing::debug!(%peer, %error, "connection ended");
            }
        });
    }
    drop(listener);
    upgrade_tasks.close();
    let drain_deadline =
        std::time::Duration::from_secs(runtime.load().config.runtime.shutdown_grace_secs);
    if tokio::time::timeout(drain_deadline, async {
        while connections.join_next().await.is_some() {}
        upgrade_tasks.wait().await;
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

#[derive(Clone, Debug)]
struct ConnectionContext {
    peer: SocketAddr,
    listener_id: String,
    runtime: RuntimeHandle,
    limits: LimitsConfig,
    shutdown: CancellationToken,
    upgrade_tasks: TaskTracker,
    tls_server_name: Option<String>,
}

async fn serve_tls_connection(
    stream: aegisproxy_tls::TlsStream<TcpStream>,
    mut context: ConnectionContext,
) -> Result<(), BoxError> {
    let protocol = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    context.tls_server_name = stream.get_ref().1.server_name().map(str::to_owned);
    if protocol.as_deref() == Some(b"h2") {
        serve_http2_connection(stream, context)
            .await
            .map_err(|error| Box::new(error) as BoxError)
    } else {
        serve_http1_connection(stream, context)
            .await
            .map_err(|error| Box::new(error) as BoxError)
    }
}

async fn serve_http1_connection<I>(
    stream: I,
    context: ConnectionContext,
) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let max_header_bytes = context.limits.max_header_bytes;
    let service = ProxyService {
        runtime: context.runtime,
        peer: context.peer,
        listener_id: context.listener_id,
        limits: context.limits,
        shutdown: context.shutdown.clone(),
        upgrade_tasks: context.upgrade_tasks,
        tls_server_name: context.tls_server_name,
    };
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(
            service.limits.request_header_timeout_secs,
        ))
        .max_buf_size(max_header_bytes)
        .keep_alive(true);
    let connection = http.serve_connection(io, service).with_upgrades();
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result,
        _ = context.shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    }
}

async fn serve_http2_connection<I>(
    stream: I,
    context: ConnectionContext,
) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let service = ProxyService {
        runtime: context.runtime,
        peer: context.peer,
        listener_id: context.listener_id,
        limits: context.limits,
        shutdown: context.shutdown.clone(),
        upgrade_tasks: context.upgrade_tasks,
        tls_server_name: context.tls_server_name,
    };
    let mut http = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    http.max_concurrent_streams(service.limits.max_http2_streams)
        .max_header_list_size(service.limits.max_header_bytes as u32);
    let connection = http.serve_connection(io, service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result,
        _ = context.shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    }
}

#[derive(Clone)]
struct ProxyService {
    runtime: RuntimeHandle,
    peer: SocketAddr,
    listener_id: String,
    limits: LimitsConfig,
    shutdown: CancellationToken,
    upgrade_tasks: TaskTracker,
    tls_server_name: Option<String>,
}

#[derive(Clone)]
struct PinnedProxyService {
    config: Arc<Config>,
    route_index: Arc<RouteIndex>,
    peer: SocketAddr,
    listener_id: String,
    limits: LimitsConfig,
    clients: UpstreamClients,
    pools: UpstreamPools,
    rate_limiters: RateLimiters,
    compression_limiters: CompressionLimiters,
    in_flight_limiters: InFlightLimiters,
    basic_auth: BasicAuthPolicies,
    shutdown: CancellationToken,
    upgrade_tasks: TaskTracker,
    tls_server_name: Option<String>,
    http_challenges: HttpChallengeRegistry,
    telemetry: Arc<telemetry::Telemetry>,
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<ResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let parent = global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });
        let method = request.method().clone();
        let protocol = match request.version() {
            hyper::Version::HTTP_2 => "http2",
            _ => "http1",
        };
        let service = self.clone();
        let snapshot = service.runtime.load();
        let pinned = PinnedProxyService {
            config: Arc::clone(&snapshot.config),
            route_index: Arc::clone(&snapshot.route_index),
            peer: service.peer,
            listener_id: service.listener_id,
            limits: service.limits,
            clients: Arc::clone(&snapshot.upstream_clients),
            pools: Arc::clone(&snapshot.upstream_pools),
            rate_limiters: Arc::clone(&snapshot.rate_limiters),
            compression_limiters: Arc::clone(&snapshot.compression_limiters),
            in_flight_limiters: Arc::clone(&snapshot.in_flight_limiters),
            basic_auth: Arc::clone(&snapshot.basic_auth),
            shutdown: service.shutdown,
            upgrade_tasks: service.upgrade_tasks,
            tls_server_name: service.tls_server_name,
            http_challenges: service.runtime.http_challenges(),
            telemetry: service.runtime.telemetry(),
        };
        let span = tracing::info_span!(
            "proxy.request",
            event_name = "proxy.request",
            listener_id = %pinned.listener_id,
            route_id = tracing::field::Empty,
            request_id = tracing::field::Empty,
            method = %method,
            protocol,
        );
        if parent.span().span_context().is_valid()
            && let Err(error) = span.set_parent(parent)
        {
            tracing::debug!(event_name = "trace.parent_rejected", %error);
        }
        Box::pin(async move { Ok(pinned.forward(request).instrument(span).await) })
    }
}

impl PinnedProxyService {
    async fn forward(&self, request: Request<Incoming>) -> Response<ResponseBody> {
        let protocol = match request.version() {
            hyper::Version::HTTP_2 => "http2",
            _ => "http1",
        };
        let mut access = middleware::access::AccessEvent::new(
            request.method().clone(),
            self.listener_id.clone(),
            protocol,
            Arc::clone(&self.telemetry),
            self.config.observability.access_log,
            self.config.observability.access_log_sample_per_million,
        );
        let mut permit = None;
        let response = self.forward_inner(request, &mut permit, &mut access).await;
        let response = match permit {
            Some(permit) => response.map(|body| middleware::limit::hold(body, permit)),
            None => response,
        };
        access.hold(response)
    }

    async fn forward_inner(
        &self,
        mut request: Request<Incoming>,
        request_permit: &mut Option<middleware::limit::InFlightPermit>,
        access: &mut middleware::access::AccessEvent,
    ) -> Response<ResponseBody> {
        if let Some(status) = reject_unsafe_request_target(&request) {
            return error_response(status, "request target is not supported\n");
        }
        match canonicalize_request_path(&mut request, self.limits.max_request_target) {
            Ok(()) => {}
            Err(PathError::TooLong) => {
                return error_response(StatusCode::URI_TOO_LONG, "request target is too long\n");
            }
            Err(PathError::Invalid) => {
                return error_response(StatusCode::BAD_REQUEST, "request path is not canonical\n");
            }
        }
        let host = match request_host(&request) {
            Ok(host) => host,
            Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid authority\n"),
        };
        let Some(listener) = self
            .config
            .listeners
            .iter()
            .find(|listener| listener.id == self.listener_id)
        else {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "listener unavailable\n");
        };
        let scheme = if listener.protocol == "https" {
            "https"
        } else {
            "http"
        };
        let mut identity = match normalize_forwarding_headers(
            request.headers_mut(),
            self.peer.ip(),
            &self.config.trusted_proxies,
            scheme,
            &host,
            listener.bind.port(),
        ) {
            Ok(identity) => identity,
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid forwarding headers\n");
            }
        };
        access.set_request_id(&identity.request_id);
        if self.tls_server_name.as_deref().is_some_and(|server_name| {
            match canonical_host(server_name) {
                Ok(server_name) => host != server_name,
                Err(()) => true,
            }
        }) {
            return error_response(
                StatusCode::MISDIRECTED_REQUEST,
                "authority does not match TLS server name\n",
            );
        }
        if request.headers().len() > self.limits.max_headers
            || request
                .headers()
                .iter()
                .map(|(name, value)| name.as_str().len() + value.len())
                .sum::<usize>()
                > self.limits.max_header_bytes
        {
            return error_response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "request headers too large\n",
            );
        }
        if request
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > self.limits.max_request_body)
        {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n");
        }
        match http_challenge_response(&self.http_challenges, &self.listener_id, &request) {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(HttpChallengeError::Unavailable) => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ACME challenge service unavailable\n",
                );
            }
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid ACME challenge\n");
            }
        }
        let websocket = is_websocket_upgrade(&request);
        let preserve_te_trailers = request.version() == hyper::Version::HTTP_2
            && request
                .headers()
                .get(hyper::header::TE)
                .is_some_and(|value| value.as_bytes() == b"trailers");
        if request.headers().contains_key(UPGRADE) && !websocket {
            return error_response(StatusCode::BAD_REQUEST, "invalid upgrade request\n");
        }
        let mut client_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
        let grpc = request
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .is_some_and(|value| is_grpc_content_type(value.as_bytes()));
        let Some(route) = self
            .route_index
            .select(&self.config, &request, &self.listener_id)
        else {
            return error_response(StatusCode::NOT_FOUND, "no matching route\n");
        };
        access.set_route(&route.id);
        if !middleware::ip::allowed(&self.config, route, identity.ip) {
            return error_response(StatusCode::FORBIDDEN, "request denied\n");
        }
        match middleware::limit::acquire(&self.in_flight_limiters, &self.config, route, identity.ip)
        {
            InFlightOutcome::NotConfigured => {}
            InFlightOutcome::Acquired(permit) => *request_permit = Some(permit),
            InFlightOutcome::Limited(status) => {
                let mut response = error_response(status, "request capacity exhausted\n");
                if status == StatusCode::TOO_MANY_REQUESTS {
                    response
                        .headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
                }
                return response;
            }
            InFlightOutcome::Unavailable => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "request limit unavailable\n",
                );
            }
        }
        let edge_limiter = middleware::rate::configured_id(
            &self.config,
            route,
            aegisproxy_config::RateLimitKey::ClientIp,
        );
        match middleware::rate::check(&self.rate_limiters, &self.config, route, identity.ip) {
            Ok(RateOutcome::Allowed) => {
                if let Some(id) = edge_limiter {
                    self.telemetry.rate_decision(id, "allowed");
                }
            }
            Ok(RateOutcome::Limited { retry_after_secs }) => {
                if let Some(id) = edge_limiter {
                    self.telemetry.rate_decision(id, "limited");
                }
                let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "rate limited\n");
                let Ok(retry_after) = HeaderValue::from_str(&retry_after_secs.to_string()) else {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "rate limit response failed\n",
                    );
                };
                response.headers_mut().insert(RETRY_AFTER, retry_after);
                return response;
            }
            Err(()) => {
                if let Some(id) = edge_limiter {
                    self.telemetry.rate_decision(id, "unavailable");
                }
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "rate limit unavailable\n");
            }
        }
        match middleware::redirect::response(&self.config, route, request.uri().query()) {
            Ok(Some(mut response)) => {
                if middleware::headers::apply(&self.config, route, scheme, &mut response).is_err() {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "middleware response failed\n",
                    );
                }
                return response;
            }
            Ok(None) => {}
            Err(()) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "redirect response failed\n",
                );
            }
        }
        match middleware::maintenance::response(&self.config, route, false) {
            Ok(Some(mut response)) => {
                if middleware::headers::apply_response_mutations(&self.config, route, &mut response)
                    .is_err()
                    || middleware::headers::apply(&self.config, route, scheme, &mut response)
                        .is_err()
                {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "middleware response failed\n",
                    );
                }
                return response;
            }
            Ok(None) => {}
            Err(()) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "maintenance response failed\n",
                );
            }
        }
        match middleware::cors::preflight(&self.config, route, &request) {
            Ok(Some(mut response)) => {
                if middleware::headers::apply(&self.config, route, scheme, &mut response).is_err() {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "middleware response failed\n",
                    );
                }
                return response;
            }
            Ok(None) => {}
            Err(()) => return error_response(StatusCode::FORBIDDEN, "CORS request denied\n"),
        }
        match middleware::auth::authenticate(
            &self.basic_auth,
            &self.config,
            route,
            request.headers(),
        )
        .await
        {
            AuthOutcome::NotConfigured => {}
            AuthOutcome::Authenticated(principal) => {
                request.headers_mut().remove(AUTHORIZATION);
                identity.principal = Some(principal);
            }
            AuthOutcome::Unauthorized(realm) => {
                let mut response =
                    error_response(StatusCode::UNAUTHORIZED, "authentication required\n");
                let Ok(challenge) =
                    HeaderValue::from_str(&format!("Basic realm=\"{realm}\", charset=\"UTF-8\""))
                else {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "authentication response failed\n",
                    );
                };
                response.headers_mut().insert(WWW_AUTHENTICATE, challenge);
                return response;
            }
            AuthOutcome::Unavailable => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication unavailable\n",
                );
            }
        }
        match middleware::auth::forward_authenticate(
            &self.clients,
            &self.pools,
            &self.config,
            route,
            &mut request,
            &identity,
            scheme,
            &host,
            listener.bind.port(),
        )
        .await
        {
            ForwardOutcome::NotConfigured => {}
            ForwardOutcome::Authenticated { principal, headers } => {
                for name in headers.keys() {
                    request.headers_mut().remove(name);
                    for value in headers.get_all(name) {
                        request.headers_mut().append(name.clone(), value.clone());
                    }
                }
                identity.principal = Some(principal);
            }
            ForwardOutcome::Denied { status, headers } => {
                let mut response = error_response(status, "authentication required\n");
                for name in headers.keys() {
                    response.headers_mut().remove(name);
                    for value in headers.get_all(name) {
                        response.headers_mut().append(name.clone(), value.clone());
                    }
                }
                return response;
            }
            ForwardOutcome::Unavailable => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication unavailable\n",
                );
            }
        }
        let principal_limiter = middleware::rate::configured_id(
            &self.config,
            route,
            aegisproxy_config::RateLimitKey::Principal,
        );
        match middleware::rate::check_principal(
            &self.rate_limiters,
            &self.config,
            route,
            identity.principal.as_deref(),
        ) {
            Ok(RateOutcome::Allowed) => {
                if let Some(id) = principal_limiter {
                    self.telemetry.rate_decision(id, "allowed");
                }
            }
            Ok(RateOutcome::Limited { retry_after_secs }) => {
                if let Some(id) = principal_limiter {
                    self.telemetry.rate_decision(id, "limited");
                }
                let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "rate limited\n");
                let Ok(retry_after) = HeaderValue::from_str(&retry_after_secs.to_string()) else {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "rate limit response failed\n",
                    );
                };
                response.headers_mut().insert(RETRY_AFTER, retry_after);
                return response;
            }
            Err(()) => {
                if let Some(id) = principal_limiter {
                    self.telemetry.rate_decision(id, "unavailable");
                }
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "rate limit unavailable\n");
            }
        }
        match middleware::maintenance::response(&self.config, route, true) {
            Ok(Some(mut response)) => {
                if middleware::headers::apply_response_mutations(&self.config, route, &mut response)
                    .is_err()
                    || middleware::headers::apply(&self.config, route, scheme, &mut response)
                        .is_err()
                {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "middleware response failed\n",
                    );
                }
                return response;
            }
            Ok(None) => {}
            Err(()) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "maintenance response failed\n",
                );
            }
        }
        request.extensions_mut().insert(identity.clone());
        if middleware::rewrite::apply(
            &self.config,
            route,
            &mut request,
            self.limits.max_request_target,
        )
        .is_err()
        {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request rewrite failed\n",
            );
        }
        if middleware::headers::apply_request_mutations(&self.config, route, &mut request).is_err()
        {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request header mutation failed\n",
            );
        }
        let Some(group_id) = route.upstream_group.as_deref() else {
            return error_response(StatusCode::BAD_GATEWAY, "route has no upstream\n");
        };
        let Some(pool) = self.pools.get(group_id) else {
            return error_response(StatusCode::BAD_GATEWAY, "upstream group missing\n");
        };
        let retry = pool.retry_policy();
        let (mut parts, body) = request.into_parts();
        let request_path = parts.uri.path().to_owned();
        let request_query = parts.uri.query().map(str::to_owned);
        strip_hop_by_hop_headers(&mut parts.headers, websocket, preserve_te_trailers);
        if rebuild_proxy_headers(
            &mut parts.headers,
            &identity,
            scheme,
            &host,
            listener.bind.port(),
        )
        .is_err()
        {
            return error_response(StatusCode::BAD_REQUEST, "invalid forwarding headers\n");
        }
        let retryable_method = is_idempotent_retry_method(&parts.method);
        let body_size = hyper::body::Body::size_hint(&body).exact();
        let may_retry = retry.max_attempts > 1
            && retryable_method
            && !websocket
            && !grpc
            && body_size.is_some_and(|size| size <= retry.replay_body_bytes as u64);
        let max_attempts = if may_retry { retry.max_attempts } else { 1 };
        let (replay_body, mut streaming_body) = if may_retry {
            let collected = match Limited::new(body, self.limits.max_request_body)
                .collect()
                .await
            {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body failed\n");
                }
            };
            (Some(collected), None)
        } else {
            (
                None,
                Some(Limited::new(body, self.limits.max_request_body).boxed()),
            )
        };
        let method = parts.method;
        let headers = parts.headers;
        let finalize_response = |response: &mut Response<ResponseBody>| -> Result<(), ()> {
            middleware::custom_error::apply(&self.config, route, response)?;
            middleware::headers::apply_response_mutations(&self.config, route, response)?;
            middleware::headers::apply(&self.config, route, scheme, response)?;
            middleware::cors::apply(&self.config, route, &headers, response)?;
            middleware::compression::apply(
                &self.compression_limiters,
                &self.config,
                route,
                middleware::compression::RequestContext {
                    method: &method,
                    headers: &headers,
                    authenticated: identity.principal.is_some(),
                    grpc,
                    websocket,
                },
                response,
            )
        };
        let proxy_error = |status, message| {
            let mut response = error_response(status, message);
            if finalize_response(&mut response).is_err() {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "response middleware failed\n",
                );
            }
            response
        };
        let total_timeout = if max_attempts > 1 {
            retry.total_timeout_secs
        } else {
            self.limits.response_header_timeout_secs
        };
        let retry_deadline = tokio::time::Instant::now() + Duration::from_secs(total_timeout);
        for attempt in 1..=max_attempts {
            let Ok(selected) = pool.select() else {
                return proxy_error(StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable\n");
            };
            let endpoint = selected.config();
            if attempt > 1 {
                self.telemetry.upstream_retry(group_id, &endpoint.id);
            }
            let attempt_started = tokio::time::Instant::now();
            let key = endpoint_key(group_id, &endpoint.id);
            let Some(client) = self.clients.get(&key) else {
                return proxy_error(StatusCode::BAD_GATEWAY, "upstream client missing\n");
            };
            let Some(uri) = upstream_uri(endpoint, &request_path, request_query.as_deref()) else {
                return proxy_error(StatusCode::BAD_GATEWAY, "invalid upstream URI\n");
            };
            let mut request_headers = headers.clone();
            request_headers.remove("traceparent");
            request_headers.remove("tracestate");
            global::get_text_map_propagator(|propagator| {
                propagator.inject_context(
                    &tracing::Span::current().context(),
                    &mut HeaderInjector(&mut request_headers),
                );
            });
            if let Some(authority) = endpoint_authority(endpoint) {
                request_headers.insert(HOST, authority);
            }
            let request_body = match &replay_body {
                Some(body) => full_body(body),
                None => match streaming_body.take() {
                    Some(body) => body,
                    None => {
                        return proxy_error(
                            StatusCode::BAD_GATEWAY,
                            "request body is unavailable\n",
                        );
                    }
                },
            };
            let mut upstream_request = match Request::builder()
                .method(method.clone())
                .uri(uri)
                .version(hyper::Version::HTTP_11)
                .body(request_body)
            {
                Ok(request) => request,
                Err(_) => {
                    return proxy_error(StatusCode::BAD_GATEWAY, "invalid upstream request\n");
                }
            };
            *upstream_request.headers_mut() = request_headers;
            let remaining = retry_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return proxy_error(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream retry budget exhausted\n",
                );
            }
            let attempt_timeout =
                Duration::from_secs(self.limits.response_header_timeout_secs).min(remaining);
            let result =
                match tokio::time::timeout(attempt_timeout, client.request(upstream_request)).await
                {
                    Ok(result) => result,
                    Err(_) => {
                        selected.record_failure();
                        self.telemetry.upstream_attempt(
                            group_id,
                            &endpoint.id,
                            "timeout",
                            attempt_started.elapsed(),
                        );
                        if attempt < max_attempts {
                            continue;
                        }
                        return proxy_error(
                            StatusCode::GATEWAY_TIMEOUT,
                            "upstream response timed out\n",
                        );
                    }
                };
            match result {
                Ok(response) => {
                    self.telemetry.upstream_attempt(
                        group_id,
                        &endpoint.id,
                        if response.status().is_server_error() {
                            "server_error"
                        } else {
                            "success"
                        },
                        attempt_started.elapsed(),
                    );
                    let mut response = response
                        .map(|body| body.map_err(|error| Box::new(error) as BoxError).boxed());
                    let body_guard = if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                        let Some(client_upgrade) = client_upgrade.take() else {
                            selected.record_failure();
                            return proxy_error(
                                StatusCode::BAD_GATEWAY,
                                "unexpected upstream upgrade\n",
                            );
                        };
                        selected.record_success();
                        let upstream_upgrade = hyper::upgrade::on(&mut response);
                        let shutdown = self.shutdown.clone();
                        let request_permit = request_permit.take();
                        self.upgrade_tasks.spawn(async move {
                            let _request_permit = request_permit;
                            let _selected = selected;
                            let Ok((client, upstream)) =
                                tokio::try_join!(client_upgrade, upstream_upgrade)
                            else {
                                return;
                            };
                            let mut client = TokioIo::new(client);
                            let mut upstream = TokioIo::new(upstream);
                            tokio::select! {
                                _ = shutdown.cancelled() => {}
                                _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                            }
                        });
                        strip_hop_by_hop_headers(response.headers_mut(), true, false);
                        None
                    } else {
                        if response.status().is_server_error() {
                            selected.record_failure();
                        } else {
                            selected.record_success();
                        }
                        strip_hop_by_hop_headers(response.headers_mut(), false, false);
                        Some(selected)
                    };
                    if finalize_response(&mut response).is_err() {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "response middleware failed\n",
                        );
                    }
                    return response.map(|body| match body_guard {
                        Some(endpoint) => GuardedBody::new(body, endpoint).boxed(),
                        None => body,
                    });
                }
                Err(error) => {
                    self.telemetry.upstream_attempt(
                        group_id,
                        &endpoint.id,
                        if error.is_connect() {
                            "connect_error"
                        } else {
                            "protocol_error"
                        },
                        attempt_started.elapsed(),
                    );
                    if error.is_connect() {
                        selected.record_failure();
                        if attempt < max_attempts {
                            continue;
                        }
                    }
                    tracing::debug!(peer = %self.peer, %error, "upstream request failed");
                    return proxy_error(StatusCode::BAD_GATEWAY, "upstream request failed\n");
                }
            }
        }
        proxy_error(StatusCode::BAD_GATEWAY, "upstream attempts exhausted\n")
    }
}

fn is_idempotent_retry_method(method: &hyper::Method) -> bool {
    matches!(
        *method,
        hyper::Method::GET
            | hyper::Method::HEAD
            | hyper::Method::OPTIONS
            | hyper::Method::PUT
            | hyper::Method::DELETE
    )
}

fn is_grpc_content_type(value: &[u8]) -> bool {
    value
        .get(..b"application/grpc".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"application/grpc"))
}

fn upstream_uri(endpoint: &EndpointConfig, request_path: &str, query: Option<&str>) -> Option<Uri> {
    let mut uri = endpoint.url.clone();
    let base_path = endpoint.url.path().trim_end_matches('/');
    let joined_path = if base_path.is_empty() {
        request_path.to_owned()
    } else if request_path == "/" {
        format!("{base_path}/")
    } else {
        format!("{base_path}/{}", request_path.trim_start_matches('/'))
    };
    uri.set_path(&joined_path);
    uri.set_query(query);
    uri.as_str().parse().ok()
}

fn reject_unsafe_request_target<B>(request: &Request<B>) -> Option<StatusCode> {
    let http2 = request.version() == hyper::Version::HTTP_2;
    if request.method() == hyper::Method::CONNECT {
        return Some(StatusCode::BAD_REQUEST);
    }
    if (!http2 && (request.uri().scheme().is_some() || request.uri().authority().is_some()))
        || (http2
            && (request.uri().scheme_str() != Some("https") || request.uri().authority().is_none()))
        || request_host(request).is_err()
    {
        return Some(StatusCode::BAD_REQUEST);
    }
    if http2
        && ["connection", "keep-alive", "proxy-connection", "upgrade"]
            .iter()
            .any(|name| request.headers().contains_key(*name))
    {
        return Some(StatusCode::BAD_REQUEST);
    }
    let invalid_http2_te = http2
        && (request.headers().get_all(hyper::header::TE).iter().count() > 1
            || request
                .headers()
                .get(hyper::header::TE)
                .is_some_and(|value| value.as_bytes() != b"trailers"));
    let content_lengths: Vec<&[u8]> = request
        .headers()
        .get_all(hyper::header::CONTENT_LENGTH)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let transfer_encodings: Vec<&str> = request
        .headers()
        .get_all(hyper::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    if invalid_http2_te
        || (http2 && !transfer_encodings.is_empty())
        || (!content_lengths.is_empty() && !transfer_encodings.is_empty())
        || content_lengths.len() > 1
        || transfer_encodings.len() > 1
        || transfer_encodings
            .first()
            .is_some_and(|value| !value.eq_ignore_ascii_case("chunked"))
    {
        return Some(StatusCode::BAD_REQUEST);
    }
    None
}

fn is_websocket_upgrade<B>(request: &Request<B>) -> bool {
    request.method() == hyper::Method::GET
        && request
            .headers()
            .get(UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && request
            .headers()
            .get_all(CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

fn strip_hop_by_hop_headers(
    headers: &mut hyper::HeaderMap,
    preserve_upgrade: bool,
    preserve_te_trailers: bool,
) {
    let connection_tokens: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    for token in connection_tokens {
        if !preserve_upgrade || token != "upgrade" {
            headers.remove(token);
        }
    }
    for name in [
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "trailer",
        "te",
    ] {
        headers.remove(name);
    }
    if preserve_upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
    if preserve_te_trailers {
        headers.insert(hyper::header::TE, HeaderValue::from_static("trailers"));
    }
}

/// Create a bounded error response.
pub fn error_response(status: StatusCode, message: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(full_body(message.as_bytes()))
        .unwrap_or_else(|_| Response::new(full_body(b"proxy error\n")))
}

fn http_challenge_response<B>(
    registry: &HttpChallengeRegistry,
    listener_id: &str,
    request: &Request<B>,
) -> Result<Option<Response<ResponseBody>>, HttpChallengeError> {
    let Ok(identifier) = request_host(request) else {
        return Ok(None);
    };
    let Some(body) =
        registry.response_for_request(listener_id, &identifier, request.uri().path())?
    else {
        return Ok(None);
    };
    if request.method() != hyper::Method::GET {
        return Ok(Some(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "ACME challenge requires GET\n",
        )));
    }
    let mut response = Response::new(full_body(body.as_ref()));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(Some(response))
}

fn full_body(bytes: &[u8]) -> ResponseBody {
    Full::new(bytes::Bytes::copy_from_slice(bytes))
        .map_err(|never: Infallible| match never {})
        .boxed()
}

#[cfg(test)]
mod tests;
