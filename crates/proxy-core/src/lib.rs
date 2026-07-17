#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Data-plane HTTP forwarding primitives.

mod acme_manager;
mod middleware;
mod route;
mod runtime;
mod tcp;
mod upstream;

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
    header::{CONNECTION, HOST, HeaderValue, UPGRADE},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
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

use upstream::{
    DnsEndpoint, GuardedBody, PolicyResolver, UpstreamPool, prepare_dns, start_dns_refreshes,
};

use middleware::normalize::{normalize_forwarding_headers, rebuild_forwarding_headers};

pub use route::RouteIndex;
use route::{PathError, canonical_host, canonicalize_request_path, request_host};
use runtime::RuntimeSnapshot;
pub use runtime::{ActivationCoordinator, ActivationError, ActivationResult, RuntimeHandle};
use tcp::{TcpListenerContext, accept_loop as tcp_accept_loop};

/// Boxed body error.
pub type BoxError = Box<dyn Error + Send + Sync>;
/// Boxed response body used by the server and upstream client.
pub type ResponseBody = BoxBody<bytes::Bytes, BoxError>;
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
    let config = tokio::task::spawn_blocking({
        let config_path = config_path.clone();
        move || aegisproxy_config::load_file(config_path)
    })
    .await
    .map_err(|error| ProxyError::Preparation(error.to_string()))??;
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
    serve_managed(config_path, revisions, snapshot, listeners, shutdown).await
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
    tracing::warn!(revision = %active.active.id, "explicit last-known-good recovery selected");
    let (snapshot, listeners) = prepare_bound(config, active.active.id, &shutdown).await?;
    serve_managed(config_path, revisions, snapshot, listeners, shutdown).await
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

async fn serve_managed(
    config_path: PathBuf,
    revisions: Arc<RevisionStore>,
    snapshot: Arc<RuntimeSnapshot>,
    listeners: Vec<(ListenerConfig, TcpListener)>,
    shutdown: CancellationToken,
) -> Result<(), ProxyError> {
    let runtime = RuntimeHandle::new(Arc::clone(&snapshot));
    let coordinator = Arc::new(ActivationCoordinator::new(
        Arc::clone(&revisions),
        runtime.clone(),
        shutdown.clone(),
    ));
    let watcher = tokio::spawn(watch_config_file(
        config_path,
        revisions,
        Arc::clone(&coordinator),
        runtime.clone(),
        shutdown.clone(),
    ));
    let result = serve_bound(runtime, snapshot, listeners, shutdown).await;
    if let Err(error) = watcher.await {
        tracing::error!(%error, "configuration watcher task failed");
    }
    result
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
    runtime: RuntimeHandle,
    shutdown: CancellationToken,
) {
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    let mut last_hash = None;
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
        last_error = None;
        if last_hash == Some(hash) {
            continue;
        }
        last_hash = Some(hash);
        let config = match parsed {
            Ok(config) => config,
            Err(error) => {
                tracing::error!(%error, "changed configuration rejected");
                continue;
            }
        };
        let candidate = tokio::task::spawn_blocking({
            let revisions = Arc::clone(&revisions);
            move || revisions.create_candidate(&config, "file")
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
        drop(snapshot);
        let handshake_permit = if tls_acceptor.is_some() {
            let Ok(permit) = handshake_permits.clone().try_acquire_owned() else {
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
        connections.spawn(async move {
            let _permit = permit;
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
                        Ok(Ok(stream)) => serve_tls_connection(stream, connection).await,
                        Ok(Err(error)) => Err(Box::new(error) as BoxError),
                        Err(_) => Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "TLS handshake timed out",
                        )) as BoxError),
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
    shutdown: CancellationToken,
    upgrade_tasks: TaskTracker,
    tls_server_name: Option<String>,
    http_challenges: HttpChallengeRegistry,
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<ResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
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
            shutdown: service.shutdown,
            upgrade_tasks: service.upgrade_tasks,
            tls_server_name: service.tls_server_name,
            http_challenges: service.runtime.http_challenges(),
        };
        Box::pin(async move { Ok(pinned.forward(request).await) })
    }
}

impl PinnedProxyService {
    async fn forward(&self, mut request: Request<Incoming>) -> Response<ResponseBody> {
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
        let identity = match normalize_forwarding_headers(
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
        request.extensions_mut().insert(identity);
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
        let Some(group_id) = route.upstream_group.as_deref() else {
            return error_response(StatusCode::BAD_GATEWAY, "route has no upstream\n");
        };
        let Some(pool) = self.pools.get(group_id) else {
            return error_response(StatusCode::BAD_GATEWAY, "upstream group missing\n");
        };
        let retry = pool.retry_policy();
        if request
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > self.limits.max_request_body)
        {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n");
        }
        let (mut parts, body) = request.into_parts();
        let request_path = parts.uri.path().to_owned();
        let request_query = parts.uri.query().map(str::to_owned);
        strip_hop_by_hop_headers(&mut parts.headers, websocket, preserve_te_trailers);
        if rebuild_forwarding_headers(
            &mut parts.headers,
            identity.ip,
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
        let total_timeout = if max_attempts > 1 {
            retry.total_timeout_secs
        } else {
            self.limits.response_header_timeout_secs
        };
        let retry_deadline = tokio::time::Instant::now() + Duration::from_secs(total_timeout);
        for attempt in 1..=max_attempts {
            let Ok(selected) = pool.select() else {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable\n");
            };
            let endpoint = selected.config();
            let key = endpoint_key(group_id, &endpoint.id);
            let Some(client) = self.clients.get(&key) else {
                return error_response(StatusCode::BAD_GATEWAY, "upstream client missing\n");
            };
            let Some(uri) = upstream_uri(endpoint, &request_path, request_query.as_deref()) else {
                return error_response(StatusCode::BAD_GATEWAY, "invalid upstream URI\n");
            };
            let mut request_headers = headers.clone();
            if let Some(authority) = endpoint_authority(endpoint) {
                request_headers.insert(HOST, authority);
            }
            let request_body = match &replay_body {
                Some(body) => full_body(body),
                None => match streaming_body.take() {
                    Some(body) => body,
                    None => {
                        return error_response(
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
                    return error_response(StatusCode::BAD_GATEWAY, "invalid upstream request\n");
                }
            };
            *upstream_request.headers_mut() = request_headers;
            let remaining = retry_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return error_response(
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
                        if attempt < max_attempts {
                            continue;
                        }
                        return error_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            "upstream response timed out\n",
                        );
                    }
                };
            match result {
                Ok(mut response) => {
                    let body_guard = if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                        let Some(client_upgrade) = client_upgrade.take() else {
                            selected.record_failure();
                            return error_response(
                                StatusCode::BAD_GATEWAY,
                                "unexpected upstream upgrade\n",
                            );
                        };
                        selected.record_success();
                        let upstream_upgrade = hyper::upgrade::on(&mut response);
                        let shutdown = self.shutdown.clone();
                        self.upgrade_tasks.spawn(async move {
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
                    return response.map(|body| {
                        let body = body.map_err(|error| Box::new(error) as BoxError);
                        match body_guard {
                            Some(endpoint) => GuardedBody::new(body, endpoint).boxed(),
                            None => body.boxed(),
                        }
                    });
                }
                Err(error) => {
                    if error.is_connect() {
                        selected.record_failure();
                        if attempt < max_attempts {
                            continue;
                        }
                    }
                    tracing::debug!(peer = %self.peer, %error, "upstream request failed");
                    return error_response(StatusCode::BAD_GATEWAY, "upstream request failed\n");
                }
            }
        }
        error_response(StatusCode::BAD_GATEWAY, "upstream attempts exhausted\n")
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
mod tests {
    use super::*;
    use aegisproxy_config::{
        AdminConfig, BalancingAlgorithm, CertificateConfig, Config, EndpointConfig, LimitsConfig,
        ListenerConfig, RouteConfig, RuntimeConfig, TrustedProxyConfig, UpstreamGroupConfig,
    };
    use http_body_util::Empty;
    use std::collections::BTreeMap;

    fn request(method: &str, host: &str, path: &str) -> Request<Empty<bytes::Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, host)
            .body(Empty::<bytes::Bytes>::new())
            .expect("test request is valid")
    }

    #[test]
    fn recognizes_grpc_content_types_without_case_bypass() {
        assert!(is_grpc_content_type(b"application/grpc"));
        assert!(is_grpc_content_type(b"Application/Grpc+Proto"));
        assert!(!is_grpc_content_type(b"application/json"));
    }

    #[tokio::test]
    async fn serves_only_active_http01_host_listener_and_token() {
        let registry = HttpChallengeRegistry::default();
        let _lease = registry
            .install(
                "public",
                "example.test",
                "token_123",
                b"token_123.thumbprint",
                Duration::from_secs(60),
            )
            .expect("install challenge");
        let challenge = request(
            "GET",
            "example.test",
            "/.well-known/acme-challenge/token_123",
        );
        let response = http_challenge_response(&registry, "public", &challenge)
            .expect("challenge lookup")
            .expect("active response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("response body")
                .to_bytes(),
            &b"token_123.thumbprint"[..]
        );
        assert!(
            http_challenge_response(&registry, "other", &challenge)
                .expect("lookup")
                .is_none()
        );
        let wrong_host = request("GET", "other.test", "/.well-known/acme-challenge/token_123");
        assert!(
            http_challenge_response(&registry, "public", &wrong_host)
                .expect("lookup")
                .is_none()
        );
        let post = request(
            "POST",
            "example.test",
            "/.well-known/acme-challenge/token_123",
        );
        assert_eq!(
            http_challenge_response(&registry, "public", &post)
                .expect("lookup")
                .expect("method response")
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    fn select_route<'a, B>(
        config: &'a Config,
        request: &Request<B>,
        listener_id: &str,
    ) -> Option<&'a RouteConfig> {
        RouteIndex::compile(config).select(config, request, listener_id)
    }

    fn config(route: RouteConfig) -> Config {
        Config {
            schema_version: 1,
            runtime: RuntimeConfig::default(),
            limits: LimitsConfig::default(),
            listeners: vec![ListenerConfig {
                id: "public".into(),
                bind: "127.0.0.1:8080".parse().expect("address"),
                protocol: "http".into(),
                certificates: vec![],
            }],
            tls: aegisproxy_config::TlsConfig::default(),
            certificates: vec![],
            acme: aegisproxy_config::AcmeConfig::default(),
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![UpstreamGroupConfig {
                id: "app".into(),
                allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
                endpoints: vec![EndpointConfig {
                    id: "app-1".into(),
                    url: "http://127.0.0.1:9000".parse().expect("url"),
                    weight: 1,
                    server_name: None,
                    ca_bundle: None,
                }],
                ..UpstreamGroupConfig::default()
            }],
            middlewares: BTreeMap::new(),
            routes: vec![route],
            admin: AdminConfig::default(),
        }
    }

    async fn start_test_proxy(
        upstream_addr: SocketAddr,
        configure: impl FnOnce(&mut Config),
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<Result<(), ProxyError>>,
    ) {
        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve proxy port");
        let proxy_addr = reserved.local_addr().expect("proxy address");
        drop(reserved);
        let mut config = config(RouteConfig {
            id: "test".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        config.listeners[0].bind = proxy_addr;
        config.upstream_groups[0].endpoints[0].url = format!("http://{upstream_addr}")
            .parse()
            .expect("endpoint URL");
        configure(&mut config);
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(Arc::new(config), shutdown.clone()));
        tokio::task::yield_now().await;
        (proxy_addr, shutdown, task)
    }

    async fn start_tcp_test_proxy(
        upstream_addr: SocketAddr,
        tls_passthrough: bool,
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<Result<(), ProxyError>>,
    ) {
        start_test_proxy(upstream_addr, |config| {
            config.listeners[0].protocol = if tls_passthrough {
                "tls_passthrough".into()
            } else {
                "tcp".into()
            };
            config.upstream_groups[0].endpoints[0].url = format!("tcp://{upstream_addr}")
                .parse()
                .expect("TCP endpoint URL");
            config.routes[0].paths.clear();
            config.routes[0].path_prefixes.clear();
            config.routes[0].methods.clear();
            config.routes[0].headers.clear();
            config.routes[0].default = !tls_passthrough;
            if !tls_passthrough {
                config.routes[0].hosts.clear();
            }
        })
        .await
    }

    fn client_hello(server_name: &str) -> Vec<u8> {
        use rustls::{ClientConfig, ClientConnection, RootCertStore, crypto::aws_lc_rs};

        let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("TLS versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
            .expect("test server name");
        let mut connection =
            ClientConnection::new(Arc::new(config), name).expect("client connection");
        let mut output = Vec::new();
        connection.write_tls(&mut output).expect("ClientHello");
        output
    }

    async fn connect_to_proxy(address: SocketAddr) -> tokio::net::TcpStream {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match tokio::net::TcpStream::connect(address).await {
                Ok(stream) => return stream,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    drop(error);
                }
                Err(error) => panic!("proxy did not become ready: {error}"),
            }
        }
    }

    async fn wait_for_listener_close(address: SocketAddr) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match TcpStream::connect(address).await {
                Err(_) => return,
                Ok(stream) if tokio::time::Instant::now() < deadline => {
                    drop(stream);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(stream) => {
                    drop(stream);
                    panic!("listener remained open during drain");
                }
            }
        }
    }

    async fn proxy_get(address: SocketAddr) -> Vec<u8> {
        proxy_request(
            address,
            b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await
    }

    async fn proxy_request(address: SocketAddr, request: &[u8]) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut client = connect_to_proxy(address).await;
        client.write_all(request).await.expect("write request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        response
    }

    async fn identified_upstream(body: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let address = listener.local_addr().expect("upstream address");
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |_| async move {
                        Ok::<_, Infallible>(Response::new(Full::new(bytes::Bytes::from_static(
                            body,
                        ))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (address, task)
    }

    async fn identified_tcp_upstream(
        identity: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TCP upstream bind");
        let address = listener.local_addr().expect("TCP upstream address");
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut request = [0_u8; 1];
                    if stream.read_exact(&mut request).await.is_err() {
                        return;
                    }
                    if stream.write_all(identity).await.is_err() {
                        return;
                    }
                    let mut remainder = [0_u8; 32];
                    while stream
                        .read(&mut remainder)
                        .await
                        .is_ok_and(|count| count > 0)
                    {}
                });
            }
        });
        (address, task)
    }

    async fn https_h2_upstream_response(server_name: &str) -> Vec<u8> {
        use rustls::{ServerConfig, crypto::aws_lc_rs, pki_types::PrivateKeyDer};
        use std::{
            fs,
            sync::atomic::{AtomicU64, Ordering},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
        let generated = rcgen::generate_simple_self_signed(vec!["upstream.test".into()])
            .expect("generate upstream identity");
        let certificate_pem = generated.cert.pem();
        let private_key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .expect("TLS versions")
                .with_no_client_auth()
                .with_single_cert(vec![generated.cert.der().clone()], private_key)
                .expect("server identity");
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.expect("upstream accept");
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
                assert_eq!(request.version(), hyper::Version::HTTP_2);
                Ok::<_, Infallible>(Response::new(Full::new(bytes::Bytes::from_static(b"ok"))))
            });
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
                .expect("serve HTTP/2 upstream");
        });
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let ca_path = std::env::temp_dir().join(format!(
            "aegisproxy-upstream-ca-{}-{sequence}.pem",
            std::process::id()
        ));
        fs::write(&ca_path, certificate_pem).expect("write CA");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600)).expect("secure CA");
        }
        let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
            let endpoint = &mut config.upstream_groups[0].endpoints[0];
            endpoint.url = format!("https://{upstream_addr}")
                .parse()
                .expect("HTTPS endpoint");
            endpoint.server_name = Some(server_name.to_owned());
            endpoint.ca_bundle = Some(format!("file://{}", ca_path.display()));
        })
        .await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("client request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("client response");
        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy run");
        upstream_task.await.expect("upstream task");
        fs::remove_file(ca_path).expect("remove CA");
        response
    }

    #[tokio::test]
    async fn managed_file_reload_is_atomic_and_rejects_invalid_change() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::oneshot;

        let idle_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("idle upstream bind");
        let idle_upstream = idle_listener.local_addr().expect("idle upstream address");
        let (idle_closed_tx, idle_closed_rx) = oneshot::channel();
        let idle_task = tokio::spawn(async move {
            let (mut stream, _) = idle_listener.accept().await.expect("idle accept");
            let mut request = [0_u8; 4096];
            loop {
                let count = stream.read(&mut request).await.expect("idle request");
                if count == 0 {
                    break;
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nidle")
                    .await
                    .expect("idle response");
            }
            idle_closed_tx.send(()).expect("signal idle close");
        });
        let first_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("first upstream bind");
        let first_upstream = first_listener.local_addr().expect("first upstream address");
        let (release_tx, release_rx) = oneshot::channel();
        let first_task = tokio::spawn(async move {
            let mut release_rx = Some(release_rx);
            loop {
                let (mut stream, _) = first_listener.accept().await.expect("first accept");
                let release = release_rx.take();
                tokio::spawn(async move {
                    let mut request = [0_u8; 4096];
                    let _ = stream.read(&mut request).await.expect("first request");
                    if let Some(release) = release {
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\na",
                            )
                            .await
                            .expect("first response chunk");
                        release.await.expect("release old snapshot stream");
                        stream.write_all(b"b").await.expect("second response chunk");
                    } else {
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nfirst",
                            )
                            .await
                            .expect("ordinary first response");
                    }
                });
            }
        });
        let (second_upstream, second_task) = identified_upstream(b"second").await;
        let reserved = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve proxy port");
        let proxy_addr = reserved.local_addr().expect("proxy address");
        drop(reserved);
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-managed-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("test directory");
        let config_path = root.join("proxy.toml");
        let mut managed = config(RouteConfig {
            id: "managed".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        managed.listeners[0].bind = proxy_addr;
        managed.runtime.state_dir = root.join("state").to_string_lossy().into_owned();
        #[cfg(not(unix))]
        {
            managed.runtime.config_poll_secs = 1;
        }
        #[cfg(unix)]
        {
            managed.runtime.config_poll_secs = 60;
        }
        managed.upstream_groups[0].endpoints[0].id = "app-idle".into();
        managed.upstream_groups[0].endpoints[0].url = format!("http://{idle_upstream}")
            .parse()
            .expect("idle upstream");
        managed.upstream_groups[0].endpoints.push(EndpointConfig {
            id: "app-stream".into(),
            url: format!("http://{first_upstream}")
                .parse()
                .expect("stream upstream"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        });
        fs::write(
            &config_path,
            toml::to_string_pretty(&managed).expect("serialize first config"),
        )
        .expect("write first config");
        let shutdown = CancellationToken::new();
        let proxy_task = tokio::spawn(run_managed(config_path.clone(), shutdown.clone()));
        assert!(proxy_get(proxy_addr).await.ends_with(b"idle"));
        let mut in_flight = connect_to_proxy(proxy_addr).await;
        in_flight
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("in-flight request");
        let mut first_chunk = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !first_chunk.ends_with(b"a") {
                assert!(first_chunk.len() < 1024, "unexpected response header size");
                let count = in_flight
                    .read_buf(&mut first_chunk)
                    .await
                    .expect("old snapshot response");
                assert!(count > 0, "old snapshot response closed early");
            }
        })
        .await
        .expect("old snapshot response timed out");
        assert!(first_chunk.starts_with(b"HTTP/1.1 200 OK"));

        managed.upstream_groups[0].endpoints = vec![EndpointConfig {
            id: "app-new".into(),
            url: format!("http://{second_upstream}")
                .parse()
                .expect("second upstream"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        }];
        fs::write(
            &config_path,
            toml::to_string_pretty(&managed).expect("serialize second config"),
        )
        .expect("write second config");
        #[cfg(unix)]
        assert!(
            std::process::Command::new("kill")
                .args(["-HUP", &std::process::id().to_string()])
                .status()
                .expect("send SIGHUP")
                .success()
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let response = proxy_get(proxy_addr).await;
            assert!(response.starts_with(b"HTTP/1.1 200 OK"));
            assert!(
                response.ends_with(b"idle")
                    || response.ends_with(b"first")
                    || response.ends_with(b"second")
            );
            if response.ends_with(b"second") {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "reload timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::timeout(Duration::from_secs(1), idle_closed_rx)
            .await
            .expect("retired idle upstream remained pooled")
            .expect("idle-close signal dropped");
        release_tx.send(()).expect("release old snapshot stream");
        let mut old_tail = Vec::new();
        in_flight
            .read_to_end(&mut old_tail)
            .await
            .expect("finish old snapshot response");
        assert!(old_tail.ends_with(b"b"));

        fs::write(&config_path, "schema_version = 1\nunknown = true\n")
            .expect("write invalid config");
        #[cfg(unix)]
        assert!(
            std::process::Command::new("kill")
                .args(["-HUP", &std::process::id().to_string()])
                .status()
                .expect("send invalid-config SIGHUP")
                .success()
        );
        #[cfg(not(unix))]
        {
            tokio::time::sleep(Duration::from_millis(1_100)).await;
        }
        #[cfg(unix)]
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(proxy_get(proxy_addr).await.ends_with(b"second"));
        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy run");

        let recovery_shutdown = CancellationToken::new();
        let recovery_task = tokio::spawn(run_last_known_good(
            config_path.clone(),
            root.join("state"),
            recovery_shutdown.clone(),
        ));
        assert!(proxy_get(proxy_addr).await.ends_with(b"second"));
        recovery_shutdown.cancel();
        recovery_task
            .await
            .expect("recovery task")
            .expect("last-known-good run");
        first_task.abort();
        idle_task.await.expect("idle upstream task");
        second_task.abort();
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[tokio::test]
    async fn managed_reload_cancels_tcp_at_drain_deadline() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (first_upstream, first_task) = identified_tcp_upstream(b"old").await;
        let (second_upstream, second_task) = identified_tcp_upstream(b"new").await;
        let reserved = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve proxy port");
        let proxy_addr = reserved.local_addr().expect("proxy address");
        drop(reserved);
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-managed-tcp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("test directory");
        let config_path = root.join("proxy.toml");
        let mut managed = config(RouteConfig {
            id: "managed-tcp".into(),
            listeners: vec!["public".into()],
            hosts: vec![],
            paths: vec![],
            path_prefixes: vec![],
            methods: vec![],
            headers: vec![],
            default: true,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        managed.listeners[0].bind = proxy_addr;
        managed.listeners[0].protocol = "tcp".into();
        managed.runtime.state_dir = root.join("state").to_string_lossy().into_owned();
        managed.runtime.config_poll_secs = 1;
        managed.upstream_groups[0].drain_timeout_secs = 1;
        managed.upstream_groups[0].endpoints[0].url = format!("tcp://{first_upstream}")
            .parse()
            .expect("first upstream");
        fs::write(
            &config_path,
            toml::to_string_pretty(&managed).expect("serialize first config"),
        )
        .expect("write first config");
        let shutdown = CancellationToken::new();
        let proxy_task = tokio::spawn(run_managed(config_path.clone(), shutdown.clone()));
        let mut old_connection = connect_to_proxy(proxy_addr).await;
        old_connection.write_all(b"x").await.expect("old request");
        let mut identity = [0_u8; 3];
        old_connection
            .read_exact(&mut identity)
            .await
            .expect("old identity");
        assert_eq!(&identity, b"old");

        managed.upstream_groups[0].endpoints[0].id = "app-new".into();
        managed.upstream_groups[0].endpoints[0].url = format!("tcp://{second_upstream}")
            .parse()
            .expect("second upstream");
        fs::write(
            &config_path,
            toml::to_string_pretty(&managed).expect("serialize second config"),
        )
        .expect("write second config");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        loop {
            let mut probe = connect_to_proxy(proxy_addr).await;
            probe.write_all(b"x").await.expect("probe request");
            probe
                .read_exact(&mut identity)
                .await
                .expect("probe identity");
            if &identity == b"new" {
                break;
            }
            assert_eq!(&identity, b"old");
            assert!(
                tokio::time::Instant::now() < deadline,
                "TCP reload timed out"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let closed = tokio::time::timeout(Duration::from_secs(2), old_connection.read_u8())
            .await
            .expect("old TCP relay exceeded drain deadline");
        assert!(closed.is_err());

        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy run");
        first_task.abort();
        second_task.abort();
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[tokio::test]
    async fn verifies_custom_ca_and_proxies_https_over_http2() {
        let response = https_h2_upstream_response("upstream.test").await;
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.ends_with(b"ok"));
    }

    #[tokio::test]
    async fn rejects_wrong_upstream_tls_name() {
        let response = https_h2_upstream_response("wrong.test").await;
        assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway"));
    }

    async fn tls_request(
        http2: bool,
        authority: &str,
    ) -> (
        Vec<u8>,
        Option<rustls::ProtocolVersion>,
        StatusCode,
        bytes::Bytes,
    ) {
        tls_request_with_versions(
            http2,
            authority,
            "1.2",
            &[&rustls::version::TLS13, &rustls::version::TLS12],
        )
        .await
    }

    async fn tls_request_with_versions(
        http2: bool,
        authority: &str,
        minimum_version: &str,
        client_versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> (
        Vec<u8>,
        Option<rustls::ProtocolVersion>,
        StatusCode,
        bytes::Bytes,
    ) {
        use age::secrecy::ExposeSecret;
        use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs, pki_types::ServerName};
        use std::{
            fs,
            sync::atomic::{AtomicU64, Ordering},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
        let generated = rcgen::generate_simple_self_signed(vec!["example.test".into()])
            .expect("generate test identity");
        let age_identity = age::x25519::Identity::generate();
        let encrypted_private_key = age::encrypt(
            &age_identity.to_public(),
            generated.signing_key.serialize_pem().as_bytes(),
        )
        .expect("encrypt private key");
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("aegisproxy-tls-{}-{sequence}", std::process::id()));
        let certificate_path = base.with_extension("cert.pem");
        let private_key_path = base.with_extension("key.age");
        let identity_path = base.with_extension("identity.txt");
        fs::write(&certificate_path, generated.cert.pem()).expect("write certificate");
        fs::write(&private_key_path, encrypted_private_key).expect("write private-key envelope");
        fs::write(
            &identity_path,
            age_identity.to_string().expose_secret().as_bytes(),
        )
        .expect("write age identity");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o600))
                .expect("secure certificate");
            fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
                .expect("secure private key");
            fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
                .expect("secure identity");
        }

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = [0_u8; 4096];
            let count = stream.read(&mut request).await.expect("upstream read");
            assert!(
                std::str::from_utf8(&request[..count])
                    .expect("request text")
                    .contains(&format!("host: {upstream_addr}"))
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .expect("upstream response");
        });
        let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
            config.listeners[0].protocol = "https".into();
            config.listeners[0].certificates = vec!["site".into()];
            config.tls.identity = Some(format!("file://{}", identity_path.display()));
            config.tls.minimum_version = minimum_version.to_owned();
            config.certificates.push(CertificateConfig {
                id: "site".into(),
                hosts: vec!["example.test".into()],
                certificate_chain: format!("file://{}", certificate_path.display()),
                private_key: format!("file://{}", private_key_path.display()),
            });
        })
        .await;
        let stream = connect_to_proxy(proxy_addr).await;
        let mut roots = RootCertStore::empty();
        roots
            .add(generated.cert.der().clone())
            .expect("add test root");
        let mut client_config =
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(client_versions)
                .expect("TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        client_config.alpn_protocols = if http2 {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(
                ServerName::try_from("example.test").expect("server name"),
                stream,
            )
            .await
            .expect("TLS connect");
        let negotiated = tls
            .get_ref()
            .1
            .alpn_protocol()
            .expect("ALPN negotiated")
            .to_vec();
        let protocol_version = tls.get_ref().1.protocol_version();
        let request = if http2 {
            Request::builder()
                .uri(format!("https://{authority}/"))
                .body(Empty::<bytes::Bytes>::new())
                .expect("HTTP/2 request")
        } else {
            Request::builder()
                .uri("/")
                .header(HOST, authority)
                .body(Empty::<bytes::Bytes>::new())
                .expect("HTTP/1.1 request")
        };
        let (status, body) = if http2 {
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                    .await
                    .expect("HTTP/2 handshake");
            let connection_task = tokio::spawn(connection);
            let response = sender.send_request(request).await.expect("HTTP/2 response");
            let status = response.status();
            let body = response
                .into_body()
                .collect()
                .await
                .expect("HTTP/2 body")
                .to_bytes();
            connection_task.abort();
            (status, body)
        } else {
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .expect("HTTP/1.1 handshake");
            let connection_task = tokio::spawn(connection);
            let response = sender
                .send_request(request)
                .await
                .expect("HTTP/1.1 response");
            let status = response.status();
            let body = response
                .into_body()
                .collect()
                .await
                .expect("HTTP/1.1 body")
                .to_bytes();
            connection_task.abort();
            (status, body)
        };
        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy run");
        if status == StatusCode::OK {
            upstream_task.await.expect("upstream task");
        } else {
            upstream_task.abort();
        }
        fs::remove_file(certificate_path).expect("remove certificate");
        fs::remove_file(private_key_path).expect("remove private key");
        fs::remove_file(identity_path).expect("remove age identity");
        (negotiated, protocol_version, status, body)
    }

    #[tokio::test]
    async fn terminates_tls_with_http1_alpn() {
        let (alpn, _, status, body) = tls_request(false, "example.test").await;
        assert_eq!(alpn, b"http/1.1");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn proxies_http2_selected_by_alpn() {
        let (alpn, _, status, body) = tls_request(true, "example.test").await;
        assert_eq!(alpn, b"h2");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn rejects_authority_that_differs_from_sni() {
        let (_, _, status, _) = tls_request(true, "other.test").await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    }

    #[tokio::test]
    async fn supports_explicit_tls12_and_tls13_matrix() {
        for (minimum, client_version, expected) in [
            (
                "1.2",
                &rustls::version::TLS12,
                rustls::ProtocolVersion::TLSv1_2,
            ),
            (
                "1.3",
                &rustls::version::TLS13,
                rustls::ProtocolVersion::TLSv1_3,
            ),
        ] {
            let (_, negotiated, status, _) =
                tls_request_with_versions(false, "example.test", minimum, &[client_version]).await;
            assert_eq!(negotiated, Some(expected));
            assert_eq!(status, StatusCode::OK);
        }
    }

    #[test]
    fn route_matching_is_deterministic_and_header_aware() {
        let route = RouteConfig {
            id: "app".into(),
            listeners: vec!["public".into()],
            hosts: vec!["*.example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/api".into()],
            methods: vec!["GET".into()],
            headers: vec![aegisproxy_config::HeaderMatch {
                name: "x-tenant".into(),
                value: Some("blue".into()),
            }],
            default: false,
            priority: 10,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        };
        let config = config(route);
        let good_request = Request::builder()
            .method("GET")
            .uri("/api/v1")
            .header(HOST, "API.Example.Test:443")
            .header("x-tenant", "blue")
            .body(Empty::<bytes::Bytes>::new())
            .expect("request");
        assert_eq!(
            select_route(&config, &good_request, "public").map(|route| route.id.as_str()),
            Some("app")
        );
        let miss = request("POST", "api.example.test", "/api/v1");
        assert!(select_route(&config, &miss, "public").is_none());
    }

    #[test]
    fn explicit_default_route_never_overrides_a_specific_match() {
        let specific = RouteConfig {
            id: "specific".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: -10,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        };
        let mut config = config(specific);
        config.routes.push(RouteConfig {
            id: "fallback".into(),
            listeners: vec!["public".into()],
            hosts: vec![],
            paths: vec![],
            path_prefixes: vec![],
            methods: vec![],
            headers: vec![],
            default: true,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });

        assert_eq!(
            select_route(&config, &request("GET", "example.test", "/"), "public")
                .map(|route| route.id.as_str()),
            Some("specific")
        );
        assert_eq!(
            select_route(&config, &request("GET", "other.test", "/"), "public")
                .map(|route| route.id.as_str()),
            Some("fallback")
        );
    }

    #[test]
    fn exact_host_and_path_outrank_prefix_with_presence_predicate() {
        let prefix = RouteConfig {
            id: "prefix".into(),
            listeners: vec!["public".into()],
            hosts: vec!["*.example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/api".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        };
        let mut config = config(prefix);
        config.routes.push(RouteConfig {
            id: "exact".into(),
            listeners: vec!["public".into()],
            hosts: vec!["api.example.test".into()],
            paths: vec!["/api/users".into()],
            path_prefixes: vec![],
            methods: vec!["GET".into()],
            headers: vec![aegisproxy_config::HeaderMatch {
                name: "x-authenticated".into(),
                value: None,
            }],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });

        let exact = Request::builder()
            .method("GET")
            .uri("/api/users")
            .header(HOST, "api.example.test")
            .header("x-authenticated", "")
            .body(Empty::<bytes::Bytes>::new())
            .expect("request");
        assert_eq!(
            select_route(&config, &exact, "public").map(|route| route.id.as_str()),
            Some("exact")
        );

        let no_header = request("GET", "api.example.test", "/api/users");
        assert_eq!(
            select_route(&config, &no_header, "public").map(|route| route.id.as_str()),
            Some("prefix")
        );
        let trailing = request("GET", "api.example.test", "/api/users/");
        assert_eq!(
            select_route(&config, &trailing, "public").map(|route| route.id.as_str()),
            Some("prefix")
        );
    }

    #[test]
    fn rejects_absolute_form_connect_and_missing_host() {
        let absolute = Request::builder()
            .method("GET")
            .uri("http://example.test/")
            .body(Empty::<bytes::Bytes>::new())
            .expect("absolute request");
        assert_eq!(
            reject_unsafe_request_target(&absolute),
            Some(StatusCode::BAD_REQUEST)
        );
        let connect = Request::builder()
            .method("CONNECT")
            .uri("/")
            .header(HOST, "example.test")
            .body(Empty::<bytes::Bytes>::new())
            .expect("connect request");
        assert_eq!(
            reject_unsafe_request_target(&connect),
            Some(StatusCode::BAD_REQUEST)
        );
        let no_host = Request::builder()
            .method("GET")
            .uri("/")
            .body(Empty::<bytes::Bytes>::new())
            .expect("request");
        assert_eq!(
            reject_unsafe_request_target(&no_host),
            Some(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn validates_http2_authority_and_connection_headers() {
        let valid = Request::builder()
            .version(hyper::Version::HTTP_2)
            .uri("https://example.test/")
            .body(Empty::<bytes::Bytes>::new())
            .expect("HTTP/2 request");
        assert_eq!(reject_unsafe_request_target(&valid), None);

        let conflicting = Request::builder()
            .version(hyper::Version::HTTP_2)
            .uri("https://example.test/")
            .header(HOST, "other.test")
            .body(Empty::<bytes::Bytes>::new())
            .expect("HTTP/2 request");
        assert_eq!(
            reject_unsafe_request_target(&conflicting),
            Some(StatusCode::BAD_REQUEST)
        );

        let connection_header = Request::builder()
            .version(hyper::Version::HTTP_2)
            .uri("https://example.test/")
            .header(CONNECTION, "close")
            .body(Empty::<bytes::Bytes>::new())
            .expect("HTTP/2 request");
        assert_eq!(
            reject_unsafe_request_target(&connection_header),
            Some(StatusCode::BAD_REQUEST)
        );
    }

    #[tokio::test]
    async fn forwards_http_request_and_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (request_seen_tx, request_seen_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = vec![0_u8; 4096];
            let count = stream.read(&mut request).await.expect("upstream read");
            let request = std::str::from_utf8(&request[..count]).expect("request text");
            assert!(request.contains(&format!("host: {upstream_addr}")));
            assert!(request.starts_with("GET /hello/~user HTTP/1.1\r\n"));
            request_seen_tx.send(()).expect("signal request");
            release_rx.await.expect("release response");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .expect("upstream write");
        });
        let proxy_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve proxy port");
        let proxy_addr = proxy_listener.local_addr().expect("proxy address");
        drop(proxy_listener);
        let mut config = config(RouteConfig {
            id: "app".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        config.listeners[0].bind = proxy_addr;
        config.upstream_groups[0].endpoints[0].url = format!("http://{upstream_addr}")
            .parse()
            .expect("endpoint url");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(Arc::new(config), shutdown.clone()));
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(
                b"GET /hello/%7euser HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("client write");
        request_seen_rx.await.expect("upstream saw request");
        shutdown.cancel();
        release_tx.send(()).expect("release upstream");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("client read");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.ends_with(b"ok"));
        task.await.expect("proxy task").expect("proxy run");
        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn trusted_proxy_headers_are_rebuilt_before_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (captured_tx, captured_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = vec![0_u8; 4096];
            let count = stream.read(&mut request).await.expect("upstream read");
            captured_tx
                .send(String::from_utf8(request[..count].to_vec()).expect("request text"))
                .expect("capture request");
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n")
                .await
                .expect("upstream write");
        });
        let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
            config.trusted_proxies = TrustedProxyConfig {
                cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
                trusted_hops: 1,
            };
        })
        .await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 198.51.100.9\r\nForwarded: for=malicious\r\nX-Forwarded-Host: malicious.test\r\nX-Request-Id: malicious\r\nConnection: close, x-forwarded-for\r\n\r\n",
            )
            .await
            .expect("client write");
        let request = captured_rx.await.expect("captured request");
        assert!(request.contains("x-forwarded-for: 198.51.100.9\r\n"));
        assert!(request.contains("x-real-ip: 198.51.100.9\r\n"));
        assert!(request.contains("x-forwarded-host: example.test\r\n"));
        assert!(request.contains("x-forwarded-proto: http\r\n"));
        assert!(
            request.contains("forwarded: for=198.51.100.9;proto=http;host=\"example.test\"\r\n")
        );
        assert!(!request.contains("malicious"));
        shutdown.cancel();
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("client read");
        assert!(response.starts_with(b"HTTP/1.1 204 No Content"));
        proxy_task.await.expect("proxy task").expect("proxy run");
        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn balances_real_requests_across_weighted_endpoints() {
        let (first_addr, first_task) = identified_upstream(b"first").await;
        let (second_addr, second_task) = identified_upstream(b"second").await;
        let (proxy_addr, shutdown, proxy_task) = start_test_proxy(first_addr, |config| {
            let group = &mut config.upstream_groups[0];
            group.algorithm = BalancingAlgorithm::SmoothWeightedRoundRobin;
            group.endpoints[0].weight = 2;
            group.endpoints.push(EndpointConfig {
                id: "app-2".into(),
                url: format!("http://{second_addr}")
                    .parse()
                    .expect("endpoint URL"),
                weight: 1,
                server_name: None,
                ca_bundle: None,
            });
        })
        .await;

        let mut counts = [0_usize; 2];
        for _ in 0..6 {
            let response = proxy_get(proxy_addr).await;
            if response.ends_with(b"first") {
                counts[0] += 1;
            } else if response.ends_with(b"second") {
                counts[1] += 1;
            } else {
                panic!("unexpected upstream response");
            }
        }

        assert_eq!(counts, [4, 2]);
        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy result");
        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn active_http_health_excludes_failed_endpoint() {
        let reserved = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve failed endpoint");
        let failed_addr = reserved.local_addr().expect("failed endpoint address");
        drop(reserved);
        let (healthy_addr, healthy_task) = identified_upstream(b"healthy").await;
        let (proxy_addr, shutdown, proxy_task) = start_test_proxy(failed_addr, |config| {
            let group = &mut config.upstream_groups[0];
            group.health = Some(aegisproxy_config::HealthCheckConfig {
                interval_secs: 2,
                timeout_secs: 1,
                unhealthy_threshold: 1,
                healthy_threshold: 1,
                ..aegisproxy_config::HealthCheckConfig::default()
            });
            group.endpoints.push(EndpointConfig {
                id: "app-2".into(),
                url: format!("http://{healthy_addr}")
                    .parse()
                    .expect("endpoint URL"),
                weight: 1,
                server_name: None,
                ca_bundle: None,
            });
        })
        .await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut consecutive_healthy = 0;
        while consecutive_healthy < 4 && tokio::time::Instant::now() < deadline {
            if proxy_get(proxy_addr).await.ends_with(b"healthy") {
                consecutive_healthy += 1;
            } else {
                consecutive_healthy = 0;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(consecutive_healthy, 4);
        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy result");
        healthy_task.abort();
    }

    #[tokio::test]
    async fn active_tcp_probe_observes_listener_state() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let address = listener.local_addr().expect("upstream address");
        let mut config = config(RouteConfig {
            id: "test".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        config.upstream_groups[0].endpoints[0].url =
            format!("http://{address}").parse().expect("endpoint URL");
        let (clients, dns_endpoints) = build_upstream_clients(&config).expect("upstream clients");
        let client = clients.get("app/app-1").expect("upstream client");
        let dns_endpoint = dns_endpoints.get("app/app-1").expect("DNS endpoint");
        let policy = aegisproxy_config::HealthCheckConfig {
            kind: HealthCheckKind::Tcp,
            ..aegisproxy_config::HealthCheckConfig::default()
        };
        assert!(
            active_health_probe(
                Some(client),
                dns_endpoint,
                &config.upstream_groups[0].endpoints[0],
                &policy,
            )
            .await
        );
        drop(listener);
        assert!(
            !active_health_probe(
                Some(client),
                dns_endpoint,
                &config.upstream_groups[0].endpoints[0],
                &policy,
            )
            .await
        );
    }

    #[tokio::test]
    async fn custom_dns_resolver_connects_only_to_pinned_address() {
        let (upstream_addr, upstream_task) = identified_upstream(b"dns").await;
        let mut config = config(RouteConfig {
            id: "test".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        config.upstream_groups[0].endpoints[0].url =
            format!("http://app.internal:{}", upstream_addr.port())
                .parse()
                .expect("DNS endpoint URL");
        let (clients, dns_endpoints) = build_upstream_clients(&config).expect("upstream clients");
        dns_endpoints
            .get("app/app-1")
            .expect("DNS endpoint")
            .install_test_answers(vec![upstream_addr.ip()])
            .expect("DNS answer");
        let request = Request::builder()
            .uri(format!("http://app.internal:{}/", upstream_addr.port()))
            .header(HOST, format!("app.internal:{}", upstream_addr.port()))
            .body(full_body(b""))
            .expect("request");
        let response = clients
            .get("app/app-1")
            .expect("client")
            .request(request)
            .await
            .expect("resolved request")
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        assert_eq!(response, b"dns".as_slice());
        upstream_task.abort();
    }

    #[tokio::test]
    async fn circuit_opens_after_configured_upstream_failures() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);
        let upstream_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = upstream.accept().await else {
                    return;
                };
                let request_count = Arc::clone(&request_count);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |_| {
                        request_count.fetch_add(1, Ordering::Relaxed);
                        async {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Full::new(bytes::Bytes::from_static(b"failed")))
                                    .expect("response"),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let (proxy_addr, shutdown, proxy_task) = start_test_proxy(upstream_addr, |config| {
            config.upstream_groups[0].circuit_breaker =
                Some(aegisproxy_config::CircuitBreakerConfig {
                    sample_size: 1,
                    minimum_requests: 1,
                    failure_percent: 100,
                    open_secs: 10,
                    half_open_requests: 1,
                });
        })
        .await;

        assert!(proxy_get(proxy_addr).await.starts_with(b"HTTP/1.1 500"));
        assert!(proxy_get(proxy_addr).await.starts_with(b"HTTP/1.1 503"));
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy result");
        upstream_task.abort();
    }

    #[tokio::test]
    async fn retries_bounded_idempotent_body_on_connect_failure() {
        let reserved = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve failed endpoint");
        let failed_addr = reserved.local_addr().expect("failed endpoint address");
        drop(reserved);
        let (healthy_addr, healthy_task) = identified_upstream(b"healthy").await;
        let (proxy_addr, shutdown, proxy_task) = start_test_proxy(failed_addr, |config| {
            let group = &mut config.upstream_groups[0];
            group.retry.max_attempts = 2;
            group.retry.replay_body_bytes = 16;
            group.endpoints.push(EndpointConfig {
                id: "app-2".into(),
                url: format!("http://{healthy_addr}")
                    .parse()
                    .expect("endpoint URL"),
                weight: 1,
                server_name: None,
                ca_bundle: None,
            });
        })
        .await;

        let response = proxy_request(
            proxy_addr,
            b"PUT / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"healthy"));
        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy result");
        healthy_task.abort();
    }

    #[tokio::test]
    async fn does_not_retry_non_idempotent_request() {
        let reserved = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve failed endpoint");
        let failed_addr = reserved.local_addr().expect("failed endpoint address");
        drop(reserved);
        let (healthy_addr, healthy_task) = identified_upstream(b"unexpected").await;
        let (proxy_addr, shutdown, proxy_task) = start_test_proxy(failed_addr, |config| {
            let group = &mut config.upstream_groups[0];
            group.retry.max_attempts = 2;
            group.retry.replay_body_bytes = 16;
            group.endpoints.push(EndpointConfig {
                id: "app-2".into(),
                url: format!("http://{healthy_addr}")
                    .parse()
                    .expect("endpoint URL"),
                weight: 1,
                server_name: None,
                ca_bundle: None,
            });
        })
        .await;

        let response = proxy_request(
            proxy_addr,
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 502"));
        shutdown.cancel();
        proxy_task.await.expect("proxy task").expect("proxy result");
        healthy_task.abort();
    }

    #[tokio::test]
    async fn tunnels_websocket_upgrade_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("handshake read");
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .expect("handshake write");
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.expect("tunnel read");
            stream.write_all(&bytes).await.expect("tunnel write");
        });

        let reserved = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve proxy port");
        let proxy_addr = reserved.local_addr().expect("proxy address");
        drop(reserved);
        let mut config = config(RouteConfig {
            id: "websocket".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/ws".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        config.listeners[0].bind = proxy_addr;
        config.upstream_groups[0].endpoints[0].url = format!("http://{upstream_addr}")
            .parse()
            .expect("endpoint url");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(Arc::new(config), shutdown.clone()));

        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .await
            .expect("client handshake");
        let mut headers = Vec::new();
        while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0_u8; 256];
            let count = client.read(&mut chunk).await.expect("handshake response");
            assert!(count > 0, "proxy closed before upgrade response");
            headers.extend_from_slice(&chunk[..count]);
        }
        assert!(headers.starts_with(b"HTTP/1.1 101"));
        client.write_all(b"ping").await.expect("tunnel send");
        let mut echo = [0_u8; 4];
        client.read_exact(&mut echo).await.expect("tunnel receive");
        assert_eq!(&echo, b"ping");

        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn maps_upstream_response_timeout_to_gateway_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("request read");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });
        let reserved = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve proxy port");
        let proxy_addr = reserved.local_addr().expect("proxy address");
        drop(reserved);
        let mut config = config(RouteConfig {
            id: "timeout".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        config.listeners[0].bind = proxy_addr;
        config.limits.response_header_timeout_secs = 1;
        config.upstream_groups[0].endpoints[0].url = format!("http://{upstream_addr}")
            .parse()
            .expect("endpoint url");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run(Arc::new(config), shutdown.clone()));
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("client write");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("client read");
        assert!(response.starts_with(b"HTTP/1.1 504 Gateway Timeout"));
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
        upstream_task.abort();
    }

    #[tokio::test]
    async fn streams_response_before_upstream_finishes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (release_tx, release_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("request read");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\na")
                .await
                .expect("first response chunk");
            release_rx.await.expect("release second chunk");
            stream.write_all(b"b").await.expect("second response chunk");
        });
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("request write");
        let mut first = [0_u8; 1024];
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut first))
                .await
                .expect("proxy buffered the response")
                .expect("response read");
        assert!(first[..count].ends_with(b"a"));
        release_tx.send(()).expect("release upstream");
        let mut rest = Vec::new();
        client
            .read_to_end(&mut rest)
            .await
            .expect("remaining response");
        assert!(rest.ends_with(b"b"));
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn streams_upload_before_client_finishes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (first_body_tx, first_body_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut received = Vec::new();
            let mut first_body_tx = Some(first_body_tx);
            loop {
                let mut chunk = [0_u8; 512];
                let count = stream.read(&mut chunk).await.expect("upstream read");
                assert!(count > 0, "proxy closed upload early");
                received.extend_from_slice(&chunk[..count]);
                if first_body_tx.is_some()
                    && received
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .is_some_and(|header_end| received.len() > header_end + 4)
                {
                    if let Some(sender) = first_body_tx.take() {
                        sender.send(()).expect("signal first body bytes");
                    }
                }
                if received.ends_with(b"0\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .expect("response write");
        });
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n")
            .await
            .expect("first upload chunk");
        tokio::time::timeout(std::time::Duration::from_secs(1), first_body_rx)
            .await
            .expect("proxy buffered upload")
            .expect("upstream signal");
        client
            .write_all(b"1\r\nb\r\n0\r\n\r\n")
            .await
            .expect("finish upload");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("response read");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn supports_http1_keep_alive() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut pending = Vec::new();
            for (body, close) in [(b"a", false), (b"b", true)] {
                while !pending.windows(4).any(|window| window == b"\r\n\r\n") {
                    let mut chunk = [0_u8; 512];
                    let count = stream.read(&mut chunk).await.expect("request read");
                    assert!(count > 0, "proxy closed keep-alive upstream");
                    pending.extend_from_slice(&chunk[..count]);
                }
                pending.clear();
                let connection = if close { "close" } else { "keep-alive" };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: 1\r\nconnection: {connection}\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("response headers");
                stream.write_all(body).await.expect("response body");
            }
        });
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("first request");
        let mut first = Vec::new();
        while !first
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .is_some_and(|headers| first.len() >= headers + 5)
        {
            let mut chunk = [0_u8; 512];
            let count = client.read(&mut chunk).await.expect("first response");
            assert!(count > 0, "proxy closed downstream keep-alive");
            first.extend_from_slice(&chunk[..count]);
        }
        assert!(first.ends_with(b"a"));
        client
            .write_all(b"GET /two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("second request");
        let mut second = Vec::new();
        client
            .read_to_end(&mut second)
            .await
            .expect("second response");
        assert!(second.starts_with(b"HTTP/1.1 200 OK"));
        assert!(second.ends_with(b"b"));
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn invalid_startup_never_binds_listener() {
        use tokio::net::TcpListener;

        let reserved = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve listener");
        let address = reserved.local_addr().expect("listener address");
        drop(reserved);
        let mut config = config(RouteConfig {
            id: "invalid".into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        });
        config.listeners[0].bind = address;
        config.limits.max_connections = 0;
        let error = run(Arc::new(config), CancellationToken::new())
            .await
            .expect_err("invalid startup must fail");
        assert!(matches!(error, ProxyError::Config(_)));
        let rebound = TcpListener::bind(address)
            .await
            .expect("invalid startup bound the listener");
        drop(rebound);
    }

    #[tokio::test]
    async fn propagates_client_cancellation_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (request_seen_tx, request_seen_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = [0_u8; 4096];
            let count = stream.read(&mut request).await.expect("request read");
            assert!(count > 0);
            request_seen_tx.send(()).expect("signal request");
            let count =
                tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut request))
                    .await
                    .expect("upstream connection stayed open after client cancellation")
                    .expect("upstream read after cancellation");
            assert_eq!(count, 0);
        });
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("request write");
        request_seen_rx.await.expect("upstream saw request");
        drop(client);
        upstream_task.await.expect("upstream task");
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn stops_accepting_when_drain_begins() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
        let idle_client = connect_to_proxy(proxy_addr).await;
        shutdown.cancel();
        wait_for_listener_close(proxy_addr).await;
        drop(idle_client);
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn proxies_plain_tcp_bidirectionally() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = [0_u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("upstream read");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.expect("upstream write");
        });
        let (proxy_addr, shutdown, task) = start_tcp_test_proxy(upstream_addr, false).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client.write_all(b"ping").await.expect("client write");
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.expect("client read");
        assert_eq!(&response, b"pong");
        drop(client);
        upstream_task.await.expect("upstream task");
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn drains_existing_tcp_connection_after_listener_shutdown() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            sync::oneshot,
        };

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (request_tx, request_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut request = [0_u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("upstream read");
            request_tx.send(()).expect("request signal");
            release_rx.await.expect("release signal");
            stream.write_all(b"pong").await.expect("upstream write");
        });
        let (proxy_addr, shutdown, task) = start_tcp_test_proxy(upstream_addr, false).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client.write_all(b"ping").await.expect("client write");
        request_rx.await.expect("upstream request");
        shutdown.cancel();
        wait_for_listener_close(proxy_addr).await;
        release_tx.send(()).expect("release upstream");
        let mut response = [0_u8; 4];
        client
            .read_exact(&mut response)
            .await
            .expect("drained response");
        assert_eq!(&response, b"pong");
        drop(client);
        upstream_task.await.expect("upstream task");
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn tls_passthrough_routes_fragmented_sni_and_preserves_prefix() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let hello = client_hello("example.test");
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let expected = hello.clone();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut received = vec![0_u8; expected.len()];
            stream
                .read_exact(&mut received)
                .await
                .expect("forwarded ClientHello");
            assert_eq!(received, expected);
            stream.write_all(b"routed").await.expect("upstream write");
        });
        let (proxy_addr, shutdown, task) = start_tcp_test_proxy(upstream_addr, true).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client.write_all(&hello[..3]).await.expect("first fragment");
        tokio::task::yield_now().await;
        client
            .write_all(&hello[3..])
            .await
            .expect("second fragment");
        let mut response = [0_u8; 6];
        client
            .read_exact(&mut response)
            .await
            .expect("routed response");
        assert_eq!(&response, b"routed");
        drop(client);
        upstream_task.await.expect("upstream task");
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn tls_passthrough_rejects_unknown_sni_without_upstream_dial() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (proxy_addr, shutdown, task) = start_tcp_test_proxy(upstream_addr, true).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(&client_hello("unknown.test"))
            .await
            .expect("ClientHello write");
        let mut byte = [0_u8; 1];
        let count = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("unknown SNI connection remained open")
            .expect("client read");
        assert_eq!(count, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.accept())
                .await
                .is_err()
        );
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn tls_passthrough_bounds_malformed_oversized_and_slow_client_hello() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn rejected(address: SocketAddr, input: &[u8]) {
            let mut client = connect_to_proxy(address).await;
            client.write_all(input).await.expect("untrusted TLS input");
            let mut byte = [0_u8; 1];
            let count = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
                .await
                .expect("TLS input was not bounded")
                .expect("client read");
            assert_eq!(count, 0);
        }

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |config| {
            config.listeners[0].protocol = "tls_passthrough".into();
            config.upstream_groups[0].endpoints[0].url = format!("tcp://{upstream_addr}")
                .parse()
                .expect("TCP endpoint URL");
            config.routes[0].paths.clear();
            config.routes[0].path_prefixes.clear();
            config.routes[0].methods.clear();
            config.routes[0].headers.clear();
            config.tls.handshake_timeout_secs = 1;
        })
        .await;

        rejected(proxy_addr, b"not tls").await;
        let mut oversized = vec![0_u8; 16 * 1024];
        oversized[..5].copy_from_slice(&[22, 3, 3, 0x40, 0]);
        rejected(proxy_addr, &oversized).await;
        rejected(proxy_addr, &[22, 3, 3, 0, 100]).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.accept())
                .await
                .is_err()
        );
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn rejects_oversized_body_before_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |config| {
            config.limits.max_request_body = 4;
        })
        .await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .expect("request write");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("response read");
        assert!(response.starts_with(b"HTTP/1.1 413 Payload Too Large"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), upstream.accept())
                .await
                .is_err()
        );
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn rejects_ambiguous_framing_before_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
            .await
            .expect("request write");
        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.read_to_end(&mut response),
        )
        .await;
        assert!(!response.starts_with(b"HTTP/1.1 200"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), upstream.accept())
                .await
                .is_err()
        );
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn rejects_encoded_path_separator_before_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |_| {}).await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(
                b"GET /public%2fadmin HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("request write");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("response read");
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), upstream.accept())
                .await
                .is_err()
        );
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }

    #[tokio::test]
    async fn closes_slow_request_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let (proxy_addr, shutdown, task) = start_test_proxy(upstream_addr, |config| {
            config.limits.request_header_timeout_secs = 1;
        })
        .await;
        let mut client = connect_to_proxy(proxy_addr).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost:")
            .await
            .expect("partial header write");
        let mut byte = [0_u8; 1];
        let count = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut byte))
            .await
            .expect("header timeout did not fire")
            .expect("read after timeout");
        assert_eq!(count, 0);
        shutdown.cancel();
        task.await.expect("proxy task").expect("proxy run");
    }
}
