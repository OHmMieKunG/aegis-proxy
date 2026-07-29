#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Data-plane HTTP and TCP reverse-proxy runtime.

mod acme_manager;
mod http;
mod lifecycle;
mod middleware;
mod provider;
mod request;
mod route;
mod runtime;
mod tcp;
mod telemetry;
mod upstream;
mod upstream_runtime;

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

pub use lifecycle::{
    load_last_known_good, run, run_last_known_good, run_last_known_good_with_control,
    run_last_known_good_with_control_on_node, run_managed, run_managed_config_with_control,
    run_managed_config_with_control_on_node, run_managed_revision_with_control_on_node,
    run_managed_with_control,
};
pub use provider::{ProviderRegistry, ProviderStatus};
pub use request::error_response;
pub use route::RouteIndex;
use route::{PathError, canonical_host, canonicalize_request_path, request_host};
use runtime::RuntimeSnapshot;
pub use runtime::{
    ActivationCoordinator, ActivationError, ActivationResult, NodeIdentity, RuntimeHandle,
    hot_reload_compatible,
};
use tcp::{TcpListenerContext, accept_loop as tcp_accept_loop};

use http::prepare_tls;
#[cfg(test)]
use lifecycle::validate_node_policy;
use request::{
    full_body, http_challenge_response, is_grpc_content_type, is_idempotent_retry_method,
    is_websocket_upgrade, reject_unsafe_request_target, strip_hop_by_hop_headers, upstream_uri,
};
#[cfg(test)]
use upstream_runtime::active_health_probe;
use upstream_runtime::{
    build_upstream_clients, build_upstream_pools, endpoint_authority, endpoint_key,
    start_active_health_checks,
};

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

#[cfg(test)]
mod tests;
