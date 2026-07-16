#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Data-plane HTTP forwarding primitives.

mod route;

use std::{
    collections::HashMap, convert::Infallible, error::Error, future::Future, net::SocketAddr,
    pin::Pin, sync::Arc, time::Duration,
};

use aegisproxy_config::{Config, ConfigError, LimitsConfig};
use aegisproxy_tls::{CertificateResolver, Identity, TlsAcceptor, load_identity, tls_acceptor};
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
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub use route::RouteIndex;
use route::{PathError, canonical_host, canonicalize_request_path, request_host};

/// Boxed body error.
pub type BoxError = Box<dyn Error + Send + Sync>;
/// Boxed response body used by the server and upstream client.
pub type ResponseBody = BoxBody<bytes::Bytes, BoxError>;
type UpstreamClient = Client<HttpsConnector<HttpConnector>, ResponseBody>;
type UpstreamClients = Arc<HashMap<String, UpstreamClient>>;

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
}

/// Run configured HTTP and HTTPS listeners until cancellation.
pub async fn run(config: Arc<Config>, shutdown: CancellationToken) -> Result<(), ProxyError> {
    aegisproxy_config::validate(&config)?;
    let route_index = Arc::new(RouteIndex::compile(&config));
    let preparation_config = Arc::clone(&config);
    let (mut tls_acceptors, upstream_clients) = tokio::task::spawn_blocking(move || {
        Ok::<_, ProxyError>((
            prepare_tls(&preparation_config)?,
            build_upstream_clients(&preparation_config)?,
        ))
    })
    .await
    .map_err(|error| ProxyError::Preparation(error.to_string()))??;
    let handshake_permits = Arc::new(Semaphore::new(config.tls.max_handshakes));
    let mut tasks = tokio::task::JoinSet::new();
    for listener in config
        .listeners
        .iter()
        .filter(|listener| matches!(listener.protocol.as_str(), "http" | "https"))
    {
        let tcp = TcpListener::bind(listener.bind).await?;
        let listener_id = listener.id.clone();
        let tls_acceptor = tls_acceptors.remove(&listener_id);
        let config = Arc::clone(&config);
        let shutdown = shutdown.clone();
        let limits = config.limits.clone();
        let handshake_permits = Arc::clone(&handshake_permits);
        let upstream_clients = Arc::clone(&upstream_clients);
        let route_index = Arc::clone(&route_index);
        tracing::info!(listener = %listener_id, bind = %listener.bind, protocol = %listener.protocol, "listener started");
        tasks.spawn(async move {
            accept_loop(
                tcp,
                ListenerContext {
                    listener_id,
                    config,
                    route_index,
                    limits,
                    tls_acceptor,
                    handshake_permits,
                    upstream_clients,
                    shutdown,
                },
            )
            .await
        });
    }
    if tasks.is_empty() {
        return Err(ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no HTTP or HTTPS listeners configured",
        )));
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn build_upstream_clients(config: &Config) -> Result<UpstreamClients, ProxyError> {
    let mut clients = HashMap::new();
    for endpoint in config
        .upstream_groups
        .iter()
        .flat_map(|group| group.endpoints.iter())
    {
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
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        if clients.insert(endpoint.id.clone(), client).is_some() {
            return Err(ProxyError::Preparation(format!(
                "duplicate upstream endpoint {}",
                endpoint.id
            )));
        }
    }
    Ok(Arc::new(clients))
}

fn prepare_tls(config: &Config) -> Result<HashMap<String, TlsAcceptor>, ProxyError> {
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
    let mut acceptors = HashMap::new();
    for listener in config
        .listeners
        .iter()
        .filter(|listener| listener.protocol == "https")
    {
        let selected: Result<Vec<Identity>, ProxyError> = listener
            .certificates
            .iter()
            .map(|id| {
                identities.get(id.as_str()).cloned().ok_or_else(|| {
                    ProxyError::Preparation(format!(
                        "listener {} references missing certificate {id}",
                        listener.id
                    ))
                })
            })
            .collect();
        let resolver = CertificateResolver::new(&selected?)?;
        acceptors.insert(
            listener.id.clone(),
            tls_acceptor(resolver, &config.tls.minimum_version)?,
        );
    }
    Ok(acceptors)
}

#[derive(Clone)]
struct ListenerContext {
    listener_id: String,
    config: Arc<Config>,
    route_index: Arc<RouteIndex>,
    limits: LimitsConfig,
    tls_acceptor: Option<TlsAcceptor>,
    handshake_permits: Arc<Semaphore>,
    upstream_clients: UpstreamClients,
    shutdown: CancellationToken,
}

async fn accept_loop(listener: TcpListener, context: ListenerContext) {
    let ListenerContext {
        listener_id,
        config,
        route_index,
        limits,
        tls_acceptor,
        handshake_permits,
        upstream_clients,
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
        let handshake_permit = if tls_acceptor.is_some() {
            let Ok(permit) = handshake_permits.clone().try_acquire_owned() else {
                tracing::debug!(%peer, "TLS handshake limit reached");
                continue;
            };
            Some(permit)
        } else {
            None
        };
        let config = Arc::clone(&config);
        let route_index = Arc::clone(&route_index);
        let shutdown = shutdown.clone();
        let limits = limits.clone();
        let listener_id = listener_id.clone();
        let tls_acceptor = tls_acceptor.clone();
        let upstream_clients = Arc::clone(&upstream_clients);
        let upgrade_tasks = upgrade_tasks.clone();
        connections.spawn(async move {
            let _permit = permit;
            let connection = ConnectionContext {
                peer,
                listener_id,
                config,
                route_index,
                limits,
                shutdown,
                upgrade_tasks,
                upstream_clients,
                tls_server_name: None,
            };
            let result = match tls_acceptor {
                Some(acceptor) => {
                    let accepted = tokio::time::timeout(
                        Duration::from_secs(connection.config.tls.handshake_timeout_secs),
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
    upgrade_tasks.close();
    let drain_deadline = std::time::Duration::from_secs(config.runtime.shutdown_grace_secs);
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
    config: Arc<Config>,
    route_index: Arc<RouteIndex>,
    limits: LimitsConfig,
    shutdown: CancellationToken,
    upgrade_tasks: TaskTracker,
    upstream_clients: UpstreamClients,
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
        config: context.config,
        route_index: context.route_index,
        peer: context.peer,
        listener_id: context.listener_id,
        limits: context.limits,
        clients: context.upstream_clients,
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
        config: context.config,
        route_index: context.route_index,
        peer: context.peer,
        listener_id: context.listener_id,
        limits: context.limits,
        clients: context.upstream_clients,
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
    config: Arc<Config>,
    route_index: Arc<RouteIndex>,
    peer: SocketAddr,
    listener_id: String,
    limits: LimitsConfig,
    clients: UpstreamClients,
    shutdown: CancellationToken,
    upgrade_tasks: TaskTracker,
    tls_server_name: Option<String>,
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<ResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move { Ok(service.forward(request).await) })
    }
}

impl ProxyService {
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
        if self
            .tls_server_name
            .as_deref()
            .is_some_and(|server_name| match request_host(&request) {
                Ok(host) => match canonical_host(server_name) {
                    Ok(server_name) => host != server_name,
                    Err(()) => true,
                },
                Err(()) => true,
            })
        {
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
        let websocket = is_websocket_upgrade(&request);
        let preserve_te_trailers = request.version() == hyper::Version::HTTP_2
            && request
                .headers()
                .get(hyper::header::TE)
                .is_some_and(|value| value.as_bytes() == b"trailers");
        if request.headers().contains_key(UPGRADE) && !websocket {
            return error_response(StatusCode::BAD_REQUEST, "invalid upgrade request\n");
        }
        let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
        let Some(route) = self
            .route_index
            .select(&self.config, &request, &self.listener_id)
        else {
            return error_response(StatusCode::NOT_FOUND, "no matching route\n");
        };
        let Some(group_id) = route.upstream_group.as_deref() else {
            return error_response(StatusCode::BAD_GATEWAY, "route has no upstream\n");
        };
        let Some(group) = self
            .config
            .upstream_groups
            .iter()
            .find(|group| group.id == group_id)
        else {
            return error_response(StatusCode::BAD_GATEWAY, "upstream group missing\n");
        };
        let Some(endpoint) = group.endpoints.first() else {
            return error_response(StatusCode::BAD_GATEWAY, "upstream unavailable\n");
        };
        let Some(client) = self.clients.get(&endpoint.id) else {
            return error_response(StatusCode::BAD_GATEWAY, "upstream client missing\n");
        };
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
        let mut upstream_uri = endpoint.url.clone();
        let base_path = endpoint.url.path().trim_end_matches('/');
        let request_path = parts.uri.path();
        let joined_path = if base_path.is_empty() {
            request_path.to_owned()
        } else if request_path == "/" {
            format!("{base_path}/")
        } else {
            format!("{base_path}/{}", request_path.trim_start_matches('/'))
        };
        upstream_uri.set_path(&joined_path);
        upstream_uri.set_query(parts.uri.query());
        let Ok(uri) = upstream_uri.as_str().parse::<Uri>() else {
            return error_response(StatusCode::BAD_GATEWAY, "invalid upstream URI\n");
        };
        parts.uri = uri;
        parts.version = hyper::Version::HTTP_11;
        strip_hop_by_hop_headers(&mut parts.headers, websocket, preserve_te_trailers);
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-real-ip",
            "x-request-id",
        ] {
            parts.headers.remove(name);
        }
        if let Some(host) = endpoint.url.host_str() {
            let mut authority = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            if let Some(port) = endpoint.url.port() {
                authority.push(':');
                authority.push_str(&port.to_string());
            }
            if let Ok(value) = HeaderValue::from_str(&authority) {
                parts.headers.insert(HOST, value);
            }
        }
        let request = Request::from_parts(
            parts,
            Limited::new(body, self.limits.max_request_body).boxed(),
        );
        let result = match tokio::time::timeout(
            std::time::Duration::from_secs(self.limits.response_header_timeout_secs),
            client.request(request),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                return error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream response timed out\n",
                );
            }
        };
        match result {
            Ok(mut response) => {
                if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                    let Some(client_upgrade) = client_upgrade else {
                        return error_response(
                            StatusCode::BAD_GATEWAY,
                            "unexpected upstream upgrade\n",
                        );
                    };
                    let upstream_upgrade = hyper::upgrade::on(&mut response);
                    let shutdown = self.shutdown.clone();
                    self.upgrade_tasks.spawn(async move {
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
                } else {
                    strip_hop_by_hop_headers(response.headers_mut(), false, false);
                }
                response.map(|body| body.map_err(|error| Box::new(error) as BoxError).boxed())
            }
            Err(error) => {
                tracing::debug!(peer = %self.peer, %error, "upstream request failed");
                error_response(StatusCode::BAD_GATEWAY, "upstream request failed\n")
            }
        }
    }
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

fn full_body(bytes: &[u8]) -> ResponseBody {
    Full::new(bytes::Bytes::copy_from_slice(bytes))
        .map_err(|never: Infallible| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::{
        AdminConfig, CertificateConfig, Config, EndpointConfig, LimitsConfig, ListenerConfig,
        RouteConfig, RuntimeConfig, TrustedProxyConfig, UpstreamGroupConfig,
    };
    use http_body_util::Empty;
    use std::collections::HashMap;

    fn request(method: &str, host: &str, path: &str) -> Request<Empty<bytes::Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, host)
            .body(Empty::<bytes::Bytes>::new())
            .expect("test request is valid")
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
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![UpstreamGroupConfig {
                id: "app".into(),
                algorithm: "round_robin".into(),
                allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
                endpoints: vec![EndpointConfig {
                    id: "app-1".into(),
                    url: "http://127.0.0.1:9000".parse().expect("url"),
                    weight: 1,
                    server_name: None,
                    ca_bundle: None,
                }],
            }],
            middlewares: HashMap::new(),
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
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(tokio::net::TcpStream::connect(proxy_addr).await.is_err());
        drop(idle_client);
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
