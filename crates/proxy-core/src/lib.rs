#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Data-plane HTTP forwarding primitives.

use std::{
    convert::Infallible, error::Error, future::Future, net::SocketAddr, pin::Pin, sync::Arc,
};

use aegisproxy_config::{Config, LimitsConfig, RouteConfig};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::service::Service;
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{CONNECTION, HOST, HeaderValue},
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;

/// Boxed body error.
pub type BoxError = Box<dyn Error + Send + Sync>;
/// Boxed response body used by the server and upstream client.
pub type ResponseBody = BoxBody<bytes::Bytes, BoxError>;

/// Proxy runtime error.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Listener bind failure.
    #[error("listener failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Run configured HTTP listeners until cancellation.
pub async fn run(config: Arc<Config>, shutdown: CancellationToken) -> Result<(), ProxyError> {
    let mut tasks = tokio::task::JoinSet::new();
    for listener in config
        .listeners
        .iter()
        .filter(|listener| listener.protocol == "http")
    {
        let tcp = TcpListener::bind(listener.bind).await?;
        let listener_id = listener.id.clone();
        let config = Arc::clone(&config);
        let shutdown = shutdown.clone();
        let limits = config.limits.clone();
        tracing::info!(listener = %listener_id, bind = %listener.bind, "http listener started");
        tasks.spawn(async move { accept_loop(tcp, listener_id, config, limits, shutdown).await });
    }
    if tasks.is_empty() {
        return Err(ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no http listeners configured",
        )));
    }
    shutdown.cancelled().await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn accept_loop(
    listener: TcpListener,
    listener_id: String,
    config: Arc<Config>,
    limits: LimitsConfig,
    shutdown: CancellationToken,
) {
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let accepted = tokio::select! { _ = shutdown.cancelled() => break, result = listener.accept() => result };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "connection limit reached");
            continue;
        };
        let config = Arc::clone(&config);
        let shutdown = shutdown.clone();
        let limits = limits.clone();
        let listener_id = listener_id.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                serve_connection(stream, peer, listener_id, config, limits, shutdown).await
            {
                tracing::debug!(%peer, %error, "connection ended");
            }
        });
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    listener_id: String,
    config: Arc<Config>,
    limits: LimitsConfig,
    shutdown: CancellationToken,
) -> Result<(), hyper::Error> {
    let io = TokioIo::new(stream);
    let client = Client::builder(TokioExecutor::new()).build_http();
    let service = ProxyService {
        config,
        peer,
        listener_id,
        limits,
        client,
        shutdown,
    };
    hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
}

#[derive(Clone)]
struct ProxyService {
    config: Arc<Config>,
    peer: SocketAddr,
    listener_id: String,
    limits: LimitsConfig,
    client: Client<HttpConnector, ResponseBody>,
    shutdown: CancellationToken,
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
    async fn forward(&self, request: Request<Incoming>) -> Response<ResponseBody> {
        let Some(route) = select_route(&self.config, &request, &self.listener_id) else {
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
        if endpoint.url.scheme() != "http" {
            return error_response(
                StatusCode::NOT_IMPLEMENTED,
                "upstream TLS is not enabled in Phase 1\n",
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
        let (mut parts, body) = request.into_parts();
        let mut upstream_uri = endpoint.url.clone();
        upstream_uri.set_path(parts.uri.path());
        upstream_uri.set_query(parts.uri.query());
        let Ok(uri) = upstream_uri.as_str().parse::<Uri>() else {
            return error_response(StatusCode::BAD_GATEWAY, "invalid upstream URI\n");
        };
        parts.uri = uri;
        parts.headers.remove(CONNECTION);
        parts.headers.remove("keep-alive");
        parts.headers.remove("proxy-connection");
        parts.headers.remove(hyper::header::TRANSFER_ENCODING);
        if let Some(host) = endpoint.url.host_str() {
            if let Ok(value) = HeaderValue::from_str(host) {
                parts.headers.insert(HOST, value);
            }
        }
        let request = Request::from_parts(
            parts,
            body.map_err(|error| Box::new(error) as BoxError).boxed(),
        );
        let result = tokio::select! {
            _ = self.shutdown.cancelled() => return error_response(StatusCode::SERVICE_UNAVAILABLE, "proxy is shutting down\n"),
            result = self.client.request(request) => result,
        };
        match result {
            Ok(response) => {
                response.map(|body| body.map_err(|error| Box::new(error) as BoxError).boxed())
            }
            Err(error) => {
                tracing::debug!(peer = %self.peer, %error, "upstream request failed");
                error_response(StatusCode::BAD_GATEWAY, "upstream request failed\n")
            }
        }
    }
}

/// Choose the highest-priority route whose listener, host, path, and method match.
pub fn select_route<'a>(
    config: &'a Config,
    request: &Request<Incoming>,
    listener_id: &str,
) -> Option<&'a RouteConfig> {
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = request.uri().path();
    config
        .routes
        .iter()
        .filter(|route| route.listeners.iter().any(|id| id == listener_id))
        .filter(|route| {
            (route.hosts.is_empty()
                || route.hosts.iter().any(|candidate| {
                    candidate == &host
                        || candidate
                            .strip_prefix("*.")
                            .is_some_and(|suffix| host.ends_with(suffix))
                }))
                && (route.path_prefixes.is_empty()
                    || route.path_prefixes.iter().any(|prefix| {
                        path == prefix
                            || path
                                .strip_prefix(prefix)
                                .is_some_and(|rest| rest.starts_with('/'))
                    }))
                && (route.methods.is_empty()
                    || route
                        .methods
                        .iter()
                        .any(|method| method.eq_ignore_ascii_case(request.method().as_str())))
        })
        .max_by_key(|route| {
            (
                route.priority,
                route
                    .path_prefixes
                    .iter()
                    .map(String::len)
                    .max()
                    .unwrap_or(0),
                route.hosts.iter().map(String::len).max().unwrap_or(0),
            )
        })
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
