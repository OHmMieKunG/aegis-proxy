#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Data-plane HTTP forwarding primitives.

use std::{
    convert::Infallible, error::Error, future::Future, net::SocketAddr, pin::Pin, sync::Arc,
};

use aegisproxy_config::{Config, ConfigError, LimitsConfig, RouteConfig};
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::service::Service;
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{CONNECTION, HOST, HeaderValue, UPGRADE},
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Boxed body error.
pub type BoxError = Box<dyn Error + Send + Sync>;
/// Boxed response body used by the server and upstream client.
pub type ResponseBody = BoxBody<bytes::Bytes, BoxError>;

/// Proxy runtime error.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Invalid startup configuration.
    #[error("configuration failed validation: {0}")]
    Config(#[from] ConfigError),
    /// Listener bind failure.
    #[error("listener failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Run configured HTTP listeners until cancellation.
pub async fn run(config: Arc<Config>, shutdown: CancellationToken) -> Result<(), ProxyError> {
    aegisproxy_config::validate(&config)?;
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
        let config = Arc::clone(&config);
        let shutdown = shutdown.clone();
        let limits = limits.clone();
        let listener_id = listener_id.clone();
        let upgrade_tasks = upgrade_tasks.clone();
        connections.spawn(async move {
            let _permit = permit;
            if let Err(error) = serve_connection(
                stream,
                peer,
                listener_id,
                config,
                limits,
                shutdown,
                upgrade_tasks,
            )
            .await
            {
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

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    listener_id: String,
    config: Arc<Config>,
    limits: LimitsConfig,
    shutdown: CancellationToken,
    upgrade_tasks: TaskTracker,
) -> Result<(), hyper::Error> {
    let io = TokioIo::new(stream);
    let client = Client::builder(TokioExecutor::new()).build_http();
    let max_header_bytes = limits.max_header_bytes;
    let service = ProxyService {
        config,
        peer,
        listener_id,
        limits,
        client,
        shutdown: shutdown.clone(),
        upgrade_tasks,
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
        _ = shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    }
}

#[derive(Clone)]
struct ProxyService {
    config: Arc<Config>,
    peer: SocketAddr,
    listener_id: String,
    limits: LimitsConfig,
    client: Client<HttpConnector, ResponseBody>,
    shutdown: CancellationToken,
    upgrade_tasks: TaskTracker,
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
        if request.headers().contains_key(UPGRADE) && !websocket {
            return error_response(StatusCode::BAD_REQUEST, "invalid upgrade request\n");
        }
        let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
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
        strip_hop_by_hop_headers(&mut parts.headers, websocket);
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
            self.client.request(request),
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
                    strip_hop_by_hop_headers(response.headers_mut(), true);
                } else {
                    strip_hop_by_hop_headers(response.headers_mut(), false);
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
    if request.method() == hyper::Method::CONNECT
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
    {
        return Some(StatusCode::BAD_REQUEST);
    }
    if request.headers().get(HOST).is_none() {
        return Some(StatusCode::BAD_REQUEST);
    }
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
    if (!content_lengths.is_empty() && !transfer_encodings.is_empty())
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

fn strip_hop_by_hop_headers(headers: &mut hyper::HeaderMap, preserve_upgrade: bool) {
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
}

/// Choose the highest-priority route whose listener, host, path, and method match.
pub fn select_route<'a, B>(
    config: &'a Config,
    request: &Request<B>,
    listener_id: &str,
) -> Option<&'a RouteConfig> {
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(normalize_host)
        .unwrap_or_default();
    let path = request.uri().path();
    config
        .routes
        .iter()
        .filter(|route| route.listeners.iter().any(|id| id == listener_id))
        .filter(|route| {
            (route.hosts.is_empty()
                || route.hosts.iter().any(|candidate| {
                    let candidate = candidate.to_ascii_lowercase();
                    candidate == host
                        || candidate.strip_prefix("*.").is_some_and(|suffix| {
                            host.strip_suffix(suffix).is_some_and(|prefix| {
                                prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
                            })
                        })
                }))
                && (route.path_prefixes.is_empty()
                    || route.path_prefixes.iter().any(|prefix| {
                        prefix == "/"
                            || path == prefix
                            || path
                                .strip_prefix(prefix)
                                .is_some_and(|rest| rest.starts_with('/'))
                    }))
                && (route.methods.is_empty()
                    || route
                        .methods
                        .iter()
                        .any(|method| method.eq_ignore_ascii_case(request.method().as_str())))
                && route.headers.iter().all(|predicate| {
                    request
                        .headers()
                        .get(&predicate.name)
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| value == predicate.value)
                })
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

fn normalize_host(value: &str) -> String {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_owned();
    }
    value
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(value.clone(), |(host, _)| host.to_owned())
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
        AdminConfig, Config, EndpointConfig, LimitsConfig, ListenerConfig, RouteConfig,
        RuntimeConfig, TrustedProxyConfig, UpstreamGroupConfig,
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

    fn config(route: RouteConfig) -> Config {
        Config {
            schema_version: 1,
            runtime: RuntimeConfig::default(),
            limits: LimitsConfig::default(),
            listeners: vec![ListenerConfig {
                id: "public".into(),
                bind: "127.0.0.1:8080".parse().expect("address"),
                protocol: "http".into(),
            }],
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
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
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

    #[test]
    fn route_matching_is_deterministic_and_header_aware() {
        let route = RouteConfig {
            id: "app".into(),
            listeners: vec!["public".into()],
            hosts: vec!["*.example.test".into()],
            path_prefixes: vec!["/api".into()],
            methods: vec!["GET".into()],
            headers: vec![aegisproxy_config::HeaderMatch {
                name: "x-tenant".into(),
                value: "blue".into(),
            }],
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
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
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
            .write_all(b"GET /hello HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
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
            path_prefixes: vec!["/ws".into()],
            methods: vec![],
            headers: vec![],
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
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
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
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
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
