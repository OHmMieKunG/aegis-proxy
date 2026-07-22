use super::*;

pub(crate) fn prepare_tls(
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
pub(crate) struct ListenerContext {
    pub(crate) listener_id: String,
    pub(crate) runtime: RuntimeHandle,
    pub(crate) limits: LimitsConfig,
    pub(crate) handshake_permits: Arc<Semaphore>,
    pub(crate) shutdown: CancellationToken,
}

pub(crate) async fn accept_loop(listener: TcpListener, context: ListenerContext) {
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
