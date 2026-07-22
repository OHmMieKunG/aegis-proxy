use super::*;

pub(crate) fn build_upstream_clients(
    config: &Config,
) -> Result<(UpstreamClients, DnsEndpoints), ProxyError> {
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

pub(crate) fn build_upstream_pools(config: &Config) -> Result<UpstreamPools, ProxyError> {
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

pub(crate) fn endpoint_key(group_id: &str, endpoint_id: &str) -> String {
    format!("{group_id}/{endpoint_id}")
}

pub(crate) fn start_active_health_checks(
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

pub(crate) async fn active_health_probe(
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

pub(crate) fn endpoint_authority(endpoint: &EndpointConfig) -> Option<HeaderValue> {
    let host = endpoint.url.host_str()?;
    let port = endpoint.url.port()?;
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    HeaderValue::from_str(&authority).ok()
}

pub(crate) fn health_interval(endpoint_id: &str, policy: &HealthCheckConfig) -> Duration {
    let hash = endpoint_id.bytes().fold(2_166_136_261_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(16_777_619)
    });
    let percent = 90 + hash % 21;
    Duration::from_millis(policy.interval_secs * 1_000 * percent / 100)
}
