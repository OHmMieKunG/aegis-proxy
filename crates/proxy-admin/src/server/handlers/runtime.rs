use super::super::*;

pub(in crate::server) async fn routes(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<RouteSummary>>, ApiError> {
    authorize(&principal, Action::ReadRoutes)?;
    let mut routes: Vec<_> = state
        .control
        .runtime()
        .config()
        .routes
        .iter()
        .map(|route| RouteSummary {
            id: route.id.clone(),
            listeners: route.listeners.clone(),
            hosts: route.hosts.clone(),
            paths: route.paths.clone(),
            path_prefixes: route.path_prefixes.clone(),
            methods: route.methods.clone(),
            default: route.default,
            priority: route.priority,
            middlewares: route.middlewares.clone(),
            upstream_group: route.upstream_group.clone(),
        })
        .collect();
    routes.sort_unstable_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(axum::Json(routes))
}

pub(in crate::server) async fn upstreams(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<UpstreamSummary>>, ApiError> {
    authorize(&principal, Action::ReadUpstreams)?;
    let mut groups: Vec<_> = state
        .control
        .runtime()
        .config()
        .upstream_groups
        .iter()
        .map(|group| UpstreamSummary {
            id: group.id.clone(),
            algorithm: group.algorithm,
            max_in_flight: group.max_in_flight,
            endpoints: group
                .endpoints
                .iter()
                .map(|endpoint| EndpointSummary {
                    id: endpoint.id.clone(),
                    transport: endpoint.url.scheme().to_owned(),
                    weight: endpoint.weight,
                    state: "configured",
                })
                .collect(),
        })
        .collect();
    groups.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(axum::Json(groups))
}

pub(in crate::server) async fn providers(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<ProviderSummary>>, ApiError> {
    authorize(&principal, Action::ReadUpstreams)?;
    Ok(axum::Json(
        state
            .control
            .provider_statuses()
            .into_iter()
            .map(provider_summary)
            .collect(),
    ))
}

pub(in crate::server) fn provider_summary(
    status: aegisproxy_core::ProviderStatus,
) -> ProviderSummary {
    ProviderSummary {
        id: status.id,
        kind: status.kind,
        state: status.state,
        source_hash: status.source_hash,
        last_success_unix_secs: status.last_success_unix_secs,
        stale_at_unix_secs: status.stale_at_unix_secs,
        endpoint_count: status.endpoint_count,
        error: status.error,
    }
}

pub(in crate::server) async fn runtime_certificates(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<axum::Json<Vec<CertificateSummary>>, ApiError> {
    authorize(&principal, Action::ReadCertificates)?;
    let config = state.control.runtime().config();
    let stored = state
        .control
        .certificate_statuses()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let mut stored: HashMap<_, _> = stored
        .into_iter()
        .map(|certificate| (certificate.id.clone(), certificate))
        .collect();
    let mut certificates = Vec::with_capacity(
        config
            .certificates
            .len()
            .saturating_add(config.acme.certificates.len()),
    );
    for certificate in &config.certificates {
        certificates.push(certificate_summary(
            certificate.id.clone(),
            certificate.hosts.clone(),
            "imported",
            None,
            stored.remove(&certificate.id),
        ));
    }
    for certificate in &config.acme.certificates {
        certificates.push(certificate_summary(
            certificate.id.clone(),
            certificate.hosts.clone(),
            "acme",
            Some(certificate.issuer.clone()),
            stored.remove(&certificate.id),
        ));
    }
    certificates.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(axum::Json(certificates))
}

fn certificate_summary(
    id: String,
    hosts: Vec<String>,
    source: &'static str,
    fallback_issuer: Option<String>,
    stored: Option<aegisproxy_core::CertificateStatus>,
) -> CertificateSummary {
    CertificateSummary {
        id,
        hosts,
        source,
        issuer: stored
            .as_ref()
            .map_or(fallback_issuer, |stored| Some(stored.issuer.clone())),
        generation: stored.as_ref().map(|stored| stored.generation.clone()),
        not_before_unix_secs: stored.as_ref().map(|stored| stored.not_before_unix_secs),
        not_after_unix_secs: stored.as_ref().map(|stored| stored.not_after_unix_secs),
        state: if stored.is_some() {
            "active"
        } else {
            "missing"
        },
    }
}
