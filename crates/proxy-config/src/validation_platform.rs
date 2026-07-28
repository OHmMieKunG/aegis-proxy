use super::*;

pub(crate) fn validate_admin(admin: &AdminConfig) -> Result<(), ConfigError> {
    if let Some(socket) = admin.unix_socket.as_deref() {
        let path = Path::new(socket);
        if socket.is_empty()
            || socket.len() > 4_096
            || socket.bytes().any(|byte| byte.is_ascii_control())
            || !path.is_absolute()
            || path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(ConfigError::Invalid(
                "admin.unix_socket must be an absolute path without parent traversal".into(),
            ));
        }
    }
    if admin.allowed_uids.len() > 64
        || admin
            .allowed_uids
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != admin.allowed_uids.len()
    {
        return Err(ConfigError::Invalid(
            "admin.allowed_uids must contain at most 64 unique values".into(),
        ));
    }
    if let Some(reference) = admin.audit_key.as_deref() {
        SecretRef::parse(reference).map_err(|_| {
            ConfigError::Invalid("admin.audit_key has an invalid secret reference".into())
        })?;
    }
    if !(1..=1024 * 1024).contains(&admin.max_body_bytes)
        || !(1..=256).contains(&admin.max_in_flight)
        || !(1..=32).contains(&admin.max_auth_in_flight)
        || !(1..=60).contains(&admin.request_timeout_secs)
        || !(1..=1_000).contains(&admin.requests_per_second)
        || admin.burst < admin.requests_per_second
        || admin.burst > 5_000
    {
        return Err(ConfigError::Invalid(
            "administrative resource limits are outside safe bounds".into(),
        ));
    }
    validate_admin_web(&admin.web)?;
    Ok(())
}

fn validate_admin_web(web: &AdminWebConfig) -> Result<(), ConfigError> {
    if !web.bind.ip().is_loopback() || web.bind.port() == 0 {
        return Err(ConfigError::Invalid(
            "admin.web.bind must use a nonzero loopback address".into(),
        ));
    }
    let expected_origin = format!("http://localhost:{}", web.bind.port());
    if web.origin != expected_origin {
        return Err(ConfigError::Invalid(format!(
            "admin.web.origin must be exactly {expected_origin}"
        )));
    }
    let Some(oidc) = &web.oidc else {
        if web.enabled {
            return Err(ConfigError::Invalid(
                "admin.web.oidc is required when browser administration is enabled".into(),
            ));
        }
        return Ok(());
    };
    validate_admin_oidc(oidc)?;
    if web.enabled && oidc.groups.admin.is_empty() {
        return Err(ConfigError::Invalid(
            "admin.web.oidc.groups.admin requires at least one group".into(),
        ));
    }
    Ok(())
}

fn validate_admin_oidc(oidc: &AdminWebOidcConfig) -> Result<(), ConfigError> {
    let issuer = Url::parse(&oidc.issuer)
        .map_err(|_| ConfigError::Invalid("admin.web.oidc.issuer is invalid".into()))?;
    let canonical_without_root = issuer
        .path()
        .eq("/")
        .then(|| issuer.as_str().strip_suffix('/'))
        .flatten();
    if oidc.issuer.len() > 2_048
        || issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
        || (oidc.issuer != issuer.as_str() && canonical_without_root != Some(&oidc.issuer))
    {
        return Err(ConfigError::Invalid(
            "admin.web.oidc.issuer must be a canonical HTTPS URL without credentials, query, or fragment"
                .into(),
        ));
    }
    if oidc.client_id.is_empty()
        || oidc.client_id.len() > 256
        || oidc.client_id.chars().any(char::is_control)
    {
        return Err(ConfigError::Invalid(
            "admin.web.oidc.client_id is outside safe bounds".into(),
        ));
    }
    for (field, reference) in [
        ("client_secret", Some(oidc.client_secret.as_str())),
        ("ca_bundle", oidc.ca_bundle.as_deref()),
    ] {
        if let Some(reference) = reference {
            SecretRef::parse(reference).map_err(|_| {
                ConfigError::Invalid(format!(
                    "admin.web.oidc.{field} has an invalid secret reference"
                ))
            })?;
        }
    }
    if oidc.groups_claim.is_empty()
        || oidc.groups_claim.len() > 128
        || oidc.groups_claim.chars().any(char::is_control)
    {
        return Err(ConfigError::Invalid(
            "admin.web.oidc.groups_claim is outside safe bounds".into(),
        ));
    }
    let groups = [
        &oidc.groups.viewer,
        &oidc.groups.auditor,
        &oidc.groups.operator,
        &oidc.groups.admin,
    ];
    if groups.iter().any(|groups| groups.len() > 64)
        || groups.iter().map(|groups| groups.len()).sum::<usize>() > 256
    {
        return Err(ConfigError::Invalid(
            "admin.web.oidc role group lists exceed safe bounds".into(),
        ));
    }
    let mut unique = HashSet::new();
    for group in groups.into_iter().flatten() {
        if group.is_empty()
            || group.len() > 256
            || group.chars().any(char::is_control)
            || !unique.insert(group)
        {
            return Err(ConfigError::Invalid(
                "admin.web.oidc group names must be bounded, nonempty, and unique across roles"
                    .into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_providers(config: &Config) -> Result<(), ConfigError> {
    use provider::ProviderConfig;

    if config.providers.len() > provider::MAX_PROVIDERS {
        return Err(ConfigError::Invalid(format!(
            "providers exceeds {} entries",
            provider::MAX_PROVIDERS
        )));
    }
    let groups: HashMap<_, _> = config
        .upstream_groups
        .iter()
        .map(|group| (group.id.as_str(), group))
        .collect();
    let mut ids = HashSet::new();
    let mut namespaces = HashSet::new();
    for (index, provider) in config.providers.iter().enumerate() {
        valid_id(provider.id())?;
        if !ids.insert(provider.id()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate provider id {}",
                provider.id()
            )));
        }
        if !namespaces.insert(provider.upstream_group()) {
            return Err(ConfigError::Invalid(format!(
                "providers assign upstream group {} more than once",
                provider.upstream_group()
            )));
        }
        let group = groups.get(provider.upstream_group()).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "providers[{index}] references unknown upstream group {}",
                provider.upstream_group()
            ))
        })?;
        if !(1..=300).contains(&provider.refresh_secs())
            || provider.stale_after_secs() < provider.refresh_secs()
            || provider.stale_after_secs() > 86_400
        {
            return Err(ConfigError::Invalid(format!(
                "provider {} refresh/stale durations are outside safe bounds",
                provider.id()
            )));
        }
        match provider {
            ProviderConfig::File(provider) => {
                let path = Path::new(&provider.path);
                if provider.path.len() > 4_096
                    || !path.is_absolute()
                    || path.file_name().is_none()
                    || provider.path.contains(['$', '~'])
                    || provider.path.bytes().any(|byte| byte.is_ascii_control())
                    || path
                        .components()
                        .any(|component| component == std::path::Component::ParentDir)
                {
                    return Err(ConfigError::Invalid(format!(
                        "provider {} path must be absolute, bounded, and contain no expansion or traversal",
                        provider.id
                    )));
                }
                if !(50..=5_000).contains(&provider.debounce_millis)
                    || !(1..=MAX_ENDPOINTS_PER_GROUP).contains(&provider.max_endpoints)
                {
                    return Err(ConfigError::Invalid(format!(
                        "provider {} debounce or endpoint bound is invalid",
                        provider.id
                    )));
                }
                validate_provider_template(
                    &provider.id,
                    provider.scheme,
                    provider.server_name.as_deref(),
                    provider.ca_bundle.as_deref(),
                    group,
                )?;
            }
            ProviderConfig::Dns(provider) => {
                valid_upstream_host(&provider.hostname).map_err(|reason| {
                    ConfigError::Invalid(format!(
                        "provider {} has invalid DNS hostname: {reason}",
                        provider.id
                    ))
                })?;
                if provider.hostname.parse::<IpAddr>().is_ok()
                    || provider.port == 0
                    || provider.weight == 0
                    || provider.weight > 10_000
                    || !(1..=64).contains(&provider.max_answers)
                {
                    return Err(ConfigError::Invalid(format!(
                        "provider {} DNS port, weight, or answer bound is invalid",
                        provider.id
                    )));
                }
                validate_provider_template(
                    &provider.id,
                    provider.scheme,
                    provider.server_name.as_deref(),
                    provider.ca_bundle.as_deref(),
                    group,
                )?;
            }
        }
    }
    Ok(())
}

fn validate_provider_template(
    id: &str,
    scheme: provider::ProviderScheme,
    server_name: Option<&str>,
    ca_bundle: Option<&str>,
    group: &UpstreamGroupConfig,
) -> Result<(), ConfigError> {
    let expected = scheme.as_str();
    if group
        .endpoints
        .iter()
        .any(|endpoint| endpoint.url.scheme() != expected)
    {
        return Err(ConfigError::Invalid(format!(
            "provider {id} transport differs from upstream group {}",
            group.id
        )));
    }
    match scheme {
        provider::ProviderScheme::Https => {
            let server_name = server_name
                .filter(|name| !name.starts_with("*."))
                .ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "HTTPS provider {id} requires an exact server_name"
                    ))
                })?;
            valid_certificate_host(server_name)?;
            if let Some(reference) = ca_bundle {
                SecretRef::parse(reference).map_err(|_| {
                    ConfigError::Invalid(format!(
                        "provider {id} has an invalid CA bundle reference"
                    ))
                })?;
            }
        }
        provider::ProviderScheme::Http | provider::ProviderScheme::Tcp => {
            if server_name.is_some() || ca_bundle.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "non-HTTPS provider {id} cannot set TLS policy"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_observability(config: &Config) -> Result<(), ConfigError> {
    let observability = &config.observability;
    if observability.access_log_sample_per_million > 1_000_000 {
        return Err(ConfigError::Invalid(
            "observability.access_log_sample_per_million exceeds 1000000".into(),
        ));
    }
    let estimated_series = estimated_metric_series(config);
    if estimated_series > MAX_METRIC_SERIES {
        return Err(ConfigError::Invalid(format!(
            "observability metrics could create {estimated_series} series, exceeding {MAX_METRIC_SERIES}; reduce route/listener combinations or disable metrics"
        )));
    }
    let Some(otlp) = &observability.otlp_traces else {
        return Ok(());
    };
    let endpoint = &otlp.endpoint;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ConfigError::Invalid(
            "observability.otlp_traces.endpoint must be an HTTP(S) URL without credentials, query, or fragment"
                .into(),
        ));
    }
    if endpoint.scheme() == "http" {
        let is_loopback = endpoint
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if !is_loopback {
            return Err(ConfigError::Invalid(
                "observability.otlp_traces.endpoint requires HTTPS unless it uses a loopback IP"
                    .into(),
            ));
        }
    }
    if otlp.sample_per_million == 0
        || otlp.sample_per_million > 1_000_000
        || otlp.max_queue_size == 0
        || otlp.max_queue_size > 16_384
        || otlp.max_export_batch_size == 0
        || otlp.max_export_batch_size > otlp.max_queue_size
        || otlp.export_timeout_secs == 0
        || otlp.export_timeout_secs > 30
    {
        return Err(ConfigError::Invalid(
            "observability.otlp_traces limits are outside safe bounds".into(),
        ));
    }
    Ok(())
}

/// Calculate the worst-case OpenMetrics series count for the current families.
#[must_use]
pub fn estimated_metric_series(config: &Config) -> usize {
    if !config.observability.metrics {
        return 0;
    }
    let route_listener_pairs = config
        .routes
        .iter()
        .fold(config.listeners.len(), |total, route| {
            total.saturating_add(route.listeners.len())
        });
    let endpoint_count = config.upstream_groups.iter().fold(0_usize, |total, group| {
        total.saturating_add(group.endpoints.len())
    });
    let rate_limiters = config
        .middlewares
        .values()
        .filter(|middleware| matches!(middleware, MiddlewareConfig::RateLimit { .. }))
        .count();
    let certificate_count = config
        .certificates
        .len()
        .saturating_add(config.acme.certificates.len());
    route_listener_pairs
        .saturating_mul(170)
        .saturating_add(endpoint_count.saturating_mul(17))
        .saturating_add(rate_limiters.saturating_mul(3))
        .saturating_add(config.listeners.len().saturating_mul(6))
        .saturating_add(certificate_count.saturating_mul(4))
        .saturating_add(config.providers.len().saturating_mul(4))
        .saturating_add(14)
}
