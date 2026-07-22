use super::*;

pub(crate) fn validate_tcp_route(
    route: &RouteConfig,
    tls_passthrough: bool,
) -> Result<(), ConfigError> {
    if !route.paths.is_empty()
        || !route.path_prefixes.is_empty()
        || !route.methods.is_empty()
        || !route.headers.is_empty()
        || !route.middlewares.is_empty()
        || route.priority != 0
    {
        return Err(ConfigError::Invalid(format!(
            "TCP-family route {} cannot use HTTP matchers, middleware, or priority",
            route.id
        )));
    }
    if tls_passthrough {
        if !route.default && route.hosts.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "TLS passthrough route {} requires an SNI host or default = true",
                route.id
            )));
        }
    } else if !route.default || !route.hosts.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "plain TCP route {} must be an explicit default route",
            route.id
        )));
    }
    Ok(())
}

pub(crate) fn validate_upstream_policy(
    group_index: usize,
    group: &UpstreamGroupConfig,
) -> Result<(), ConfigError> {
    let field = |name: &str| format!("upstream_groups[{group_index}].{name}");
    if group.dns.max_answers == 0
        || group.dns.max_answers > 64
        || group.dns.lookup_timeout_secs == 0
        || group.dns.lookup_timeout_secs > 30
        || group.dns.min_ttl_secs == 0
        || group.dns.min_ttl_secs > group.dns.max_ttl_secs
        || group.dns.max_ttl_secs > 86_400
        || group.dns.stale_timeout_secs > 3_600
    {
        return Err(ConfigError::Invalid(format!(
            "{} contains an unsafe answer, timeout, TTL, or stale bound",
            field("dns")
        )));
    }
    if group.drain_timeout_secs == 0 || group.drain_timeout_secs > 3_600 {
        return Err(ConfigError::Invalid(format!(
            "{} is outside 1..=3600",
            field("drain_timeout_secs")
        )));
    }
    if group.max_in_flight == 0 || group.max_in_flight > 100_000 {
        return Err(ConfigError::Invalid(format!(
            "{} is outside 1..=100000",
            field("max_in_flight")
        )));
    }
    let passive = &group.passive_health;
    if passive.failure_threshold == 0
        || passive.failure_threshold > 100
        || passive.healthy_threshold == 0
        || passive.healthy_threshold > 100
        || passive.window_secs == 0
        || passive.window_secs > 3_600
        || passive.max_samples == 0
        || passive.max_samples > 1_024
        || passive.failure_threshold as usize > passive.max_samples
    {
        return Err(ConfigError::Invalid(format!(
            "{} contains an unsafe threshold, window, or sample bound",
            field("passive_health")
        )));
    }
    let retry = &group.retry;
    if retry.max_attempts == 0
        || retry.max_attempts > 5
        || retry.total_timeout_secs == 0
        || retry.total_timeout_secs > 300
        || retry.replay_body_bytes > 1024 * 1024
    {
        return Err(ConfigError::Invalid(format!(
            "{} contains an unsafe attempt, time, or replay-body bound",
            field("retry")
        )));
    }
    if let Some(health) = &group.health {
        if health.interval_secs == 0
            || health.interval_secs > 3_600
            || health.timeout_secs == 0
            || health.timeout_secs >= health.interval_secs
            || health.unhealthy_threshold == 0
            || health.unhealthy_threshold > 100
            || health.healthy_threshold == 0
            || health.healthy_threshold > 100
        {
            return Err(ConfigError::Invalid(format!(
                "{} contains an unsafe interval, timeout, or threshold",
                field("health")
            )));
        }
        match health.kind {
            HealthCheckKind::Http => {
                let method = Method::from_bytes(health.method.as_bytes()).map_err(|_| {
                    ConfigError::Invalid(format!("{}.method is invalid", field("health")))
                })?;
                if !matches!(method, Method::GET | Method::HEAD) {
                    return Err(ConfigError::Invalid(format!(
                        "{}.method must be GET or HEAD",
                        field("health")
                    )));
                }
                validate_path(
                    &format!("upstream group {} health", group.id),
                    &health.path,
                    false,
                )?;
                if health.expected_statuses.is_empty()
                    || health.expected_statuses.len() > 32
                    || health
                        .expected_statuses
                        .iter()
                        .any(|status| !(100..=599).contains(status))
                    || health
                        .expected_statuses
                        .iter()
                        .collect::<HashSet<_>>()
                        .len()
                        != health.expected_statuses.len()
                {
                    return Err(ConfigError::Invalid(format!(
                        "{}.expected_statuses must contain 1..=32 unique HTTP statuses",
                        field("health")
                    )));
                }
            }
            HealthCheckKind::Tcp => {
                if health.method != "GET" || health.path != "/" || health.expected_statuses != [200]
                {
                    return Err(ConfigError::Invalid(format!(
                        "{} TCP probes cannot configure HTTP fields",
                        field("health")
                    )));
                }
            }
        }
    }
    if let Some(circuit) = &group.circuit_breaker
        && (circuit.sample_size == 0
            || circuit.sample_size > 10_000
            || circuit.minimum_requests == 0
            || circuit.minimum_requests > circuit.sample_size
            || circuit.failure_percent == 0
            || circuit.failure_percent > 100
            || circuit.open_secs == 0
            || circuit.open_secs > 3_600
            || circuit.half_open_requests == 0
            || circuit.half_open_requests > 100)
    {
        return Err(ConfigError::Invalid(format!(
            "{} contains an unsafe sample, threshold, or half-open bound",
            field("circuit_breaker")
        )));
    }
    Ok(())
}

pub(crate) fn validate_route_matchers(route: &RouteConfig) -> Result<(), ConfigError> {
    if route.default {
        if !route.hosts.is_empty()
            || !route.paths.is_empty()
            || !route.path_prefixes.is_empty()
            || !route.methods.is_empty()
            || !route.headers.is_empty()
            || route.priority != 0
        {
            return Err(ConfigError::Invalid(format!(
                "route {} is default and cannot contain matchers or a nonzero priority",
                route.id
            )));
        }
        return Ok(());
    }

    if route.hosts.is_empty()
        && route.paths.is_empty()
        && route.methods.is_empty()
        && route.headers.is_empty()
        && (route.path_prefixes.is_empty()
            || route.path_prefixes.iter().any(|prefix| prefix == "/"))
    {
        return Err(ConfigError::Invalid(format!(
            "route {} is a catch-all and must set default = true",
            route.id
        )));
    }

    let mut hosts = HashSet::new();
    for host in &route.hosts {
        valid_certificate_host(host).map_err(|_| {
            ConfigError::Invalid(format!("route {} has invalid host {host:?}", route.id))
        })?;
        if !hosts.insert(host.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate host {host:?}",
                route.id
            )));
        }
    }

    let mut exact_paths = HashSet::new();
    for path in &route.paths {
        validate_path(&route.id, path, false)?;
        if !exact_paths.insert(path.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate exact path {path:?}",
                route.id
            )));
        }
    }

    let mut paths = HashSet::new();
    for prefix in &route.path_prefixes {
        validate_path(&route.id, prefix, true)?;
        if !paths.insert(prefix.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate path prefix {prefix:?}",
                route.id
            )));
        }
    }

    let mut methods = HashSet::new();
    for method in &route.methods {
        let parsed = Method::from_bytes(method.as_bytes()).map_err(|_| {
            ConfigError::Invalid(format!("route {} has invalid method {method:?}", route.id))
        })?;
        if parsed.as_str() != method
            || method.bytes().any(|byte| byte.is_ascii_lowercase())
            || parsed == Method::CONNECT
        {
            return Err(ConfigError::Invalid(format!(
                "route {} method {method:?} is not canonical or supported",
                route.id
            )));
        }
        if !methods.insert(method.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate method {method:?}",
                route.id
            )));
        }
    }

    let mut headers = HashSet::new();
    for predicate in &route.headers {
        let name = HeaderName::from_bytes(predicate.name.as_bytes()).map_err(|_| {
            ConfigError::Invalid(format!(
                "route {} has invalid header name {:?}",
                route.id, predicate.name
            ))
        })?;
        if let Some(value) = &predicate.value {
            if value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(ConfigError::Invalid(format!(
                    "route {} header {} value exceeds {MAX_HEADER_VALUE_BYTES} bytes",
                    route.id, predicate.name
                )));
            }
            HeaderValue::try_from(value.as_str()).map_err(|_| {
                ConfigError::Invalid(format!(
                    "route {} header {} has an invalid value",
                    route.id, predicate.name
                ))
            })?;
        }
        if name.as_str() != predicate.name || prohibited_route_header(&name) {
            return Err(ConfigError::Invalid(format!(
                "route {} header {:?} is not canonical or routable",
                route.id, predicate.name
            )));
        }
        if !headers.insert(name) {
            return Err(ConfigError::Invalid(format!(
                "route {} contains duplicate header predicate {:?}",
                route.id, predicate.name
            )));
        }
    }
    Ok(())
}

fn validate_path(route_id: &str, path: &str, prefix: bool) -> Result<(), ConfigError> {
    let valid = !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path.is_ascii()
        && path.starts_with('/')
        && !path.contains('%')
        && !path.contains('\\')
        && !path.contains('?')
        && !path.contains('#')
        && !path.contains("//")
        && (!prefix || path == "/" || !path.ends_with('/'))
        && !path.split('/').any(|segment| matches!(segment, "." | ".."));
    if !valid {
        return Err(ConfigError::Invalid(format!(
            "route {route_id} has non-canonical path {path:?}"
        )));
    }
    Ok(())
}

fn prohibited_route_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "content-length"
            | "host"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub(crate) fn validate_unique_strings(
    route_id: &str,
    field: &str,
    values: &[String],
) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route {route_id} contains duplicate {field} reference {value:?}"
            )));
        }
    }
    Ok(())
}

/// Validate one resolved upstream address against the configured egress policy.
pub fn validate_egress_ip(
    ip: IpAddr,
    allowed: &[IpNet],
    denied: &[IpNet],
) -> Result<(), &'static str> {
    if ip.is_unspecified() || ip.is_multicast() {
        return Err("unspecified and multicast addresses are forbidden");
    }
    let link_local = match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    };
    if link_local {
        return Err("link-local addresses are forbidden");
    }
    if denied.iter().any(|network| network.contains(&ip)) {
        return Err("address is explicitly denied");
    }
    let private = match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00 || ip.is_loopback(),
    };
    if private && !allowed.iter().any(|network| network.contains(&ip)) {
        return Err("private or loopback address requires allowed_cidrs");
    }
    Ok(())
}

pub(crate) fn valid_upstream_host(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 253 || value != value.to_ascii_lowercase() {
        return Err("name must be bounded lowercase ASCII");
    }
    if value.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err("name contains an invalid DNS label");
    }
    Ok(())
}

pub(crate) fn valid_id(value: &str) -> Result<(), ConfigError> {
    let bytes = value.as_bytes();
    let valid = bytes.first().is_some_and(u8::is_ascii_lowercase)
        && value.len() <= 63
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        });
    if !valid {
        return Err(ConfigError::Invalid(format!(
            "invalid identifier {value:?}"
        )));
    }
    Ok(())
}

pub(crate) fn valid_certificate_host(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.to_ascii_lowercase()
        || value.ends_with('.')
        || value.contains(':')
    {
        return Err(ConfigError::Invalid(format!(
            "invalid certificate host {value:?}"
        )));
    }
    let name = value.strip_prefix("*.").unwrap_or(value);
    if value.contains('*') && !value.starts_with("*.") || name.split('.').count() < 2 {
        return Err(ConfigError::Invalid(format!(
            "invalid certificate wildcard {value:?}"
        )));
    }
    if name.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err(ConfigError::Invalid(format!(
            "invalid certificate host {value:?}"
        )));
    }
    Ok(())
}

/// Validate one exact canonical ASCII host name used by typed control-plane objects.
pub fn validate_exact_host(value: &str) -> Result<(), ConfigError> {
    if value.contains('*') {
        return Err(ConfigError::Invalid(
            "wildcard hosts are unsupported for this object".into(),
        ));
    }
    valid_certificate_host(value)
}

/// Validate one canonical ASCII DNS upstream name without performing resolution.
pub fn validate_upstream_hostname(value: &str) -> Result<(), ConfigError> {
    valid_upstream_host(value).map_err(|message| ConfigError::Invalid(message.into()))
}
