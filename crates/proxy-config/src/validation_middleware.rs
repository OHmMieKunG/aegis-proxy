use super::*;

pub(crate) fn validate_middleware(
    id: &str,
    middleware: &MiddlewareConfig,
) -> Result<(), ConfigError> {
    match middleware {
        MiddlewareConfig::SecurityHeaders {
            hsts,
            content_security_policy,
            acknowledge_hsts_risk,
            ..
        } => {
            if hsts.is_none() && content_security_policy.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} has no security headers"
                )));
            }
            if let Some(value) = hsts {
                validate_header_value(id, "hsts", value)?;
                let mut max_age = None;
                let mut persistent = false;
                for directive in value.split(';').map(str::trim) {
                    if let Some(value) = directive
                        .to_ascii_lowercase()
                        .strip_prefix("max-age=")
                        .map(str::to_owned)
                    {
                        if max_age.replace(value).is_some() {
                            return Err(ConfigError::Invalid(format!(
                                "middleware {id} repeats HSTS max-age"
                            )));
                        }
                    } else if directive.eq_ignore_ascii_case("includesubdomains")
                        || directive.eq_ignore_ascii_case("preload")
                    {
                        persistent = true;
                    } else {
                        return Err(ConfigError::Invalid(format!(
                            "middleware {id} contains an unsupported HSTS directive"
                        )));
                    }
                }
                if max_age
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|seconds| *seconds <= 63_072_000)
                    .is_none()
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} HSTS requires max-age within 0..=63072000"
                    )));
                }
                if persistent && !acknowledge_hsts_risk {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} must acknowledge HSTS subdomain/preload risk"
                    )));
                }
            }
            if let Some(value) = content_security_policy {
                validate_header_value(id, "content_security_policy", value)?;
            }
        }
        MiddlewareConfig::RateLimit {
            key: _,
            requests_per_second,
            burst,
            max_keys,
            idle_secs,
        } => {
            if !(1..=1_000_000).contains(requests_per_second)
                || !(1..=1_000_000).contains(burst)
                || !(1..=100_000).contains(max_keys)
                || !(1..=86_400).contains(idle_secs)
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} rate limit is outside safe bounds"
                )));
            }
        }
        MiddlewareConfig::InFlightLimit {
            max_requests,
            max_per_client,
            status,
        } => {
            if !(1..=100_000).contains(max_requests)
                || !(1..=*max_requests).contains(max_per_client)
                || !matches!(*status, 429 | 503)
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} in-flight limit is outside safe bounds"
                )));
            }
        }
        MiddlewareConfig::IpPolicy { allow, deny } => {
            if allow.len() > MAX_MIDDLEWARE_CIDRS
                || deny.len() > MAX_MIDDLEWARE_CIDRS
                || (allow.is_empty() && deny.is_empty())
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} IP policy is empty or exceeds CIDR bounds"
                )));
            }
            let mut cidrs = HashSet::new();
            if allow.iter().chain(deny).any(|cidr| !cidrs.insert(cidr)) {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} IP policy contains duplicate CIDRs"
                )));
            }
        }
        MiddlewareConfig::Cors {
            origins,
            methods,
            headers,
            allow_credentials,
            max_age_secs,
        } => {
            if origins.is_empty()
                || origins.len() > 64
                || methods.is_empty()
                || methods.len() > 32
                || headers.len() > 64
                || *max_age_secs > 86_400
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} CORS policy exceeds safe bounds"
                )));
            }
            let wildcard = origins.iter().any(|origin| origin == "*");
            if wildcard && (origins.len() != 1 || *allow_credentials) {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} CORS wildcard cannot mix origins or credentials"
                )));
            }
            let mut unique = HashSet::new();
            for origin in origins.iter().filter(|origin| origin.as_str() != "*") {
                if origin.len() > MAX_HEADER_VALUE_BYTES {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an oversized CORS origin"
                    )));
                }
                let url = Url::parse(origin).map_err(|_| {
                    ConfigError::Invalid(format!("middleware {id} has an invalid CORS origin"))
                })?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || url.origin().ascii_serialization() != *origin
                    || !unique.insert(origin)
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an unsafe or duplicate CORS origin"
                    )));
                }
            }
            unique.clear();
            for method in methods {
                if method.len() > 32 {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an oversized CORS method"
                    )));
                }
                let parsed = Method::from_bytes(method.as_bytes()).map_err(|_| {
                    ConfigError::Invalid(format!("middleware {id} has an invalid CORS method"))
                })?;
                if parsed == Method::CONNECT || parsed.as_str() != method || !unique.insert(method)
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an unsafe or duplicate CORS method"
                    )));
                }
            }
            unique.clear();
            for header in headers {
                if header.len() > 64 {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an oversized CORS header"
                    )));
                }
                let parsed = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                    ConfigError::Invalid(format!("middleware {id} has an invalid CORS header"))
                })?;
                if parsed.as_str() != header || !unique.insert(header) {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} requires lowercase unique CORS headers"
                    )));
                }
            }
        }
        MiddlewareConfig::BasicAuth {
            realm,
            users,
            max_concurrent_verifications,
            timeout_secs,
        } => {
            if realm.is_empty()
                || realm.len() > 64
                || !realm.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.')
                })
                || users.is_empty()
                || users.len() > 64
                || !(1..=1_024).contains(max_concurrent_verifications)
                || !(1..=30).contains(timeout_secs)
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} Basic authentication policy exceeds safe bounds"
                )));
            }
            for (username, reference) in users {
                if username.is_empty()
                    || username.len() > 64
                    || !username
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b':' | b'"' | b'\\'))
                    || SecretRef::parse(reference).is_err()
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an invalid Basic authentication user"
                    )));
                }
            }
        }
        MiddlewareConfig::ForwardAuth {
            upstream_group,
            path,
            request_headers,
            response_headers,
            principal_header,
            redirect_hosts,
            timeout_secs,
        } => {
            valid_id(upstream_group)?;
            validate_rewrite_path(id, path, false)?;
            if request_headers.len() > 32
                || response_headers.is_empty()
                || response_headers.len() > 32
                || redirect_hosts.len() > 16
                || !(1..=10).contains(timeout_secs)
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} ForwardAuth policy exceeds safe bounds"
                )));
            }
            validate_forward_auth_headers(id, "request", request_headers, true)?;
            validate_forward_auth_headers(id, "response", response_headers, false)?;
            let principal = validate_forward_auth_header(id, "principal", principal_header, false)?;
            if !principal.starts_with("x-")
                || !response_headers.iter().any(|name| name == principal)
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} ForwardAuth principal_header must be response-allowlisted"
                )));
            }
            let mut hosts = HashSet::new();
            for host in redirect_hosts {
                if host.starts_with("*.")
                    || host != &host.to_ascii_lowercase()
                    || !hosts.insert(host.as_str())
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an unsafe or duplicate ForwardAuth redirect host"
                    )));
                }
                valid_certificate_host(host)?;
            }
        }
        MiddlewareConfig::Rewrite { from_prefix, to } => {
            validate_rewrite_path(id, to, from_prefix.is_some())?;
            if let Some(from_prefix) = from_prefix {
                validate_rewrite_path(id, from_prefix, true)?;
                if from_prefix == to {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} rewrite does not change the path"
                    )));
                }
            }
        }
        MiddlewareConfig::HeaderMutation {
            request_set,
            request_add,
            request_remove,
            response_set,
            response_add,
            response_remove,
        } => {
            validate_header_mutations(
                id,
                "request",
                request_set,
                request_add,
                request_remove,
                true,
            )?;
            validate_header_mutations(
                id,
                "response",
                response_set,
                response_add,
                response_remove,
                false,
            )?;
            let operations = request_set.len()
                + request_add.values().map(Vec::len).sum::<usize>()
                + request_remove.len()
                + response_set.len()
                + response_add.values().map(Vec::len).sum::<usize>()
                + response_remove.len();
            if operations == 0 || operations > 64 {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} header mutation count is outside 1..=64"
                )));
            }
        }
        MiddlewareConfig::Maintenance {
            status,
            body,
            content_type,
            retry_after_secs,
            ..
        } => {
            if !matches!(*status, 200 | 503)
                || body.is_empty()
                || body.len() > 64 * 1024
                || !matches!(
                    content_type.as_str(),
                    "text/plain; charset=utf-8" | "text/html; charset=utf-8"
                )
                || retry_after_secs.is_some_and(|seconds| !(1..=86_400).contains(&seconds))
                || *status == 200 && retry_after_secs.is_some()
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} has an unsafe maintenance response"
                )));
            }
        }
        MiddlewareConfig::CustomError {
            statuses,
            body,
            content_type,
        } => {
            let unique: HashSet<_> = statuses.iter().copied().collect();
            if statuses.is_empty()
                || statuses.len() > 16
                || unique.len() != statuses.len()
                || statuses.iter().any(|status| !(500..=599).contains(status))
                || body.is_empty()
                || body.len() > 64 * 1024
                || !matches!(
                    content_type.as_str(),
                    "text/plain; charset=utf-8" | "text/html; charset=utf-8"
                )
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} has an unsafe custom error response"
                )));
            }
        }
        MiddlewareConfig::Compression {
            encodings,
            content_types,
            min_bytes,
            max_concurrent,
            ..
        } => {
            let encoding_set: HashSet<_> = encodings.iter().copied().collect();
            let mut type_set = HashSet::new();
            if encodings.is_empty()
                || encodings.len() > 2
                || encoding_set.len() != encodings.len()
                || content_types.is_empty()
                || content_types.len() > 32
                || !(256..=1_048_576).contains(min_bytes)
                || !(1..=32).contains(max_concurrent)
                || content_types.iter().any(|value| {
                    value.is_empty()
                        || value.len() > 127
                        || value != &value.to_ascii_lowercase()
                        || value.contains(';')
                        || value.contains(char::is_whitespace)
                        || !value.contains('/')
                        || !type_set.insert(value.as_str())
                })
            {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} has an unsafe compression policy"
                )));
            }
        }
        MiddlewareConfig::Redirect {
            location,
            status,
            preserve_query,
        } => {
            if !matches!(*status, 301 | 302 | 303 | 307 | 308) {
                return Err(ConfigError::Invalid(format!(
                    "middleware {id} has an invalid redirect status"
                )));
            }
            validate_header_value(id, "location", location)?;
            if let Ok(url) = Url::parse(location) {
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                    || (*preserve_query && url.query().is_some())
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an unsafe absolute redirect"
                    )));
                }
            } else {
                let uri = location.parse::<Uri>().map_err(|_| {
                    ConfigError::Invalid(format!(
                        "middleware {id} has an invalid relative redirect"
                    ))
                })?;
                if !uri.path().starts_with('/')
                    || uri.path().starts_with("//")
                    || uri.scheme().is_some()
                    || uri.authority().is_some()
                    || (*preserve_query && uri.query().is_some())
                {
                    return Err(ConfigError::Invalid(format!(
                        "middleware {id} has an unsafe relative redirect"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_header_value(id: &str, field: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > MAX_HEADER_VALUE_BYTES
        || HeaderValue::from_str(value).is_err()
    {
        return Err(ConfigError::Invalid(format!(
            "middleware {id} has an invalid {field} header value"
        )));
    }
    Ok(())
}

fn validate_rewrite_path(id: &str, path: &str, prefix: bool) -> Result<(), ConfigError> {
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
            "middleware {id} has a non-canonical rewrite path"
        )));
    }
    Ok(())
}

fn validate_header_mutations(
    id: &str,
    side: &str,
    set: &BTreeMap<String, String>,
    add: &BTreeMap<String, Vec<String>>,
    remove: &[String],
    request: bool,
) -> Result<(), ConfigError> {
    let mut names = HashSet::new();
    for (name, value) in set {
        validate_mutable_header(id, side, name, request)?;
        validate_header_value(id, side, value)?;
        names.insert(name.as_str());
    }
    for (name, values) in add {
        validate_mutable_header(id, side, name, request)?;
        if values.is_empty() || values.len() > 8 || !names.insert(name.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "middleware {id} has ambiguous {side} header mutations"
            )));
        }
        for value in values {
            validate_header_value(id, side, value)?;
        }
    }
    let mut removed = HashSet::new();
    for name in remove {
        validate_mutable_header(id, side, name, request)?;
        if !removed.insert(name.as_str()) || !names.insert(name.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "middleware {id} has ambiguous {side} header mutations"
            )));
        }
    }
    Ok(())
}

fn validate_mutable_header(
    id: &str,
    side: &str,
    value: &str,
    request: bool,
) -> Result<(), ConfigError> {
    let name = HeaderName::from_bytes(value.as_bytes()).map_err(|_| {
        ConfigError::Invalid(format!("middleware {id} has an invalid {side} header name"))
    })?;
    if value.len() > MAX_HEADER_NAME_BYTES
        || name.as_str() != value
        || prohibited_mutation_header(&name, request)
    {
        return Err(ConfigError::Invalid(format!(
            "middleware {id} cannot mutate protected {side} header {value}"
        )));
    }
    Ok(())
}

fn prohibited_mutation_header(name: &HeaderName, request: bool) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "access-control-allow-credentials"
            | "access-control-allow-headers"
            | "access-control-allow-methods"
            | "access-control-allow-origin"
            | "access-control-expose-headers"
            | "access-control-max-age"
            | "connection"
            | "content-encoding"
            | "content-length"
            | "content-security-policy"
            | "cookie"
            | "forwarded"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "set-cookie"
            | "strict-transport-security"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-aegisproxy-user"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-method"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-forwarded-uri"
            | "x-original-uri"
            | "x-real-ip"
            | "x-request-id"
    ) || (!request && name.as_str() == "www-authenticate")
}

fn validate_forward_auth_headers(
    id: &str,
    field: &str,
    values: &[String],
    request: bool,
) -> Result<(), ConfigError> {
    let mut unique = HashSet::new();
    for value in values {
        let name = validate_forward_auth_header(id, field, value, request)?;
        if !unique.insert(name) {
            return Err(ConfigError::Invalid(format!(
                "middleware {id} has duplicate ForwardAuth {field} headers"
            )));
        }
    }
    Ok(())
}

fn validate_forward_auth_header<'a>(
    id: &str,
    field: &str,
    value: &'a str,
    request: bool,
) -> Result<&'a str, ConfigError> {
    let name = HeaderName::from_bytes(value.as_bytes()).map_err(|_| {
        ConfigError::Invalid(format!(
            "middleware {id} has an invalid ForwardAuth {field} header"
        ))
    })?;
    let forbidden = matches!(
        name.as_str(),
        "connection"
            | "content-encoding"
            | "content-length"
            | "forwarded"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "set-cookie"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-aegisproxy-user"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-method"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-forwarded-uri"
            | "x-original-uri"
            | "x-real-ip"
            | "x-request-id"
    ) || (request && name.as_str().starts_with("x-authentik-"))
        || (!request && matches!(name.as_str(), "cookie" | "www-authenticate"));
    if value.len() > MAX_HEADER_NAME_BYTES || name.as_str() != value || forbidden {
        return Err(ConfigError::Invalid(format!(
            "middleware {id} cannot use protected ForwardAuth {field} header {value}"
        )));
    }
    Ok(value)
}
