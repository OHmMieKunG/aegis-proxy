use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use hyper::{
    Method, Request, Response, StatusCode,
    header::{
        ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD,
        HeaderMap, HeaderValue, ORIGIN, VARY,
    },
};

use crate::{ResponseBody, full_body};

pub(crate) fn preflight<B>(
    config: &Config,
    route: &RouteConfig,
    request: &Request<B>,
) -> Result<Option<Response<ResponseBody>>, ()> {
    let Some(policy) = policy(config, route) else {
        return Ok(None);
    };
    if request.method() != Method::OPTIONS
        || !request
            .headers()
            .contains_key(ACCESS_CONTROL_REQUEST_METHOD)
    {
        return Ok(None);
    }
    let origin = single_header(request.headers(), ORIGIN)?;
    let allow_origin = allowed_origin(&policy, origin)?;
    let method = single_header(request.headers(), ACCESS_CONTROL_REQUEST_METHOD)?
        .to_str()
        .map_err(|_| ())?;
    if !policy.methods.iter().any(|allowed| allowed == method) {
        return Err(());
    }
    let requested_headers = requested_headers(request.headers())?;
    if requested_headers
        .iter()
        .any(|requested| !policy.headers.iter().any(|allowed| allowed == requested))
    {
        return Err(());
    }

    let mut response = Response::new(full_body(b""));
    *response.status_mut() = StatusCode::NO_CONTENT;
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_str(&policy.methods.join(", ")).map_err(|_| ())?,
    );
    if !policy.headers.is_empty() {
        headers.insert(
            ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_str(&policy.headers.join(", ")).map_err(|_| ())?,
        );
    }
    if policy.allow_credentials {
        headers.insert(
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    if policy.max_age_secs > 0 {
        headers.insert(
            ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_str(&policy.max_age_secs.to_string()).map_err(|_| ())?,
        );
    }
    headers.insert(
        VARY,
        HeaderValue::from_static(
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        ),
    );
    Ok(Some(response))
}

pub(crate) fn apply<B>(
    config: &Config,
    route: &RouteConfig,
    request_headers: &HeaderMap,
    response: &mut Response<B>,
) -> Result<(), ()> {
    let Some(policy) = policy(config, route) else {
        return Ok(());
    };
    for name in [
        ACCESS_CONTROL_ALLOW_ORIGIN,
        ACCESS_CONTROL_ALLOW_CREDENTIALS,
        ACCESS_CONTROL_ALLOW_METHODS,
        ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ACCESS_CONTROL_MAX_AGE,
    ] {
        response.headers_mut().remove(name);
    }
    let Ok(origin) = single_header(request_headers, ORIGIN) else {
        return Ok(());
    };
    let Ok(allow_origin) = allowed_origin(&policy, origin) else {
        return Ok(());
    };
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
    if policy.allow_credentials {
        response.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    append_vary_origin(response.headers_mut());
    Ok(())
}

struct Policy<'a> {
    origins: &'a [String],
    methods: &'a [String],
    headers: &'a [String],
    allow_credentials: bool,
    max_age_secs: u64,
}

fn policy<'a>(config: &'a Config, route: &RouteConfig) -> Option<Policy<'a>> {
    route
        .middlewares
        .iter()
        .find_map(|id| match config.middlewares.get(id)? {
            MiddlewareConfig::Cors {
                origins,
                methods,
                headers,
                allow_credentials,
                max_age_secs,
            } => Some(Policy {
                origins,
                methods,
                headers,
                allow_credentials: *allow_credentials,
                max_age_secs: *max_age_secs,
            }),
            _ => None,
        })
}

fn single_header(headers: &HeaderMap, name: hyper::header::HeaderName) -> Result<&HeaderValue, ()> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    Ok(value)
}

fn allowed_origin(policy: &Policy<'_>, origin: &HeaderValue) -> Result<HeaderValue, ()> {
    let origin = origin.to_str().map_err(|_| ())?;
    if policy.origins.iter().any(|allowed| allowed == "*") {
        return Ok(HeaderValue::from_static("*"));
    }
    if !policy.origins.iter().any(|allowed| allowed == origin) {
        return Err(());
    }
    HeaderValue::from_str(origin).map_err(|_| ())
}

fn requested_headers(headers: &HeaderMap) -> Result<Vec<String>, ()> {
    let mut values = headers.get_all(ACCESS_CONTROL_REQUEST_HEADERS).iter();
    let Some(value) = values.next() else {
        return Ok(Vec::new());
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if value.len() > 4_096 {
        return Err(());
    }
    let requested = value
        .split(',')
        .map(str::trim)
        .take(65)
        .map(|header| {
            let parsed = header
                .parse::<hyper::header::HeaderName>()
                .map_err(|_| ())?;
            Ok::<String, ()>(parsed.as_str().to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if requested.len() > 64 {
        return Err(());
    }
    Ok(requested)
}

fn append_vary_origin(headers: &mut HeaderMap) {
    if headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("origin") || value.trim() == "*")
    {
        return;
    }
    headers.append(VARY, HeaderValue::from_static("Origin"));
}
