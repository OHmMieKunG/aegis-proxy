use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use hyper::{Response, header::HeaderValue};

use crate::{ResponseBody, full_body};

pub(crate) fn apply(
    config: &Config,
    route: &RouteConfig,
    response: &mut Response<ResponseBody>,
) -> Result<(), ()> {
    let Some((statuses, body, content_type)) = route.middlewares.iter().find_map(|id| match config
        .middlewares
        .get(id)?
    {
        MiddlewareConfig::CustomError {
            statuses,
            body,
            content_type,
        } => Some((statuses, body.as_bytes(), content_type.as_str())),
        _ => None,
    }) else {
        return Ok(());
    };
    if !statuses.contains(&response.status().as_u16()) {
        return Ok(());
    }
    *response.body_mut() = full_body(body);
    for name in [
        hyper::header::CONTENT_LENGTH,
        hyper::header::CONTENT_ENCODING,
        hyper::header::CONTENT_RANGE,
        hyper::header::ETAG,
        hyper::header::LAST_MODIFIED,
        hyper::header::ACCEPT_RANGES,
    ] {
        response.headers_mut().remove(name);
    }
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).map_err(|_| ())?,
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::RouteConfig;
    use http_body_util::BodyExt;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn replaces_only_selected_status_without_interpolation() {
        let mut config: Config = toml::from_str("schema_version = 1").expect("config");
        config.middlewares = BTreeMap::from([(
            "errors".into(),
            MiddlewareConfig::CustomError {
                statuses: vec![502, 503],
                body: "service unavailable".into(),
                content_type: "text/plain; charset=utf-8".into(),
            },
        )]);
        let route = route();
        let mut response = Response::new(full_body(b"upstream leak"));
        *response.status_mut() = hyper::StatusCode::BAD_GATEWAY;
        response.headers_mut().insert(
            hyper::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        apply(&config, &route, &mut response).expect("custom error");
        assert!(
            !response
                .headers()
                .contains_key(hyper::header::CONTENT_ENCODING)
        );
        assert_eq!(response.headers()[hyper::header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
            "service unavailable"
        );
    }

    fn route() -> RouteConfig {
        RouteConfig {
            id: "route".into(),
            listeners: vec!["public".into()],
            hosts: vec![],
            paths: vec![],
            path_prefixes: vec![],
            methods: vec![],
            headers: vec![],
            default: true,
            priority: 0,
            middlewares: vec!["errors".into()],
            upstream_group: Some("app".into()),
        }
    }
}
