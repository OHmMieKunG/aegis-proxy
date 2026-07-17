use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use hyper::{Response, StatusCode, header::HeaderValue};

use crate::{ResponseBody, full_body};

pub(crate) fn response(
    config: &Config,
    route: &RouteConfig,
    authenticated_stage: bool,
) -> Result<Option<Response<ResponseBody>>, ()> {
    let Some((status, body, content_type, retry_after_secs, authenticated)) = route
        .middlewares
        .iter()
        .find_map(|id| match config.middlewares.get(id)? {
            MiddlewareConfig::Maintenance {
                status,
                body,
                content_type,
                retry_after_secs,
                authenticated,
            } => Some((
                *status,
                body.as_bytes(),
                content_type.as_str(),
                *retry_after_secs,
                *authenticated,
            )),
            _ => None,
        })
    else {
        return Ok(None);
    };
    if authenticated != authenticated_stage {
        return Ok(None);
    }
    let mut response = Response::new(full_body(body));
    *response.status_mut() = StatusCode::from_u16(status).map_err(|_| ())?;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).map_err(|_| ())?,
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    if let Some(seconds) = retry_after_secs {
        response.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            HeaderValue::from_str(&seconds.to_string()).map_err(|_| ())?,
        );
    }
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::RouteConfig;
    use http_body_util::BodyExt;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn maintenance_response_is_static_uncacheable_and_stage_scoped() {
        let mut config: Config = toml::from_str("schema_version = 1").expect("config");
        config.middlewares = BTreeMap::from([(
            "maintenance".into(),
            MiddlewareConfig::Maintenance {
                status: 503,
                body: "planned outage".into(),
                content_type: "text/plain; charset=utf-8".into(),
                retry_after_secs: Some(120),
                authenticated: false,
            },
        )]);
        let route = route();
        assert!(response(&config, &route, true).expect("stage").is_none());
        let response = response(&config, &route, false)
            .expect("response")
            .expect("maintenance");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[hyper::header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[hyper::header::RETRY_AFTER], "120");
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
            "planned outage"
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
            middlewares: vec!["maintenance".into()],
            upstream_group: None,
        }
    }
}
