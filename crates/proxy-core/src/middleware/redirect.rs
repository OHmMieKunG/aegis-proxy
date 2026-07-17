use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use hyper::{Response, StatusCode, header::LOCATION};

use crate::{ResponseBody, full_body};

pub(crate) fn response(
    config: &Config,
    route: &RouteConfig,
    query: Option<&str>,
) -> Result<Option<Response<ResponseBody>>, ()> {
    let Some((location, status, preserve_query)) =
        route
            .middlewares
            .iter()
            .find_map(|id| match config.middlewares.get(id)? {
                MiddlewareConfig::Redirect {
                    location,
                    status,
                    preserve_query,
                } => Some((location.as_str(), *status, *preserve_query)),
                _ => None,
            })
    else {
        return Ok(None);
    };
    let location = match (preserve_query, query) {
        (true, Some(query)) => format!("{location}?{query}"),
        _ => location.to_owned(),
    };
    let location = location
        .parse::<hyper::header::HeaderValue>()
        .map_err(|_| ())?;
    let status = StatusCode::from_u16(status).map_err(|_| ())?;
    let response = Response::builder()
        .status(status)
        .header(LOCATION, location)
        .body(full_body(b""))
        .map_err(|_| ())?;
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn fixed_redirect_preserves_query_only_when_enabled() {
        let mut config = Config {
            middlewares: BTreeMap::new(),
            ..test_config()
        };
        config.middlewares.insert(
            "redirect".into(),
            MiddlewareConfig::Redirect {
                location: "/new".into(),
                status: 308,
                preserve_query: true,
            },
        );
        let route = RouteConfig {
            middlewares: vec!["redirect".into()],
            ..test_route()
        };
        let response = response(&config, &route, Some("page=2"))
            .expect("redirect")
            .expect("response");
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers()[LOCATION], "/new?page=2");
    }

    fn test_config() -> Config {
        toml::from_str(
            r#"
            schema_version = 1
            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"
        "#,
        )
        .expect("test config")
    }

    fn test_route() -> RouteConfig {
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
            middlewares: vec![],
            upstream_group: None,
        }
    }
}
