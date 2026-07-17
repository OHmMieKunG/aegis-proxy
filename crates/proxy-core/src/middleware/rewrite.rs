use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use hyper::{Request, Uri};

use crate::route::canonicalize_request_path;

pub(crate) fn apply<B>(
    config: &Config,
    route: &RouteConfig,
    request: &mut Request<B>,
    max_target_bytes: usize,
) -> Result<(), ()> {
    let Some((from_prefix, to)) =
        route
            .middlewares
            .iter()
            .find_map(|id| match config.middlewares.get(id) {
                Some(MiddlewareConfig::Rewrite { from_prefix, to }) => {
                    Some((from_prefix.as_deref(), to.as_str()))
                }
                _ => None,
            })
    else {
        return Ok(());
    };
    let current = request.uri().path();
    let rewritten = match from_prefix {
        None => to.to_owned(),
        Some(from) => {
            let Some(suffix) = prefix_suffix(current, from) else {
                return Ok(());
            };
            if suffix.is_empty() {
                to.to_owned()
            } else if to == "/" {
                suffix.to_owned()
            } else {
                format!("{to}{suffix}")
            }
        }
    };
    let path_and_query = match request.uri().query() {
        Some(query) => format!("{rewritten}?{query}"),
        None => rewritten,
    };
    if path_and_query.len() > max_target_bytes {
        return Err(());
    }
    let mut parts = request.uri().clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().map_err(|_| ())?);
    *request.uri_mut() = Uri::from_parts(parts).map_err(|_| ())?;
    canonicalize_request_path(request, max_target_bytes).map_err(|_| ())
}

fn prefix_suffix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix == "/" {
        return Some(if path == "/" { "" } else { path });
    }
    if path == prefix {
        return Some("");
    }
    path.strip_prefix(prefix)
        .filter(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::RouteConfig;
    use http_body_util::Empty;
    use std::collections::BTreeMap;

    #[test]
    fn prefix_rewrite_is_segment_aware_and_preserves_query() {
        let mut config: Config = toml::from_str("schema_version = 1").expect("config");
        config.middlewares = BTreeMap::from([(
            "rewrite".into(),
            MiddlewareConfig::Rewrite {
                from_prefix: Some("/api".into()),
                to: "/internal".into(),
            },
        )]);
        let route = route();
        let mut request = Request::builder()
            .uri("/api/users?page=2")
            .body(Empty::<bytes::Bytes>::new())
            .expect("request");
        apply(&config, &route, &mut request, 1024).expect("rewrite");
        assert_eq!(request.uri(), "/internal/users?page=2");

        *request.uri_mut() = "/apix/users".parse().expect("URI");
        apply(&config, &route, &mut request, 1024).expect("no rewrite");
        assert_eq!(request.uri(), "/apix/users");
    }

    #[test]
    fn exact_replacement_is_bounded() {
        let mut config: Config = toml::from_str("schema_version = 1").expect("config");
        config.middlewares = BTreeMap::from([(
            "rewrite".into(),
            MiddlewareConfig::Rewrite {
                from_prefix: None,
                to: "/fixed".into(),
            },
        )]);
        let route = route();
        let mut request = Request::builder()
            .uri("/anything?q=1")
            .body(Empty::<bytes::Bytes>::new())
            .expect("request");
        apply(&config, &route, &mut request, 1024).expect("rewrite");
        assert_eq!(request.uri(), "/fixed?q=1");
        assert!(apply(&config, &route, &mut request, 4).is_err());
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
            middlewares: vec!["rewrite".into()],
            upstream_group: Some("app".into()),
        }
    }
}
