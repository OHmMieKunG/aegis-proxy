use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use hyper::{Response, header::HeaderName};

const HSTS: HeaderName = HeaderName::from_static("strict-transport-security");
const CSP: HeaderName = HeaderName::from_static("content-security-policy");

pub(crate) fn apply<B>(
    config: &Config,
    route: &RouteConfig,
    scheme: &str,
    response: &mut Response<B>,
) -> Result<(), ()> {
    let Some((hsts, csp, override_existing)) = route.middlewares.iter().find_map(|id| match config
        .middlewares
        .get(id)?
    {
        MiddlewareConfig::SecurityHeaders {
            hsts,
            content_security_policy,
            override_existing,
            ..
        } => Some((
            hsts.as_deref(),
            content_security_policy.as_deref(),
            *override_existing,
        )),
        _ => None,
    }) else {
        return Ok(());
    };
    if hsts.is_some() && scheme != "https" {
        return Err(());
    }
    set(response, HSTS, hsts, override_existing)?;
    set(response, CSP, csp, override_existing)?;
    Ok(())
}

fn set<B>(
    response: &mut Response<B>,
    name: HeaderName,
    value: Option<&str>,
    override_existing: bool,
) -> Result<(), ()> {
    if let Some(value) = value {
        if override_existing || !response.headers().contains_key(&name) {
            response
                .headers_mut()
                .insert(name, value.parse().map_err(|_| ())?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::RouteConfig;
    use hyper::header::HeaderValue;
    use std::collections::BTreeMap;

    #[test]
    fn preserves_or_overrides_upstream_headers_explicitly() {
        let mut config: Config = toml::from_str(
            r#"
            schema_version = 1
            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"
        "#,
        )
        .expect("test config");
        config.middlewares = BTreeMap::from([(
            "headers".into(),
            MiddlewareConfig::SecurityHeaders {
                hsts: None,
                content_security_policy: Some("default-src 'none'".into()),
                override_existing: false,
                acknowledge_hsts_risk: false,
            },
        )]);
        let route = test_route();
        let mut response = Response::new(crate::full_body(b""));
        response
            .headers_mut()
            .insert(CSP, HeaderValue::from_static("default-src 'self'"));
        apply(&config, &route, "http", &mut response).expect("preserve");
        assert_eq!(response.headers()[CSP], "default-src 'self'");

        let Some(MiddlewareConfig::SecurityHeaders {
            override_existing, ..
        }) = config.middlewares.get_mut("headers")
        else {
            panic!("headers middleware");
        };
        *override_existing = true;
        apply(&config, &route, "http", &mut response).expect("override");
        assert_eq!(response.headers()[CSP], "default-src 'none'");
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
            middlewares: vec!["headers".into()],
            upstream_group: Some("app".into()),
        }
    }
}
