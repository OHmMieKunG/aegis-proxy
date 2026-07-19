use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use hyper::{HeaderMap, Request, Response, header::HeaderName};

pub(crate) fn apply_request_mutations<B>(
    config: &Config,
    route: &RouteConfig,
    request: &mut Request<B>,
) -> Result<(), ()> {
    let Some((set, add, remove)) = mutations(config, route, true) else {
        return Ok(());
    };
    apply_mutations(request.headers_mut(), set, add, remove)
}

pub(crate) fn apply_response_mutations<B>(
    config: &Config,
    route: &RouteConfig,
    response: &mut Response<B>,
) -> Result<(), ()> {
    let Some((set, add, remove)) = mutations(config, route, false) else {
        return Ok(());
    };
    apply_mutations(response.headers_mut(), set, add, remove)
}

type Mutation<'a> = (
    &'a std::collections::BTreeMap<String, String>,
    &'a std::collections::BTreeMap<String, Vec<String>>,
    &'a [String],
);

fn mutations<'a>(config: &'a Config, route: &RouteConfig, request: bool) -> Option<Mutation<'a>> {
    route.middlewares.iter().find_map(|id| {
        let MiddlewareConfig::HeaderMutation {
            request_set,
            request_add,
            request_remove,
            response_set,
            response_add,
            response_remove,
        } = config.middlewares.get(id)?
        else {
            return None;
        };
        Some(if request {
            (request_set, request_add, request_remove.as_slice())
        } else {
            (response_set, response_add, response_remove.as_slice())
        })
    })
}

fn apply_mutations(
    headers: &mut HeaderMap,
    set: &std::collections::BTreeMap<String, String>,
    add: &std::collections::BTreeMap<String, Vec<String>>,
    remove: &[String],
) -> Result<(), ()> {
    for name in remove {
        headers.remove(name);
    }
    for (name, value) in set {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?,
            value.parse().map_err(|_| ())?,
        );
    }
    for (name, values) in add {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
        for value in values {
            headers.append(name.clone(), value.parse().map_err(|_| ())?);
        }
    }
    Ok(())
}

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
    if let Some(value) = value
        && (override_existing || !response.headers().contains_key(&name))
    {
        response
            .headers_mut()
            .insert(name, value.parse().map_err(|_| ())?);
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

    #[test]
    fn typed_mutations_remove_set_and_append_deterministically() {
        let mut config: Config = toml::from_str("schema_version = 1").expect("test config");
        config.middlewares = BTreeMap::from([(
            "mutate".into(),
            MiddlewareConfig::HeaderMutation {
                request_set: BTreeMap::from([("x-env".into(), "prod".into())]),
                request_add: BTreeMap::from([(
                    "x-scope".into(),
                    vec!["read".into(), "write".into()],
                )]),
                request_remove: vec!["x-remove".into()],
                response_set: BTreeMap::new(),
                response_add: BTreeMap::new(),
                response_remove: vec![],
            },
        )]);
        let mut route = test_route();
        route.middlewares = vec!["mutate".into()];
        let mut request = Request::builder()
            .uri("/")
            .header("x-env", "dev")
            .header("x-remove", "secret")
            .body(())
            .expect("request");
        apply_request_mutations(&config, &route, &mut request).expect("mutate");
        assert_eq!(request.headers()["x-env"], "prod");
        assert!(!request.headers().contains_key("x-remove"));
        assert_eq!(request.headers().get_all("x-scope").iter().count(), 2);
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
