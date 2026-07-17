use std::net::IpAddr;

use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};

pub(crate) fn allowed(config: &Config, route: &RouteConfig, address: IpAddr) -> bool {
    let Some((allow, deny)) =
        route
            .middlewares
            .iter()
            .find_map(|id| match config.middlewares.get(id)? {
                MiddlewareConfig::IpPolicy { allow, deny } => Some((allow, deny)),
                _ => None,
            })
    else {
        return true;
    };
    if deny.iter().any(|network| network.contains(&address)) {
        return false;
    }
    allow.is_empty() || allow.iter().any(|network| network.contains(&address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn deny_precedes_allow() {
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
            "ip".into(),
            MiddlewareConfig::IpPolicy {
                allow: vec!["10.0.0.0/8".parse().expect("CIDR")],
                deny: vec!["10.1.0.0/16".parse().expect("CIDR")],
            },
        )]);
        let route = test_route();
        assert!(allowed(&config, &route, "10.2.0.1".parse().expect("IP")));
        assert!(!allowed(&config, &route, "10.1.0.1".parse().expect("IP")));
        assert!(!allowed(&config, &route, "192.0.2.1".parse().expect("IP")));
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
            middlewares: vec!["ip".into()],
            upstream_group: Some("app".into()),
        }
    }
}
