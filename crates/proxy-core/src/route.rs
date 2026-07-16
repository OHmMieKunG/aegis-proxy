//! Immutable route index and request-target canonicalization.

use std::collections::BTreeMap;

use aegisproxy_config::{Config, RouteConfig};
use hyper::{Request, Uri, header::HOST, http::uri::Authority};

/// A validated, immutable per-listener route index.
#[derive(Debug)]
pub struct RouteIndex {
    by_listener: BTreeMap<String, Vec<usize>>,
    fingerprint: u64,
}

impl RouteIndex {
    /// Compile route references into deterministic listener indexes.
    #[must_use]
    pub fn compile(config: &Config) -> Self {
        let mut by_listener: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (route_index, route) in config.routes.iter().enumerate() {
            for listener in &route.listeners {
                by_listener
                    .entry(listener.clone())
                    .or_default()
                    .push(route_index);
            }
        }
        for routes in by_listener.values_mut() {
            routes.sort_unstable_by(|left, right| {
                config.routes[*left].id.cmp(&config.routes[*right].id)
            });
        }
        Self {
            by_listener,
            fingerprint: route_fingerprint(&config.routes),
        }
    }

    /// Stable route fingerprint for diagnostics, not for authentication or integrity checks.
    #[must_use]
    pub const fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Deterministic route IDs for one listener.
    #[must_use]
    pub fn route_ids<'a>(&self, config: &'a Config, listener: &str) -> Vec<&'a str> {
        self.by_listener
            .get(listener)
            .into_iter()
            .flatten()
            .map(|index| config.routes[*index].id.as_str())
            .collect()
    }

    /// Select one route using explicit priority and compiled specificity rules.
    pub fn select<'a, B>(
        &self,
        config: &'a Config,
        request: &Request<B>,
        listener: &str,
    ) -> Option<&'a RouteConfig> {
        let host = request_host(request).ok()?;
        let path = request.uri().path();
        self.by_listener
            .get(listener)?
            .iter()
            .filter_map(|index| {
                let route = &config.routes[*index];
                route_match_score(route, request, &host, path).map(|score| (score, route))
            })
            .max_by(|(left_score, left), (right_score, right)| {
                left_score
                    .cmp(right_score)
                    .then_with(|| right.id.cmp(&left.id))
            })
            .map(|(_, route)| route)
    }

    pub(crate) fn select_sni<'a>(
        &self,
        config: &'a Config,
        listener: &str,
        server_name: Option<&str>,
    ) -> Option<&'a RouteConfig> {
        let canonical = server_name.map(canonical_host).transpose().ok()?;
        self.by_listener
            .get(listener)?
            .iter()
            .filter_map(|index| {
                let route = &config.routes[*index];
                if route.default {
                    Some(((0_u8, 0_usize), route))
                } else {
                    canonical
                        .as_deref()
                        .and_then(|host| host_match_score(&route.hosts, host))
                        .map(|score| (score, route))
                }
            })
            .max_by(|(left_score, left), (right_score, right)| {
                left_score
                    .cmp(right_score)
                    .then_with(|| right.id.cmp(&left.id))
            })
            .map(|(_, route)| route)
    }
}

type RouteMatchScore = (bool, i32, u8, usize, u8, usize, bool, usize, usize, usize);

fn route_match_score<B>(
    route: &RouteConfig,
    request: &Request<B>,
    host: &str,
    path: &str,
) -> Option<RouteMatchScore> {
    if route.default {
        return Some((false, 0, 0, 0, 0, 0, false, 0, 0, 0));
    }
    let (host_kind, host_length) = host_match_score(&route.hosts, host)?;
    let (path_kind, path_length) = path_match_score(route, path)?;
    let method_specific = !route.methods.is_empty();
    if method_specific
        && !route
            .methods
            .iter()
            .any(|method| method == request.method().as_str())
    {
        return None;
    }
    if !route.headers.iter().all(|predicate| {
        let value = request.headers().get(&predicate.name);
        match &predicate.value {
            Some(expected) => value
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == expected),
            None => value.is_some(),
        }
    }) {
        return None;
    }
    let exact_headers = route
        .headers
        .iter()
        .filter(|predicate| predicate.value.is_some())
        .count();
    Some((
        true,
        route.priority,
        host_kind,
        host_length,
        path_kind,
        path_length,
        method_specific,
        if method_specific {
            usize::MAX - route.methods.len()
        } else {
            0
        },
        route.headers.len(),
        exact_headers,
    ))
}

fn host_match_score(hosts: &[String], host: &str) -> Option<(u8, usize)> {
    if hosts.is_empty() {
        return Some((0, 0));
    }
    hosts
        .iter()
        .filter_map(|candidate| {
            if candidate == host {
                Some((2, candidate.len()))
            } else if candidate.strip_prefix("*.").is_some_and(|suffix| {
                host.strip_suffix(suffix).is_some_and(|prefix| {
                    prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
                })
            }) {
                Some((1, candidate.len()))
            } else {
                None
            }
        })
        .max()
}

fn path_match_score(route: &RouteConfig, path: &str) -> Option<(u8, usize)> {
    if let Some(length) = route
        .paths
        .iter()
        .filter(|candidate| candidate.as_str() == path)
        .map(String::len)
        .max()
    {
        return Some((2, length));
    }
    if let Some(length) = route
        .path_prefixes
        .iter()
        .filter(|prefix| {
            prefix.as_str() == "/"
                || path == prefix.as_str()
                || path
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .map(String::len)
        .max()
    {
        return Some((1, length));
    }
    (route.paths.is_empty() && route.path_prefixes.is_empty()).then_some((0, 0))
}

pub(crate) fn request_host<B>(request: &Request<B>) -> Result<String, ()> {
    if request.headers().get_all(HOST).iter().count() > 1 {
        return Err(());
    }
    let authority_host = request
        .uri()
        .authority()
        .map(canonical_authority_host)
        .transpose()?;
    let header_host = request
        .headers()
        .get(HOST)
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()?
        .map(|value| value.parse::<Authority>().map_err(|_| ()))
        .transpose()?
        .map(|authority| canonical_authority_host(&authority))
        .transpose()?;
    match (authority_host, header_host) {
        (Some(authority), Some(header)) if authority != header => Err(()),
        (Some(authority), _) => Ok(authority),
        (_, Some(header)) => Ok(header),
        _ => Err(()),
    }
}

fn canonical_authority_host(authority: &Authority) -> Result<String, ()> {
    if authority.as_str().contains('@')
        || authority.as_str().ends_with(':')
        || (authority.port().is_some() && authority.port_u16().is_none())
    {
        return Err(());
    }
    canonical_host(authority.host())
}

pub(crate) fn canonical_host(value: &str) -> Result<String, ()> {
    let unbracketed = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    if let Ok(address) = unbracketed.parse::<std::net::IpAddr>() {
        return Ok(address.to_string());
    }
    let host = unbracketed.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.contains('*')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(());
    }
    Ok(host)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PathError {
    TooLong,
    Invalid,
}

pub(crate) fn canonicalize_request_path<B>(
    request: &mut Request<B>,
    max_target_bytes: usize,
) -> Result<(), PathError> {
    let path_and_query = request.uri().path_and_query().ok_or(PathError::Invalid)?;
    if path_and_query.as_str().len() > max_target_bytes {
        return Err(PathError::TooLong);
    }
    let canonical = canonical_path(request.uri().path()).map_err(|()| PathError::Invalid)?;
    if canonical == request.uri().path() {
        return Ok(());
    }
    let path_and_query = match request.uri().query() {
        Some(query) => format!("{canonical}?{query}"),
        None => canonical,
    };
    let mut parts = request.uri().clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().map_err(|_| PathError::Invalid)?);
    *request.uri_mut() = Uri::from_parts(parts).map_err(|_| PathError::Invalid)?;
    Ok(())
}

fn canonical_path(path: &str) -> Result<String, ()> {
    if !path.starts_with('/') || !path.is_ascii() || path.contains('\\') || path.contains("//") {
        return Err(());
    }
    let bytes = path.as_bytes();
    let mut output = String::with_capacity(path.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = *bytes.get(index + 1).ok_or(())?;
            let low = *bytes.get(index + 2).ok_or(())?;
            let decoded = decode_hex(high, low).ok_or(())?;
            if decoded == b'/' || decoded == b'\\' || decoded.is_ascii_control() {
                return Err(());
            }
            if is_unreserved(decoded) {
                output.push(char::from(decoded));
            } else {
                output.push('%');
                output.push(char::from(high.to_ascii_uppercase()));
                output.push(char::from(low.to_ascii_uppercase()));
            }
            index += 3;
            continue;
        }
        if byte.is_ascii_control() || byte == 0x7f {
            return Err(());
        }
        output.push(char::from(byte));
        index += 1;
    }
    if output
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(());
    }
    Ok(output)
}

const fn decode_hex(high: u8, low: u8) -> Option<u8> {
    let Some(high) = hex_value(high) else {
        return None;
    };
    let Some(low) = hex_value(low) else {
        return None;
    };
    Some((high << 4) | low)
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

const fn is_unreserved(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~')
}

fn route_fingerprint(routes: &[RouteConfig]) -> u64 {
    let mut sorted: Vec<&RouteConfig> = routes.iter().collect();
    sorted.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    let mut hash = Fnv1a::new();
    for route in sorted {
        hash.field("route", &route.id);
        hash.set("listener", &route.listeners);
        hash.set("host", &route.hosts);
        hash.set("path", &route.paths);
        hash.set("prefix", &route.path_prefixes);
        hash.set("method", &route.methods);
        let mut headers: Vec<String> = route
            .headers
            .iter()
            .map(|predicate| {
                format!(
                    "{}:{}:{}",
                    if predicate.value.is_some() { "V" } else { "P" },
                    predicate.name,
                    predicate.value.as_deref().unwrap_or("")
                )
            })
            .collect();
        headers.sort_unstable();
        hash.set("header", &headers);
        hash.field("default", if route.default { "true" } else { "false" });
        hash.field("priority", &route.priority.to_string());
        for middleware in &route.middlewares {
            hash.field("middleware", middleware);
        }
        hash.field(
            "upstream",
            route.upstream_group.as_deref().unwrap_or("<none>"),
        );
    }
    hash.finish()
}

struct Fnv1a(u64);

impl Fnv1a {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn field(&mut self, name: &str, value: &str) {
        self.bytes(&(name.len() as u64).to_le_bytes());
        self.bytes(name.as_bytes());
        self.bytes(&(value.len() as u64).to_le_bytes());
        self.bytes(value.as_bytes());
    }

    fn set(&mut self, name: &str, values: &[String]) {
        let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        for value in sorted {
            self.field(name, value);
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aegisproxy_config::{
        AdminConfig, Config, LimitsConfig, RouteConfig, RuntimeConfig, TlsConfig,
        TrustedProxyConfig,
    };
    use hyper::header::HOST;
    use proptest::prelude::*;

    use super::*;

    fn route(id: &str) -> RouteConfig {
        RouteConfig {
            id: id.into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/".into()],
            methods: vec![],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        }
    }

    #[test]
    fn sni_selection_prefers_exact_then_wildcard_then_default() {
        let exact = route("exact");
        let mut wildcard = route("wildcard");
        wildcard.hosts = vec!["*.example.test".into()];
        let mut default = route("default");
        default.hosts.clear();
        default.path_prefixes.clear();
        default.default = true;
        let config = config(vec![default, wildcard, exact]);
        let index = RouteIndex::compile(&config);
        assert_eq!(
            index
                .select_sni(&config, "public", Some("example.test"))
                .map(|route| route.id.as_str()),
            Some("exact")
        );
        assert_eq!(
            index
                .select_sni(&config, "public", Some("api.example.test"))
                .map(|route| route.id.as_str()),
            Some("wildcard")
        );
        assert_eq!(
            index
                .select_sni(&config, "public", None)
                .map(|route| route.id.as_str()),
            Some("default")
        );
    }

    fn config(routes: Vec<RouteConfig>) -> Config {
        Config {
            schema_version: 1,
            runtime: RuntimeConfig::default(),
            limits: LimitsConfig::default(),
            listeners: vec![],
            tls: TlsConfig::default(),
            certificates: vec![],
            acme: aegisproxy_config::AcmeConfig::default(),
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![],
            middlewares: BTreeMap::new(),
            routes,
            admin: AdminConfig::default(),
        }
    }

    #[test]
    fn canonicalizes_path_once_and_rejects_ambiguous_forms() {
        assert_eq!(canonical_path("/a/%7e/%3a"), Ok("/a/~/%3A".into()));
        for invalid in [
            "/bad%",
            "/bad%2",
            "/bad%zz",
            "/a/%2f/b",
            "/a/%5C/b",
            "/a/%00/b",
            "/a/./b",
            "/a/%2e%2e/b",
            "/a//b",
            "/a\\b",
        ] {
            assert_eq!(canonical_path(invalid), Err(()), "accepted {invalid}");
        }
    }

    #[test]
    fn request_path_mutation_preserves_query_and_enforces_target_limit() {
        let mut request = Request::builder()
            .uri("/users/%7ejane?view=full")
            .body(())
            .expect("request");
        assert_eq!(canonicalize_request_path(&mut request, 128), Ok(()));
        assert_eq!(request.uri().path(), "/users/~jane");
        assert_eq!(request.uri().query(), Some("view=full"));
        assert_eq!(
            canonicalize_request_path(&mut request, 8),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn canonicalizes_authority_and_rejects_host_ambiguity() {
        let request = Request::builder()
            .uri("/")
            .header(HOST, "Example.Test.:443")
            .body(())
            .expect("request");
        assert_eq!(request_host(&request), Ok("example.test".into()));

        let duplicate = Request::builder()
            .uri("/")
            .header(HOST, "example.test")
            .header(HOST, "example.test")
            .body(())
            .expect("request");
        assert_eq!(request_host(&duplicate), Err(()));

        let mismatch = Request::builder()
            .uri("https://example.test/")
            .header(HOST, "other.test")
            .body(())
            .expect("request");
        assert_eq!(request_host(&mismatch), Err(()));

        let ipv6 = Request::builder()
            .uri("/")
            .header(HOST, "[::1]:443")
            .body(())
            .expect("request");
        assert_eq!(request_host(&ipv6), Ok("::1".into()));
    }

    #[test]
    fn idna_policy_requires_canonical_ascii_labels() {
        assert_eq!(
            canonical_host("XN--BCHER-KVA.EXAMPLE."),
            Ok("xn--bcher-kva.example".into())
        );
        assert_eq!(canonical_host("bücher.example"), Err(()));
        assert_eq!(canonical_host("bad_label.example"), Err(()));
    }

    #[test]
    fn route_order_and_fingerprint_ignore_declaration_and_set_order() {
        let mut first = route("b");
        first.hosts = vec!["b.example.test".into(), "a.example.test".into()];
        let second = route("a");
        let left = config(vec![first.clone(), second.clone()]);
        first.hosts.reverse();
        let right = config(vec![second, first]);
        let left_index = RouteIndex::compile(&left);
        let right_index = RouteIndex::compile(&right);
        assert_eq!(left_index.route_ids(&left, "public"), vec!["a", "b"]);
        assert_eq!(right_index.route_ids(&right, "public"), vec!["a", "b"]);
        assert_eq!(left_index.fingerprint(), right_index.fingerprint());

        let mut changed = right.clone();
        changed.routes[0].priority = 1;
        assert_ne!(
            right_index.fingerprint(),
            RouteIndex::compile(&changed).fingerprint()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn canonical_path_is_idempotent(
            segments in prop::collection::vec("[A-Za-z0-9_-]{1,12}", 1..16)
        ) {
            let path = format!("/{}", segments.join("/"));
            let once = canonical_path(&path).expect("generated canonical path");
            let twice = canonical_path(&once).expect("canonical path remains valid");
            prop_assert_eq!(once, twice);
        }

        #[test]
        fn declaration_order_never_changes_selected_route(
            prefix_priority in -100_i32..100,
            exact_priority in -100_i32..100,
        ) {
            let mut prefix = route("prefix");
            prefix.priority = prefix_priority;
            let mut exact = route("exact");
            exact.priority = exact_priority;
            exact.paths = vec!["/".into()];
            exact.path_prefixes.clear();

            let left = config(vec![prefix.clone(), exact.clone()]);
            let right = config(vec![exact, prefix]);
            let request = Request::builder()
                .uri("/")
                .header(HOST, "example.test")
                .body(())
                .expect("request");
            let left_id = RouteIndex::compile(&left)
                .select(&left, &request, "public")
                .map(|route| route.id.as_str());
            let right_id = RouteIndex::compile(&right)
                .select(&right, &request, "public")
                .map(|route| route.id.as_str());
            prop_assert_eq!(left_id, right_id);
        }
    }
}
