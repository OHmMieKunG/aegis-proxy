#[test]
fn route_matching_is_deterministic_and_header_aware() {
    let route = RouteConfig {
        id: "app".into(),
        listeners: vec!["public".into()],
        hosts: vec!["*.example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/api".into()],
        methods: vec!["GET".into()],
        headers: vec![aegisproxy_config::HeaderMatch {
            name: "x-tenant".into(),
            value: Some("blue".into()),
        }],
        default: false,
        priority: 10,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    };
    let config = config(route);
    let good_request = Request::builder()
        .method("GET")
        .uri("/api/v1")
        .header(HOST, "API.Example.Test:443")
        .header("x-tenant", "blue")
        .body(Empty::<bytes::Bytes>::new())
        .expect("request");
    assert_eq!(
        select_route(&config, &good_request, "public").map(|route| route.id.as_str()),
        Some("app")
    );
    let miss = request("POST", "api.example.test", "/api/v1");
    assert!(select_route(&config, &miss, "public").is_none());
}

#[test]
fn explicit_default_route_never_overrides_a_specific_match() {
    let specific = RouteConfig {
        id: "specific".into(),
        listeners: vec!["public".into()],
        hosts: vec!["example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/".into()],
        methods: vec![],
        headers: vec![],
        default: false,
        priority: -10,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    };
    let mut config = config(specific);
    config.routes.push(RouteConfig {
        id: "fallback".into(),
        listeners: vec!["public".into()],
        hosts: vec![],
        paths: vec![],
        path_prefixes: vec![],
        methods: vec![],
        headers: vec![],
        default: true,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    });

    assert_eq!(
        select_route(&config, &request("GET", "example.test", "/"), "public")
            .map(|route| route.id.as_str()),
        Some("specific")
    );
    assert_eq!(
        select_route(&config, &request("GET", "other.test", "/"), "public")
            .map(|route| route.id.as_str()),
        Some("fallback")
    );
}

#[test]
fn exact_host_and_path_outrank_prefix_with_presence_predicate() {
    let prefix = RouteConfig {
        id: "prefix".into(),
        listeners: vec!["public".into()],
        hosts: vec!["*.example.test".into()],
        paths: vec![],
        path_prefixes: vec!["/api".into()],
        methods: vec![],
        headers: vec![],
        default: false,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    };
    let mut config = config(prefix);
    config.routes.push(RouteConfig {
        id: "exact".into(),
        listeners: vec!["public".into()],
        hosts: vec!["api.example.test".into()],
        paths: vec!["/api/users".into()],
        path_prefixes: vec![],
        methods: vec!["GET".into()],
        headers: vec![aegisproxy_config::HeaderMatch {
            name: "x-authenticated".into(),
            value: None,
        }],
        default: false,
        priority: 0,
        middlewares: vec![],
        upstream_group: Some("app".into()),
    });

    let exact = Request::builder()
        .method("GET")
        .uri("/api/users")
        .header(HOST, "api.example.test")
        .header("x-authenticated", "")
        .body(Empty::<bytes::Bytes>::new())
        .expect("request");
    assert_eq!(
        select_route(&config, &exact, "public").map(|route| route.id.as_str()),
        Some("exact")
    );

    let no_header = request("GET", "api.example.test", "/api/users");
    assert_eq!(
        select_route(&config, &no_header, "public").map(|route| route.id.as_str()),
        Some("prefix")
    );
    let trailing = request("GET", "api.example.test", "/api/users/");
    assert_eq!(
        select_route(&config, &trailing, "public").map(|route| route.id.as_str()),
        Some("prefix")
    );
}

#[test]
fn rejects_absolute_form_connect_and_missing_host() {
    let absolute = Request::builder()
        .method("GET")
        .uri("http://example.test/")
        .body(Empty::<bytes::Bytes>::new())
        .expect("absolute request");
    assert_eq!(
        reject_unsafe_request_target(&absolute),
        Some(StatusCode::BAD_REQUEST)
    );
    let connect = Request::builder()
        .method("CONNECT")
        .uri("/")
        .header(HOST, "example.test")
        .body(Empty::<bytes::Bytes>::new())
        .expect("connect request");
    assert_eq!(
        reject_unsafe_request_target(&connect),
        Some(StatusCode::BAD_REQUEST)
    );
    let no_host = Request::builder()
        .method("GET")
        .uri("/")
        .body(Empty::<bytes::Bytes>::new())
        .expect("request");
    assert_eq!(
        reject_unsafe_request_target(&no_host),
        Some(StatusCode::BAD_REQUEST)
    );
}

#[test]
fn validates_http2_authority_and_connection_headers() {
    let valid = Request::builder()
        .version(hyper::Version::HTTP_2)
        .uri("https://example.test/")
        .body(Empty::<bytes::Bytes>::new())
        .expect("HTTP/2 request");
    assert_eq!(reject_unsafe_request_target(&valid), None);

    let conflicting = Request::builder()
        .version(hyper::Version::HTTP_2)
        .uri("https://example.test/")
        .header(HOST, "other.test")
        .body(Empty::<bytes::Bytes>::new())
        .expect("HTTP/2 request");
    assert_eq!(
        reject_unsafe_request_target(&conflicting),
        Some(StatusCode::BAD_REQUEST)
    );

    let connection_header = Request::builder()
        .version(hyper::Version::HTTP_2)
        .uri("https://example.test/")
        .header(CONNECTION, "close")
        .body(Empty::<bytes::Bytes>::new())
        .expect("HTTP/2 request");
    assert_eq!(
        reject_unsafe_request_target(&connection_header),
        Some(StatusCode::BAD_REQUEST)
    );
}
