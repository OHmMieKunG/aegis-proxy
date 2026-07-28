use std::os::unix::fs::PermissionsExt;

use super::*;

fn temporary_directory(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "aegisproxy-admin-{name}-{}-{}",
        std::process::id(),
        request_id().expect("request ID")
    ))
}

#[tokio::test]
async fn socket_is_private_and_removed_only_by_its_guard() {
    let root = temporary_directory("socket");
    fs::create_dir(&root).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    let path = root.join("admin.sock");
    let (_listener, guard) = bind_private_socket(&path).expect("private socket");
    let mode = fs::symlink_metadata(&path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o660);
    drop(guard);
    assert!(!path.exists());
    fs::remove_dir(root).expect("remove root");
}

#[tokio::test]
async fn errors_use_stable_nested_contract_and_hide_internal_tag() {
    let response = error_contract(ApiError::Forbidden.into_response(), "request-123");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("x-aegis-error-code").is_none());
    let body = axum::body::to_bytes(response.into_body(), 4_096)
        .await
        .expect("error body");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("error JSON");
    assert_eq!(value["error"]["code"], "forbidden");
    assert_eq!(value["error"]["request_id"], "request-123");
    assert_eq!(value["error"]["details"], serde_json::json!([]));
}

#[test]
fn checked_openapi_contains_every_private_route() {
    let openapi = include_str!("../../../../config/schema/admin-openapi.yaml");
    for path in [
        "/health/details:",
        "/live:",
        "/metrics:",
        "/ready:",
        "/v1/live:",
        "/v1/ready:",
        "/v1/status:",
        "/v1/node/drain:",
        "/v1/config/active:",
        "/v1/config/validate:",
        "/v1/config/preview:",
        "/v1/access-policies:",
        "/v1/access-policies/{id}:",
        "/v1/proxy-hosts:",
        "/v1/proxy-hosts/{id}:",
        "/v1/proxy-hosts/validate:",
        "/v1/proxy-hosts/preview:",
        "/v1/proxy-hosts/candidates/{id}/activate:",
        "/v1/proxy-hosts/revisions/{id}/rollback:",
        "/v1/config/typed-candidates/{id}/preview:",
        "/v1/config/typed-candidates/{id}/activate:",
        "/v1/config/typed-revisions/{id}/rollback:",
        "/v1/stream-hosts:",
        "/v1/stream-hosts/{id}:",
        "/v1/stream-hosts/validate:",
        "/v1/stream-hosts/preview:",
        "/v1/discovery-sources:",
        "/v1/discovery-sources/{id}:",
        "/v1/discovery-sources/validate:",
        "/v1/discovery-sources/preview:",
        "/v1/config/candidates:",
        "/v1/config/candidates/{id}/activate:",
        "/v1/config/revisions:",
        "/v1/config/revisions/{id}:",
        "/v1/config/revisions/{id}/rollback:",
        "/v1/routes:",
        "/v1/upstreams:",
        "/v1/runtime/providers:",
        "/v1/certificates:",
        "/v1/certificates/{id}:",
        "/v1/certificates/{id}/renew:",
        "/v1/runtime/certificates:",
        "/v1/runtime/certificates/{id}/renew:",
        "/v1/audit:",
        "/v1/tokens:",
        "/v1/tokens/{id}/revoke:",
        "/v1/backups:",
        "/v1/restore/validate:",
    ] {
        assert!(openapi.contains(path), "OpenAPI missing {path}");
    }
    assert!(!openapi.contains("0.0.0.0"));
    assert!(!openapi.contains("private_key"));
    assert!(!openapi.contains("password_hash"));
    assert!(openapi.contains("pattern: '^[a-z][a-z0-9_-]{0,62}$'"));
    let scopes = [
        "read_status",
        "read_config",
        "validate_config",
        "preview_config",
        "create_candidate",
        "activate_config",
        "rollback_config",
        "read_revisions",
        "read_proxy_hosts",
        "create_proxy_host",
        "update_proxy_host",
        "delete_proxy_host",
        "activate_proxy_host",
        "rollback_proxy_host",
        "activate_typed_candidate",
        "rollback_typed_revision",
        "read_access_policies",
        "create_access_policy",
        "update_access_policy",
        "delete_access_policy",
        "read_routes",
        "read_upstreams",
        "drain",
        "read_certificates",
        "read_certificate_objects",
        "create_certificate",
        "update_certificate",
        "delete_certificate",
        "read_stream_hosts",
        "create_stream_host",
        "update_stream_host",
        "delete_stream_host",
        "read_discovery_sources",
        "create_discovery_source",
        "update_discovery_source",
        "delete_discovery_source",
        "renew_certificate",
        "read_audit",
        "create_backup",
        "validate_restore",
        "manage_identities",
    ];
    let scope_line = openapi
        .lines()
        .find(|line| line.trim_start().starts_with("enum: [read_status,"))
        .expect("TokenScope enum");
    assert_eq!(
        scope_line
            .split_once('[')
            .expect("scope start")
            .1
            .trim_end_matches(']')
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>(),
        scopes
    );
    assert_eq!(openapi.matches("maxItems: 41").count(), 2);
    assert!(openapi.contains("operationId: createAccessPolicy"));
    assert!(openapi.contains("operationId: updateAccessPolicy"));
    assert!(openapi.contains("operationId: deleteAccessPolicy"));
    assert!(openapi.contains("operationId: createCertificate"));
    assert!(openapi.contains("operationId: updateCertificate"));
    assert!(openapi.contains("operationId: deleteCertificate"));
    assert!(openapi.contains("schema: {$ref: \"#/components/schemas/AccessPolicyObject\"}"));
    assert!(
        openapi
            .matches("description: Quoted object generation")
            .count()
            >= 2
    );
}

#[tokio::test]
async fn invalid_access_policy_state_fails_admin_initialization_closed() {
    let root = temporary_directory("access-policy-init");
    let parent = root.join("admin");
    fs::create_dir_all(&parent).expect("admin state");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("private admin state");
    let path = parent.join("access-policies.json");
    fs::write(&path, b"{\"schema_version\":2,\"policies\":[]}").expect("invalid store");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private store");
    assert!(matches!(
        open_access_policy_store(path).await,
        Err(AdminServerError::AccessPolicies)
    ));
    assert!(!parent.join("admin.sock").exists());
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn duplicate_or_non_text_authorization_never_downgrades_to_peer_auth() {
    let mut headers = HeaderMap::new();
    headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer first"));
    headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
    assert!(authorization_header(&headers).is_err());

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_bytes(&[0xff]).expect("opaque header value"),
    );
    assert!(authorization_header(&headers).is_err());
}

#[test]
fn provider_status_export_contains_only_redacted_bounded_fields() {
    let summary = provider_summary(aegisproxy_core::ProviderStatus {
        id: "nodes".into(),
        kind: "file",
        state: "degraded",
        source_hash: Some("a".repeat(64)),
        last_success_unix_secs: Some(1_700_000_000),
        stale_at_unix_secs: Some(1_700_000_300),
        endpoint_count: 2,
        error: Some("invalid_source"),
    });
    let json = serde_json::to_string(&summary).expect("provider JSON");
    assert!(json.contains("\"source_hash\":\"aaaaaaaa"));
    assert!(!json.contains("/run/"));
    assert!(!json.contains("example.test"));
    assert!(!json.contains("secret"));
}

#[test]
fn principal_rate_limit_enforces_burst_refill_and_key_bound() {
    let start = Instant::now();
    let limiter = RateLimiter {
        requests_per_second: 2.0,
        burst: 2.0,
        max_keys: 1,
        buckets: Mutex::new(HashMap::new()),
    };
    let first = Principal {
        actor_type: "unix_peer",
        actor_id: "1000".into(),
        role: Role::Admin,
        owner_id: Some("uid-1000".parse().expect("owner")),
        token_scopes: None,
    };
    assert!(limiter.check_at(&first, start).is_ok());
    assert!(limiter.check_at(&first, start).is_ok());
    assert!(limiter.check_at(&first, start).is_err());
    assert!(
        limiter
            .check_at(&first, start + Duration::from_millis(500))
            .is_ok()
    );

    let second = Principal {
        actor_type: "api_token",
        actor_id: "second".into(),
        role: Role::Viewer,
        owner_id: Some("alice".parse().expect("owner")),
        token_scopes: Some(
            TokenScopes::new(Role::Viewer, vec![Action::ReadStatus]).expect("viewer scope"),
        ),
    };
    assert!(limiter.check_at(&second, start).is_err());
}

#[test]
fn token_authorization_requires_role_and_explicit_scope() {
    let scoped = Principal {
        actor_type: "api_token",
        actor_id: "scoped".into(),
        role: Role::Admin,
        owner_id: Some("alice".parse().expect("owner")),
        token_scopes: Some(
            TokenScopes::new(Role::Admin, vec![Action::ReadStatus]).expect("admin scope"),
        ),
    };
    assert!(authorize(&scoped, Action::ReadStatus).is_ok());
    assert!(authorize(&scoped, Action::ActivateConfig).is_err());

    let legacy = Principal {
        actor_type: "api_token",
        actor_id: "legacy".into(),
        role: Role::Admin,
        owner_id: None,
        token_scopes: Some(TokenScopes::default()),
    };
    assert!(authorize(&legacy, Action::ReadStatus).is_err());

    let peer = Principal {
        actor_type: "unix_peer",
        actor_id: "1000".into(),
        role: Role::Admin,
        owner_id: Some("uid-1000".parse().expect("owner")),
        token_scopes: None,
    };
    assert!(authorize(&peer, Action::ActivateConfig).is_ok());
}

#[test]
fn pagination_and_etags_are_bounded() {
    assert_eq!(
        page_limit(&Page {
            after_sequence: None,
            limit: None,
        })
        .expect("default page"),
        100
    );
    assert!(
        page_limit(&Page {
            after_sequence: None,
            limit: Some(0),
        })
        .is_err()
    );
    assert!(
        page_limit(&Page {
            after_sequence: None,
            limit: Some(101),
        })
        .is_err()
    );
    assert_eq!(etag("0001-deadbeef").expect("ETag"), "\"0001-deadbeef\"");
    assert!(etag("bad\nrevision").is_none());
}

#[test]
fn mutation_preconditions_are_exact_and_single_valued() {
    let revision = format!("{:020}-{}", 1, "a".repeat(64));
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/toml"));
    headers.insert(
        IF_MATCH,
        HeaderValue::from_str(&format!("\"{revision}\"")).expect("If-Match"),
    );
    assert!(require_toml(&headers).is_ok());
    assert_eq!(expected_revision(&headers).expect("revision"), revision);

    let mut json_headers = HeaderMap::new();
    json_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    assert!(require_json(&json_headers).is_ok());
    json_headers.insert("x-aegis-object-generation", HeaderValue::from_static("42"));
    assert_eq!(
        expected_object_generation(&json_headers).expect("generation"),
        42
    );
    json_headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    assert!(require_json(&json_headers).is_err());
    json_headers.append("x-aegis-object-generation", HeaderValue::from_static("42"));
    assert!(expected_object_generation(&json_headers).is_err());

    headers.append(CONTENT_TYPE, HeaderValue::from_static("application/toml"));
    assert!(require_toml(&headers).is_err());
    headers.append(IF_MATCH, HeaderValue::from_static("\"duplicate\""));
    assert!(expected_revision(&headers).is_err());

    let mut weak = HeaderMap::new();
    weak.insert(
        IF_MATCH,
        HeaderValue::from_str(&format!("W/\"{revision}\"")).expect("weak ETag"),
    );
    assert!(expected_revision(&weak).is_err());
    assert!(valid_api_path(Path::new("/var/backups/aegis.age")));
    assert!(!valid_api_path(Path::new("relative.age")));
    assert!(!valid_api_path(Path::new("/var/backups/../escape.age")));
}

#[test]
fn broad_socket_parent_is_rejected() {
    let root = temporary_directory("broad");
    fs::create_dir(&root).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("broad root");
    let result = bind_private_socket(&root.join("admin.sock"));
    assert!(result.is_err());
    fs::remove_dir(root).expect("remove root");
}
