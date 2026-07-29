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

#[test]
fn disabled_user_blocks_subject_token_but_legacy_identity_remains_parseable() {
    let root = temporary_directory("subject-disable");
    let store = UserStore::open(root.join("admin/users.json")).expect("user store");
    let user: ApiObject<UserSpec> = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "metadata": {"id": "alice", "owner_id": "alice"},
        "spec": {"display_name": "Alice", "role": "operator", "enabled": true}
    }))
    .expect("user");
    store.create(user.clone()).expect("create");
    let metadata = crate::TokenMetadata {
        id: "abcdefghijklmnop".into(),
        role: Role::Operator,
        owner_id: Some("alice".parse().expect("owner")),
        user_ref: Some("alice".parse().expect("subject")),
        scopes: TokenScopes::new(Role::Operator, vec![Action::ReadStatus]).expect("scopes"),
        expires_unix_secs: u64::MAX,
        revoked: false,
    };
    assert!(subject_is_enabled(&metadata, &store));
    let mut disabled = user;
    disabled.spec.enabled = false;
    store.update(disabled, 1).expect("disable");
    assert!(!subject_is_enabled(&metadata, &store));
    let legacy = crate::TokenMetadata {
        user_ref: None,
        ..metadata
    };
    assert!(subject_is_enabled(&legacy, &store));
    fs::remove_dir_all(root).expect("cleanup");
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
        "/v1/web/status:",
        "/v1/auth/login:",
        "/v1/auth/callback:",
        "/v1/session:",
        "/v1/session/logout:",
        "/v1/web/setup-token:",
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
        "/v1/credentials:",
        "/v1/credentials/{id}:",
        "/v1/audit:",
        "/v1/tokens:",
        "/v1/tokens/{id}/revoke:",
        "/v1/users:",
        "/v1/users/{id}:",
        "/v1/roles:",
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
        "read_credentials",
        "create_credential",
        "update_credential",
        "revoke_credential",
        "renew_certificate",
        "read_audit",
        "create_backup",
        "validate_restore",
        "manage_identities",
        "read_tokens",
        "create_token",
        "revoke_token",
        "read_users",
        "create_user",
        "update_user",
        "read_roles",
        "create_web_setup_token",
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
    assert_eq!(openapi.matches("maxItems: 53").count(), 3);
    assert!(openapi.contains("x-aegis-authentication: unix-peer-only"));
    assert!(openapi.contains("scheme: aegis-unix-peer"));
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

#[test]
fn body_deserialization_remains_behind_authorization() {
    fn ordered(source: &str, start: &str, authorization: &str, deserialization: &str) {
        let source = source
            .split_once(start)
            .unwrap_or_else(|| panic!("missing function marker {start}"))
            .1;
        let authorization = source
            .find(authorization)
            .unwrap_or_else(|| panic!("missing authorization marker after {start}"));
        let deserialization = source
            .find(deserialization)
            .unwrap_or_else(|| panic!("missing deserialization marker after {start}"));
        assert!(
            authorization < deserialization,
            "{start} deserializes before authorization"
        );
    }

    let access = include_str!("handlers/access_policies.rs");
    ordered(
        access,
        "async fn create_access_policy",
        "begin_mutation(",
        "serde_json::from_slice",
    );
    ordered(
        access,
        "async fn update_access_policy",
        "begin_mutation(",
        "serde_json::from_slice",
    );
    let proxy = include_str!("handlers/proxy_hosts.rs");
    ordered(
        proxy,
        "async fn create_proxy_host",
        "begin_mutation(",
        "serde_json::from_slice",
    );
    ordered(
        proxy,
        "async fn update_proxy_host",
        "begin_mutation(",
        "serde_json::from_slice",
    );
    let domains = include_str!("domains.rs");
    ordered(
        domains,
        "async fn create<D: Domain>",
        "begin_domain_mutation(",
        "parse_owned::<D>",
    );
    ordered(
        domains,
        "async fn update<D: Domain>",
        "begin_domain_mutation(",
        "parse_owned::<D>",
    );
    let certificates = include_str!("certificates.rs");
    ordered(
        certificates,
        "async fn create_certificate",
        "begin_mutation(",
        "serde_json::from_slice",
    );
    ordered(
        certificates,
        "async fn update_certificate",
        "begin_mutation(",
        "serde_json::from_slice",
    );
    let credentials = include_str!("credentials.rs");
    ordered(
        credentials,
        "async fn create_credential",
        "begin_credential_mutation(",
        "parse_credential(",
    );
    ordered(
        credentials,
        "async fn update_credential",
        "begin_credential_mutation(",
        "parse_credential(",
    );
    let users = include_str!("users.rs");
    ordered(
        users,
        "async fn mutate_user",
        "begin_mutation(",
        "serde_json::from_slice",
    );
    let operations = include_str!("handlers/operations.rs");
    for start in [
        "async fn create_token",
        "async fn create_backup_archive",
        "async fn validate_restore_archive",
    ] {
        ordered(
            operations,
            start,
            "begin_mutation(",
            "parse_operation_json(",
        );
    }
    ordered(
        operations,
        "async fn parse_operation_json",
        "require_json(",
        "serde_json::from_slice",
    );
}

#[tokio::test]
async fn timed_out_requests_finish_before_shutdown_drain() {
    let permits = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&permits)
        .acquire_owned()
        .await
        .expect("request permit");
    let (release, released) = tokio::sync::oneshot::channel();
    let (completed, completion) = tokio::sync::oneshot::channel();
    let result = run_request_to_completion(Duration::from_millis(10), permit, async move {
        let _ = released.await;
        let _ = completed.send(());
        StatusCode::NO_CONTENT.into_response()
    })
    .await;
    assert!(matches!(result, Err(ApiError::Timeout)));
    assert_eq!(permits.available_permits(), 0);
    let mut drain = Box::pin(drain_requests(Arc::clone(&permits), 1));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut drain)
            .await
            .is_err()
    );
    release.send(()).expect("release request");
    tokio::time::timeout(Duration::from_secs(1), completion)
        .await
        .expect("request completion")
        .expect("completion signal");
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .expect("request drain")
        .expect("drain result");
    assert_eq!(permits.available_permits(), 1);
}

#[test]
fn user_store_errors_preserve_client_contracts() {
    for (error, status, code) in [
        (
            UserStoreError::Conflict,
            StatusCode::CONFLICT,
            "object_conflict",
        ),
        (
            UserStoreError::Invalid,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            UserStoreError::Limit,
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_exhausted",
        ),
        (
            UserStoreError::RecoveryRequired,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
    ] {
        let (audit_code, api_error) = user_store_error_contract(&error);
        assert!(!audit_code.is_empty());
        assert_eq!(api_error.contract().0, status);
        assert_eq!(api_error.contract().1, code);
    }
}

#[test]
fn candidate_route_migration_is_fail_closed() {
    assert!(candidate_schema_matches_route(1, true));
    assert!(candidate_schema_matches_route(2, false));
    assert!(!candidate_schema_matches_route(2, true));
    assert!(!candidate_schema_matches_route(1, false));
    assert!(!candidate_schema_matches_route(0, true));
    assert!(!candidate_schema_matches_route(3, false));
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
