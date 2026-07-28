use super::*;
use aegisproxy_config::{
    CertificateConfig, ListenerConfig, MiddlewareConfig, revision::RevisionStore,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn base_config() -> Config {
    let mut config =
        aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
            .expect("valid base config");
    config.tls.identity = Some("env://TEST_AGE_IDENTITY".into());
    config.certificates.push(CertificateConfig {
        id: "managed-new-example".into(),
        hosts: vec!["new.example.test".into()],
        certificate_chain: "file:///test/cert.pem".into(),
        private_key: "file:///test/key.age".into(),
    });
    config.listeners.push(ListenerConfig {
        id: "secure".into(),
        bind: "127.0.0.1:8443".parse().expect("socket address"),
        protocol: "https".into(),
        certificates: vec!["managed-new-example".into()],
    });
    config.middlewares.insert(
        "private-policy".into(),
        MiddlewareConfig::IpPolicy {
            allow: vec!["10.0.0.0/8".parse().expect("CIDR")],
            deny: Vec::new(),
        },
    );
    validate(&config).expect("valid extended base");
    config
}

fn object() -> ApiObject<ProxyHostSpec> {
    serde_json::from_str(
        r#"{
            "api_version":"v1",
            "metadata":{"id":"proxy-new","owner_id":"alice"},
            "spec":{
                "domain":"new.example.test",
                "forward_host":"upstream.example.test",
                "forward_port":8080,
                "forward_protocol":"http",
                "automatic_https":"disabled",
                "access_policy_ref":null,
                "enabled":true
            }
        }"#,
    )
    .expect("typed object")
}

struct Parts {
    owner: ObjectId,
    policies: BTreeMap<ObjectId, AccessPolicyMetadata>,
    objects: BTreeSet<(ObjectId, ObjectId)>,
    domains: BTreeMap<String, (ObjectId, ObjectId)>,
}

fn parts() -> Parts {
    Parts {
        owner: "alice".parse().expect("owner"),
        policies: BTreeMap::new(),
        objects: BTreeSet::new(),
        domains: BTreeMap::new(),
    }
}

fn policy_metadata(
    config: &Config,
    id: &str,
    owner: &str,
    shared_with: &[&str],
    enabled: bool,
) -> (ObjectId, AccessPolicyMetadata) {
    let object: ApiObject<crate::AccessPolicySpec> = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "metadata": {"id": id, "owner_id": owner},
        "spec": {
            "enabled": enabled,
            "shared_with": shared_with,
            "middlewares": ["private-policy"]
        }
    }))
    .expect("policy object");
    let metadata = crate::compile_access_policy_metadata(&object, config).expect("policy metadata");
    (object.metadata.id, metadata)
}

fn context<'a>(
    config: &'a Config,
    parts: &'a Parts,
    https: Option<&'a ManagedHttpsPolicy>,
) -> CompileContext<'a> {
    CompileContext {
        base_config: config,
        owner_id: &parts.owner,
        http_listener_id: "public",
        upstream_template_id: "app",
        access_policies: &parts.policies,
        claimed_objects: &parts.objects,
        claimed_domains: &parts.domains,
        managed_https: https,
    }
}

fn set_context<'a>(
    config: &'a Config,
    policies: &'a BTreeMap<ObjectId, AccessPolicyMetadata>,
    https: &'a BTreeMap<(ObjectId, ObjectId), ManagedHttpsPolicy>,
) -> ProxyHostSetCompileContext<'a> {
    ProxyHostSetCompileContext {
        base_config: config,
        http_listener_id: "public",
        upstream_template_id: "app",
        access_policies: policies,
        managed_https: https,
    }
}

#[test]
fn compiles_valid_variants_deterministically() {
    let config = base_config();
    let mut parts = parts();
    let (policy_id, metadata) = policy_metadata(&config, "private", "alice", &[], true);
    parts.policies.insert(policy_id, metadata);
    let https = ManagedHttpsPolicy {
        listener_id: "secure".into(),
        certificate_id: "managed-new-example".into(),
    };
    let compile = |value: &ApiObject<ProxyHostSpec>| {
        compile_proxy_host(value, &context(&config, &parts, Some(&https)))
            .expect("compiled candidate")
    };

    let http = object();
    let first = compile(&http);
    let second = compile(&http);
    assert_eq!(
        serde_json::to_vec(first.config()).expect("serialize candidate"),
        serde_json::to_vec(second.config()).expect("serialize candidate")
    );
    validate(first.config()).expect("semantic validation");
    assert_eq!(
        first.config().routes.last().expect("generated route").id,
        "ph-4e2643bcdffd306e42206db2e8bdc69f-route"
    );

    let mut upstream_tls = http.clone();
    upstream_tls.spec.forward_protocol = ForwardProtocol::Https;
    let upstream_tls = compile(&upstream_tls);
    let endpoint = &upstream_tls
        .config()
        .upstream_groups
        .last()
        .expect("generated group")
        .endpoints[0];
    assert_eq!(endpoint.url.scheme(), "https");
    assert_eq!(
        endpoint.server_name.as_deref(),
        Some("upstream.example.test")
    );

    let mut managed = http.clone();
    managed.spec.automatic_https = AutomaticHttps::Managed;
    assert_eq!(
        compile(&managed)
            .config()
            .routes
            .last()
            .expect("generated route")
            .listeners,
        ["secure"]
    );

    let mut protected = http.clone();
    protected.spec.access_policy_ref =
        Some(serde_json::from_str("\"private\"").expect("policy reference"));
    assert_eq!(
        compile(&protected)
            .config()
            .routes
            .last()
            .expect("generated route")
            .middlewares,
        ["private-policy"]
    );

    let mut disabled = http;
    disabled.spec.enabled = false;
    let disabled = compile(&disabled);
    assert_eq!(disabled.config().routes.len(), config.routes.len());
    assert_eq!(
        disabled.config().upstream_groups.len(),
        config.upstream_groups.len()
    );
    assert!(!disabled.object().spec.enabled);
}

#[test]
fn shared_access_policy_compiles_only_for_explicit_owner() {
    let config = base_config();
    let mut parts = parts();
    parts.owner = "bob".parse().expect("owner");
    let (policy_id, metadata) = policy_metadata(&config, "shared", "alice", &["bob"], true);
    parts.policies.insert(policy_id, metadata);
    let mut value = object();
    value.metadata.owner_id = parts.owner.clone();
    value.spec.access_policy_ref = Some(serde_json::from_str("\"shared\"").expect("reference"));

    let candidate =
        compile_proxy_host(&value, &context(&config, &parts, None)).expect("shared policy");
    assert_eq!(
        candidate
            .config()
            .routes
            .last()
            .expect("generated route")
            .middlewares,
        ["private-policy"]
    );
    let managed_https = BTreeMap::new();
    let aggregate = compile_proxy_hosts(
        &[],
        &[value.clone()],
        &set_context(&config, &parts.policies, &managed_https),
    )
    .expect("aggregate shared policy");
    assert_eq!(
        aggregate
            .config()
            .routes
            .last()
            .expect("aggregate route")
            .middlewares,
        ["private-policy"]
    );
    validate(aggregate.config()).expect("aggregate semantic validation");

    parts.owner = "charlie".parse().expect("owner");
    value.metadata.owner_id = parts.owner.clone();
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("unshared owner"),
        ProxyHostCompileError::UnauthorizedAccessPolicy
    );
}

#[test]
fn access_policy_cannot_bypass_listener_semantics() {
    let mut config = base_config();
    config.middlewares.insert(
        "basic".into(),
        MiddlewareConfig::BasicAuth {
            realm: "test".into(),
            users: BTreeMap::from([("operator".into(), "env://TEST_PASSWORD_HASH".into())]),
            max_concurrent_verifications: 1,
            timeout_secs: 1,
        },
    );
    validate(&config).expect("valid unused middleware");
    let policy: ApiObject<crate::AccessPolicySpec> = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "metadata": {"id": "authenticated", "owner_id": "alice"},
        "spec": {
            "enabled": true,
            "shared_with": [],
            "middlewares": ["basic"]
        }
    }))
    .expect("policy object");
    let metadata =
        crate::compile_access_policy_metadata(&policy, &config).expect("policy metadata");
    let mut parts = parts();
    parts.policies.insert(policy.metadata.id, metadata);
    let mut value = object();
    value.spec.access_policy_ref =
        Some(serde_json::from_str("\"authenticated\"").expect("reference"));

    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None))
            .expect_err("Basic auth on HTTP"),
        ProxyHostCompileError::SemanticValidation
    );
}

#[test]
fn compiles_complete_desired_state_deterministically_and_preserves_pending_objects() {
    let config = base_config();
    let policies = BTreeMap::new();
    let https = BTreeMap::new();
    let first = object();
    let mut second = object();
    second.metadata.owner_id = "bob".parse().expect("owner");
    second.metadata.id = "proxy-second".parse().expect("object ID");
    second.spec.domain = "second.example.test".into();

    let ordered = compile_proxy_hosts(
        &[],
        &[second.clone(), first.clone()],
        &set_context(&config, &policies, &https),
    )
    .expect("aggregate candidate");
    let repeated = compile_proxy_hosts(
        &[],
        &[first.clone(), second.clone()],
        &set_context(&config, &policies, &https),
    )
    .expect("repeat aggregate candidate");
    assert_eq!(ordered.objects()[0].metadata.owner_id.as_str(), "alice");
    assert_eq!(ordered.objects()[1].metadata.owner_id.as_str(), "bob");
    assert_eq!(
        serde_json::to_vec(ordered.config()).expect("ordered config"),
        serde_json::to_vec(repeated.config()).expect("repeated config")
    );
    assert_eq!(ordered.config().routes.len(), config.routes.len() + 2);

    let pending = compile_proxy_hosts(
        std::slice::from_ref(&first),
        &[first.clone(), second],
        &set_context(&config, &policies, &https),
    )
    .expect("pending desired state");
    assert_eq!(pending.config().routes.len(), config.routes.len() + 2);
    validate(pending.config()).expect("semantic validation");
}

#[test]
fn aggregate_replaces_only_reserved_managed_resources() {
    let config = base_config();
    let parts = parts();
    let policies = BTreeMap::new();
    let https = BTreeMap::new();
    let current = object();
    let active = compile_proxy_host(&current, &context(&config, &parts, None))
        .expect("active generated config")
        .config()
        .clone();
    let mut desired = current.clone();
    desired.spec.domain = "replacement.example.test".into();

    let replacement = compile_proxy_hosts(
        std::slice::from_ref(&current),
        std::slice::from_ref(&desired),
        &set_context(&active, &policies, &https),
    )
    .expect("replacement candidate");
    assert_eq!(replacement.config().routes.len(), config.routes.len() + 1);
    assert!(
        replacement
            .config()
            .routes
            .iter()
            .any(|route| route.hosts == ["replacement.example.test"])
    );
    assert!(
        !replacement
            .config()
            .routes
            .iter()
            .any(|route| { route.hosts == ["new.example.test"] })
    );

    desired.spec.enabled = false;
    let disabled = compile_proxy_hosts(
        std::slice::from_ref(&current),
        std::slice::from_ref(&desired),
        &set_context(&active, &policies, &https),
    )
    .expect("disabled candidate");
    assert_eq!(disabled.config().routes.len(), config.routes.len());
    assert_eq!(
        disabled.config().upstream_groups.len(),
        config.upstream_groups.len()
    );
}

#[test]
fn aggregate_rejects_manual_takeover_partial_resources_and_duplicate_state() {
    let config = base_config();
    let parts = parts();
    let policies = BTreeMap::new();
    let https = BTreeMap::new();
    let current = object();
    let active = compile_proxy_host(&current, &context(&config, &parts, None))
        .expect("active generated config")
        .config()
        .clone();

    assert_eq!(
        compile_proxy_hosts(
            &[],
            std::slice::from_ref(&current),
            &set_context(&active, &policies, &https),
        )
        .expect_err("unreserved manual collision"),
        ProxyHostCompileError::ConflictingDomain
    );

    let mut partial = active.clone();
    partial
        .routes
        .iter_mut()
        .find(|route| route.id == ManagedIds::new(&current).route)
        .expect("managed route")
        .paths
        .push("/tampered".into());
    validate(&partial).expect("structurally valid tamper");
    assert_eq!(
        compile_proxy_hosts(
            std::slice::from_ref(&current),
            std::slice::from_ref(&current),
            &set_context(&partial, &policies, &https),
        )
        .expect_err("partial managed shape"),
        ProxyHostCompileError::ManagedResourceConflict
    );

    assert_eq!(
        compile_proxy_hosts(
            &[],
            &[current.clone(), current],
            &set_context(&config, &policies, &https),
        )
        .expect_err("duplicate objects"),
        ProxyHostCompileError::ConflictingObjectId
    );
}

#[test]
fn rejects_invalid_conflicting_and_unauthorized_inputs() {
    let config = base_config();
    let mut parts = parts();
    let mut value = object();

    let mut unsupported = config.clone();
    unsupported.schema_version = 2;
    assert_eq!(
        compile_proxy_host(&value, &context(&unsupported, &parts, None))
            .expect_err("unsupported configuration version"),
        ProxyHostCompileError::UnsupportedConfigurationVersion
    );

    for (domain, expected) in [
        ("", ProxyHostCompileError::InvalidDomain),
        ("bad..example", ProxyHostCompileError::InvalidDomain),
        (
            "*.example.test",
            ProxyHostCompileError::UnsupportedDomainForm,
        ),
        ("täst.example", ProxyHostCompileError::UnsupportedDomainForm),
        (
            "example.test.",
            ProxyHostCompileError::UnsupportedDomainForm,
        ),
    ] {
        value.spec.domain = domain.into();
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("invalid domain"),
            expected
        );
    }

    value = object();
    value.spec.forward_host = "bad host".into();
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("invalid upstream"),
        ProxyHostCompileError::InvalidUpstreamHost
    );
    value = object();
    value.spec.forward_port = 0;
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("invalid port"),
        ProxyHostCompileError::InvalidPort
    );
    value = object();
    value.spec.automatic_https = AutomaticHttps::Managed;
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None))
            .expect_err("missing HTTPS policy"),
        ProxyHostCompileError::InvalidCertificatePolicy
    );

    value = object();
    value.metadata.owner_id = "bob".parse().expect("owner");
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("wrong owner"),
        ProxyHostCompileError::UnauthorizedOwner
    );

    value = object();
    value.spec.access_policy_ref = Some(serde_json::from_str("\"missing\"").expect("reference"));
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("missing policy"),
        ProxyHostCompileError::MissingAccessPolicy
    );
    let (policy_id, metadata) = policy_metadata(&config, "disabled", "alice", &[], false);
    parts.policies.insert(policy_id, metadata);
    value.spec.access_policy_ref = Some(serde_json::from_str("\"disabled\"").expect("reference"));
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("disabled policy"),
        ProxyHostCompileError::MissingAccessPolicy
    );
    let (policy_id, metadata) = policy_metadata(&config, "private", "bob", &[], true);
    parts.policies.insert(policy_id, metadata);
    value.spec.access_policy_ref = Some(serde_json::from_str("\"private\"").expect("reference"));
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None))
            .expect_err("unauthorized policy"),
        ProxyHostCompileError::UnauthorizedAccessPolicy
    );

    value = object();
    parts
        .objects
        .insert((parts.owner.clone(), value.metadata.id.clone()));
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("object collision"),
        ProxyHostCompileError::ConflictingObjectId
    );
    parts.objects.clear();
    value.spec.domain = "example.test".into();
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None))
            .expect_err("existing route domain"),
        ProxyHostCompileError::ConflictingDomain
    );
    value.spec.domain = "new.example.test".into();
    parts.domains.insert(
        value.spec.domain.clone(),
        ("bob".parse().expect("owner"), "other".parse().expect("ID")),
    );
    assert_eq!(
        compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("domain collision"),
        ProxyHostCompileError::ConflictingDomain
    );
}

#[test]
fn revision_candidate_does_not_activate_or_leak_plaintext() {
    let config = base_config();
    let parts = parts();
    let candidate =
        compile_proxy_host(&object(), &context(&config, &parts, None)).expect("compiled candidate");
    let state = temp_state();
    let store = RevisionStore::open(&state).expect("revision store");
    let mut rejected = object();
    rejected.spec.domain = "*.example.test".into();
    assert!(compile_proxy_host(&rejected, &context(&config, &parts, None)).is_err());
    assert!(store.list().expect("revision list").is_empty());
    assert!(store.active().expect("active pointer").is_none());
    let revision = store
        .create_candidate(candidate.config(), "typed-proxy-host")
        .expect("persist candidate");
    assert!(store.active().expect("active pointer").is_none());
    assert_eq!(
        store
            .load(&revision.id)
            .expect("load candidate")
            .routes
            .len(),
        config.routes.len() + 1
    );
    let serialized = serde_json::to_string(candidate.config()).expect("serialize candidate");
    for secret in [
        "plaintext-password",
        "private-key-canary",
        "api-token-canary",
    ] {
        assert!(!serialized.contains(secret));
    }
    let debug = format!("{candidate:?}");
    assert!(!debug.contains("file:///"));
    for error in [
        ProxyHostCompileError::MissingAccessPolicy,
        ProxyHostCompileError::UnauthorizedAccessPolicy,
        ProxyHostCompileError::InvalidCertificatePolicy,
        ProxyHostCompileError::SemanticValidation,
    ] {
        assert!(!error.to_string().contains("canary"));
    }
    fs::remove_dir_all(state).expect("remove test state");
}

fn temp_state() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("aegisproxy-compile-{}-{nonce}", std::process::id()))
}
