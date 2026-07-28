use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use aegisproxy_config::{
    AcmeCertificateConfig, AcmeChallenge, AcmeEnvironment, AcmeIssuerConfig, AdminConfig,
    CertificateConfig, Config, EndpointConfig, LimitsConfig, ListenerConfig, RuntimeConfig,
    TlsConfig, TrustedProxyConfig, UpstreamGroupConfig, revision::RevisionStore,
};
use aegisproxy_tls::{
    ManagedCertificateEnvironment, ManagedCertificateProvenance, load_stored_identity,
    persist_managed_certificate,
};
use age::secrecy::ExposeSecret;

use super::*;

#[test]
fn validates_bounded_node_identity() {
    let identity = NodeIdentity::new("node-a".into(), 7).expect("valid identity");
    assert_eq!(identity.id().as_ref(), "node-a");
    assert_eq!(identity.fleet_generation(), 7);
    assert!(NodeIdentity::new("Node A".into(), 7).is_err());
    assert!(NodeIdentity::new("a".repeat(64), 7).is_err());
}

#[test]
fn browser_admin_changes_require_restart() {
    let current = config(8080);
    let mut candidate = (*current).clone();
    candidate.admin.web.enabled = true;
    assert!(!hot_reload_compatible(&current, &candidate));
}

#[tokio::test]
async fn drain_is_one_way_and_revision_hash_is_exact() {
    let shutdown = CancellationToken::new();
    let hash = "a".repeat(64);
    let snapshot = RuntimeSnapshot::prepare(config(8080), format!("{:020}-{hash}", 1), &shutdown)
        .await
        .expect("snapshot");
    let runtime = RuntimeHandle::new(snapshot);
    assert_eq!(runtime.revision_hash().as_deref(), Some(hash.as_str()));
    assert!(!runtime.is_draining());
    assert!(!runtime.audit_ready());
    runtime.set_audit_ready(true);
    assert!(runtime.audit_ready());
    assert!(runtime.begin_drain());
    assert!(runtime.is_draining());
    assert!(!runtime.begin_drain());
}

fn config(port: u16) -> Arc<Config> {
    Arc::new(Config {
        schema_version: 1,
        runtime: RuntimeConfig::default(),
        limits: LimitsConfig::default(),
        listeners: vec![ListenerConfig {
            id: "http".into(),
            bind: format!("127.0.0.1:{port}").parse().expect("address"),
            protocol: "http".into(),
            certificates: vec![],
        }],
        tls: TlsConfig::default(),
        certificates: vec![],
        acme: aegisproxy_config::AcmeConfig::default(),
        trusted_proxies: TrustedProxyConfig::default(),
        upstream_groups: vec![],
        providers: vec![],
        middlewares: BTreeMap::new(),
        routes: vec![],
        admin: AdminConfig::default(),
        observability: aegisproxy_config::ObservabilityConfig::default(),
    })
}

fn temporary_state() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "aegisproxy-runtime-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos()
    ))
}

fn config_with_upstream(port: u16, upstream_port: u16) -> Arc<Config> {
    let mut config = (*config(port)).clone();
    config.upstream_groups.push(UpstreamGroupConfig {
        id: "app".into(),
        allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
        endpoints: vec![EndpointConfig {
            id: "app-1".into(),
            url: format!("http://127.0.0.1:{upstream_port}")
                .parse()
                .expect("upstream URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        }],
        ..UpstreamGroupConfig::default()
    });
    Arc::new(config)
}

#[tokio::test]
async fn publication_is_one_atomic_pointer_swap() {
    let shutdown = CancellationToken::new();
    let first = RuntimeSnapshot::prepare(config(8080), "first", &shutdown)
        .await
        .expect("first");
    let handle = RuntimeHandle::new(first);
    let second = RuntimeSnapshot::prepare(config(8081), "second", &shutdown)
        .await
        .expect("second");
    let retired = handle.publish(second);
    assert_eq!(&*retired.revision, "first");
    assert_eq!(&*handle.revision(), "second");
    retired.stop_background().await;
}

#[tokio::test]
async fn reuses_only_complete_unchanged_upstream_groups() {
    let shutdown = CancellationToken::new();
    let first = RuntimeSnapshot::prepare(config_with_upstream(8080, 9000), "first", &shutdown)
        .await
        .expect("first");
    let mut same_config = (*first.config).clone();
    same_config.runtime.config_poll_secs = 2;
    let same =
        RuntimeSnapshot::prepare_reusing(Arc::new(same_config), "same", &shutdown, Some(&first))
            .await
            .expect("same");
    assert!(Arc::ptr_eq(
        first.upstream_pools.get("app").expect("first pool"),
        same.upstream_pools.get("app").expect("same pool")
    ));
    assert!(Arc::ptr_eq(
        first
            .dns_endpoints
            .get("app/app-1")
            .expect("first DNS endpoint"),
        same.dns_endpoints
            .get("app/app-1")
            .expect("same DNS endpoint")
    ));

    let changed = RuntimeSnapshot::prepare_reusing(
        config_with_upstream(8080, 9001),
        "changed",
        &shutdown,
        Some(&same),
    )
    .await
    .expect("changed");
    assert!(!Arc::ptr_eq(
        same.upstream_pools.get("app").expect("same pool"),
        changed.upstream_pools.get("app").expect("changed pool")
    ));
    let drains = begin_replaced_pool_drains(&same, &changed);
    assert!(
        same.upstream_pools
            .get("app")
            .expect("retired pool")
            .select()
            .is_err()
    );
    assert!(
        changed
            .upstream_pools
            .get("app")
            .expect("active pool")
            .select()
            .is_ok()
    );
    finish_drains(drains).await;
    first.stop_background().await;
    same.stop_background().await;
    changed.stop_background().await;
}

#[tokio::test]
async fn retains_tls_alpn_challenges_across_snapshot_reload() {
    let shutdown = CancellationToken::new();
    let first = RuntimeSnapshot::prepare(config(8080), "first", &shutdown)
        .await
        .expect("first");
    let lease = first
        .tls_challenges
        .install(
            "example.test",
            [0x42; 32],
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("install challenge");
    let second = RuntimeSnapshot::prepare_reusing(config(8080), "second", &shutdown, Some(&first))
        .await
        .expect("second");
    assert!(matches!(
        second
            .tls_challenges
            .install(
                "example.test",
                [0x24; 32],
                std::time::Duration::from_secs(60)
            )
            .await,
        Err(aegisproxy_tls::acme::TlsAlpnChallengeError::Collision)
    ));
    let handle = RuntimeHandle::new(second);
    assert!(matches!(
        handle
            .tls_challenges()
            .install(
                "example.test",
                [0x11; 32],
                std::time::Duration::from_secs(60)
            )
            .await,
        Err(aegisproxy_tls::acme::TlsAlpnChallengeError::Collision)
    ));
    drop(lease);
}

#[tokio::test]
async fn missing_managed_certificate_starts_closed_then_publishes_atomically() {
    let state = temporary_state();
    fs::create_dir(&state).expect("state directory");
    let identity = age::x25519::Identity::generate();
    let identity_path = state.join("identity.txt");
    fs::write(
        &identity_path,
        identity.to_string().expose_secret().as_bytes(),
    )
    .expect("identity file");
    #[cfg(unix)]
    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
        .expect("private identity permissions");
    let mut managed = (*config(8080)).clone();
    managed.runtime.state_dir = state.display().to_string();
    managed.tls.identity = Some(format!("file://{}", identity_path.display()));
    managed.tls.state_encryption_recipients = vec![identity.to_public().to_string()];
    managed.listeners.push(ListenerConfig {
        id: "https".into(),
        bind: "127.0.0.1:8443".parse().expect("HTTPS address"),
        protocol: "https".into(),
        certificates: vec!["managed".into()],
    });
    managed.acme.issuers.push(AcmeIssuerConfig {
        id: "pebble".into(),
        directory_url: "https://127.0.0.1:14000/dir"
            .parse()
            .expect("directory URL"),
        environment: AcmeEnvironment::Staging,
        account_email: None,
        terms_of_service_agreed: true,
        ca_bundle: Some("file:///pebble-ca.pem".into()),
        external_account: None,
        max_concurrent_orders: 1,
    });
    managed.acme.certificates.push(AcmeCertificateConfig {
        id: "managed".into(),
        hosts: vec!["example.test".into()],
        issuer: "pebble".into(),
        challenge: AcmeChallenge::Http01,
        challenge_listener: Some("http".into()),
        dns_provider: None,
        profile: None,
        renew_before_days: 30,
    });
    managed.acme.renewal_owner = Some("node-a".into());
    let shutdown = CancellationToken::new();
    let snapshot = RuntimeSnapshot::prepare(Arc::new(managed), "managed", &shutdown)
        .await
        .expect("managed snapshot");
    assert!(
        snapshot
            .tls_resolvers
            .get("https")
            .expect("HTTPS resolver")
            .resolve_name("example.test")
            .is_none()
    );
    let replica = RuntimeHandle::new_with_identity(
        Arc::clone(&snapshot),
        NodeIdentity::new("node-b".into(), 1).expect("replica identity"),
    );
    assert!(!replica.certificate_owner());
    let runtime = RuntimeHandle::new_with_identity(
        snapshot,
        NodeIdentity::new("node-a".into(), 1).expect("owner identity"),
    );
    assert!(runtime.certificate_owner());
    let generated =
        rcgen::generate_simple_self_signed(vec!["example.test".into()]).expect("certificate");
    persist_managed_certificate(
        &state,
        "managed",
        vec!["example.test".into()],
        generated.cert.pem().as_bytes(),
        generated.signing_key.serialize_pem().as_bytes(),
        ManagedCertificateProvenance {
            issuer_id: "pebble".into(),
            environment: ManagedCertificateEnvironment::Staging,
            profile: None,
        },
        &[identity.to_public().to_string()],
    )
    .expect("persist managed certificate");
    let loaded = load_stored_identity(
        &state,
        "managed",
        &format!("file://{}", identity_path.display()),
    )
    .expect("load managed certificate");
    let _guard = runtime.lock_mutation().await;
    let prepared = runtime
        .prepare_certificate_publication("managed", loaded)
        .expect("prepare publication");
    assert!(
        runtime
            .load()
            .tls_resolvers
            .get("https")
            .expect("HTTPS resolver")
            .resolve_name("example.test")
            .is_none()
    );
    runtime
        .publish_certificate(prepared)
        .expect("publish certificate");
    assert!(
        runtime
            .load()
            .tls_resolvers
            .get("https")
            .expect("HTTPS resolver")
            .resolve_name("example.test")
            .is_some()
    );
    fs::remove_dir_all(state).expect("cleanup");
}

#[tokio::test]
async fn coordinator_commits_and_rolls_back_failed_probation() {
    let state = temporary_state();
    let revisions = Arc::new(RevisionStore::open(&state).expect("revisions"));
    let first_config = config(8080);
    let mut second_config = (*first_config).clone();
    second_config.runtime.config_poll_secs = 2;
    let mut third_config = second_config.clone();
    third_config.runtime.config_poll_secs = 3;
    let first = revisions
        .create_candidate(&first_config, "first")
        .expect("first");
    let second = revisions
        .create_candidate(&second_config, "second")
        .expect("second");
    let third = revisions
        .create_candidate(&third_config, "third")
        .expect("third");
    let mut preparation_failure = second_config.clone();
    let missing = format!("file://{}", state.join("missing-secret").display());
    preparation_failure.tls.identity = Some(missing.clone());
    preparation_failure.certificates.push(CertificateConfig {
        id: "missing".into(),
        hosts: vec!["missing.example".into()],
        certificate_chain: missing.clone(),
        private_key: missing,
    });
    let preparation_failure = revisions
        .create_candidate(&preparation_failure, "preparation-failure")
        .expect("preparation failure candidate");
    let restart = revisions
        .create_candidate(&config(8081), "restart")
        .expect("restart");
    revisions
        .begin_activation(&first.id, None)
        .expect("first intent");
    revisions
        .mark_probation(&first.id)
        .expect("first probation");
    revisions
        .commit_activation(&first.id)
        .expect("first commit");

    let shutdown = CancellationToken::new();
    let initial = RuntimeSnapshot::prepare(first_config, first.id.clone(), &shutdown)
        .await
        .expect("initial");
    let runtime = RuntimeHandle::new(initial);
    let coordinator = ActivationCoordinator::new(Arc::clone(&revisions), runtime.clone(), shutdown);
    let activated = coordinator
        .activate(&second.id, Some(&first.id))
        .await
        .expect("activate");
    assert_eq!(activated.previous.as_deref(), Some(first.id.as_str()));
    assert_eq!(&*runtime.revision(), second.id);
    assert!(matches!(
        coordinator
            .activate(&preparation_failure.id, Some(&second.id))
            .await,
        Err(ActivationError::Preparation(_))
    ));
    assert_eq!(&*runtime.revision(), second.id);
    assert!(matches!(
        coordinator.activate(&restart.id, Some(&second.id)).await,
        Err(ActivationError::RestartRequired)
    ));
    assert_eq!(&*runtime.revision(), second.id);

    assert!(matches!(
        coordinator
            .activate_with_probe(&third.id, Some(&second.id), async { false })
            .await,
        Err(ActivationError::Probation)
    ));
    assert_eq!(&*runtime.revision(), second.id);
    assert_eq!(
        revisions
            .active()
            .expect("active")
            .expect("active")
            .active
            .id,
        second.id
    );
    assert!(coordinator.administration_ready());
    drop(coordinator);
    drop(revisions);
    fs::remove_dir_all(state).expect("cleanup");
}

#[tokio::test]
#[ignore = "manual release-mode reload benchmark"]
async fn benchmark_atomic_reload() {
    let state = temporary_state();
    let revisions = Arc::new(RevisionStore::open(&state).expect("revisions"));
    let initial_config = config(8080);
    let initial = revisions
        .create_candidate(&initial_config, "benchmark")
        .expect("initial candidate");
    revisions
        .begin_activation(&initial.id, None)
        .expect("initial intent");
    revisions
        .mark_probation(&initial.id)
        .expect("initial probation");
    revisions
        .commit_activation(&initial.id)
        .expect("initial commit");
    let shutdown = CancellationToken::new();
    let snapshot = RuntimeSnapshot::prepare(initial_config, initial.id.clone(), &shutdown)
        .await
        .expect("initial snapshot");
    let runtime = RuntimeHandle::new(snapshot);
    let coordinator =
        ActivationCoordinator::new(Arc::clone(&revisions), runtime.clone(), shutdown.clone());
    let mut active = initial.id;
    let mut samples = Vec::with_capacity(25);
    for poll_secs in 2..=26 {
        let mut candidate_config = (*config(8080)).clone();
        candidate_config.runtime.config_poll_secs = poll_secs;
        let candidate = revisions
            .create_candidate(&candidate_config, "benchmark")
            .expect("candidate");
        let started = std::time::Instant::now();
        coordinator
            .activate(&candidate.id, Some(&active))
            .await
            .expect("activation");
        samples.push(started.elapsed().as_micros());
        active = candidate.id;
    }
    samples.sort_unstable();
    let percentile = |numerator: usize| samples[(samples.len() - 1) * numerator / 100];
    println!(
        "reload_us samples={} p50={} p90={} p99={} max={} raw={samples:?}",
        samples.len(),
        percentile(50),
        percentile(90),
        percentile(99),
        samples[samples.len() - 1]
    );
    assert_eq!(&*runtime.revision(), active);
    shutdown.cancel();
    drop(coordinator);
    drop(revisions);
    fs::remove_dir_all(state).expect("cleanup");
}
