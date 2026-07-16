use std::{
    collections::HashMap,
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use aegisproxy_config::{
    Config,
    revision::{RevisionError, RevisionStore},
};
use aegisproxy_tls::TlsAcceptor;
use arc_swap::ArcSwap;
use thiserror::Error;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::{
    DnsEndpoints, ProxyError, RouteIndex, UpstreamClients, UpstreamPools, build_upstream_clients,
    build_upstream_pools, prepare_dns, prepare_tls, start_active_health_checks,
    start_dns_refreshes,
};

pub(crate) struct RuntimeSnapshot {
    pub(crate) revision: Arc<str>,
    pub(crate) config: Arc<Config>,
    pub(crate) route_index: Arc<RouteIndex>,
    pub(crate) tls_acceptors: HashMap<String, TlsAcceptor>,
    pub(crate) upstream_clients: UpstreamClients,
    pub(crate) upstream_pools: UpstreamPools,
    pub(crate) dns_endpoints: DnsEndpoints,
    background_cancel: CancellationToken,
    health_tasks: TaskTracker,
    dns_tasks: TaskTracker,
}

impl fmt::Debug for RuntimeSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeSnapshot")
            .field("revision", &self.revision)
            .field("listeners", &self.config.listeners.len())
            .field("routes", &self.config.routes.len())
            .field("upstream_groups", &self.config.upstream_groups.len())
            .finish_non_exhaustive()
    }
}

impl Drop for RuntimeSnapshot {
    fn drop(&mut self) {
        self.background_cancel.cancel();
    }
}

impl RuntimeSnapshot {
    pub(crate) async fn prepare(
        config: Arc<Config>,
        revision: impl Into<Arc<str>>,
        process_shutdown: &CancellationToken,
    ) -> Result<Arc<Self>, ProxyError> {
        Self::prepare_reusing(config, revision, process_shutdown, None).await
    }

    async fn prepare_reusing(
        config: Arc<Config>,
        revision: impl Into<Arc<str>>,
        process_shutdown: &CancellationToken,
        previous: Option<&RuntimeSnapshot>,
    ) -> Result<Arc<Self>, ProxyError> {
        aegisproxy_config::validate(&config)?;
        let route_index = Arc::new(RouteIndex::compile(&config));
        let preparation_config = Arc::clone(&config);
        let previous_upstreams = previous.map(|previous| {
            (
                Arc::clone(&previous.config),
                Arc::clone(&previous.upstream_clients),
                Arc::clone(&previous.upstream_pools),
                Arc::clone(&previous.dns_endpoints),
            )
        });
        let (tls_acceptors, upstream_clients, upstream_pools, dns_endpoints) =
            tokio::task::spawn_blocking(move || {
                let (mut clients, mut dns_endpoints) = build_upstream_clients(&preparation_config)?;
                let mut pools = build_upstream_pools(&preparation_config)?;
                if let Some((previous_config, previous_clients, previous_pools, previous_dns)) =
                    previous_upstreams
                {
                    for group in &preparation_config.upstream_groups {
                        if !previous_config
                            .upstream_groups
                            .iter()
                            .any(|previous| previous == group)
                        {
                            continue;
                        }
                        if let Some(previous_pool) = previous_pools.get(&group.id) {
                            Arc::make_mut(&mut pools)
                                .insert(group.id.clone(), Arc::clone(previous_pool));
                        }
                        for endpoint in &group.endpoints {
                            let key = super::endpoint_key(&group.id, &endpoint.id);
                            if let Some(previous_client) = previous_clients.get(&key) {
                                Arc::make_mut(&mut clients)
                                    .insert(key.clone(), previous_client.clone());
                            }
                            if let Some(previous_dns) = previous_dns.get(&key) {
                                Arc::make_mut(&mut dns_endpoints)
                                    .insert(key, Arc::clone(previous_dns));
                            }
                        }
                    }
                }
                Ok::<_, ProxyError>((
                    prepare_tls(&preparation_config)?,
                    clients,
                    pools,
                    dns_endpoints,
                ))
            })
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??;
        let dns_resolver = prepare_dns(
            &dns_endpoints.values().cloned().collect::<Vec<_>>(),
            config.limits.max_dns_lookups,
        )
        .await
        .map_err(|error| ProxyError::Preparation(error.to_string()))?;
        let background_cancel = process_shutdown.child_token();
        let health_tasks = start_active_health_checks(
            &config,
            &upstream_clients,
            &upstream_pools,
            &dns_endpoints,
            &background_cancel,
        )?;
        let dns_tasks = start_dns_refreshes(
            &dns_endpoints.values().cloned().collect::<Vec<_>>(),
            dns_resolver,
            config.limits.max_dns_lookups,
            &background_cancel,
        );
        Ok(Arc::new(Self {
            revision: revision.into(),
            config,
            route_index,
            tls_acceptors,
            upstream_clients,
            upstream_pools,
            dns_endpoints,
            background_cancel,
            health_tasks,
            dns_tasks,
        }))
    }

    pub(crate) async fn stop_background(&self) {
        self.background_cancel.cancel();
        self.health_tasks.wait().await;
        self.dns_tasks.wait().await;
    }
}

/// Atomic owner of the current immutable proxy runtime snapshot.
#[derive(Clone)]
pub struct RuntimeHandle {
    current: Arc<ArcSwap<RuntimeSnapshot>>,
}

impl fmt::Debug for RuntimeHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeHandle")
            .field("revision", &self.current.load().revision)
            .finish_non_exhaustive()
    }
}

impl RuntimeHandle {
    pub(crate) fn new(initial: Arc<RuntimeSnapshot>) -> Self {
        Self {
            current: Arc::new(ArcSwap::from(initial)),
        }
    }

    pub(crate) fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    fn publish(&self, candidate: Arc<RuntimeSnapshot>) -> Arc<RuntimeSnapshot> {
        self.current.swap(candidate)
    }

    /// Return the active immutable revision identifier.
    pub fn revision(&self) -> Arc<str> {
        Arc::clone(&self.current.load().revision)
    }
}

/// Transactional runtime activation failure.
#[derive(Debug, Error)]
pub enum ActivationError {
    /// Durable revision state failed.
    #[error("revision activation failed: {0}")]
    Revision(#[from] RevisionError),
    /// Candidate runtime preparation failed.
    #[error("candidate preparation failed: {0}")]
    Preparation(#[from] ProxyError),
    /// Candidate requires process restart because listener/resource limits changed.
    #[error("candidate changes restart-only listener or resource settings")]
    RestartRequired,
    /// Structural probation rejected the published candidate.
    #[error("candidate failed structural probation")]
    Probation,
    /// In-memory rollback succeeded but durable rollback failed.
    #[error("durable rollback failed; administrative mutations are disabled")]
    RecoveryRequired,
}

/// Successful atomic activation outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationResult {
    /// Newly active immutable revision ID.
    pub active: String,
    /// Previously active immutable revision ID, when present.
    pub previous: Option<String>,
}

/// Serialized prepare-before-publish activation coordinator.
#[derive(Debug)]
pub struct ActivationCoordinator {
    revisions: Arc<RevisionStore>,
    runtime: RuntimeHandle,
    process_shutdown: CancellationToken,
    mutation: tokio::sync::Mutex<()>,
    administration_ready: AtomicBool,
}

impl ActivationCoordinator {
    /// Create a coordinator for one locked revision store and runtime.
    pub fn new(
        revisions: Arc<RevisionStore>,
        runtime: RuntimeHandle,
        process_shutdown: CancellationToken,
    ) -> Self {
        Self {
            revisions,
            runtime,
            process_shutdown,
            mutation: tokio::sync::Mutex::new(()),
            administration_ready: AtomicBool::new(true),
        }
    }

    /// Prepare and atomically activate an immutable candidate using exact CAS.
    pub async fn activate(
        &self,
        candidate_id: &str,
        expected_active: Option<&str>,
    ) -> Result<ActivationResult, ActivationError> {
        self.activate_with_probe(candidate_id, expected_active, async { true })
            .await
    }

    /// Whether durable mutation remains safe after the latest activation.
    pub fn administration_ready(&self) -> bool {
        self.administration_ready.load(Ordering::Acquire)
    }

    async fn activate_with_probe<F>(
        &self,
        candidate_id: &str,
        expected_active: Option<&str>,
        probation: F,
    ) -> Result<ActivationResult, ActivationError>
    where
        F: Future<Output = bool>,
    {
        let _guard = self.mutation.lock().await;
        if !self.administration_ready() {
            return Err(ActivationError::RecoveryRequired);
        }
        let candidate_id = candidate_id.to_owned();
        let expected_active = expected_active.map(str::to_owned);
        let revisions = Arc::clone(&self.revisions);
        let candidate_config = tokio::task::spawn_blocking({
            let candidate_id = candidate_id.clone();
            move || revisions.load(&candidate_id)
        })
        .await
        .map_err(|error| ProxyError::Preparation(error.to_string()))??;
        let current = self.runtime.load();
        if !hot_reload_compatible(&current.config, &candidate_config) {
            return Err(ActivationError::RestartRequired);
        }
        let candidate = RuntimeSnapshot::prepare_reusing(
            Arc::new(candidate_config),
            Arc::<str>::from(candidate_id.clone()),
            &self.process_shutdown,
            Some(&current),
        )
        .await?;
        let revisions = Arc::clone(&self.revisions);
        let journal = tokio::task::spawn_blocking({
            let candidate_id = candidate_id.clone();
            let expected_active = expected_active.clone();
            move || revisions.begin_activation(&candidate_id, expected_active.as_deref())
        })
        .await
        .map_err(|error| ProxyError::Preparation(error.to_string()))??;

        let retired = self.runtime.publish(Arc::clone(&candidate));
        if let Err(error) = self.mark_probation(&candidate_id).await {
            return Err(self
                .restore_after_publication(&candidate_id, retired, error)
                .await);
        }
        if !probation.await {
            return Err(self
                .restore_after_publication(&candidate_id, retired, ActivationError::Probation)
                .await);
        }
        if let Err(error) = self.commit(&candidate_id).await {
            return Err(self
                .restore_after_publication(&candidate_id, retired, error)
                .await);
        }
        retire_replaced_pools(&retired, &candidate);
        retired.stop_background().await;
        Ok(ActivationResult {
            active: candidate_id,
            previous: journal.previous.map(|previous| previous.id),
        })
    }

    async fn mark_probation(&self, candidate_id: &str) -> Result<(), ActivationError> {
        let revisions = Arc::clone(&self.revisions);
        let candidate_id = candidate_id.to_owned();
        tokio::task::spawn_blocking(move || revisions.mark_probation(&candidate_id))
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??;
        Ok(())
    }

    async fn commit(&self, candidate_id: &str) -> Result<(), ActivationError> {
        let revisions = Arc::clone(&self.revisions);
        let candidate_id = candidate_id.to_owned();
        tokio::task::spawn_blocking(move || revisions.commit_activation(&candidate_id))
            .await
            .map_err(|error| ProxyError::Preparation(error.to_string()))??;
        Ok(())
    }

    async fn restore_after_publication(
        &self,
        candidate_id: &str,
        retired: Arc<RuntimeSnapshot>,
        original: ActivationError,
    ) -> ActivationError {
        let failed = self.runtime.publish(retired);
        failed.stop_background().await;
        let revisions = Arc::clone(&self.revisions);
        let candidate_id = candidate_id.to_owned();
        match tokio::task::spawn_blocking(move || revisions.rollback_activation(&candidate_id))
            .await
        {
            Ok(Ok(_)) => original,
            Ok(Err(error)) => {
                tracing::error!(%error, "durable activation rollback failed");
                self.administration_ready.store(false, Ordering::Release);
                ActivationError::RecoveryRequired
            }
            Err(error) => {
                tracing::error!(%error, "durable activation rollback task failed");
                self.administration_ready.store(false, Ordering::Release);
                ActivationError::RecoveryRequired
            }
        }
    }
}

fn hot_reload_compatible(current: &Config, candidate: &Config) -> bool {
    current.runtime.state_dir == candidate.runtime.state_dir
        && current.limits == candidate.limits
        && current.tls.max_handshakes == candidate.tls.max_handshakes
        && current.listeners.len() == candidate.listeners.len()
        && current.listeners.iter().all(|listener| {
            candidate.listeners.iter().any(|candidate| {
                listener.id == candidate.id
                    && listener.bind == candidate.bind
                    && listener.protocol == candidate.protocol
            })
        })
}

fn retire_replaced_pools(retired: &RuntimeSnapshot, active: &RuntimeSnapshot) {
    for (group_id, pool) in retired.upstream_pools.iter() {
        if active
            .upstream_pools
            .get(group_id)
            .is_some_and(|active_pool| Arc::ptr_eq(pool, active_pool))
        {
            continue;
        }
        for endpoint in pool.endpoints() {
            let _ = pool.begin_drain(&endpoint.config().id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aegisproxy_config::{
        AdminConfig, Config, EndpointConfig, LimitsConfig, ListenerConfig, RuntimeConfig,
        TlsConfig, TrustedProxyConfig, UpstreamGroupConfig, revision::RevisionStore,
    };

    use super::*;

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
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![],
            middlewares: BTreeMap::new(),
            routes: vec![],
            admin: AdminConfig::default(),
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
        let same = RuntimeSnapshot::prepare_reusing(
            Arc::new(same_config),
            "same",
            &shutdown,
            Some(&first),
        )
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
        retire_replaced_pools(&same, &changed);
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
        first.stop_background().await;
        same.stop_background().await;
        changed.stop_background().await;
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
        let coordinator =
            ActivationCoordinator::new(Arc::clone(&revisions), runtime.clone(), shutdown);
        let activated = coordinator
            .activate(&second.id, Some(&first.id))
            .await
            .expect("activate");
        assert_eq!(activated.previous.as_deref(), Some(first.id.as_str()));
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
}
