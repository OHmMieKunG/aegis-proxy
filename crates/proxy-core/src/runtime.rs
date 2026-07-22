use std::{
    collections::HashMap,
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use aegisproxy_config::{
    Config,
    revision::{RevisionError, RevisionStore},
};
use aegisproxy_tls::{
    CertificateResolver, Identity, PreparedCertificateMaps, TlsAcceptor,
    acme::{HttpChallengeRegistry, TlsAlpnChallengeRegistry},
};
use arc_swap::ArcSwap;
use thiserror::Error;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::telemetry::Telemetry;
use crate::upstream::DrainingEndpoint;

use super::{
    DnsEndpoints, ProxyError, RouteIndex, UpstreamClients, UpstreamPools, build_upstream_clients,
    build_upstream_pools, prepare_dns, prepare_tls, start_active_health_checks,
    start_dns_refreshes,
};
use crate::middleware::{
    auth::{self, BasicAuthPolicies},
    compression::{self, CompressionLimiters},
    limit::{self, InFlightLimiters},
    rate::{self, RateLimiters},
};

pub(crate) struct RuntimeSnapshot {
    pub(crate) revision: Arc<str>,
    pub(crate) config: Arc<Config>,
    pub(crate) route_index: Arc<RouteIndex>,
    pub(crate) tls_acceptors: HashMap<String, TlsAcceptor>,
    pub(crate) tls_resolvers: HashMap<String, CertificateResolver>,
    pub(crate) tls_identities: Arc<ArcSwap<HashMap<String, Identity>>>,
    pub(crate) upstream_clients: UpstreamClients,
    pub(crate) upstream_pools: UpstreamPools,
    pub(crate) dns_endpoints: DnsEndpoints,
    pub(crate) rate_limiters: RateLimiters,
    pub(crate) compression_limiters: CompressionLimiters,
    pub(crate) in_flight_limiters: InFlightLimiters,
    pub(crate) basic_auth: BasicAuthPolicies,
    pub(crate) tls_challenges: TlsAlpnChallengeRegistry,
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
        let rate_limiters = rate::build(
            &config,
            previous.map(|snapshot| (&*snapshot.config, &snapshot.rate_limiters)),
        );
        let compression_limiters = compression::build(
            &config,
            previous.map(|snapshot| (&*snapshot.config, &snapshot.compression_limiters)),
        );
        let in_flight_limiters = limit::build(
            &config,
            previous.map(|snapshot| (&*snapshot.config, &snapshot.in_flight_limiters)),
        );
        let preparation_config = Arc::clone(&config);
        let previous_upstreams = previous.map(|previous| {
            (
                Arc::clone(&previous.config),
                Arc::clone(&previous.upstream_clients),
                Arc::clone(&previous.upstream_pools),
                Arc::clone(&previous.dns_endpoints),
            )
        });
        let tls_challenges = previous
            .map(|previous| previous.tls_challenges.clone())
            .unwrap_or_default();
        let preparation_tls_challenges = tls_challenges.clone();
        let (
            tls_acceptors,
            tls_resolvers,
            tls_identities,
            upstream_clients,
            upstream_pools,
            dns_endpoints,
            basic_auth,
        ) = tokio::task::spawn_blocking(move || {
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
                            Arc::make_mut(&mut dns_endpoints).insert(key, Arc::clone(previous_dns));
                        }
                    }
                }
            }
            let tls = prepare_tls(&preparation_config, preparation_tls_challenges)?;
            let basic_auth = auth::build(&preparation_config)
                .map_err(|error| ProxyError::Preparation(error.to_string()))?;
            Ok::<_, ProxyError>((
                tls.acceptors,
                tls.resolvers,
                tls.identities,
                clients,
                pools,
                dns_endpoints,
                basic_auth,
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
            tls_resolvers,
            tls_identities: Arc::new(ArcSwap::from_pointee(tls_identities)),
            upstream_clients,
            upstream_pools,
            dns_endpoints,
            rate_limiters,
            compression_limiters,
            in_flight_limiters,
            basic_auth,
            tls_challenges,
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
    identity: NodeIdentity,
    draining: Arc<AtomicBool>,
    audit_ready: Arc<AtomicBool>,
    telemetry: Arc<Telemetry>,
    http_challenges: HttpChallengeRegistry,
    tls_challenges: TlsAlpnChallengeRegistry,
    mutation: Arc<tokio::sync::Mutex<()>>,
}

/// Stable process identity kept outside declarative configuration hashes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIdentity {
    id: Arc<str>,
    fleet_generation: u64,
}

impl NodeIdentity {
    /// Validate a node ID and its externally monotonic fleet generation.
    pub fn new(id: String, fleet_generation: u64) -> Result<Self, ProxyError> {
        let bytes = id.as_bytes();
        let valid = bytes.first().is_some_and(u8::is_ascii_lowercase)
            && id.len() <= 63
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            });
        if !valid {
            return Err(ProxyError::Preparation("invalid node identifier".into()));
        }
        Ok(Self {
            id: Arc::from(id),
            fleet_generation,
        })
    }

    /// Single-node bootstrap identity.
    #[must_use]
    pub fn standalone() -> Self {
        Self {
            id: Arc::from("standalone"),
            fleet_generation: 0,
        }
    }

    /// Stable node identifier.
    #[must_use]
    pub fn id(&self) -> Arc<str> {
        Arc::clone(&self.id)
    }

    /// Externally assigned rollout generation.
    #[must_use]
    pub fn fleet_generation(&self) -> u64 {
        self.fleet_generation
    }
}

pub(crate) struct PreparedCertificatePublication {
    snapshot: Arc<RuntimeSnapshot>,
    previous_identities: Arc<HashMap<String, Identity>>,
    identities: Arc<HashMap<String, Identity>>,
    resolvers: Vec<(CertificateResolver, PreparedCertificateMaps)>,
}

impl fmt::Debug for PreparedCertificatePublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCertificatePublication")
            .field("revision", &self.snapshot.revision)
            .field("identity_count", &self.identities.len())
            .field("resolver_count", &self.resolvers.len())
            .finish()
    }
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
        Self::new_with_identity(initial, NodeIdentity::standalone())
    }

    pub(crate) fn new_with_identity(initial: Arc<RuntimeSnapshot>, identity: NodeIdentity) -> Self {
        let tls_challenges = initial.tls_challenges.clone();
        let telemetry = Telemetry::new(&initial.config);
        Self {
            current: Arc::new(ArcSwap::from(initial)),
            identity,
            draining: Arc::new(AtomicBool::new(false)),
            audit_ready: Arc::new(AtomicBool::new(false)),
            telemetry,
            http_challenges: HttpChallengeRegistry::default(),
            tls_challenges,
            mutation: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Stable node identifier supplied outside declarative configuration.
    #[must_use]
    pub fn node_id(&self) -> Arc<str> {
        self.identity.id()
    }

    /// Externally monotonic fleet rollout generation.
    #[must_use]
    pub fn fleet_generation(&self) -> u64 {
        self.identity.fleet_generation()
    }

    /// Whether this node exclusively owns managed certificate renewal.
    #[must_use]
    pub fn certificate_owner(&self) -> bool {
        let snapshot = self.current.load();
        !snapshot.config.acme.certificates.is_empty()
            && snapshot
                .config
                .acme
                .renewal_owner
                .as_deref()
                .map_or(self.fleet_generation() == 0, |owner| {
                    owner == self.identity.id.as_ref()
                })
    }

    /// Enter one-way load-balancer drain state; returns whether state changed.
    pub fn begin_drain(&self) -> bool {
        !self.draining.swap(true, Ordering::AcqRel)
    }

    /// Return whether load-balancer drain has begun.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Return whether durable administrative audit is currently writable.
    #[must_use]
    pub fn audit_ready(&self) -> bool {
        self.audit_ready.load(Ordering::Acquire)
    }

    /// Extract the SHA-256 content hash from the active durable revision ID.
    #[must_use]
    pub fn revision_hash(&self) -> Option<String> {
        let revision = self.revision();
        let (_, hash) = revision.rsplit_once('-')?;
        (hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
        .then(|| hash.to_owned())
    }

    pub(crate) fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    pub(crate) fn telemetry(&self) -> Arc<Telemetry> {
        Arc::clone(&self.telemetry)
    }

    fn publish(&self, candidate: Arc<RuntimeSnapshot>) -> Arc<RuntimeSnapshot> {
        self.telemetry.reconcile(&candidate.config);
        self.current.swap(candidate)
    }

    /// Return the active immutable revision identifier.
    pub fn revision(&self) -> Arc<str> {
        Arc::clone(&self.current.load().revision)
    }

    /// Return the active immutable configuration.
    #[must_use]
    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.current.load().config)
    }

    /// Return whether a candidate can replace the active snapshot without rebinding listeners.
    #[must_use]
    pub fn can_hot_reload(&self, candidate: &Config) -> bool {
        hot_reload_compatible(&self.current.load().config, candidate)
    }

    /// Encode process metrics using OpenMetrics text exposition.
    pub fn render_openmetrics(&self) -> Result<String, fmt::Error> {
        let snapshot = self.current.load();
        for (upstream, pool) in snapshot.upstream_pools.iter() {
            for endpoint in pool.endpoints() {
                self.telemetry.update_upstream_state(
                    upstream,
                    &endpoint.config().id,
                    endpoint.active(),
                    endpoint.healthy(),
                );
            }
        }
        self.telemetry.render()
    }

    /// Update the bounded administrative-audit readiness gauge.
    pub fn set_audit_ready(&self, ready: bool) {
        self.audit_ready.store(ready, Ordering::Release);
        self.telemetry.audit_ready(ready);
    }

    /// Record one bounded durable administrative-audit outcome.
    pub fn record_audit_operation(&self, outcome: &'static str) {
        self.telemetry.audit_operation(outcome);
    }

    /// Record a bounded certificate automation outcome.
    pub fn record_certificate_renewal(&self, certificate: &str, outcome: &'static str) {
        self.telemetry.certificate_renewal(certificate, outcome);
    }

    /// Update bounded discovery-provider gauges.
    pub fn update_provider_status(&self, status: &crate::ProviderStatus) {
        self.telemetry.update_provider(status);
    }

    /// Return the process-wide HTTP-01 registry retained across configuration reloads.
    #[must_use]
    pub fn http_challenges(&self) -> HttpChallengeRegistry {
        self.http_challenges.clone()
    }

    /// Return the process-wide TLS-ALPN-01 registry retained across configuration reloads.
    #[must_use]
    pub fn tls_challenges(&self) -> TlsAlpnChallengeRegistry {
        self.tls_challenges.clone()
    }

    pub(crate) async fn lock_mutation(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.mutation).lock_owned().await
    }

    pub(crate) fn prepare_certificate_publication(
        &self,
        certificate_id: &str,
        identity: Identity,
    ) -> Result<PreparedCertificatePublication, ProxyError> {
        let snapshot = self.load();
        if !snapshot
            .config
            .acme
            .certificates
            .iter()
            .any(|certificate| certificate.id == certificate_id)
        {
            return Err(ProxyError::Preparation(
                "managed certificate is not present in active configuration".into(),
            ));
        }
        let previous_identities = snapshot.tls_identities.load_full();
        let mut identities = (*previous_identities).clone();
        identities.insert(certificate_id.to_owned(), identity);
        let mut resolvers = Vec::new();
        for listener in snapshot
            .config
            .listeners
            .iter()
            .filter(|listener| listener.protocol == "https")
        {
            let selected = listener
                .certificates
                .iter()
                .filter_map(|id| identities.get(id).cloned())
                .collect::<Vec<_>>();
            let prepared = CertificateResolver::prepare_replacement(&selected)?;
            let resolver = snapshot.tls_resolvers.get(&listener.id).ok_or_else(|| {
                ProxyError::Preparation("active HTTPS resolver is missing".into())
            })?;
            resolvers.push((resolver.clone(), prepared));
        }
        Ok(PreparedCertificatePublication {
            snapshot,
            previous_identities,
            identities: Arc::new(identities),
            resolvers,
        })
    }

    pub(crate) fn publish_certificate(
        &self,
        prepared: PreparedCertificatePublication,
    ) -> Result<(), ProxyError> {
        let current = self.load();
        if !Arc::ptr_eq(&current, &prepared.snapshot)
            || !Arc::ptr_eq(
                &current.tls_identities.load_full(),
                &prepared.previous_identities,
            )
        {
            return Err(ProxyError::Preparation(
                "runtime changed during managed certificate publication".into(),
            ));
        }
        for (resolver, certificates) in prepared.resolvers {
            resolver.publish_prepared(certificates);
        }
        current.tls_identities.store(prepared.identities);
        Ok(())
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
        let started = Instant::now();
        let result = self
            .activate_with_probe(candidate_id, expected_active, async { true })
            .await;
        let outcome = match &result {
            Ok(_) => "success",
            Err(ActivationError::Probation) => "rolled_back",
            Err(_) => "rejected",
        };
        self.runtime.telemetry().reload(outcome, started.elapsed());
        result
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
        let _runtime_guard = self.runtime.lock_mutation().await;
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
        drop(current);
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
        let drains = begin_replaced_pool_drains(&retired, &candidate);
        retired.stop_background().await;
        drop(retired);
        finish_drains(drains).await;
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
        && current.observability == candidate.observability
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

fn begin_replaced_pool_drains(
    retired: &RuntimeSnapshot,
    active: &RuntimeSnapshot,
) -> Vec<(String, DrainingEndpoint)> {
    let mut drains = Vec::new();
    for (group_id, pool) in retired.upstream_pools.iter() {
        if active
            .upstream_pools
            .get(group_id)
            .is_some_and(|active_pool| Arc::ptr_eq(pool, active_pool))
        {
            continue;
        }
        for endpoint in pool.endpoints() {
            if let Ok(handle) = pool.begin_drain(&endpoint.config().id) {
                drains.push((endpoint.config().id.clone(), handle));
            }
        }
    }
    drains
}

async fn finish_drains(drains: Vec<(String, DrainingEndpoint)>) {
    let mut tasks = tokio::task::JoinSet::new();
    for (endpoint_id, drain) in drains {
        tasks.spawn(async move { (endpoint_id, drain.wait().await) });
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((endpoint_id, false)) => {
                tracing::warn!(endpoint = %endpoint_id, "upstream drain deadline reached");
            }
            Ok((_, true)) => {}
            Err(error) => tracing::error!(%error, "upstream drain task failed"),
        }
    }
}

#[cfg(test)]
mod tests;
