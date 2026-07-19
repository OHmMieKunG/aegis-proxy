//! Bounded service-discovery polling and normalized snapshot candidates.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aegisproxy_config::{
    Config, EndpointConfig,
    provider::{self, ProviderConfig},
};
use hickory_resolver::{Resolver, TokioResolver};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

/// Redacted provider health exposed to the private control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderStatus {
    /// Stable configured provider ID.
    pub id: String,
    /// Bounded provider kind (`file` or `dns`).
    pub kind: &'static str,
    /// Bounded state (`disabled`, `pending`, `fresh`, `degraded`, or `stale`).
    pub state: &'static str,
    /// SHA-256 of the last accepted source data.
    pub source_hash: Option<String>,
    /// Last successful refresh as Unix seconds.
    pub last_success_unix_secs: Option<u64>,
    /// Hard stale deadline as Unix seconds.
    pub stale_at_unix_secs: Option<u64>,
    /// Number of endpoints in the last accepted result.
    pub endpoint_count: usize,
    /// Stable failure class without source data.
    pub error: Option<&'static str>,
}

/// Cloneable, bounded provider-status registry.
#[derive(Clone, Debug, Default)]
pub struct ProviderRegistry {
    inner: Arc<RwLock<Vec<ProviderStatus>>>,
}

impl ProviderRegistry {
    /// Return one consistent status snapshot.
    #[must_use]
    pub fn statuses(&self) -> Vec<ProviderStatus> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn replace(&self, statuses: Vec<ProviderStatus>) {
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = statuses;
    }
}

#[derive(Debug)]
struct ProviderState {
    policy: ProviderConfig,
    endpoints: Vec<EndpointConfig>,
    source_hash: Option<[u8; 32]>,
    last_attempt: Option<Instant>,
    last_success_unix_secs: Option<u64>,
    stale_until: Option<Instant>,
    stale_at_unix_secs: Option<u64>,
    pending_hash: Option<[u8; 32]>,
    pending_since: Option<Instant>,
    error: Option<&'static str>,
}

impl ProviderState {
    fn new(policy: ProviderConfig) -> Self {
        Self {
            policy,
            endpoints: Vec::new(),
            source_hash: None,
            last_attempt: None,
            last_success_unix_secs: None,
            stale_until: None,
            stale_at_unix_secs: None,
            pending_hash: None,
            pending_since: None,
            error: None,
        }
    }

    fn usable(&self, now: Instant) -> bool {
        !self.endpoints.is_empty() && self.stale_until.is_some_and(|deadline| now <= deadline)
    }

    fn status(&self, enabled: bool, now: Instant) -> ProviderStatus {
        let state = if !enabled {
            "disabled"
        } else if self.pending_hash.is_some() {
            "pending"
        } else if self.error.is_none() && self.usable(now) {
            "fresh"
        } else if self.usable(now) {
            "degraded"
        } else {
            "stale"
        };
        ProviderStatus {
            id: self.policy.id().to_owned(),
            kind: self.policy.kind(),
            state,
            source_hash: self.source_hash.map(hex_sha256),
            last_success_unix_secs: self.last_success_unix_secs,
            stale_at_unix_secs: self.stale_at_unix_secs,
            endpoint_count: self.endpoints.len(),
            error: self.error,
        }
    }
}

#[derive(Debug)]
struct Resolved {
    endpoints: Vec<EndpointConfig>,
    source_hash: [u8; 32],
}

/// Result of one provider reconciliation pass.
#[derive(Debug)]
pub(crate) struct ReconciledConfig {
    pub(crate) config: Config,
    pub(crate) fingerprint: [u8; 32],
}

/// Serialized owner of provider source state.
#[derive(Debug, Default)]
pub(crate) struct ProviderCoordinator {
    states: Mutex<HashMap<String, ProviderState>>,
    resolver: Mutex<Option<Arc<TokioResolver>>>,
    registry: ProviderRegistry,
}

impl ProviderCoordinator {
    pub(crate) fn registry(&self) -> ProviderRegistry {
        self.registry.clone()
    }

    pub(crate) async fn reconcile(&self, base: Config, base_hash: [u8; 32]) -> ReconciledConfig {
        let now = Instant::now();
        let providers = base.providers.clone();
        let mut merged = base.clone();
        let mut statuses = Vec::with_capacity(providers.len());
        let mut fingerprint = Sha256::new();
        fingerprint.update(base_hash);

        {
            let configured: std::collections::HashSet<_> =
                providers.iter().map(|item| item.id().to_owned()).collect();
            self.states
                .lock()
                .await
                .retain(|id, _| configured.contains(id));
        }

        for provider in providers {
            let mut state = self
                .states
                .lock()
                .await
                .remove(provider.id())
                .filter(|state| state.policy == provider)
                .unwrap_or_else(|| ProviderState::new(provider.clone()));
            if provider.enabled() && refresh_due(&state, &provider, now) {
                state.last_attempt = Some(now);
                match self.resolve(&base, &provider).await {
                    Ok(resolved) => {
                        if accept_debounce(&mut state, &provider, resolved.source_hash, now) {
                            if valid_overlay(&base, &provider, &resolved.endpoints) {
                                install_success(&mut state, &provider, resolved, now);
                            } else {
                                state.pending_hash = None;
                                state.pending_since = None;
                                state.error = Some("invalid_result");
                            }
                        }
                    }
                    Err(error) => {
                        if matches!(provider, ProviderConfig::File(_)) {
                            state.pending_hash = None;
                            state.pending_since = None;
                        }
                        state.error = Some(error);
                    }
                }
            }
            if provider.enabled() && state.usable(now) {
                replace_group_endpoints(
                    &mut merged,
                    provider.upstream_group(),
                    state.endpoints.clone(),
                );
                if let Some(hash) = state.source_hash {
                    fingerprint.update(provider.id().as_bytes());
                    fingerprint.update([0]);
                    fingerprint.update(b"provider");
                    fingerprint.update(hash);
                }
            } else {
                fingerprint.update(provider.id().as_bytes());
                fingerprint.update([0]);
                fingerprint.update(b"static");
            }
            statuses.push(state.status(provider.enabled(), now));
            self.states
                .lock()
                .await
                .insert(provider.id().to_owned(), state);
        }
        self.registry.replace(statuses);
        ReconciledConfig {
            config: merged,
            fingerprint: fingerprint.finalize().into(),
        }
    }

    async fn resolve(
        &self,
        base: &Config,
        provider: &ProviderConfig,
    ) -> Result<Resolved, &'static str> {
        match provider {
            ProviderConfig::File(config) => {
                let config = config.clone();
                tokio::task::spawn_blocking(move || {
                    let (bytes, document) =
                        provider::file::load(config.path.as_ref()).map_err(|_| "invalid_source")?;
                    let endpoints = provider::file::endpoints(&config, &document)
                        .map_err(|_| "invalid_source")?;
                    Ok(Resolved {
                        endpoints,
                        source_hash: Sha256::digest(bytes).into(),
                    })
                })
                .await
                .map_err(|_| "task_failed")?
            }
            ProviderConfig::Dns(config) => {
                let resolver = self.resolver(base.limits.max_dns_lookups).await?;
                let timeout_secs = base
                    .upstream_groups
                    .iter()
                    .find(|group| group.id == config.upstream_group)
                    .map_or(3, |group| group.dns.lookup_timeout_secs);
                let query = format!("{}.", config.hostname);
                let lookup = tokio::time::timeout(
                    Duration::from_secs(timeout_secs),
                    resolver.lookup_ip(query),
                )
                .await
                .map_err(|_| "lookup_failed")?
                .map_err(|_| "lookup_failed")?;
                let mut addresses: Vec<IpAddr> =
                    lookup.iter().take(config.max_answers + 1).collect();
                if addresses.len() > config.max_answers {
                    return Err("answer_limit");
                }
                addresses.sort_unstable();
                addresses.dedup();
                let endpoints = provider::dns::endpoints(config, addresses.iter().copied())
                    .map_err(|_| "invalid_source")?;
                let mut hash = Sha256::new();
                for address in addresses {
                    match address {
                        IpAddr::V4(address) => {
                            hash.update([4]);
                            hash.update(address.octets());
                        }
                        IpAddr::V6(address) => {
                            hash.update([6]);
                            hash.update(address.octets());
                        }
                    }
                }
                Ok(Resolved {
                    endpoints,
                    source_hash: hash.finalize().into(),
                })
            }
        }
    }

    async fn resolver(&self, max_lookups: usize) -> Result<Arc<TokioResolver>, &'static str> {
        let mut current = self.resolver.lock().await;
        if let Some(resolver) = current.as_ref() {
            return Ok(Arc::clone(resolver));
        }
        let mut builder = Resolver::builder_tokio().map_err(|_| "resolver_unavailable")?;
        let options = builder.options_mut();
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.max_active_requests = max_lookups;
        options.cache_size = 4_096;
        let resolver = Arc::new(builder.build().map_err(|_| "resolver_unavailable")?);
        *current = Some(Arc::clone(&resolver));
        Ok(resolver)
    }
}

fn refresh_due(state: &ProviderState, provider: &ProviderConfig, now: Instant) -> bool {
    state.pending_hash.is_some()
        || state.last_attempt.is_none_or(|attempt| {
            now.saturating_duration_since(attempt) >= Duration::from_secs(provider.refresh_secs())
        })
}

fn accept_debounce(
    state: &mut ProviderState,
    provider: &ProviderConfig,
    source_hash: [u8; 32],
    now: Instant,
) -> bool {
    let ProviderConfig::File(file) = provider else {
        return true;
    };
    if state.source_hash == Some(source_hash) {
        state.pending_hash = None;
        state.pending_since = None;
        return true;
    }
    if state.pending_hash != Some(source_hash) {
        state.pending_hash = Some(source_hash);
        state.pending_since = Some(now);
        state.error = None;
        return false;
    }
    state.pending_since.is_some_and(|started| {
        now.saturating_duration_since(started) >= Duration::from_millis(file.debounce_millis)
    })
}

fn valid_overlay(base: &Config, provider: &ProviderConfig, endpoints: &[EndpointConfig]) -> bool {
    let mut candidate = base.clone();
    replace_group_endpoints(
        &mut candidate,
        provider.upstream_group(),
        endpoints.to_vec(),
    );
    aegisproxy_config::validate(&candidate).is_ok()
}

fn replace_group_endpoints(config: &mut Config, group_id: &str, endpoints: Vec<EndpointConfig>) {
    if let Some(group) = config
        .upstream_groups
        .iter_mut()
        .find(|group| group.id == group_id)
    {
        group.endpoints = endpoints;
    }
}

fn install_success(
    state: &mut ProviderState,
    provider: &ProviderConfig,
    resolved: Resolved,
    now: Instant,
) {
    let unix_now = unix_now();
    state.endpoints = resolved.endpoints;
    state.source_hash = Some(resolved.source_hash);
    state.last_success_unix_secs = Some(unix_now);
    state.stale_until = Some(now + Duration::from_secs(provider.stale_after_secs()));
    state.stale_at_unix_secs = Some(unix_now.saturating_add(provider.stale_after_secs()));
    state.pending_hash = None;
    state.pending_since = None;
    state.error = None;
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn hex_sha256(hash: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in hash {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use aegisproxy_config::{
        AdminConfig, LimitsConfig, ListenerConfig, ObservabilityConfig, RuntimeConfig, TlsConfig,
        TrustedProxyConfig, UpstreamGroupConfig,
        provider::{FileProviderConfig, ProviderScheme},
    };

    use super::*;

    fn base(path: String) -> Config {
        Config {
            schema_version: 1,
            runtime: RuntimeConfig::default(),
            limits: LimitsConfig::default(),
            listeners: vec![ListenerConfig {
                id: "public".into(),
                bind: "127.0.0.1:8080".parse().expect("address"),
                protocol: "http".into(),
                certificates: vec![],
            }],
            tls: TlsConfig::default(),
            certificates: vec![],
            acme: Default::default(),
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![UpstreamGroupConfig {
                id: "app".into(),
                allowed_cidrs: vec!["127.0.0.1/32".parse().expect("CIDR")],
                endpoints: vec![EndpointConfig {
                    id: "fallback".into(),
                    url: "http://127.0.0.1:9000".parse().expect("URL"),
                    weight: 1,
                    server_name: None,
                    ca_bundle: None,
                }],
                ..UpstreamGroupConfig::default()
            }],
            providers: vec![ProviderConfig::File(FileProviderConfig {
                id: "nodes".into(),
                enabled: true,
                upstream_group: "app".into(),
                path,
                scheme: ProviderScheme::Http,
                server_name: None,
                ca_bundle: None,
                refresh_secs: 1,
                debounce_millis: 50,
                stale_after_secs: 3,
                max_endpoints: 4,
            })],
            middlewares: BTreeMap::new(),
            routes: vec![],
            admin: AdminConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }

    fn temp_file() -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "aegisproxy-provider-{}-{}-{}",
            std::process::id(),
            unix_now(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn partial_update_never_replaces_last_valid_endpoints() {
        let path = temp_file();
        fs::write(
            &path,
            "schema_version=1\nprovider_id=\"nodes\"\n[[endpoints]]\nid=\"node-a\"\naddress=\"127.0.0.1:9100\"\n",
        )
        .expect("write provider");
        let config = base(path.display().to_string());
        let coordinator = ProviderCoordinator::default();
        let first = coordinator.reconcile(config.clone(), [1; 32]).await;
        assert_eq!(first.config.upstream_groups[0].endpoints[0].id, "fallback");
        tokio::time::sleep(Duration::from_millis(60)).await;
        let accepted = coordinator.reconcile(config.clone(), [1; 32]).await;
        assert_eq!(accepted.config.upstream_groups[0].endpoints[0].id, "node-a");

        fs::write(&path, "schema_version=1\nprovider_id=").expect("partial write");
        tokio::time::sleep(Duration::from_millis(1_010)).await;
        let rejected = coordinator.reconcile(config, [1; 32]).await;
        assert_eq!(rejected.config.upstream_groups[0].endpoints[0].id, "node-a");
        let status = coordinator.registry().statuses().remove(0);
        assert_eq!(status.state, "degraded");
        assert_eq!(status.error, Some("invalid_source"));

        fs::write(
            &path,
            "schema_version=1\nprovider_id=\"nodes\"\n[[endpoints]]\nid=\"node-b\"\naddress=\"127.0.0.1:9200\"\n",
        )
        .expect("recovery write");
        tokio::time::sleep(Duration::from_millis(1_010)).await;
        let pending = coordinator
            .reconcile(base(path.display().to_string()), [1; 32])
            .await;
        assert_eq!(pending.config.upstream_groups[0].endpoints[0].id, "node-a");
        tokio::time::sleep(Duration::from_millis(60)).await;
        let recovered = coordinator
            .reconcile(base(path.display().to_string()), [1; 32])
            .await;
        assert_eq!(
            recovered.config.upstream_groups[0].endpoints[0].id,
            "node-b"
        );
        fs::remove_file(path).expect("remove provider");
    }

    #[test]
    fn provider_document_cannot_bypass_egress_policy() {
        let path = temp_file();
        let config = base(path.display().to_string());
        let provider = &config.providers[0];
        let endpoints = vec![EndpointConfig {
            id: "metadata".into(),
            url: "http://169.254.169.254:80".parse().expect("URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        }];
        assert!(!valid_overlay(&config, provider, &endpoints));

        let duplicate = vec![
            config.upstream_groups[0].endpoints[0].clone(),
            config.upstream_groups[0].endpoints[0].clone(),
        ];
        assert!(!valid_overlay(&config, provider, &duplicate));
    }

    #[test]
    fn rename_storm_requires_one_stable_debounce_window() {
        let config = base("/run/aegisproxy/nodes.toml".into());
        let policy = config.providers[0].clone();
        let now = Instant::now();
        let mut state = ProviderState::new(policy.clone());
        assert!(!accept_debounce(&mut state, &policy, [1; 32], now));
        assert!(!accept_debounce(
            &mut state,
            &policy,
            [2; 32],
            now + Duration::from_millis(20)
        ));
        assert!(!accept_debounce(
            &mut state,
            &policy,
            [1; 32],
            now + Duration::from_millis(40)
        ));
        assert!(accept_debounce(
            &mut state,
            &policy,
            [1; 32],
            now + Duration::from_millis(100)
        ));
    }

    #[test]
    fn event_storm_keeps_only_one_bounded_pending_hash() {
        let config = base("/run/aegisproxy/nodes.toml".into());
        let policy = config.providers[0].clone();
        let now = Instant::now();
        let mut state = ProviderState::new(policy.clone());
        for index in 0_u64..100_000 {
            let mut hash = [0_u8; 32];
            hash[..8].copy_from_slice(&index.to_be_bytes());
            assert!(!accept_debounce(&mut state, &policy, hash, now));
        }
        assert!(state.pending_hash.is_some());
        assert!(state.endpoints.is_empty());
    }

    #[test]
    fn hard_stale_deadline_disables_provider_output() {
        let config = base("/run/aegisproxy/nodes.toml".into());
        let policy = config.providers[0].clone();
        let now = Instant::now();
        let mut state = ProviderState::new(policy.clone());
        install_success(
            &mut state,
            &policy,
            Resolved {
                endpoints: config.upstream_groups[0].endpoints.clone(),
                source_hash: [3; 32],
            },
            now,
        );
        assert!(state.usable(now + Duration::from_secs(3)));
        assert!(!state.usable(now + Duration::from_secs(4)));
        assert_eq!(
            state.status(true, now + Duration::from_secs(4)).state,
            "stale"
        );
    }

    #[tokio::test]
    async fn invalid_provider_update_cannot_change_active_snapshot() {
        use aegisproxy_config::revision::RevisionStore;
        use tokio_util::sync::CancellationToken;

        let root = temp_file();
        fs::create_dir(&root).expect("test root");
        let source = root.join("nodes.toml");
        fs::write(
            &source,
            "schema_version=1\nprovider_id=\"nodes\"\n[[endpoints]]\nid=\"node-a\"\naddress=\"127.0.0.1:9100\"\n",
        )
        .expect("provider source");
        let mut config = base(source.display().to_string());
        config.runtime.state_dir = root.join("state").display().to_string();
        let revisions = Arc::new(RevisionStore::open(root.join("state")).expect("revision store"));
        let initial = revisions
            .create_candidate(&config, "test")
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
        let snapshot = crate::runtime::RuntimeSnapshot::prepare(
            Arc::new(config.clone()),
            initial.id.clone(),
            &shutdown,
        )
        .await
        .expect("initial runtime");
        let runtime = crate::RuntimeHandle::new(snapshot);
        let activation = crate::ActivationCoordinator::new(
            Arc::clone(&revisions),
            runtime.clone(),
            shutdown.clone(),
        );
        let discovery = ProviderCoordinator::default();
        let _pending = discovery.reconcile(config.clone(), [9; 32]).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let accepted = discovery.reconcile(config.clone(), [9; 32]).await;
        let candidate = revisions
            .create_candidate(&accepted.config, "test-provider")
            .expect("provider candidate");
        activation
            .activate(&candidate.id, Some(&initial.id))
            .await
            .expect("provider activation");
        assert_eq!(
            runtime.config().upstream_groups[0].endpoints[0].id,
            "node-a"
        );

        fs::write(&source, "schema_version=1\nprovider_id=").expect("invalid source");
        tokio::time::sleep(Duration::from_millis(1_010)).await;
        let rejected = discovery.reconcile(config, [9; 32]).await;
        let duplicate = revisions
            .create_candidate(&rejected.config, "test-provider")
            .expect("deduplicated candidate");
        assert_eq!(duplicate.id, candidate.id);
        assert_eq!(runtime.revision().as_ref(), candidate.id);
        let status = discovery.registry().statuses().remove(0);
        assert_eq!(status.state, "degraded");
        assert_eq!(status.source_hash.as_deref().map(str::len), Some(64));
        assert!(status.last_success_unix_secs.is_some());
        assert!(status.stale_at_unix_secs.is_some());

        shutdown.cancel();
        drop(activation);
        drop(runtime);
        drop(revisions);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
