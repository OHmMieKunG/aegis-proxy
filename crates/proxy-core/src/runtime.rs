use std::{collections::HashMap, fmt, sync::Arc};

use aegisproxy_config::Config;
use aegisproxy_tls::TlsAcceptor;
use arc_swap::ArcSwap;
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
        aegisproxy_config::validate(&config)?;
        let route_index = Arc::new(RouteIndex::compile(&config));
        let preparation_config = Arc::clone(&config);
        let (tls_acceptors, upstream_clients, upstream_pools, dns_endpoints) =
            tokio::task::spawn_blocking(move || {
                let (clients, dns_endpoints) = build_upstream_clients(&preparation_config)?;
                Ok::<_, ProxyError>((
                    prepare_tls(&preparation_config)?,
                    clients,
                    build_upstream_pools(&preparation_config)?,
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

    #[cfg(test)]
    fn publish(&self, candidate: Arc<RuntimeSnapshot>) -> Arc<RuntimeSnapshot> {
        self.current.swap(candidate)
    }

    /// Return the active immutable revision identifier.
    pub fn revision(&self) -> Arc<str> {
        Arc::clone(&self.current.load().revision)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aegisproxy_config::{
        AdminConfig, Config, LimitsConfig, ListenerConfig, RuntimeConfig, TlsConfig,
        TrustedProxyConfig,
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
}
