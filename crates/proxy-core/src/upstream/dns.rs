use std::{
    future::{Ready, ready},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use aegisproxy_config::{DnsConfig, EndpointConfig, UpstreamGroupConfig, validate_egress_ip};
use hickory_resolver::{Resolver, TokioResolver};
use hyper_util::client::legacy::connect::dns::Name;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_service::Service;

#[derive(Debug, Error)]
pub(crate) enum DnsError {
    #[error("system DNS resolver configuration is unavailable")]
    ResolverConfig,
    #[error("DNS lookup failed for endpoint {0}")]
    Lookup(String),
    #[error("DNS lookup for endpoint {0} returned no addresses")]
    Empty(String),
    #[error("DNS lookup for endpoint {0} exceeded its answer limit")]
    TooMany(String),
    #[error("DNS lookup for endpoint {0} returned a forbidden address: {1}")]
    Forbidden(String, &'static str),
    #[error("DNS preparation task failed")]
    Task,
    #[error("endpoint {0} is missing a validated host or port")]
    InvalidEndpoint(String),
}

#[derive(Debug)]
struct AddressState {
    addresses: Vec<IpAddr>,
    expires: Option<Instant>,
    stale_until: Option<Instant>,
}

#[derive(Debug)]
pub(crate) struct DnsEndpoint {
    id: String,
    host: String,
    port: u16,
    policy: DnsConfig,
    allowed: Vec<ipnet::IpNet>,
    denied: Vec<ipnet::IpNet>,
    dynamic: bool,
    state: RwLock<AddressState>,
}

impl DnsEndpoint {
    pub(crate) fn new(
        endpoint: &EndpointConfig,
        group: &UpstreamGroupConfig,
    ) -> Result<Self, DnsError> {
        let host = endpoint
            .url
            .host_str()
            .ok_or_else(|| DnsError::InvalidEndpoint(endpoint.id.clone()))?
            .to_owned();
        let port = endpoint
            .url
            .port()
            .ok_or_else(|| DnsError::InvalidEndpoint(endpoint.id.clone()))?;
        let literal = host.parse::<IpAddr>().ok();
        Ok(Self {
            id: format!("{}/{}", group.id, endpoint.id),
            host,
            port,
            policy: group.dns.clone(),
            allowed: group.allowed_cidrs.clone(),
            denied: group.denied_cidrs.clone(),
            dynamic: literal.is_none(),
            state: RwLock::new(AddressState {
                addresses: literal.into_iter().collect(),
                expires: None,
                stale_until: None,
            }),
        })
    }

    pub(crate) fn resolver(self: &Arc<Self>) -> PolicyResolver {
        PolicyResolver {
            endpoint: Arc::clone(self),
        }
    }

    pub(crate) fn connection_addresses(&self) -> io::Result<Vec<SocketAddr>> {
        self.addresses_at(Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn install_test_answers(&self, addresses: Vec<IpAddr>) -> Result<(), DnsError> {
        self.install_answers(addresses, Duration::from_secs(60), Instant::now())
    }

    fn install_answers(
        &self,
        mut addresses: Vec<IpAddr>,
        source_ttl: Duration,
        now: Instant,
    ) -> Result<(), DnsError> {
        if addresses.is_empty() {
            return Err(DnsError::Empty(self.id.clone()));
        }
        if addresses.len() > self.policy.max_answers {
            return Err(DnsError::TooMany(self.id.clone()));
        }
        addresses.sort_unstable();
        addresses.dedup();
        for address in &addresses {
            validate_egress_ip(*address, &self.allowed, &self.denied)
                .map_err(|reason| DnsError::Forbidden(self.id.clone(), reason))?;
        }
        let ttl = source_ttl.clamp(
            Duration::from_secs(self.policy.min_ttl_secs),
            Duration::from_secs(self.policy.max_ttl_secs),
        );
        let expires = now + ttl;
        let stale_until = expires + Duration::from_secs(self.policy.stale_timeout_secs);
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = AddressState {
            addresses,
            expires: Some(expires),
            stale_until: Some(stale_until),
        };
        Ok(())
    }

    fn addresses_at(&self, now: Instant) -> io::Result<Vec<SocketAddr>> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.addresses.is_empty()
            || state
                .stale_until
                .is_some_and(|stale_until| now > stale_until)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "upstream DNS address set is unavailable",
            ));
        }
        state
            .addresses
            .iter()
            .map(|address| {
                validate_egress_ip(*address, &self.allowed, &self.denied).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "upstream DNS address failed egress policy",
                    )
                })?;
                Ok(SocketAddr::new(*address, self.port))
            })
            .collect()
    }

    fn refresh_delay(&self, now: Instant) -> Duration {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .expires
            .map(|expires| expires.saturating_duration_since(now).mul_f32(0.9))
            .unwrap_or_else(|| Duration::from_secs(self.policy.min_ttl_secs))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyResolver {
    endpoint: Arc<DnsEndpoint>,
}

impl Service<Name> for PolicyResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        if !name.as_str().eq_ignore_ascii_case(&self.endpoint.host) {
            return ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "connector requested an unconfigured DNS name",
            )));
        }
        ready(
            self.endpoint
                .addresses_at(Instant::now())
                .map(Vec::into_iter),
        )
    }
}

pub(crate) async fn prepare_dns(
    endpoints: &[Arc<DnsEndpoint>],
    max_lookups: usize,
) -> Result<Option<Arc<TokioResolver>>, DnsError> {
    let dynamic: Vec<_> = endpoints
        .iter()
        .filter(|endpoint| endpoint.dynamic)
        .cloned()
        .collect();
    if dynamic.is_empty() {
        return Ok(None);
    }
    let mut builder = Resolver::builder_tokio().map_err(|_| DnsError::ResolverConfig)?;
    let options = builder.options_mut();
    options.attempts = 1;
    options.num_concurrent_reqs = 1;
    options.max_active_requests = max_lookups;
    options.cache_size = 4_096;
    let resolver = Arc::new(builder.build().map_err(|_| DnsError::ResolverConfig)?);
    let permits = Arc::new(Semaphore::new(max_lookups));
    let mut tasks = tokio::task::JoinSet::new();
    for endpoint in dynamic {
        let resolver = Arc::clone(&resolver);
        let permits = Arc::clone(&permits);
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await.map_err(|_| DnsError::Task)?;
            resolve_once(&resolver, &endpoint).await
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| DnsError::Task)??;
    }
    Ok(Some(resolver))
}

pub(crate) fn start_dns_refreshes(
    endpoints: &[Arc<DnsEndpoint>],
    resolver: Option<Arc<TokioResolver>>,
    max_lookups: usize,
    shutdown: &CancellationToken,
) -> TaskTracker {
    let tracker = TaskTracker::new();
    let Some(resolver) = resolver else {
        tracker.close();
        return tracker;
    };
    let permits = Arc::new(Semaphore::new(max_lookups));
    for endpoint in endpoints.iter().filter(|endpoint| endpoint.dynamic) {
        let endpoint = Arc::clone(endpoint);
        let resolver = Arc::clone(&resolver);
        let permits = Arc::clone(&permits);
        let shutdown = shutdown.clone();
        tracker.spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    () = tokio::time::sleep(endpoint.refresh_delay(Instant::now())) => {}
                }
                let permit = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = permits.clone().acquire_owned() => match result {
                        Ok(permit) => permit,
                        Err(_) => break,
                    }
                };
                let failed = resolve_once(&resolver, &endpoint).await.is_err();
                drop(permit);
                if failed {
                    tracing::warn!(endpoint = %endpoint.id, "upstream DNS refresh failed");
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        () = tokio::time::sleep(Duration::from_secs(endpoint.policy.min_ttl_secs)) => {}
                    }
                }
            }
        });
    }
    tracker.close();
    tracker
}

async fn resolve_once(resolver: &TokioResolver, endpoint: &DnsEndpoint) -> Result<(), DnsError> {
    let query = format!("{}.", endpoint.host);
    let lookup = tokio::time::timeout(
        Duration::from_secs(endpoint.policy.lookup_timeout_secs),
        resolver.lookup_ip(query),
    )
    .await
    .map_err(|_| DnsError::Lookup(endpoint.id.clone()))?
    .map_err(|_| DnsError::Lookup(endpoint.id.clone()))?;
    let now = Instant::now();
    let source_ttl = lookup.valid_until().saturating_duration_since(now);
    let addresses = lookup
        .iter()
        .take(endpoint.policy.max_answers + 1)
        .collect();
    endpoint.install_answers(addresses, source_ttl, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> DnsEndpoint {
        let endpoint = EndpointConfig {
            id: "app-1".into(),
            url: "http://app.internal:8080".parse().expect("URL"),
            weight: 1,
            server_name: None,
            ca_bundle: None,
        };
        let group = UpstreamGroupConfig {
            id: "app".into(),
            allowed_cidrs: vec!["10.0.0.0/8".parse().expect("CIDR")],
            endpoints: vec![endpoint.clone()],
            ..UpstreamGroupConfig::default()
        };
        DnsEndpoint::new(&endpoint, &group).expect("DNS endpoint")
    }

    #[test]
    fn rejected_rebind_keeps_last_allowed_addresses() {
        let endpoint = endpoint();
        let now = Instant::now();
        endpoint
            .install_answers(
                vec!["10.0.0.1".parse().expect("IP")],
                Duration::from_secs(10),
                now,
            )
            .expect("allowed answer");
        assert!(
            endpoint
                .install_answers(
                    vec![
                        "10.0.0.2".parse().expect("IP"),
                        "169.254.169.254".parse().expect("IP"),
                    ],
                    Duration::from_secs(10),
                    now,
                )
                .is_err()
        );
        assert_eq!(
            endpoint.addresses_at(now).expect("last allowed answer"),
            vec!["10.0.0.1:8080".parse().expect("address")]
        );
    }

    #[test]
    fn stale_answers_expire_at_hard_deadline() {
        let endpoint = endpoint();
        let now = Instant::now();
        endpoint
            .install_answers(
                vec!["10.0.0.1".parse().expect("IP")],
                Duration::from_secs(5),
                now,
            )
            .expect("answer");
        assert!(
            endpoint
                .addresses_at(now + Duration::from_secs(305))
                .is_ok()
        );
        assert!(
            endpoint
                .addresses_at(now + Duration::from_secs(306))
                .is_err()
        );
    }

    #[test]
    fn raw_answer_count_is_bounded() {
        let mut endpoint = endpoint();
        endpoint.policy.max_answers = 1;
        assert!(
            endpoint
                .install_answers(
                    vec![
                        "10.0.0.1".parse().expect("IP"),
                        "10.0.0.2".parse().expect("IP"),
                    ],
                    Duration::from_secs(5),
                    Instant::now(),
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn policy_resolver_returns_only_pinned_configured_addresses() {
        let endpoint = Arc::new(endpoint());
        let now = Instant::now();
        endpoint
            .install_answers(
                vec!["10.0.0.1".parse().expect("IP")],
                Duration::from_secs(5),
                now,
            )
            .expect("answer");
        let mut resolver = endpoint.resolver();
        let addresses = resolver
            .call("app.internal".parse().expect("DNS name"))
            .await
            .expect("resolution")
            .collect::<Vec<_>>();
        assert_eq!(addresses, vec!["10.0.0.1:8080".parse().expect("address")]);
        assert!(
            resolver
                .call("other.internal".parse().expect("DNS name"))
                .await
                .is_err()
        );
    }
}
