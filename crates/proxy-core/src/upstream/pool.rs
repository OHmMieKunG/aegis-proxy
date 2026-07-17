use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use aegisproxy_config::{
    BalancingAlgorithm, EndpointConfig, PassiveHealthConfig, RetryConfig, UpstreamGroupConfig,
};
use hyper::body::{Body, Frame, SizeHint};
use thiserror::Error;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use super::{
    circuit::{CircuitBreaker, CircuitPermit},
    health::{EndpointHealth, EndpointState},
};
use crate::BoxError;

#[derive(Debug, Error)]
pub(crate) enum PoolError {
    #[error("upstream group has no endpoints")]
    Empty,
    #[error("upstream endpoint has zero weight")]
    ZeroWeight,
    #[error("no upstream endpoint is available")]
    Unavailable,
    #[error("upstream group is at its in-flight limit")]
    AtCapacity,
    #[error("upstream circuit is open")]
    CircuitOpen,
    #[error("upstream endpoint does not exist")]
    UnknownEndpoint,
}

#[derive(Debug)]
pub(crate) struct EndpointRuntime {
    config: Arc<EndpointConfig>,
    health: EndpointHealth,
    active: AtomicUsize,
    drain_cancel: CancellationToken,
}

impl EndpointRuntime {
    fn new(config: EndpointConfig, active_health: bool) -> Self {
        let initial = if active_health {
            EndpointState::Starting
        } else {
            EndpointState::Healthy
        };
        Self {
            config: Arc::new(config),
            health: EndpointHealth::new(initial),
            active: AtomicUsize::new(0),
            drain_cancel: CancellationToken::new(),
        }
    }

    pub(crate) fn config(&self) -> &EndpointConfig {
        &self.config
    }

    pub(crate) fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub(crate) fn health(&self) -> &EndpointHealth {
        &self.health
    }
}

#[derive(Debug)]
pub(crate) struct SelectedEndpoint {
    endpoint: Arc<EndpointRuntime>,
    group_active: Arc<AtomicUsize>,
    passive_health: Arc<PassiveHealthConfig>,
    active_health: bool,
    circuit_permit: Option<CircuitPermit>,
}

#[derive(Debug)]
pub(crate) struct DrainingEndpoint {
    endpoint: Arc<EndpointRuntime>,
    timeout: Duration,
}

impl DrainingEndpoint {
    pub(crate) async fn wait(self) -> bool {
        let timeout = self.timeout;
        self.wait_for(timeout).await
    }

    async fn wait_for(self, timeout: Duration) -> bool {
        let drained = tokio::time::timeout(timeout, async {
            while self.endpoint.active() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .is_ok();
        if !drained {
            self.endpoint.drain_cancel.cancel();
        }
        drained
    }
}

impl SelectedEndpoint {
    pub(crate) fn config(&self) -> &EndpointConfig {
        self.endpoint.config()
    }

    pub(crate) fn record_success(&self) {
        if let Some(permit) = &self.circuit_permit {
            permit.record_success();
        }
        self.endpoint
            .health
            .record_passive_success(self.passive_health.healthy_threshold, self.active_health);
    }

    pub(crate) fn record_failure(&self) {
        if let Some(permit) = &self.circuit_permit {
            permit.record_failure();
        }
        self.endpoint
            .health
            .record_passive_failure(std::time::Instant::now(), &self.passive_health);
    }

    pub(crate) fn drain_token(&self) -> CancellationToken {
        self.endpoint.drain_cancel.clone()
    }
}

impl Drop for SelectedEndpoint {
    fn drop(&mut self) {
        self.endpoint.active.fetch_sub(1, Ordering::AcqRel);
        self.group_active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub(crate) struct GuardedBody<B> {
    body: Pin<Box<B>>,
    _endpoint: SelectedEndpoint,
    drain_cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl<B> GuardedBody<B> {
    pub(crate) fn new(body: B, endpoint: SelectedEndpoint) -> Self {
        let drain = endpoint.drain_token();
        Self {
            body: Box::pin(body),
            _endpoint: endpoint,
            drain_cancelled: Box::pin(drain.cancelled_owned()),
        }
    }
}

impl<B> Body for GuardedBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.drain_cancelled.as_mut().poll(context).is_ready() {
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream drain deadline reached",
            )))));
        }
        match self.body.as_mut().poll_frame(context) {
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[derive(Debug)]
pub(crate) struct UpstreamPool {
    algorithm: BalancingAlgorithm,
    endpoints: Vec<Arc<EndpointRuntime>>,
    round_robin: AtomicU64,
    random_counter: AtomicU64,
    smooth_current: Mutex<Vec<i64>>,
    passive_health: Arc<PassiveHealthConfig>,
    active_health: bool,
    circuit: Option<Arc<CircuitBreaker>>,
    retry: RetryConfig,
    drain_timeout: Duration,
    max_in_flight: usize,
    active: Arc<AtomicUsize>,
}

impl UpstreamPool {
    pub(crate) fn new(group: &UpstreamGroupConfig) -> Result<Self, PoolError> {
        if group.endpoints.is_empty() {
            return Err(PoolError::Empty);
        }
        if group.endpoints.iter().any(|endpoint| endpoint.weight == 0) {
            return Err(PoolError::ZeroWeight);
        }
        let endpoints: Vec<_> = group
            .endpoints
            .iter()
            .cloned()
            .map(|endpoint| Arc::new(EndpointRuntime::new(endpoint, group.health.is_some())))
            .collect();
        Ok(Self {
            algorithm: group.algorithm,
            smooth_current: Mutex::new(vec![0; endpoints.len()]),
            endpoints,
            round_robin: AtomicU64::new(0),
            random_counter: AtomicU64::new(0x9e37_79b9_7f4a_7c15),
            passive_health: Arc::new(group.passive_health.clone()),
            active_health: group.health.is_some(),
            circuit: group.circuit_breaker.clone().map(CircuitBreaker::new),
            retry: group.retry.clone(),
            drain_timeout: Duration::from_secs(group.drain_timeout_secs),
            max_in_flight: group.max_in_flight,
            active: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub(crate) fn select(&self) -> Result<SelectedEndpoint, PoolError> {
        let circuit_permit = self
            .circuit
            .as_ref()
            .map(|circuit| circuit.acquire().ok_or(PoolError::CircuitOpen))
            .transpose()?;
        let eligible = self.eligible_indices();
        if eligible.is_empty() {
            return Err(PoolError::Unavailable);
        }
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.max_in_flight).then_some(active + 1)
            })
            .map_err(|_| PoolError::AtCapacity)?;
        let selected = match self.algorithm {
            BalancingAlgorithm::RoundRobin => self.select_round_robin(&eligible),
            BalancingAlgorithm::SmoothWeightedRoundRobin => self.select_smooth(&eligible),
            BalancingAlgorithm::Random => eligible[self.random_index(eligible.len())],
            BalancingAlgorithm::PowerOfTwo => self.select_power_of_two(&eligible),
        };
        let endpoint = Arc::clone(&self.endpoints[selected]);
        endpoint.active.fetch_add(1, Ordering::AcqRel);
        Ok(SelectedEndpoint {
            endpoint,
            group_active: Arc::clone(&self.active),
            passive_health: Arc::clone(&self.passive_health),
            active_health: self.active_health,
            circuit_permit,
        })
    }

    pub(crate) fn endpoints(&self) -> &[Arc<EndpointRuntime>] {
        &self.endpoints
    }

    pub(crate) fn retry_policy(&self) -> &RetryConfig {
        &self.retry
    }

    pub(crate) fn begin_drain(&self, endpoint_id: &str) -> Result<DrainingEndpoint, PoolError> {
        let endpoint = self
            .endpoints
            .iter()
            .find(|endpoint| endpoint.config().id == endpoint_id)
            .cloned()
            .ok_or(PoolError::UnknownEndpoint)?;
        endpoint.health.mark_draining();
        Ok(DrainingEndpoint {
            endpoint,
            timeout: self.drain_timeout,
        })
    }

    fn eligible_indices(&self) -> Vec<usize> {
        let now = std::time::Instant::now();
        let healthy: Vec<_> = self
            .endpoints
            .iter()
            .enumerate()
            .filter_map(|(index, endpoint)| {
                (endpoint
                    .health
                    .state_for_selection(now, &self.passive_health, self.active_health)
                    == EndpointState::Healthy)
                    .then_some(index)
            })
            .collect();
        if !healthy.is_empty() {
            return healthy;
        }
        self.endpoints
            .iter()
            .enumerate()
            .filter_map(|(index, endpoint)| {
                (endpoint
                    .health
                    .state_for_selection(now, &self.passive_health, self.active_health)
                    == EndpointState::Starting)
                    .then_some(index)
            })
            .collect()
    }

    fn select_round_robin(&self, eligible: &[usize]) -> usize {
        let cursor = self.round_robin.fetch_add(1, Ordering::Relaxed) as usize;
        eligible[cursor % eligible.len()]
    }

    fn select_smooth(&self, eligible: &[usize]) -> usize {
        let mut current = self
            .smooth_current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let total: i64 = eligible
            .iter()
            .map(|index| i64::from(self.endpoints[*index].config.weight))
            .sum();
        let mut best = eligible[0];
        for index in eligible {
            current[*index] += i64::from(self.endpoints[*index].config.weight);
            if current[*index] > current[best] {
                best = *index;
            }
        }
        current[best] -= total;
        best
    }

    fn select_power_of_two(&self, eligible: &[usize]) -> usize {
        if eligible.len() == 1 {
            return eligible[0];
        }
        let first_position = self.random_index(eligible.len());
        let mut second_position = self.random_index(eligible.len() - 1);
        if second_position >= first_position {
            second_position += 1;
        }
        let first = eligible[first_position];
        let second = eligible[second_position];
        if self.endpoints[first].active() <= self.endpoints[second].active() {
            first
        } else {
            second
        }
    }

    fn random_index(&self, length: usize) -> usize {
        let value = self.random_counter.fetch_add(1, Ordering::Relaxed);
        let mut mixed = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        ((mixed ^ (mixed >> 31)) as usize) % length
    }
}

impl Drop for UpstreamPool {
    fn drop(&mut self) {
        for endpoint in &self.endpoints {
            endpoint.health.mark_draining();
        }
    }
}

#[cfg(test)]
mod tests {
    use aegisproxy_config::UpstreamGroupConfig;

    use super::*;

    fn group(algorithm: BalancingAlgorithm, weights: &[u32]) -> UpstreamGroupConfig {
        UpstreamGroupConfig {
            id: "app".into(),
            algorithm,
            endpoints: weights
                .iter()
                .enumerate()
                .map(|(index, weight)| EndpointConfig {
                    id: format!("endpoint-{index}"),
                    url: format!("http://192.0.2.{}:8080", index + 1)
                        .parse()
                        .expect("URL"),
                    weight: *weight,
                    server_name: None,
                    ca_bundle: None,
                })
                .collect(),
            ..UpstreamGroupConfig::default()
        }
    }

    #[test]
    fn round_robin_skips_unhealthy_and_draining_endpoints() {
        let pool =
            UpstreamPool::new(&group(BalancingAlgorithm::RoundRobin, &[1, 1, 1])).expect("pool");
        pool.endpoints[1].health.mark_unhealthy();
        pool.endpoints[2].health.mark_draining();
        for _ in 0..10 {
            assert_eq!(pool.select().expect("selection").config().id, "endpoint-0");
        }
    }

    #[test]
    fn starting_endpoints_are_bootstrap_only() {
        let mut config = group(BalancingAlgorithm::RoundRobin, &[1, 1]);
        config.health = Some(aegisproxy_config::HealthCheckConfig::default());
        let pool = UpstreamPool::new(&config).expect("pool");
        assert!(pool.select().is_ok());
        pool.endpoints[0].health.mark_healthy();
        for _ in 0..8 {
            assert_eq!(pool.select().expect("selection").config().id, "endpoint-0");
        }
    }

    #[test]
    fn all_unavailable_fails_without_fallback() {
        let pool =
            UpstreamPool::new(&group(BalancingAlgorithm::RoundRobin, &[1, 1])).expect("pool");
        for endpoint in &pool.endpoints {
            endpoint.health.mark_unhealthy();
        }
        assert!(matches!(pool.select(), Err(PoolError::Unavailable)));
    }

    #[test]
    fn group_in_flight_limit_releases_with_selection_guard() {
        let mut config = group(BalancingAlgorithm::RoundRobin, &[1]);
        config.max_in_flight = 1;
        let pool = UpstreamPool::new(&config).expect("pool");
        let selected = pool.select().expect("first selection");
        assert!(matches!(pool.select(), Err(PoolError::AtCapacity)));
        drop(selected);
        assert!(pool.select().is_ok());
    }

    #[test]
    fn smooth_weighted_round_robin_matches_configured_share() {
        let pool = UpstreamPool::new(&group(
            BalancingAlgorithm::SmoothWeightedRoundRobin,
            &[5, 1],
        ))
        .expect("pool");
        let mut counts = [0_usize; 2];
        for _ in 0..600 {
            let selected = pool.select().expect("selection");
            counts[usize::from(selected.config().id == "endpoint-1")] += 1;
        }
        assert_eq!(counts, [500, 100]);
    }

    #[test]
    fn selected_guard_releases_active_count() {
        let pool = UpstreamPool::new(&group(BalancingAlgorithm::RoundRobin, &[1])).expect("pool");
        let selected = pool.select().expect("selection");
        assert_eq!(pool.endpoints[0].active(), 1);
        drop(selected);
        assert_eq!(pool.endpoints[0].active(), 0);
    }

    #[tokio::test]
    async fn drain_excludes_new_work_and_waits_for_active_guard() {
        let mut config = group(BalancingAlgorithm::RoundRobin, &[1, 1]);
        config.drain_timeout_secs = 7;
        let pool = UpstreamPool::new(&config).expect("pool");
        let selected = pool.select().expect("selection");
        assert_eq!(selected.config().id, "endpoint-0");
        let draining = pool.begin_drain("endpoint-0").expect("drain handle");
        for _ in 0..4 {
            assert_eq!(pool.select().expect("selection").config().id, "endpoint-1");
        }
        assert!(!draining.wait_for(Duration::from_millis(1)).await);

        let draining = pool.begin_drain("endpoint-0").expect("drain handle");
        drop(selected);
        assert!(draining.wait().await);
        assert!(matches!(
            pool.begin_drain("missing"),
            Err(PoolError::UnknownEndpoint)
        ));
    }

    #[tokio::test]
    async fn drain_deadline_cancels_guarded_response_body() {
        use http_body_util::BodyExt;

        let pool = UpstreamPool::new(&group(BalancingAlgorithm::RoundRobin, &[1])).expect("pool");
        let selected = pool.select().expect("selection");
        let body = GuardedBody::new(http_body_util::Empty::<bytes::Bytes>::new(), selected);
        let draining = pool.begin_drain("endpoint-0").expect("drain handle");
        assert!(!draining.wait_for(Duration::from_millis(1)).await);
        assert!(body.collect().await.is_err());
    }

    #[test]
    fn power_of_two_avoids_the_busier_candidate() {
        let pool =
            UpstreamPool::new(&group(BalancingAlgorithm::PowerOfTwo, &[1, 1])).expect("pool");
        pool.endpoints[0].active.store(10, Ordering::Release);
        for _ in 0..20 {
            assert_eq!(pool.select().expect("selection").config().id, "endpoint-1");
        }
    }
}
