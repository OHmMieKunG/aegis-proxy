use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicU8, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use aegisproxy_config::PassiveHealthConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EndpointState {
    Starting = 0,
    Healthy = 1,
    Unhealthy = 2,
    Draining = 3,
}

impl EndpointState {
    fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Starting,
            1 => Self::Healthy,
            2 => Self::Unhealthy,
            _ => Self::Draining,
        }
    }
}

#[derive(Debug)]
pub(crate) struct EndpointHealth {
    state: AtomicU8,
    consecutive_successes: AtomicU32,
    consecutive_failures: AtomicU32,
    passive_failures: Mutex<VecDeque<Instant>>,
}

impl EndpointHealth {
    pub(crate) fn new(state: EndpointState) -> Self {
        Self {
            state: AtomicU8::new(state as u8),
            consecutive_successes: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            passive_failures: Mutex::new(VecDeque::new()),
        }
    }

    pub(crate) fn state(&self) -> EndpointState {
        EndpointState::from_byte(self.state.load(Ordering::Acquire))
    }

    pub(crate) fn state_for_selection(
        &self,
        now: Instant,
        policy: &PassiveHealthConfig,
        active_health: bool,
    ) -> EndpointState {
        let state = self.state();
        if state != EndpointState::Unhealthy || active_health {
            return state;
        }
        let mut failures = self
            .passive_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cooldown_elapsed = failures.back().is_some_and(|failure| {
            now.saturating_duration_since(*failure) >= Duration::from_secs(policy.window_secs)
        });
        if !cooldown_elapsed {
            return state;
        }
        failures.clear();
        self.consecutive_failures.store(0, Ordering::Release);
        self.consecutive_successes.store(0, Ordering::Release);
        drop(failures);
        self.mark_healthy();
        self.state()
    }

    pub(crate) fn mark_healthy(&self) {
        self.transition_unless_draining(EndpointState::Healthy);
    }

    pub(crate) fn mark_unhealthy(&self) {
        self.transition_unless_draining(EndpointState::Unhealthy);
    }

    pub(crate) fn mark_draining(&self) {
        self.state
            .store(EndpointState::Draining as u8, Ordering::Release);
    }

    pub(crate) fn record_active_success(&self, healthy_threshold: u32) {
        self.consecutive_failures.store(0, Ordering::Release);
        let successes = self
            .consecutive_successes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(1))
            })
            .unwrap_or_else(|current| current)
            .saturating_add(1);
        if successes >= healthy_threshold {
            self.mark_healthy();
        }
    }

    #[cfg(test)]
    pub(crate) fn record_active_failure(&self, unhealthy_threshold: u32) {
        self.consecutive_successes.store(0, Ordering::Release);
        let failures = self
            .consecutive_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(1))
            })
            .unwrap_or_else(|current| current)
            .saturating_add(1);
        if failures >= unhealthy_threshold {
            self.mark_unhealthy();
        }
    }

    pub(crate) fn record_passive_success(&self, healthy_threshold: u32) {
        let was_unhealthy = self.state() == EndpointState::Unhealthy;
        self.record_active_success(healthy_threshold);
        if was_unhealthy && self.state() == EndpointState::Healthy {
            self.passive_failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
    }

    pub(crate) fn record_passive_failure(&self, now: Instant, policy: &PassiveHealthConfig) {
        self.consecutive_successes.store(0, Ordering::Release);
        let cutoff = now
            .checked_sub(Duration::from_secs(policy.window_secs))
            .unwrap_or(now);
        let mut failures = self
            .passive_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while failures.front().is_some_and(|failure| *failure < cutoff) {
            failures.pop_front();
        }
        if failures.len() == policy.max_samples {
            failures.pop_front();
        }
        failures.push_back(now);
        if failures.len() >= policy.failure_threshold as usize {
            drop(failures);
            self.mark_unhealthy();
        }
    }

    fn transition_unless_draining(&self, state: EndpointState) {
        let _ = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (EndpointState::from_byte(current) != EndpointState::Draining)
                    .then_some(state as u8)
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_thresholds_transition_exactly() {
        let health = EndpointHealth::new(EndpointState::Starting);
        health.record_active_success(2);
        assert_eq!(health.state(), EndpointState::Starting);
        health.record_active_success(2);
        assert_eq!(health.state(), EndpointState::Healthy);
        health.record_active_failure(3);
        health.record_active_failure(3);
        assert_eq!(health.state(), EndpointState::Healthy);
        health.record_active_failure(3);
        assert_eq!(health.state(), EndpointState::Unhealthy);
    }

    #[test]
    fn passive_window_is_bounded_and_prunes_old_failures() {
        let health = EndpointHealth::new(EndpointState::Healthy);
        let policy = PassiveHealthConfig {
            failure_threshold: 2,
            max_samples: 2,
            window_secs: 10,
            ..PassiveHealthConfig::default()
        };
        let start = Instant::now();
        health.record_passive_failure(start, &policy);
        health.record_passive_failure(start + Duration::from_secs(11), &policy);
        assert_eq!(health.state(), EndpointState::Healthy);
        health.record_passive_failure(start + Duration::from_secs(12), &policy);
        assert_eq!(health.state(), EndpointState::Unhealthy);
        assert_eq!(
            health
                .passive_failures
                .lock()
                .expect("failure window")
                .len(),
            2
        );
        health.record_passive_success(2);
        assert_eq!(health.state(), EndpointState::Unhealthy);
        health.record_passive_success(2);
        assert_eq!(health.state(), EndpointState::Healthy);
        assert!(
            health
                .passive_failures
                .lock()
                .expect("failure window")
                .is_empty()
        );
    }

    #[test]
    fn draining_is_terminal_for_health_observations() {
        let health = EndpointHealth::new(EndpointState::Healthy);
        health.mark_draining();
        health.record_active_success(1);
        health.record_active_failure(1);
        health.record_passive_success(1);
        assert_eq!(health.state(), EndpointState::Draining);
    }

    #[test]
    fn passive_quarantine_recovers_after_bounded_cooldown() {
        let health = EndpointHealth::new(EndpointState::Healthy);
        let policy = PassiveHealthConfig {
            failure_threshold: 1,
            window_secs: 10,
            ..PassiveHealthConfig::default()
        };
        let start = Instant::now();
        health.record_passive_failure(start, &policy);
        assert_eq!(
            health.state_for_selection(start + Duration::from_secs(9), &policy, false),
            EndpointState::Unhealthy
        );
        assert_eq!(
            health.state_for_selection(start + Duration::from_secs(10), &policy, false),
            EndpointState::Healthy
        );
    }
}
