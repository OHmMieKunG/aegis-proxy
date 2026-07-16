use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use aegisproxy_config::CircuitBreakerConfig;

#[derive(Debug)]
enum Mode {
    Closed { failures: VecDeque<bool> },
    Open { until: Instant },
    HalfOpen { in_flight: usize, successes: usize },
}

#[derive(Debug)]
struct State {
    epoch: u64,
    mode: Mode,
}

#[derive(Debug)]
pub(crate) struct CircuitBreaker {
    policy: CircuitBreakerConfig,
    state: Mutex<State>,
}

impl CircuitBreaker {
    pub(crate) fn new(policy: CircuitBreakerConfig) -> Arc<Self> {
        Arc::new(Self {
            policy,
            state: Mutex::new(State {
                epoch: 0,
                mode: Mode::Closed {
                    failures: VecDeque::new(),
                },
            }),
        })
    }

    pub(crate) fn acquire(self: &Arc<Self>) -> Option<CircuitPermit> {
        self.acquire_at(Instant::now())
    }

    fn acquire_at(self: &Arc<Self>, now: Instant) -> Option<CircuitPermit> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(&state.mode, Mode::Open { until } if now >= *until) {
            state.mode = Mode::HalfOpen {
                in_flight: 0,
                successes: 0,
            };
        }
        let half_open = match &mut state.mode {
            Mode::Closed { .. } => false,
            Mode::Open { .. } => return None,
            Mode::HalfOpen { in_flight, .. } => {
                if *in_flight >= self.policy.half_open_requests {
                    return None;
                }
                *in_flight += 1;
                true
            }
        };
        Some(CircuitPermit {
            breaker: Arc::clone(self),
            epoch: state.epoch,
            half_open,
            recorded: AtomicBool::new(false),
        })
    }

    fn record(&self, epoch: u64, half_open: bool, failed: bool, now: Instant) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if epoch != state.epoch {
            return;
        }
        match &mut state.mode {
            Mode::Closed { failures } if !half_open => {
                if failures.len() == self.policy.sample_size {
                    failures.pop_front();
                }
                failures.push_back(failed);
                let failure_count = failures.iter().filter(|failed| **failed).count();
                if failures.len() >= self.policy.minimum_requests
                    && failure_count * 100
                        >= failures.len() * usize::from(self.policy.failure_percent)
                {
                    state.epoch = state.epoch.wrapping_add(1);
                    state.mode = Mode::Open {
                        until: now + Duration::from_secs(self.policy.open_secs),
                    };
                }
            }
            Mode::HalfOpen { successes, .. } if half_open => {
                if failed {
                    state.epoch = state.epoch.wrapping_add(1);
                    state.mode = Mode::Open {
                        until: now + Duration::from_secs(self.policy.open_secs),
                    };
                } else {
                    *successes += 1;
                    if *successes >= self.policy.half_open_requests {
                        state.epoch = state.epoch.wrapping_add(1);
                        state.mode = Mode::Closed {
                            failures: VecDeque::new(),
                        };
                    }
                }
            }
            _ => {}
        }
    }

    fn release(&self, epoch: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if epoch == state.epoch
            && let Mode::HalfOpen { in_flight, .. } = &mut state.mode
        {
            *in_flight = in_flight.saturating_sub(1);
        }
    }
}

#[derive(Debug)]
pub(crate) struct CircuitPermit {
    breaker: Arc<CircuitBreaker>,
    epoch: u64,
    half_open: bool,
    recorded: AtomicBool,
}

impl CircuitPermit {
    pub(crate) fn record_success(&self) {
        self.record(false);
    }

    pub(crate) fn record_failure(&self) {
        self.record(true);
    }

    fn record(&self, failed: bool) {
        if !self.recorded.swap(true, Ordering::AcqRel) {
            self.breaker
                .record(self.epoch, self.half_open, failed, Instant::now());
        }
    }

    #[cfg(test)]
    fn record_at(&self, failed: bool, now: Instant) {
        if !self.recorded.swap(true, Ordering::AcqRel) {
            self.breaker.record(self.epoch, self.half_open, failed, now);
        }
    }
}

impl Drop for CircuitPermit {
    fn drop(&mut self) {
        if self.half_open {
            self.breaker.release(self.epoch);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            sample_size: 4,
            minimum_requests: 2,
            failure_percent: 50,
            open_secs: 1,
            half_open_requests: 1,
        }
    }

    #[test]
    fn opens_at_threshold_and_limits_half_open_work() {
        let circuit = CircuitBreaker::new(policy());
        let now = Instant::now();
        circuit
            .acquire_at(now)
            .expect("permit")
            .record_at(true, now);
        circuit
            .acquire_at(now)
            .expect("permit")
            .record_at(true, now);
        assert!(circuit.acquire_at(now).is_none());
        let probe = circuit
            .acquire_at(now + Duration::from_secs(1))
            .expect("half-open probe");
        assert!(circuit.acquire_at(now + Duration::from_secs(1)).is_none());
        probe.record_at(false, now + Duration::from_secs(1));
        drop(probe);
        assert!(circuit.acquire_at(now + Duration::from_secs(1)).is_some());
    }

    #[test]
    fn rolling_sample_is_bounded_and_evicts_old_results() {
        let circuit = CircuitBreaker::new(CircuitBreakerConfig {
            sample_size: 3,
            minimum_requests: 3,
            failure_percent: 67,
            ..policy()
        });
        let now = Instant::now();
        circuit
            .acquire_at(now)
            .expect("permit")
            .record_at(true, now);
        circuit
            .acquire_at(now)
            .expect("permit")
            .record_at(true, now);
        circuit
            .acquire_at(now)
            .expect("permit")
            .record_at(false, now);
        circuit
            .acquire_at(now)
            .expect("permit")
            .record_at(false, now);
        let state = circuit
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Mode::Closed { failures } = &state.mode else {
            panic!("circuit unexpectedly opened");
        };
        assert_eq!(failures.len(), 3);
        assert_eq!(failures.iter().filter(|failed| **failed).count(), 1);
    }

    #[test]
    fn failed_half_open_probe_reopens_circuit() {
        let circuit = CircuitBreaker::new(policy());
        let now = Instant::now();
        circuit
            .acquire_at(now)
            .expect("permit")
            .record_at(true, now);
        circuit
            .acquire_at(now)
            .expect("permit")
            .record_at(true, now);
        let probe = circuit
            .acquire_at(now + Duration::from_secs(1))
            .expect("half-open probe");
        probe.record_at(true, now + Duration::from_secs(1));
        drop(probe);
        assert!(
            circuit
                .acquire_at(now + Duration::from_millis(1_500))
                .is_none()
        );
    }
}
