//! Bounded OpenMetrics state shared by data and control planes.

use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use aegisproxy_config::Config;
use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

const DURATION_BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];
const MAX_OPENMETRICS_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, EncodeLabelSet, Eq, Hash, PartialEq)]
struct RequestLabels {
    listener: String,
    route: String,
    protocol: String,
    status_class: String,
}

#[derive(Clone, Debug, EncodeLabelSet, Eq, Hash, PartialEq)]
struct ActiveRequestLabels {
    listener: String,
    route: String,
    protocol: String,
}

#[derive(Clone, Debug, EncodeLabelSet, Eq, Hash, PartialEq)]
struct ConnectionLabels {
    listener: String,
    protocol: String,
}

#[derive(Clone, Debug, EncodeLabelSet, Eq, Hash, PartialEq)]
struct OutcomeLabels {
    outcome: String,
}

type DurationFamily = Family<RequestLabels, Histogram, fn() -> Histogram>;

/// Process telemetry with no labels derived from raw request data.
pub struct Telemetry {
    registry: Registry,
    enabled: bool,
    allowed: RwLock<AllowedLabels>,
    request_labels: Mutex<HashSet<RequestLabels>>,
    active_request_labels: Mutex<HashSet<ActiveRequestLabels>>,
    requests: Family<RequestLabels, Counter>,
    response_bytes: Family<RequestLabels, Counter>,
    request_duration: DurationFamily,
    active_requests: Family<ActiveRequestLabels, Gauge>,
    connections: Family<ConnectionLabels, Counter>,
    active_connections: Family<ConnectionLabels, Gauge>,
    reloads: Family<OutcomeLabels, Counter>,
    telemetry_drops: Family<OutcomeLabels, Counter>,
}

#[derive(Debug)]
struct AllowedLabels {
    listeners: HashSet<String>,
    routes: HashSet<String>,
}

impl fmt::Debug for Telemetry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Telemetry")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl Telemetry {
    pub(crate) fn new(config: &Config) -> Arc<Self> {
        let requests = Family::default();
        let response_bytes = Family::default();
        let request_duration = Family::new_with_constructor(histogram as fn() -> Histogram);
        let active_requests = Family::default();
        let connections = Family::default();
        let active_connections = Family::default();
        let reloads = Family::default();
        let telemetry_drops = Family::default();
        let mut registry = Registry::with_prefix("aegisproxy");
        registry.register(
            "http_requests",
            "Completed HTTP requests by configured IDs and bounded outcome class",
            requests.clone(),
        );
        registry.register(
            "http_response_bytes",
            "HTTP response body bytes by configured IDs and bounded outcome class",
            response_bytes.clone(),
        );
        registry.register(
            "http_request_duration_seconds",
            "HTTP request duration by configured IDs and bounded outcome class",
            request_duration.clone(),
        );
        registry.register(
            "http_requests_active",
            "HTTP requests currently active after route selection",
            active_requests.clone(),
        );
        registry.register(
            "connections_accepted",
            "Accepted data-plane connections by configured listener and protocol",
            connections.clone(),
        );
        registry.register(
            "connections_active",
            "Active data-plane connections by configured listener and protocol",
            active_connections.clone(),
        );
        registry.register(
            "config_reloads",
            "Configuration activation outcomes",
            reloads.clone(),
        );
        registry.register(
            "telemetry_drops",
            "Best-effort telemetry dropped by bounded component and reason",
            telemetry_drops.clone(),
        );
        Arc::new(Self {
            registry,
            enabled: config.observability.metrics,
            allowed: RwLock::new(allowed(config)),
            request_labels: Mutex::new(HashSet::new()),
            active_request_labels: Mutex::new(HashSet::new()),
            requests,
            response_bytes,
            request_duration,
            active_requests,
            connections,
            active_connections,
            reloads,
            telemetry_drops,
        })
    }

    pub(crate) fn request_started(
        self: &Arc<Self>,
        listener: &str,
        route: &str,
        protocol: &str,
    ) -> Option<RequestGuard> {
        if !self.enabled || !self.allowed(listener, route) {
            return None;
        }
        let labels = ActiveRequestLabels {
            listener: listener.to_owned(),
            route: route.to_owned(),
            protocol: bounded_protocol(protocol).to_owned(),
        };
        self.active_requests.get_or_create(&labels).inc();
        self.active_request_labels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(labels.clone());
        Some(RequestGuard {
            telemetry: Arc::clone(self),
            labels,
        })
    }

    pub(crate) fn request_finished(&self, event: RequestMetric<'_>) {
        if !self.enabled || !self.allowed(event.listener, event.route) {
            return;
        }
        let labels = RequestLabels {
            listener: event.listener.to_owned(),
            route: event.route.to_owned(),
            protocol: bounded_protocol(event.protocol).to_owned(),
            status_class: status_class(event.status).to_owned(),
        };
        self.request_labels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(labels.clone());
        self.requests.get_or_create(&labels).inc();
        self.response_bytes
            .get_or_create(&labels)
            .inc_by(event.response_bytes);
        self.request_duration
            .get_or_create(&labels)
            .observe(event.duration.as_secs_f64());
    }

    pub(crate) fn connection_started(
        self: &Arc<Self>,
        listener: &str,
        protocol: &str,
    ) -> Option<ConnectionGuard> {
        if !self.enabled || !self.allowed_listener(listener) {
            return None;
        }
        let labels = ConnectionLabels {
            listener: listener.to_owned(),
            protocol: bounded_protocol(protocol).to_owned(),
        };
        self.connections.get_or_create(&labels).inc();
        self.active_connections.get_or_create(&labels).inc();
        Some(ConnectionGuard {
            telemetry: Arc::clone(self),
            labels,
        })
    }

    pub(crate) fn reload(&self, outcome: &'static str) {
        if self.enabled {
            self.reloads
                .get_or_create(&OutcomeLabels {
                    outcome: bounded_reload_outcome(outcome).to_owned(),
                })
                .inc();
        }
    }

    pub(crate) fn drop_signal(&self, reason: &'static str) {
        if self.enabled {
            self.telemetry_drops
                .get_or_create(&OutcomeLabels {
                    outcome: bounded_drop_reason(reason).to_owned(),
                })
                .inc();
        }
    }

    pub(crate) fn reconcile(&self, config: &Config) {
        *self
            .allowed
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = allowed(config);
        self.request_labels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|labels| {
                if self.allowed(&labels.listener, &labels.route) {
                    true
                } else {
                    self.requests.remove(labels);
                    self.response_bytes.remove(labels);
                    self.request_duration.remove(labels);
                    false
                }
            });
        self.prune_inactive_request_labels();
    }

    /// Encode the current registry using OpenMetrics text exposition.
    pub fn render(&self) -> Result<String, fmt::Error> {
        if !self.enabled {
            return Ok(String::new());
        }
        let mut output = LimitedText::new(MAX_OPENMETRICS_BYTES);
        encode(&mut output, &self.registry)?;
        Ok(output.into_string())
    }

    fn allowed(&self, listener: &str, route: &str) -> bool {
        let allowed = self
            .allowed
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        allowed.listeners.contains(listener)
            && (route == "unmatched" || allowed.routes.contains(route))
    }

    fn allowed_listener(&self, listener: &str) -> bool {
        self.allowed
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .listeners
            .contains(listener)
    }

    fn prune_inactive_request_labels(&self) {
        self.active_request_labels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|labels| {
                let active = self
                    .active_requests
                    .get(labels)
                    .is_some_and(|gauge| gauge.get() != 0);
                if active || self.allowed(&labels.listener, &labels.route) {
                    true
                } else {
                    self.active_requests.remove(labels);
                    false
                }
            });
    }
}

fn allowed(config: &Config) -> AllowedLabels {
    AllowedLabels {
        listeners: config
            .listeners
            .iter()
            .map(|listener| listener.id.clone())
            .collect(),
        routes: config.routes.iter().map(|route| route.id.clone()).collect(),
    }
}

#[derive(Debug)]
struct LimitedText {
    value: String,
    maximum: usize,
}

impl LimitedText {
    fn new(maximum: usize) -> Self {
        Self {
            value: String::with_capacity(16 * 1024),
            maximum,
        }
    }

    fn into_string(self) -> String {
        self.value
    }
}

impl fmt::Write for LimitedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.value.len().saturating_add(value.len()) > self.maximum {
            return Err(fmt::Error);
        }
        self.value.push_str(value);
        Ok(())
    }
}

/// Bounded request metric input.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestMetric<'a> {
    pub(crate) listener: &'a str,
    pub(crate) route: &'a str,
    pub(crate) protocol: &'a str,
    pub(crate) status: u16,
    pub(crate) response_bytes: u64,
    pub(crate) duration: Duration,
}

#[derive(Debug)]
pub(crate) struct RequestGuard {
    telemetry: Arc<Telemetry>,
    labels: ActiveRequestLabels,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.telemetry
            .active_requests
            .get_or_create(&self.labels)
            .dec();
        self.telemetry.prune_inactive_request_labels();
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionGuard {
    telemetry: Arc<Telemetry>,
    labels: ConnectionLabels,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.telemetry
            .active_connections
            .get_or_create(&self.labels)
            .dec();
    }
}

fn histogram() -> Histogram {
    Histogram::new(DURATION_BUCKETS)
}

fn bounded_protocol(protocol: &str) -> &'static str {
    match protocol {
        "http1" => "http1",
        "http2" => "http2",
        "http" => "http",
        "https" => "https",
        "websocket" => "websocket",
        "tcp" => "tcp",
        "tls_passthrough" => "tls_passthrough",
        _ => "unknown",
    }
}

fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "invalid",
    }
}

fn bounded_reload_outcome(outcome: &str) -> &'static str {
    match outcome {
        "success" => "success",
        "rejected" => "rejected",
        "rolled_back" => "rolled_back",
        _ => "internal_error",
    }
}

fn bounded_drop_reason(reason: &str) -> &'static str {
    match reason {
        "access_sampled" => "access_sampled",
        "trace_queue_full" => "trace_queue_full",
        "export_failed" => "export_failed",
        _ => "internal_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_bounded_and_raw_values_never_create_series() {
        let config = toml::from_str(
            r#"
            schema_version = 1
            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"
            [[routes]]
            id = "app"
            listeners = ["public"]
            hosts = ["example.test"]
            upstream_group = "app"
            [[upstream_groups]]
            id = "app"
            allowed_cidrs = ["127.0.0.1/32"]
            [[upstream_groups.endpoints]]
            id = "app-1"
            url = "http://127.0.0.1:9000"
            "#,
        )
        .expect("config");
        let telemetry = Telemetry::new(&config);
        telemetry.request_finished(RequestMetric {
            listener: "public",
            route: "app",
            protocol: "http1",
            status: 200,
            response_bytes: 12,
            duration: Duration::from_millis(5),
        });
        telemetry.request_finished(RequestMetric {
            listener: "attacker.example",
            route: "/raw/path?secret=canary",
            protocol: "attacker-controlled",
            status: 777,
            response_bytes: 1,
            duration: Duration::ZERO,
        });
        let output = telemetry.render().expect("metrics");
        assert!(output.contains("listener=\"public\""));
        assert!(output.contains("route=\"app\""));
        assert!(!output.contains("attacker.example"));
        assert!(!output.contains("raw/path"));
        assert!(!output.contains("canary"));

        let guard = telemetry
            .request_started("public", "app", "http1")
            .expect("active request metric");
        let mut replacement = config.clone();
        replacement.routes[0].id = "replacement".into();
        telemetry.reconcile(&replacement);
        assert!(
            telemetry
                .render()
                .expect("metrics")
                .contains("route=\"app\"")
        );
        drop(guard);
        assert!(
            !telemetry
                .render()
                .expect("metrics")
                .contains("route=\"app\"")
        );
    }
}
