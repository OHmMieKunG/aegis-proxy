//! Structured JSON logging and optional bounded OTLP trace export.

use std::{error::Error, time::Duration};

use aegisproxy_config::ObservabilityConfig;
use opentelemetry::{global, trace::TracerProvider as _};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    trace::{BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider},
};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

type BoxError = Box<dyn Error + Send + Sync>;

/// Provider owner used for bounded shutdown flushing.
#[derive(Debug)]
pub(crate) struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
    shutdown_timeout: Duration,
}

pub(crate) fn init(config: &ObservabilityConfig) -> Result<TelemetryGuard, BoxError> {
    global::set_text_map_propagator(TraceContextPropagator::new());
    let (provider, otlp_layer) = match &config.otlp_traces {
        Some(config) => {
            let timeout = Duration::from_secs(config.export_timeout_secs);
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(config.endpoint.as_str())
                .with_timeout(timeout)
                .build()?;
            let processor = BatchSpanProcessor::builder(exporter)
                .with_batch_config(
                    BatchConfigBuilder::default()
                        .with_max_queue_size(config.max_queue_size)
                        .with_max_export_batch_size(config.max_export_batch_size)
                        .with_scheduled_delay(Duration::from_secs(1))
                        .build(),
                )
                .build();
            let provider = SdkTracerProvider::builder()
                .with_resource(
                    Resource::builder_empty()
                        .with_service_name("aegisproxy")
                        .build(),
                )
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                    f64::from(config.sample_per_million) / 1_000_000.0,
                ))))
                .with_span_processor(processor)
                .build();
            let tracer = provider.tracer("aegisproxy");
            (
                Some(provider),
                Some(tracing_opentelemetry::layer().with_tracer(tracer)),
            )
        }
        None => (None, None),
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .with(otlp_layer)
        .try_init()?;
    Ok(TelemetryGuard {
        provider,
        shutdown_timeout: config
            .otlp_traces
            .as_ref()
            .map_or(Duration::ZERO, |config| {
                Duration::from_secs(config.export_timeout_secs)
            }),
    })
}

impl TelemetryGuard {
    pub(crate) async fn shutdown(self) {
        let Some(provider) = self.provider else {
            return;
        };
        let timeout = self.shutdown_timeout;
        match tokio::task::spawn_blocking(move || provider.shutdown_with_timeout(timeout)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(event_name = "telemetry.flush_failed", %error),
            Err(error) => tracing::warn!(event_name = "telemetry.shutdown_failed", %error),
        }
    }
}
