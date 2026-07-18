use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use http_body_util::BodyExt;
use hyper::{Method, Response, StatusCode, body::Body};

use crate::{
    ResponseBody,
    telemetry::{RequestGuard, RequestMetric, Telemetry},
};

static ACCESS_SAMPLE_SEQUENCE: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
pub(crate) struct AccessEvent {
    started: Instant,
    method: Method,
    listener_id: String,
    protocol: &'static str,
    route_id: Option<String>,
    request_id: Option<String>,
    status: Option<StatusCode>,
    response_bytes: u64,
    telemetry: Option<Arc<Telemetry>>,
    request_guard: Option<RequestGuard>,
    access_log: bool,
    sample_per_million: u32,
}

impl AccessEvent {
    pub(crate) fn new(
        method: Method,
        listener_id: String,
        protocol: &'static str,
        telemetry: Arc<Telemetry>,
        access_log: bool,
        sample_per_million: u32,
    ) -> Self {
        Self {
            started: Instant::now(),
            method,
            listener_id,
            protocol,
            route_id: None,
            request_id: None,
            status: None,
            response_bytes: 0,
            telemetry: Some(telemetry),
            request_guard: None,
            access_log,
            sample_per_million,
        }
    }

    #[cfg(test)]
    fn test_event(method: Method, listener_id: String) -> Self {
        Self {
            started: Instant::now(),
            method,
            listener_id,
            protocol: "http1",
            route_id: None,
            request_id: None,
            status: None,
            response_bytes: 0,
            telemetry: None,
            request_guard: None,
            access_log: false,
            sample_per_million: 0,
        }
    }

    pub(crate) fn set_request_id(&mut self, request_id: &str) {
        self.request_id = Some(request_id.to_owned());
        tracing::Span::current().record("request_id", request_id);
    }

    pub(crate) fn set_route(&mut self, route_id: &str) {
        self.route_id = Some(route_id.to_owned());
        tracing::Span::current().record("route_id", route_id);
        self.request_guard = self.telemetry.as_ref().and_then(|telemetry| {
            telemetry.request_started(&self.listener_id, route_id, self.protocol)
        });
    }

    pub(crate) fn hold(mut self, response: Response<ResponseBody>) -> Response<ResponseBody> {
        self.status = Some(response.status());
        response.map(|body| {
            AccessBody {
                body: Box::pin(body),
                event: Some(self),
            }
            .boxed()
        })
    }

    fn emit(self, completed: bool, body_error: bool) {
        let elapsed = self.started.elapsed();
        let route_id = self.route_id.as_deref().unwrap_or("unmatched");
        if let Some(telemetry) = &self.telemetry {
            telemetry.request_finished(RequestMetric {
                listener: &self.listener_id,
                route: route_id,
                protocol: self.protocol,
                status: self.status.map_or(500, |status| status.as_u16()),
                response_bytes: self.response_bytes,
                duration: elapsed,
            });
        }
        if !self.access_log {
            return;
        }
        if self.sample_per_million < 1_000_000
            && ACCESS_SAMPLE_SEQUENCE.fetch_add(1, Ordering::Relaxed) % 1_000_000
                >= self.sample_per_million
        {
            if let Some(telemetry) = &self.telemetry {
                telemetry.drop_signal("access_sampled");
            }
            return;
        }
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        tracing::info!(
            target: "aegisproxy_access",
            event_name = "http.access",
            listener_id = %self.listener_id,
            route_id,
            request_id = self.request_id.as_deref().unwrap_or("unavailable"),
            method = %self.method,
            protocol = self.protocol,
            status = self.status.map(|status| status.as_u16()).unwrap_or(500),
            response_bytes = self.response_bytes,
            duration_ms = elapsed_ms,
            completed,
            body_error,
            "access"
        );
    }
}

#[derive(Debug)]
struct AccessBody {
    body: Pin<Box<ResponseBody>>,
    event: Option<AccessEvent>,
}

impl AccessBody {
    fn finish(&mut self, completed: bool, body_error: bool) {
        if let Some(event) = self.event.take() {
            event.emit(completed, body_error);
        }
    }
}

impl Body for AccessBody {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.body.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(event), Some(data)) = (self.event.as_mut(), frame.data_ref()) {
                    event.response_bytes = event
                        .response_bytes
                        .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish(false, true);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finish(true, false);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

impl Drop for AccessBody {
    fn drop(&mut self) {
        self.finish(self.body.is_end_stream(), false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};

    #[tokio::test]
    async fn wrapper_preserves_body_and_counts_bounded_frames() {
        let event = AccessEvent::test_event(Method::GET, "public".into());
        let response = Response::new(
            Full::new(Bytes::from_static(b"hello"))
                .map_err(|never| match never {})
                .boxed(),
        );
        let bytes = event
            .hold(response)
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(bytes, "hello");
    }
}
