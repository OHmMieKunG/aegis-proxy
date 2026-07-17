use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use http_body_util::BodyExt;
use hyper::{Method, Response, StatusCode, body::Body};

use crate::ResponseBody;

#[derive(Debug)]
pub(crate) struct AccessEvent {
    started: Instant,
    method: Method,
    listener_id: String,
    route_id: Option<String>,
    request_id: Option<String>,
    status: Option<StatusCode>,
    response_bytes: u64,
}

impl AccessEvent {
    pub(crate) fn new(method: Method, listener_id: String) -> Self {
        Self {
            started: Instant::now(),
            method,
            listener_id,
            route_id: None,
            request_id: None,
            status: None,
            response_bytes: 0,
        }
    }

    pub(crate) fn set_request_id(&mut self, request_id: &str) {
        self.request_id = Some(request_id.to_owned());
    }

    pub(crate) fn set_route(&mut self, route_id: &str) {
        self.route_id = Some(route_id.to_owned());
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
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        tracing::info!(
            target: "aegisproxy_access",
            listener_id = %self.listener_id,
            route_id = self.route_id.as_deref().unwrap_or("unmatched"),
            request_id = self.request_id.as_deref().unwrap_or("unavailable"),
            method = %self.method,
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
        let event = AccessEvent::new(Method::GET, "public".into());
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
