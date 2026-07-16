use std::{future::Future, time::Duration};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client as HyperClient, connect::HttpConnector},
    rt::TokioExecutor,
};
use instant_acme::{
    Account, AccountBuilder, BodyWrapper, BytesResponse, Error as InstantAcmeError, HttpClient,
};
use thiserror::Error;
use tokio::time::timeout;
use url::Url;

const MAX_ACME_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ACME_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_ACME_HTTP1_BUFFER_BYTES: usize = 32 * 1024;
const MAX_ACME_HEADER_COUNT: usize = 64;
const ACME_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACME_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ACME_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

type Client = HyperClient<HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>;

#[derive(Debug, Error)]
pub(super) enum AcmeTransportError {
    #[error("ACME transport initialization failed")]
    Initialization,
    #[error("ACME endpoint violates the configured directory origin")]
    Origin,
    #[error("ACME request failed")]
    Request,
    #[error("ACME response exceeded its resource bound")]
    ResponseBound,
    #[error("ACME request timed out")]
    Timeout,
}

#[derive(Clone)]
struct BoundedAcmeHttpClient {
    client: Client,
    origin: Url,
    response_limit: usize,
    request_timeout: Duration,
}

pub(super) async fn account_builder(
    directory_url: &Url,
    ca_bundle: Option<&str>,
) -> Result<AccountBuilder, AcmeTransportError> {
    let directory_url = directory_url.clone();
    let ca_bundle = ca_bundle.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        BoundedAcmeHttpClient::new(directory_url, ca_bundle.as_deref())
            .map(|client| Account::builder_with_http(Box::new(client)))
    })
    .await
    .map_err(|_| AcmeTransportError::Initialization)?
}

impl BoundedAcmeHttpClient {
    fn new(origin: Url, ca_bundle: Option<&str>) -> Result<Self, AcmeTransportError> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(ACME_CONNECT_TIMEOUT));

        let connector = match ca_bundle {
            Some(reference) => HttpsConnectorBuilder::new()
                .with_tls_config(
                    crate::client_config(Some(reference))
                        .map_err(|_| AcmeTransportError::Initialization)?,
                )
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .wrap_connector(http),
            None => HttpsConnectorBuilder::new()
                .try_with_platform_verifier()
                .map_err(|_| AcmeTransportError::Initialization)?
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .wrap_connector(http),
        };

        let mut builder = HyperClient::builder(TokioExecutor::new());
        builder
            .pool_idle_timeout(ACME_IDLE_TIMEOUT)
            .pool_max_idle_per_host(2)
            .http1_max_buf_size(MAX_ACME_HTTP1_BUFFER_BYTES)
            .http1_max_headers(MAX_ACME_HEADER_COUNT)
            .http2_max_header_list_size(MAX_ACME_HTTP1_BUFFER_BYTES as u32);
        Ok(Self {
            client: builder.build(connector),
            origin,
            response_limit: MAX_ACME_RESPONSE_BYTES,
            request_timeout: ACME_REQUEST_TIMEOUT,
        })
    }

    fn permits(&self, request: &Request<BodyWrapper<Bytes>>) -> bool {
        let raw = request.uri().to_string();
        if raw.len() > MAX_ACME_ENDPOINT_BYTES {
            return false;
        }
        let Ok(endpoint) = Url::parse(&raw) else {
            return false;
        };
        same_origin(&self.origin, &endpoint)
    }
}

fn same_origin(origin: &Url, endpoint: &Url) -> bool {
    endpoint.scheme() == origin.scheme()
        && endpoint.host_str().is_some_and(|host| {
            origin
                .host_str()
                .is_some_and(|expected| host.eq_ignore_ascii_case(expected))
        })
        && endpoint.port_or_known_default() == origin.port_or_known_default()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.fragment().is_none()
}

impl HttpClient for BoundedAcmeHttpClient {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<BytesResponse, InstantAcmeError>> + Send>>
    {
        if !self.permits(&request) {
            return Box::pin(async {
                Err(InstantAcmeError::Other(Box::new(
                    AcmeTransportError::Origin,
                )))
            });
        }
        let client = self.client.clone();
        let response_limit = self.response_limit;
        let request_timeout = self.request_timeout;
        Box::pin(async move {
            with_timeout(request_timeout, async move {
                let response = client
                    .request(request)
                    .await
                    .map_err(|_| AcmeTransportError::Request)?;
                bounded_response(response, response_limit).await
            })
            .await
            .map_err(|error| InstantAcmeError::Other(Box::new(error)))
        })
    }
}

async fn with_timeout<F, T>(duration: Duration, future: F) -> Result<T, AcmeTransportError>
where
    F: Future<Output = Result<T, AcmeTransportError>>,
{
    timeout(duration, future)
        .await
        .map_err(|_| AcmeTransportError::Timeout)?
}

async fn bounded_response<B>(
    response: Response<B>,
    limit: usize,
) -> Result<BytesResponse, AcmeTransportError>
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = response.into_parts();
    let body = Limited::new(body, limit)
        .collect()
        .await
        .map_err(|_| AcmeTransportError::ResponseBound)?
        .to_bytes();
    Ok(BytesResponse {
        parts,
        body: Box::new(body),
    })
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use http_body_util::Full;

    use super::*;

    #[test]
    fn rejects_oversized_response_before_collection_completes() {
        test_runtime().block_on(async {
            let response = Response::new(Full::new(Bytes::from_static(b"too-large")));
            assert!(matches!(
                bounded_response(response, 4).await,
                Err(AcmeTransportError::ResponseBound)
            ));
        });
    }

    #[test]
    fn enforces_total_request_deadline() {
        test_runtime().block_on(async {
            let result = with_timeout(
                Duration::from_millis(1),
                pending::<Result<(), AcmeTransportError>>(),
            )
            .await;
            assert!(matches!(result, Err(AcmeTransportError::Timeout)));
        });
    }

    #[test]
    fn rejects_cross_origin_and_credentialed_endpoints() {
        let origin = Url::parse("https://acme.test/directory").expect("origin");
        let same = Url::parse("https://ACME.test/new-order").expect("same origin");
        let cross_host = Url::parse("https://metadata.test/new-order").expect("cross host");
        let cross_scheme = Url::parse("http://acme.test/new-order").expect("cross scheme");
        let credentialed =
            Url::parse("https://canary:secret@acme.test/new-order").expect("credentials");
        assert!(same_origin(&origin, &same));
        assert!(!same_origin(&origin, &cross_host));
        assert!(!same_origin(&origin, &cross_scheme));
        assert!(!same_origin(&origin, &credentialed));
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime")
    }
}
