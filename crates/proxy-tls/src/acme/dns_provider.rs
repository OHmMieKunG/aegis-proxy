use std::{fmt, sync::Arc, time::Duration};

use aegisproxy_secrets::{SecretBytes, SecretRef};
use bytes::Bytes;
use http::{Method, Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client as HyperClient, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::timeout;
use url::Url;
use zeroize::Zeroizing;

use super::order::valid_dns_identifier;

const CLOUDFLARE_API_ORIGIN: &str = "https://api.cloudflare.com";
const MAX_TOKEN_BYTES: usize = 512;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HTTP_BUFFER_BYTES: usize = 32 * 1024;
const MAX_HEADER_COUNT: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

type Client = HyperClient<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Sanitized Cloudflare DNS-01 provider failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DnsProviderError {
    /// Provider configuration or challenge material was invalid.
    #[error("invalid DNS provider input")]
    Input,
    /// The provider client or secret could not be prepared.
    #[error("DNS provider initialization failed")]
    Initialization,
    /// The provider request failed or timed out.
    #[error("DNS provider request failed")]
    Request,
    /// The provider response exceeded its byte bound.
    #[error("DNS provider response exceeded its resource bound")]
    ResponseBound,
    /// The provider returned an unsuccessful or malformed response.
    #[error("invalid DNS provider response")]
    Response,
}

/// Opaque Cloudflare record ownership proof required for exact cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareDnsRecord {
    zone_id: String,
    record_id: String,
    name: String,
}

impl CloudflareDnsRecord {
    /// Exact public TXT record name created for this authorization.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Cloudflare v4 DNS writer using one explicit zone and scoped API token.
#[derive(Clone)]
pub struct CloudflareDnsProvider {
    zone_id: String,
    api_token: Arc<SecretBytes>,
    client: Client,
}

impl fmt::Debug for CloudflareDnsProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareDnsProvider")
            .field("zone_id", &self.zone_id)
            .field("api_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl CloudflareDnsProvider {
    /// Resolve the token reference off Tokio workers and create a bounded HTTPS client.
    pub async fn new(zone_id: String, api_token: &str) -> Result<Self, DnsProviderError> {
        if !valid_cloudflare_id(&zone_id) {
            return Err(DnsProviderError::Input);
        }
        let reference = SecretRef::parse(api_token).map_err(|_| DnsProviderError::Input)?;
        tokio::task::spawn_blocking(move || {
            let token = reference
                .resolve(MAX_TOKEN_BYTES)
                .map_err(|_| DnsProviderError::Initialization)?;
            Self::from_secret(zone_id, token)
        })
        .await
        .map_err(|_| DnsProviderError::Initialization)?
    }

    /// Create one exact TXT record and return the provider record ID needed for cleanup.
    pub async fn present(
        &self,
        identifier: &str,
        value: &str,
    ) -> Result<CloudflareDnsRecord, DnsProviderError> {
        let name = challenge_record_name(identifier)?;
        validate_dns_value(value)?;
        if let Some(record) = self.find_existing(&name, value).await? {
            return Ok(record);
        }
        let request = create_request(
            &self.zone_id,
            self.api_token.as_ref().as_ref(),
            &name,
            value,
        )?;
        let created = async {
            let (status, body) = self.execute(request).await?;
            if status != StatusCode::OK {
                return Err(DnsProviderError::Response);
            }
            let record_id = parse_record_response(&body)?;
            Ok(CloudflareDnsRecord {
                zone_id: self.zone_id.clone(),
                record_id,
                name: name.clone(),
            })
        }
        .await;
        match created {
            Ok(record) => Ok(record),
            Err(original) => match self.find_existing(&name, value).await {
                Ok(Some(record)) => Ok(record),
                _ => Err(original),
            },
        }
    }

    /// Delete only a record handle created for this provider's configured zone.
    pub async fn cleanup(&self, record: &CloudflareDnsRecord) -> Result<(), DnsProviderError> {
        if record.zone_id != self.zone_id || !valid_cloudflare_id(&record.record_id) {
            return Err(DnsProviderError::Input);
        }
        let request = delete_request(
            &self.zone_id,
            self.api_token.as_ref().as_ref(),
            &record.record_id,
        )?;
        let (status, body) = self.execute(request).await?;
        if status != StatusCode::OK || parse_record_response(&body)? != record.record_id {
            return Err(DnsProviderError::Response);
        }
        Ok(())
    }

    fn from_secret(zone_id: String, api_token: SecretBytes) -> Result<Self, DnsProviderError> {
        validate_api_token(api_token.as_ref())?;
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|_| DnsProviderError::Initialization)?
            .https_only()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        let mut builder = HyperClient::builder(TokioExecutor::new());
        builder
            .pool_idle_timeout(IDLE_TIMEOUT)
            .pool_max_idle_per_host(2)
            .http1_max_buf_size(MAX_HTTP_BUFFER_BYTES)
            .http1_max_headers(MAX_HEADER_COUNT)
            .http2_max_header_list_size(MAX_HTTP_BUFFER_BYTES as u32);
        Ok(Self {
            zone_id,
            api_token: Arc::new(api_token),
            client: builder.build(connector),
        })
    }

    async fn execute(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<(StatusCode, Bytes), DnsProviderError> {
        let response = timeout(REQUEST_TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| DnsProviderError::Request)?
            .map_err(|_| DnsProviderError::Request)?;
        bounded_response(response, MAX_RESPONSE_BYTES).await
    }

    async fn find_existing(
        &self,
        name: &str,
        value: &str,
    ) -> Result<Option<CloudflareDnsRecord>, DnsProviderError> {
        let request = list_request(&self.zone_id, self.api_token.as_ref().as_ref(), name, value)?;
        let (status, body) = self.execute(request).await?;
        if status != StatusCode::OK {
            return Err(DnsProviderError::Response);
        }
        parse_list_response(&body, &self.zone_id, name, value)
    }
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    content: &'a str,
    ttl: u16,
}

#[derive(Debug, Deserialize)]
struct ProviderResponse {
    success: bool,
    result: Option<RecordResult>,
}

#[derive(Debug, Deserialize)]
struct RecordResult {
    id: String,
}

#[derive(Debug, Deserialize)]
struct ListProviderResponse {
    success: bool,
    result: Option<Vec<ListRecordResult>>,
}

#[derive(Debug, Deserialize)]
struct ListRecordResult {
    id: String,
    name: String,
    content: String,
    #[serde(rename = "type")]
    record_type: String,
}

fn create_request(
    zone_id: &str,
    token: &[u8],
    name: &str,
    value: &str,
) -> Result<Request<Full<Bytes>>, DnsProviderError> {
    let uri = provider_uri(zone_id, None)?;
    let body = serde_json::to_vec(&CreateRecordRequest {
        record_type: "TXT",
        name,
        content: value,
        ttl: 60,
    })
    .map_err(|_| DnsProviderError::Input)?;
    request(Method::POST, uri, token, Bytes::from(body))
}

fn delete_request(
    zone_id: &str,
    token: &[u8],
    record_id: &str,
) -> Result<Request<Full<Bytes>>, DnsProviderError> {
    request(
        Method::DELETE,
        provider_uri(zone_id, Some(record_id))?,
        token,
        Bytes::new(),
    )
}

fn list_request(
    zone_id: &str,
    token: &[u8],
    name: &str,
    value: &str,
) -> Result<Request<Full<Bytes>>, DnsProviderError> {
    let mut url = Url::parse(&provider_uri(zone_id, None)?.to_string())
        .map_err(|_| DnsProviderError::Input)?;
    url.query_pairs_mut()
        .append_pair("type", "TXT")
        .append_pair("name.exact", name)
        .append_pair("content.exact", value)
        .append_pair("match", "all")
        .append_pair("per_page", "2");
    request(
        Method::GET,
        url.as_str()
            .parse::<Uri>()
            .map_err(|_| DnsProviderError::Input)?,
        token,
        Bytes::new(),
    )
}

fn request(
    method: Method,
    uri: Uri,
    token: &[u8],
    body: Bytes,
) -> Result<Request<Full<Bytes>>, DnsProviderError> {
    let mut authorization = Zeroizing::new(Vec::with_capacity(7 + token.len()));
    authorization.extend_from_slice(b"Bearer ");
    authorization.extend_from_slice(token);
    let mut authorization =
        http::HeaderValue::from_bytes(&authorization).map_err(|_| DnsProviderError::Input)?;
    authorization.set_sensitive(true);
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, authorization)
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(body))
        .map_err(|_| DnsProviderError::Input)
}

fn provider_uri(zone_id: &str, record_id: Option<&str>) -> Result<Uri, DnsProviderError> {
    if !valid_cloudflare_id(zone_id) || record_id.is_some_and(|id| !valid_cloudflare_id(id)) {
        return Err(DnsProviderError::Input);
    }
    let suffix = record_id.map_or_else(String::new, |id| format!("/{id}"));
    format!("{CLOUDFLARE_API_ORIGIN}/client/v4/zones/{zone_id}/dns_records{suffix}")
        .parse()
        .map_err(|_| DnsProviderError::Input)
}

fn challenge_record_name(identifier: &str) -> Result<String, DnsProviderError> {
    if !valid_dns_identifier(identifier) {
        return Err(DnsProviderError::Input);
    }
    let identifier = identifier.strip_prefix("*.").unwrap_or(identifier);
    let name = format!("_acme-challenge.{identifier}");
    if name.len() > 255 {
        return Err(DnsProviderError::Input);
    }
    Ok(name)
}

fn validate_dns_value(value: &str) -> Result<(), DnsProviderError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DnsProviderError::Input);
    }
    Ok(())
}

fn validate_api_token(token: &[u8]) -> Result<(), DnsProviderError> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || !token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DnsProviderError::Initialization);
    }
    Ok(())
}

fn valid_cloudflare_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn parse_record_response(body: &[u8]) -> Result<String, DnsProviderError> {
    let response: ProviderResponse =
        serde_json::from_slice(body).map_err(|_| DnsProviderError::Response)?;
    let id = response
        .success
        .then_some(response.result)
        .flatten()
        .map(|result| result.id)
        .filter(|id| valid_cloudflare_id(id))
        .ok_or(DnsProviderError::Response)?;
    Ok(id)
}

fn parse_list_response(
    body: &[u8],
    zone_id: &str,
    name: &str,
    value: &str,
) -> Result<Option<CloudflareDnsRecord>, DnsProviderError> {
    let response: ListProviderResponse =
        serde_json::from_slice(body).map_err(|_| DnsProviderError::Response)?;
    if !response.success {
        return Err(DnsProviderError::Response);
    }
    let records = response.result.ok_or(DnsProviderError::Response)?;
    if records.len() > 1 {
        return Err(DnsProviderError::Response);
    }
    records
        .into_iter()
        .next()
        .map(|record| {
            if !valid_cloudflare_id(&record.id)
                || record.record_type != "TXT"
                || record.name != name
                || record.content != value
            {
                return Err(DnsProviderError::Response);
            }
            Ok(CloudflareDnsRecord {
                zone_id: zone_id.to_owned(),
                record_id: record.id,
                name: record.name,
            })
        })
        .transpose()
}

async fn bounded_response<B>(
    response: http::Response<B>,
    limit: usize,
) -> Result<(StatusCode, Bytes), DnsProviderError>
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = response.into_parts();
    let body = Limited::new(body, limit)
        .collect()
        .await
        .map_err(|_| DnsProviderError::ResponseBound)?
        .to_bytes();
    Ok((parts.status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE_ID: &str = "0123456789abcdef0123456789abcdef";
    const RECORD_ID: &str = "fedcba9876543210fedcba9876543210";
    const TOKEN: &[u8] = b"scoped-token_CANARY";
    const DNS_VALUE: &str = "abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE";

    #[test]
    fn builds_exact_scoped_create_and_delete_requests() {
        test_runtime().block_on(async {
            let request = create_request(ZONE_ID, TOKEN, "_acme-challenge.example.test", DNS_VALUE)
                .expect("create request");
            assert_eq!(request.method(), Method::POST);
            assert_eq!(
                request.uri().path(),
                format!("/client/v4/zones/{ZONE_ID}/dns_records")
            );
            assert!(request.headers()[header::AUTHORIZATION].is_sensitive());
            let body = request
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).expect("JSON"),
                serde_json::json!({
                    "type": "TXT",
                    "name": "_acme-challenge.example.test",
                    "content": DNS_VALUE,
                    "ttl": 60
                })
            );

            let request = delete_request(ZONE_ID, TOKEN, RECORD_ID).expect("delete request");
            assert_eq!(request.method(), Method::DELETE);
            assert_eq!(
                request.uri().path(),
                format!("/client/v4/zones/{ZONE_ID}/dns_records/{RECORD_ID}")
            );

            let request = list_request(ZONE_ID, TOKEN, "_acme-challenge.example.test", DNS_VALUE)
                .expect("list request");
            assert_eq!(request.method(), Method::GET);
            let url = Url::parse(&request.uri().to_string()).expect("list URL");
            assert_eq!(
                url.query_pairs().collect::<Vec<_>>(),
                [
                    ("type".into(), "TXT".into()),
                    ("name.exact".into(), "_acme-challenge.example.test".into()),
                    ("content.exact".into(), DNS_VALUE.into()),
                    ("match".into(), "all".into()),
                    ("per_page".into(), "2".into()),
                ]
            );
        });
    }

    #[test]
    fn validates_exact_challenge_names_values_and_provider_ids() {
        assert_eq!(
            challenge_record_name("*.example.test").as_deref(),
            Ok("_acme-challenge.example.test")
        );
        assert!(challenge_record_name("Example.test").is_err());
        assert!(challenge_record_name("example.test.").is_err());
        assert!(validate_dns_value(DNS_VALUE).is_ok());
        assert!(validate_dns_value("not-a-sha256-value").is_err());
        assert!(provider_uri("../../metadata", None).is_err());
        assert!(delete_request(ZONE_ID, TOKEN, "../other").is_err());
    }

    #[test]
    fn accepts_only_successful_bounded_matching_record_responses() {
        let success = format!(r#"{{"success":true,"result":{{"id":"{RECORD_ID}"}}}}"#);
        assert_eq!(
            parse_record_response(success.as_bytes()).as_deref(),
            Ok(RECORD_ID)
        );
        assert!(parse_record_response(br#"{"success":false,"result":null}"#).is_err());
        assert!(parse_record_response(br#"{"success":true,"result":{"id":"../bad"}}"#).is_err());

        let listed = format!(
            r#"{{"success":true,"result":[{{"id":"{RECORD_ID}","name":"_acme-challenge.example.test","content":"{DNS_VALUE}","type":"TXT"}}]}}"#
        );
        assert_eq!(
            parse_list_response(
                listed.as_bytes(),
                ZONE_ID,
                "_acme-challenge.example.test",
                DNS_VALUE
            )
            .expect("list response")
            .map(|record| record.record_id),
            Some(RECORD_ID.into())
        );
        let duplicate = format!(
            r#"{{"success":true,"result":[{{"id":"{RECORD_ID}","name":"_acme-challenge.example.test","content":"{DNS_VALUE}","type":"TXT"}},{{"id":"{ZONE_ID}","name":"_acme-challenge.example.test","content":"{DNS_VALUE}","type":"TXT"}}]}}"#
        );
        assert!(
            parse_list_response(
                duplicate.as_bytes(),
                ZONE_ID,
                "_acme-challenge.example.test",
                DNS_VALUE
            )
            .is_err()
        );

        test_runtime().block_on(async {
            let response = http::Response::new(Full::new(Bytes::from_static(b"too-large")));
            assert!(matches!(
                bounded_response(response, 4).await,
                Err(DnsProviderError::ResponseBound)
            ));
        });
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime")
    }
}
