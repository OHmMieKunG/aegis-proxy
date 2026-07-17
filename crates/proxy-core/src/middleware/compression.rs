use std::{collections::HashMap, io, sync::Arc};

use aegisproxy_config::{CompressionEncoding, Config, MiddlewareConfig, RouteConfig};
use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder};
use bytes::Bytes;
use futures_util::{TryStreamExt, stream};
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    HeaderMap, Method, Response, StatusCode,
    body::Frame,
    header::{
        ACCEPT_ENCODING, ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH,
        CONTENT_RANGE, CONTENT_TYPE, ETAG, RANGE, TRAILER, VARY,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, BufReader},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_util::io::StreamReader;

use crate::{BoxError, ResponseBody};

pub(crate) type CompressionLimiters = Arc<HashMap<String, Arc<Semaphore>>>;

#[derive(Debug)]
pub(crate) struct RequestContext<'a> {
    pub(crate) method: &'a Method,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) authenticated: bool,
    pub(crate) grpc: bool,
    pub(crate) websocket: bool,
}

pub(crate) fn build(
    config: &Config,
    previous: Option<(&Config, &CompressionLimiters)>,
) -> CompressionLimiters {
    Arc::new(
        config
            .middlewares
            .iter()
            .filter_map(|(id, definition)| {
                let MiddlewareConfig::Compression { max_concurrent, .. } = definition else {
                    return None;
                };
                let limiter = previous
                    .and_then(|(old_config, old_limiters)| {
                        (old_config.middlewares.get(id) == Some(definition))
                            .then(|| old_limiters.get(id))
                            .flatten()
                            .cloned()
                    })
                    .unwrap_or_else(|| Arc::new(Semaphore::new(*max_concurrent)));
                Some((id.clone(), limiter))
            })
            .collect(),
    )
}

pub(crate) fn apply(
    limiters: &CompressionLimiters,
    config: &Config,
    route: &RouteConfig,
    request: RequestContext<'_>,
    response: &mut Response<ResponseBody>,
) -> Result<(), ()> {
    let Some((id, encodings, content_types, min_bytes, allow_authenticated)) =
        route.middlewares.iter().find_map(|id| {
            let MiddlewareConfig::Compression {
                encodings,
                content_types,
                min_bytes,
                allow_authenticated,
                ..
            } = config.middlewares.get(id)?
            else {
                return None;
            };
            Some((
                id,
                encodings,
                content_types,
                *min_bytes,
                *allow_authenticated,
            ))
        })
    else {
        return Ok(());
    };
    if request.method != Method::GET
        || !response.status().is_success()
        || matches!(
            response.status(),
            StatusCode::NO_CONTENT | StatusCode::PARTIAL_CONTENT
        )
        || request.grpc
        || request.websocket
        || (request.authenticated && !allow_authenticated)
        || request.headers.contains_key(RANGE)
        || response.headers().contains_key(CONTENT_ENCODING)
        || response.headers().contains_key(CONTENT_RANGE)
        || response.headers().contains_key(TRAILER)
        || has_no_transform(request.headers)
        || has_no_transform(response.headers())
    {
        return Ok(());
    }
    let size = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if !size.is_some_and(|size| size >= min_bytes) {
        return Ok(());
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !content_type.is_some_and(|value| {
        !value.eq_ignore_ascii_case("text/event-stream")
            && content_types
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(value))
    }) {
        return Ok(());
    }
    let Some(encoding) = select_encoding(request.headers, encodings) else {
        return Ok(());
    };
    let Some(limiter) = limiters.get(id) else {
        return Err(());
    };
    let Ok(permit) = Arc::clone(limiter).try_acquire_owned() else {
        return Ok(());
    };
    let body = std::mem::replace(response.body_mut(), empty_body());
    let reader = BufReader::new(StreamReader::new(
        body.into_data_stream().map_err(io::Error::other),
    ));
    *response.body_mut() = match encoding {
        CompressionEncoding::Gzip => encoded_body(GzipEncoder::new(reader), permit),
        CompressionEncoding::Brotli => encoded_body(BrotliEncoder::new(reader), permit),
    };
    response.headers_mut().remove(CONTENT_LENGTH);
    response.headers_mut().remove(ETAG);
    response.headers_mut().remove(ACCEPT_RANGES);
    response.headers_mut().insert(
        CONTENT_ENCODING,
        match encoding {
            CompressionEncoding::Gzip => hyper::header::HeaderValue::from_static("gzip"),
            CompressionEncoding::Brotli => hyper::header::HeaderValue::from_static("br"),
        },
    );
    if !response
        .headers()
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("accept-encoding") || value.trim() == "*")
    {
        response.headers_mut().append(
            VARY,
            hyper::header::HeaderValue::from_static("Accept-Encoding"),
        );
    }
    Ok(())
}

fn empty_body() -> ResponseBody {
    http_body_util::Empty::new()
        .map_err(|never| match never {})
        .boxed()
}

fn encoded_body<R>(reader: R, permit: OwnedSemaphorePermit) -> ResponseBody
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
{
    let frames = stream::try_unfold((reader, permit), |(mut reader, permit)| async move {
        let mut bytes = vec![0_u8; 16 * 1024];
        let count = reader.read(&mut bytes).await?;
        if count == 0 {
            return Ok(None);
        }
        bytes.truncate(count);
        Ok::<_, io::Error>(Some((Frame::data(Bytes::from(bytes)), (reader, permit))))
    });
    BodyExt::map_err(StreamBody::new(frames), |error| Box::new(error) as BoxError).boxed()
}

fn has_no_transform(headers: &HeaderMap) -> bool {
    headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
}

fn select_encoding(
    headers: &HeaderMap,
    encodings: &[CompressionEncoding],
) -> Option<CompressionEncoding> {
    encodings
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(preference, encoding)| {
            quality(headers, encoding).map(|quality| (quality, usize::MAX - preference, encoding))
        })
        .max_by_key(|(quality, preference, _)| (*quality, *preference))
        .map(|(_, _, encoding)| encoding)
}

fn quality(headers: &HeaderMap, encoding: CompressionEncoding) -> Option<u16> {
    let wanted = match encoding {
        CompressionEncoding::Gzip => "gzip",
        CompressionEncoding::Brotli => "br",
    };
    let mut exact = None;
    let mut wildcard = None;
    for item in headers
        .get_all(ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
    {
        let mut parts = item.trim().split(';');
        let name = parts.next()?.trim();
        let mut q = 1_000;
        for parameter in parts {
            let (key, value) = parameter.trim().split_once('=')?;
            if !key.trim().eq_ignore_ascii_case("q") {
                return None;
            }
            q = parse_quality(value.trim())?;
        }
        if name.eq_ignore_ascii_case(wanted) {
            exact = Some(q);
        } else if name == "*" {
            wildcard = Some(q);
        }
    }
    exact.or(wildcard).filter(|quality| *quality > 0)
}

fn parse_quality(value: &str) -> Option<u16> {
    if value == "0" {
        return Some(0);
    }
    if value == "1" || value == "1.0" || value == "1.00" || value == "1.000" {
        return Some(1_000);
    }
    let digits = value.strip_prefix("0.")?;
    if digits.len() > 3 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    format!("{digits:0<3}").parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::RouteConfig;
    use http_body_util::{BodyExt, Full};
    use std::collections::BTreeMap;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn streams_gzip_and_skips_sensitive_or_unbounded_responses() {
        let config = config();
        let route = route();
        let limiters = build(&config, None);
        let request_headers = HeaderMap::from_iter([(
            ACCEPT_ENCODING,
            hyper::header::HeaderValue::from_static("br;q=0.4, gzip"),
        )]);
        let original = vec![b'a'; 2_048];
        let mut compressed_response = response(&original);
        apply(
            &limiters,
            &config,
            &route,
            RequestContext {
                method: &Method::GET,
                headers: &request_headers,
                authenticated: false,
                grpc: false,
                websocket: false,
            },
            &mut compressed_response,
        )
        .expect("compression");
        assert_eq!(compressed_response.headers()[CONTENT_ENCODING], "gzip");
        assert!(!compressed_response.headers().contains_key(CONTENT_LENGTH));
        let compressed = compressed_response
            .into_body()
            .collect()
            .await
            .expect("compressed body")
            .to_bytes();
        let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(&compressed[..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).await.expect("decode");
        assert_eq!(decoded, original);

        let mut authenticated = response(&original);
        apply(
            &limiters,
            &config,
            &route,
            RequestContext {
                method: &Method::GET,
                headers: &request_headers,
                authenticated: true,
                grpc: false,
                websocket: false,
            },
            &mut authenticated,
        )
        .expect("skip authenticated");
        assert!(!authenticated.headers().contains_key(CONTENT_ENCODING));

        let mut unknown_size = response(&original);
        unknown_size.headers_mut().remove(CONTENT_LENGTH);
        apply(
            &limiters,
            &config,
            &route,
            RequestContext {
                method: &Method::GET,
                headers: &request_headers,
                authenticated: false,
                grpc: false,
                websocket: false,
            },
            &mut unknown_size,
        )
        .expect("skip unknown size");
        assert!(!unknown_size.headers().contains_key(CONTENT_ENCODING));

        let held = Arc::clone(&limiters["compress"])
            .acquire_many_owned(2)
            .await
            .expect("permits");
        let mut saturated = response(&original);
        apply(
            &limiters,
            &config,
            &route,
            RequestContext {
                method: &Method::GET,
                headers: &request_headers,
                authenticated: false,
                grpc: false,
                websocket: false,
            },
            &mut saturated,
        )
        .expect("skip saturated encoder");
        assert!(!saturated.headers().contains_key(CONTENT_ENCODING));
        drop(held);
    }

    #[test]
    fn negotiation_honors_quality_and_explicit_rejection() {
        let headers = HeaderMap::from_iter([(
            ACCEPT_ENCODING,
            hyper::header::HeaderValue::from_static("gzip;q=0, br;q=0.5, *;q=1"),
        )]);
        assert_eq!(quality(&headers, CompressionEncoding::Gzip), None);
        assert_eq!(quality(&headers, CompressionEncoding::Brotli), Some(500));
        assert_eq!(parse_quality("0"), Some(0));
        assert_eq!(parse_quality("0.125"), Some(125));
        assert_eq!(parse_quality("1.001"), None);
    }

    fn response(body: &[u8]) -> Response<ResponseBody> {
        let mut response = Response::new(
            Full::new(Bytes::copy_from_slice(body))
                .map_err(|never| match never {})
                .boxed(),
        );
        response.headers_mut().insert(
            CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response.headers_mut().insert(
            CONTENT_LENGTH,
            hyper::header::HeaderValue::from_str(&body.len().to_string()).expect("length"),
        );
        response
    }

    fn config() -> Config {
        let mut config: Config = toml::from_str("schema_version = 1").expect("config");
        config.middlewares = BTreeMap::from([(
            "compress".into(),
            MiddlewareConfig::Compression {
                encodings: vec![CompressionEncoding::Brotli, CompressionEncoding::Gzip],
                content_types: vec!["text/plain".into()],
                min_bytes: 1_024,
                max_concurrent: 2,
                allow_authenticated: false,
            },
        )]);
        config
    }

    fn route() -> RouteConfig {
        RouteConfig {
            id: "route".into(),
            listeners: vec!["public".into()],
            hosts: vec![],
            paths: vec![],
            path_prefixes: vec![],
            methods: vec![],
            headers: vec![],
            default: true,
            priority: 0,
            middlewares: vec!["compress".into()],
            upstream_group: Some("app".into()),
        }
    }
}
