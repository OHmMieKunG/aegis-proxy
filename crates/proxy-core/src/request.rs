use super::*;

pub(crate) fn is_idempotent_retry_method(method: &hyper::Method) -> bool {
    matches!(
        *method,
        hyper::Method::GET
            | hyper::Method::HEAD
            | hyper::Method::OPTIONS
            | hyper::Method::PUT
            | hyper::Method::DELETE
    )
}

pub(crate) fn is_grpc_content_type(value: &[u8]) -> bool {
    value
        .get(..b"application/grpc".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"application/grpc"))
}

pub(crate) fn upstream_uri(
    endpoint: &EndpointConfig,
    request_path: &str,
    query: Option<&str>,
) -> Option<Uri> {
    let mut uri = endpoint.url.clone();
    let base_path = endpoint.url.path().trim_end_matches('/');
    let joined_path = if base_path.is_empty() {
        request_path.to_owned()
    } else if request_path == "/" {
        format!("{base_path}/")
    } else {
        format!("{base_path}/{}", request_path.trim_start_matches('/'))
    };
    uri.set_path(&joined_path);
    uri.set_query(query);
    uri.as_str().parse().ok()
}

pub(crate) fn reject_unsafe_request_target<B>(request: &Request<B>) -> Option<StatusCode> {
    let http2 = request.version() == hyper::Version::HTTP_2;
    if request.method() == hyper::Method::CONNECT {
        return Some(StatusCode::BAD_REQUEST);
    }
    if (!http2 && (request.uri().scheme().is_some() || request.uri().authority().is_some()))
        || (http2
            && (request.uri().scheme_str() != Some("https") || request.uri().authority().is_none()))
        || request_host(request).is_err()
    {
        return Some(StatusCode::BAD_REQUEST);
    }
    if http2
        && ["connection", "keep-alive", "proxy-connection", "upgrade"]
            .iter()
            .any(|name| request.headers().contains_key(*name))
    {
        return Some(StatusCode::BAD_REQUEST);
    }
    let invalid_http2_te = http2
        && (request.headers().get_all(hyper::header::TE).iter().count() > 1
            || request
                .headers()
                .get(hyper::header::TE)
                .is_some_and(|value| value.as_bytes() != b"trailers"));
    let content_lengths: Vec<&[u8]> = request
        .headers()
        .get_all(hyper::header::CONTENT_LENGTH)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let transfer_encodings: Vec<&str> = request
        .headers()
        .get_all(hyper::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    if invalid_http2_te
        || (http2 && !transfer_encodings.is_empty())
        || (!content_lengths.is_empty() && !transfer_encodings.is_empty())
        || content_lengths.len() > 1
        || transfer_encodings.len() > 1
        || transfer_encodings
            .first()
            .is_some_and(|value| !value.eq_ignore_ascii_case("chunked"))
    {
        return Some(StatusCode::BAD_REQUEST);
    }
    None
}

pub(crate) fn is_websocket_upgrade<B>(request: &Request<B>) -> bool {
    request.method() == hyper::Method::GET
        && request
            .headers()
            .get(UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && request
            .headers()
            .get_all(CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

pub(crate) fn strip_hop_by_hop_headers(
    headers: &mut hyper::HeaderMap,
    preserve_upgrade: bool,
    preserve_te_trailers: bool,
) {
    let connection_tokens: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    for token in connection_tokens {
        if !preserve_upgrade || token != "upgrade" {
            headers.remove(token);
        }
    }
    for name in [
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "trailer",
        "te",
    ] {
        headers.remove(name);
    }
    if preserve_upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
    if preserve_te_trailers {
        headers.insert(hyper::header::TE, HeaderValue::from_static("trailers"));
    }
}

/// Create a bounded error response.
pub fn error_response(status: StatusCode, message: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(full_body(message.as_bytes()))
        .unwrap_or_else(|_| Response::new(full_body(b"proxy error\n")))
}

pub(crate) fn http_challenge_response<B>(
    registry: &HttpChallengeRegistry,
    listener_id: &str,
    request: &Request<B>,
) -> Result<Option<Response<ResponseBody>>, HttpChallengeError> {
    let Ok(identifier) = request_host(request) else {
        return Ok(None);
    };
    let Some(body) =
        registry.response_for_request(listener_id, &identifier, request.uri().path())?
    else {
        return Ok(None);
    };
    if request.method() != hyper::Method::GET {
        return Ok(Some(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "ACME challenge requires GET\n",
        )));
    }
    let mut response = Response::new(full_body(body.as_ref()));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(Some(response))
}

pub(crate) fn full_body(bytes: &[u8]) -> ResponseBody {
    Full::new(bytes::Bytes::copy_from_slice(bytes))
        .map_err(|never: Infallible| match never {})
        .boxed()
}
