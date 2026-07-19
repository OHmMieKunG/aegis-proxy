//! Feature-gated entry points for out-of-workspace fuzz targets.

use std::{net::IpAddr, str};

use aegisproxy_config::TrustedProxyConfig;
use hyper::{
    Request, Uri,
    header::{HeaderMap, HeaderName, HeaderValue},
};

/// Exercise host canonicalization with bounded UTF-8 input.
pub fn host(input: &[u8]) {
    if let Ok(value) = str::from_utf8(input) {
        let _ = super::route::canonical_host(value);
    }
}

/// Exercise request-path canonicalization with bounded URI input.
pub fn path(input: &[u8]) {
    let Ok(value) = str::from_utf8(input) else {
        return;
    };
    let Ok(uri) = value.parse::<Uri>() else {
        return;
    };
    let Ok(mut request) = Request::builder().uri(uri).body(()) else {
        return;
    };
    let _ = super::route::canonicalize_request_path(&mut request, 2_048);
}

/// Exercise hop-by-hop stripping and HTTP framing checks.
pub fn headers(input: &[u8]) {
    let mut headers = HeaderMap::new();
    let mut fields = input.split(|byte| *byte == 0).take(128);
    while let (Some(name), Some(value)) = (fields.next(), fields.next()) {
        let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
        else {
            continue;
        };
        headers.append(name, value);
    }
    let Ok(request) = Request::builder()
        .uri("/")
        .header("host", "example.test")
        .body(())
    else {
        return;
    };
    let mut request = request;
    *request.headers_mut() = headers.clone();
    let _ = super::reject_unsafe_request_target(&request);
    super::strip_hop_by_hop_headers(&mut headers, false, false);
}

/// Exercise trusted forwarding-chain and request-ID parsing.
pub fn forwarded(input: &[u8]) {
    let Ok(value) = HeaderValue::from_bytes(input) else {
        return;
    };
    let Ok(cidr) = "10.0.0.0/8".parse() else {
        return;
    };
    let Ok(peer) = "10.0.0.1".parse::<IpAddr>() else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", value.clone());
    headers.insert("x-request-id", value);
    let policy = TrustedProxyConfig {
        cidrs: vec![cidr],
        trusted_hops: 8,
    };
    let _ = super::middleware::normalize::normalize_forwarding_headers(
        &mut headers,
        peer,
        &policy,
        "https",
        "example.test",
        443,
    );
}
