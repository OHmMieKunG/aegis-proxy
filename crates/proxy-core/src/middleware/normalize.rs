use std::net::IpAddr;

use aegisproxy_config::TrustedProxyConfig;
use hyper::header::{HeaderMap, HeaderValue};
use thiserror::Error;

const MAX_FORWARDED_ADDRESSES: usize = 33;
const MAX_REQUEST_ID_BYTES: usize = 64;
const FORWARDED_HEADERS: [&str; 8] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "x-request-id",
    "x-aegisproxy-user",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestContext {
    pub(crate) ip: IpAddr,
    pub(crate) request_id: String,
    pub(crate) principal: Option<String>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum NormalizeError {
    #[error("invalid trusted forwarding header")]
    InvalidForwarding,
    #[error("canonical forwarding header construction failed")]
    InvalidCanonicalHeader,
    #[error("operating system random source unavailable")]
    RandomUnavailable,
}

pub(crate) fn normalize_forwarding_headers(
    headers: &mut HeaderMap,
    peer: IpAddr,
    policy: &TrustedProxyConfig,
    scheme: &str,
    host: &str,
    port: u16,
) -> Result<RequestContext, NormalizeError> {
    let peer_is_trusted = trusted(peer, policy);
    let client_ip = if peer_is_trusted {
        trusted_client_ip(headers, peer, policy)?
    } else {
        peer
    };
    let request_id = match (peer_is_trusted, trusted_request_id(headers)) {
        (true, Some(request_id)) => request_id,
        _ => generate_request_id()?,
    };
    for name in FORWARDED_HEADERS {
        headers.remove(name);
    }
    let context = RequestContext {
        ip: client_ip,
        request_id,
        principal: None,
    };
    rebuild_proxy_headers(headers, &context, scheme, host, port)?;
    Ok(context)
}

pub(crate) fn rebuild_proxy_headers(
    headers: &mut HeaderMap,
    context: &RequestContext,
    scheme: &str,
    host: &str,
    port: u16,
) -> Result<(), NormalizeError> {
    insert(headers, "x-forwarded-for", &context.ip.to_string())?;
    insert(headers, "x-real-ip", &context.ip.to_string())?;
    insert(headers, "x-forwarded-host", host)?;
    insert(headers, "x-forwarded-proto", scheme)?;
    insert(headers, "x-forwarded-port", &port.to_string())?;
    insert(headers, "x-request-id", &context.request_id)?;
    if let Some(principal) = &context.principal {
        insert(headers, "x-aegisproxy-user", principal)?;
    }
    let forwarded_for = match context.ip {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("\"[{address}]\""),
    };
    insert(
        headers,
        "forwarded",
        &format!("for={forwarded_for};proto={scheme};host=\"{host}\""),
    )?;
    Ok(())
}

fn trusted_request_id(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all("x-request-id").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(value.to_owned())
}

fn generate_request_id() -> Result<String, NormalizeError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| NormalizeError::RandomUnavailable)?;
    let mut id = String::with_capacity(random.len() * 2);
    for byte in random {
        id.push(HEX[usize::from(byte >> 4)] as char);
        id.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(id)
}

fn trusted_client_ip(
    headers: &HeaderMap,
    peer: IpAddr,
    policy: &TrustedProxyConfig,
) -> Result<IpAddr, NormalizeError> {
    let mut values = headers.get_all("x-forwarded-for").iter();
    let Some(value) = values.next() else {
        return Ok(peer);
    };
    if values.next().is_some() {
        return Err(NormalizeError::InvalidForwarding);
    }
    let value = value
        .to_str()
        .map_err(|_| NormalizeError::InvalidForwarding)?;
    let addresses = value
        .split(',')
        .map(str::trim)
        .map(|value| {
            if value.is_empty() {
                return Err(NormalizeError::InvalidForwarding);
            }
            value
                .parse::<IpAddr>()
                .map_err(|_| NormalizeError::InvalidForwarding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if addresses.is_empty() || addresses.len() > MAX_FORWARDED_ADDRESSES {
        return Err(NormalizeError::InvalidForwarding);
    }

    let mut current = peer;
    for (followed, address) in addresses.into_iter().rev().enumerate() {
        if followed >= policy.trusted_hops || !trusted(current, policy) {
            break;
        }
        current = address;
    }
    Ok(current)
}

fn trusted(address: IpAddr, policy: &TrustedProxyConfig) -> bool {
    policy
        .cidrs
        .iter()
        .any(|network| network.contains(&address))
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), NormalizeError> {
    let value = HeaderValue::from_str(value).map_err(|_| NormalizeError::InvalidCanonicalHeader)?;
    headers.insert(name, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(hops: usize) -> TrustedProxyConfig {
        TrustedProxyConfig {
            cidrs: vec!["10.0.0.0/8".parse().expect("CIDR")],
            trusted_hops: hops,
        }
    }

    #[test]
    fn untrusted_peer_cannot_spoof_client_identity() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.10"));
        headers.insert(
            "x-request-id",
            HeaderValue::from_static("client-controlled"),
        );
        let identity = normalize_forwarding_headers(
            &mut headers,
            "203.0.113.5".parse().expect("IP"),
            &policy(1),
            "https",
            "example.test",
            443,
        )
        .expect("normalize");
        assert_eq!(identity.ip, "203.0.113.5".parse::<IpAddr>().expect("IP"));
        assert_eq!(headers["x-forwarded-for"], "203.0.113.5");
        assert_eq!(headers["x-request-id"].as_bytes().len(), 32);
        assert_ne!(headers["x-request-id"], "client-controlled");
    }

    #[test]
    fn trusted_chain_is_scanned_right_to_left_until_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.9, 10.0.0.2"),
        );
        let identity = normalize_forwarding_headers(
            &mut headers,
            "10.0.0.3".parse().expect("IP"),
            &policy(2),
            "http",
            "example.test",
            8080,
        )
        .expect("normalize");
        assert_eq!(identity.ip, "198.51.100.9".parse::<IpAddr>().expect("IP"));
        assert_eq!(headers["x-forwarded-for"], "198.51.100.9");
        assert_eq!(headers["x-forwarded-proto"], "http");
        assert_eq!(headers["x-forwarded-port"], "8080");
    }

    #[test]
    fn trusted_request_id_is_bounded_and_validated() {
        for (value, accepted) in [
            ("edge-Request_123.4", true),
            ("contains space", false),
            ("", false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-request-id",
                HeaderValue::from_str(value).expect("header"),
            );
            let context = normalize_forwarding_headers(
                &mut headers,
                "10.0.0.3".parse().expect("IP"),
                &policy(1),
                "https",
                "example.test",
                443,
            )
            .expect("normalize");
            assert_eq!(context.request_id == value, accepted);
            assert_eq!(headers["x-request-id"], context.request_id);
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-request-id",
            HeaderValue::from_str(&"a".repeat(MAX_REQUEST_ID_BYTES + 1)).expect("header"),
        );
        let context = normalize_forwarding_headers(
            &mut headers,
            "10.0.0.3".parse().expect("IP"),
            &policy(1),
            "https",
            "example.test",
            443,
        )
        .expect("normalize");
        assert_eq!(context.request_id.len(), 32);

        let mut headers = HeaderMap::new();
        headers.append("x-request-id", HeaderValue::from_static("first"));
        headers.append("x-request-id", HeaderValue::from_static("second"));
        let context = normalize_forwarding_headers(
            &mut headers,
            "10.0.0.3".parse().expect("IP"),
            &policy(1),
            "https",
            "example.test",
            443,
        )
        .expect("normalize");
        assert_eq!(context.request_id.len(), 32);
    }

    #[test]
    fn malformed_or_excess_trusted_chain_fails_closed() {
        for value in ["", "not-an-ip", "192.0.2.1,,10.0.0.2"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(value).expect("header"),
            );
            assert_eq!(
                normalize_forwarding_headers(
                    &mut headers,
                    "10.0.0.3".parse().expect("IP"),
                    &policy(2),
                    "https",
                    "example.test",
                    443,
                ),
                Err(NormalizeError::InvalidForwarding)
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&vec!["10.0.0.2"; MAX_FORWARDED_ADDRESSES + 1].join(","))
                .expect("header"),
        );
        assert_eq!(
            normalize_forwarding_headers(
                &mut headers,
                "10.0.0.3".parse().expect("IP"),
                &policy(2),
                "https",
                "example.test",
                443,
            ),
            Err(NormalizeError::InvalidForwarding)
        );
    }
}
