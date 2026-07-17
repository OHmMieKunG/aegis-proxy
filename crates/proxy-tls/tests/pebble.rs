#![forbid(unsafe_code)]

use std::{
    error::Error,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    time::Duration,
};

use aegisproxy_tls::acme::{
    AcmeAccountCreateRequest, AcmeChallengeKind, AcmeChallengeMaterial, AcmeClient,
    AcmeOrderRequest,
};
use serde_json::{Value, json};
use url::Url;

const DIRECTORY: &str = "https://localhost:14000/dir";
const MANAGEMENT: &str = "127.0.0.1:8055";
const POLL_TIMEOUT: Duration = Duration::from_secs(60);
const MANAGEMENT_RESPONSE_LIMIT: u64 = 64 * 1024;
const RENEWAL_CYCLES: usize = 3;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
#[ignore = "requires tests/pebble/compose.yml"]
fn issues_with_all_supported_challenges() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let directory = Url::parse(DIRECTORY)?;
        let ca_reference = test_ca_reference()?;
        aegisproxy_tls::client_config(Some(&ca_reference))?;
        let (created, credentials) = AcmeClient::create(
            AcmeAccountCreateRequest {
                directory_url: &directory,
                account_email: Some("acme-test@aegis.invalid"),
                terms_of_service_agreed: true,
                external_account: None,
            },
            Some(&ca_reference),
        )
        .await?;
        assert!(!created.account_id().is_empty());
        let client = AcmeClient::restore(credentials.as_slice(), Some(&ca_reference)).await?;

        for _ in 0..RENEWAL_CYCLES {
            issue(&client, AcmeChallengeKind::Http01, "http.aegis.test").await?;
            issue(&client, AcmeChallengeKind::Dns01, "*.dns.aegis.test").await?;
            issue(&client, AcmeChallengeKind::TlsAlpn01, "tls-alpn.aegis.test").await?;
        }
        reject_invalid_http_challenge(&client).await
    })
}

async fn reject_invalid_http_challenge(client: &AcmeClient) -> TestResult {
    let names = vec!["invalid-http.aegis.test".to_owned()];
    let mut order = client
        .new_order(AcmeOrderRequest {
            identifiers: &names,
            challenge: AcmeChallengeKind::Http01,
            profile: None,
        })
        .await?;
    let material = order.prepare_challenges().await?;
    let item = material.first().ok_or("missing HTTP-01 challenge")?;
    management_post(
        "add-http01",
        &json!({ "token": item.token(), "content": "deliberately-invalid" }),
    )?;
    order.notify_challenges_ready().await?;
    let result = order.poll_ready(Duration::from_secs(10)).await;
    management_post("del-http01", &json!({ "token": item.token() }))?;
    assert!(
        result.is_err(),
        "Pebble accepted an invalid HTTP-01 response"
    );
    Ok(())
}

async fn issue(client: &AcmeClient, challenge: AcmeChallengeKind, name: &str) -> TestResult {
    let names = vec![name.to_owned()];
    let mut order = client
        .new_order(AcmeOrderRequest {
            identifiers: &names,
            challenge,
            profile: None,
        })
        .await?;
    let material = order.prepare_challenges().await?;
    let cleanup = provision(challenge, &material)?;
    let authorization = async {
        order.notify_challenges_ready().await?;
        order.poll_ready(POLL_TIMEOUT).await
    }
    .await;
    cleanup_challenges(&cleanup)?;
    authorization?;
    order.finalize().await?;
    let issued = order.poll_certificate(POLL_TIMEOUT).await?;
    issued.runtime_identity(format!("pebble-{challenge:?}"), names)?;
    Ok(())
}

#[derive(Debug)]
struct Cleanup {
    endpoint: &'static str,
    body: Value,
}

fn provision(
    challenge: AcmeChallengeKind,
    material: &[AcmeChallengeMaterial],
) -> TestResult<Vec<Cleanup>> {
    material
        .iter()
        .map(|item| match challenge {
            AcmeChallengeKind::Http01 => {
                management_post(
                    "add-http01",
                    &json!({
                        "token": item.token(),
                        "content": item.http_key_authorization().ok_or("missing HTTP-01 response")?,
                    }),
                )?;
                Ok(Cleanup {
                    endpoint: "del-http01",
                    body: json!({ "token": item.token() }),
                })
            }
            AcmeChallengeKind::Dns01 => {
                let host = format!(
                    "_acme-challenge.{}.",
                    item.identifier()
                        .strip_prefix("*.")
                        .unwrap_or(item.identifier())
                );
                management_post(
                    "set-txt",
                    &json!({
                        "host": host,
                        "value": item.dns_value().ok_or("missing DNS-01 response")?,
                    }),
                )?;
                Ok(Cleanup {
                    endpoint: "clear-txt",
                    body: json!({ "host": host }),
                })
            }
            AcmeChallengeKind::TlsAlpn01 => {
                management_post(
                    "add-tlsalpn01",
                    &json!({
                        "host": item.identifier(),
                        "content": item
                            .tls_alpn_key_authorization()
                            .ok_or("missing TLS-ALPN-01 response")?,
                    }),
                )?;
                Ok(Cleanup {
                    endpoint: "del-tlsalpn01",
                    body: json!({ "host": item.identifier() }),
                })
            }
        })
        .collect()
}

fn cleanup_challenges(cleanup: &[Cleanup]) -> TestResult {
    for item in cleanup.iter().rev() {
        management_post(item.endpoint, &item.body)?;
    }
    Ok(())
}

fn management_post(endpoint: &str, body: &Value) -> TestResult {
    let body = serde_json::to_vec(body)?;
    let mut stream = TcpStream::connect_timeout(&MANAGEMENT.parse()?, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "POST /{endpoint} HTTP/1.1\r\nHost: {MANAGEMENT}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let mut response = Vec::new();
    stream
        .take(MANAGEMENT_RESPONSE_LIMIT)
        .read_to_end(&mut response)?;
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if !status.starts_with(b"HTTP/1.1 200") {
        return Err(format!("challtestsrv rejected {endpoint}").into());
    }
    Ok(())
}

fn test_ca_reference() -> TestResult<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("pebble")
        .join("pebble.minica.pem")
        .canonicalize()?;
    let path = root.to_string_lossy();
    #[cfg(windows)]
    {
        let path = path
            .strip_prefix(r"\\?\")
            .unwrap_or(&path)
            .replace('\\', "/");
        Ok(format!("file:///{path}"))
    }
    #[cfg(not(windows))]
    Ok(format!("file://{path}"))
}
