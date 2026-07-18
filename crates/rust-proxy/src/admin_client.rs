//! Bounded HTTP/1 client for the private Unix administration socket.

use std::{error::Error, fmt, path::Path};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, client::conn::http1, header::HOST};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

type BoxError = Box<dyn Error + Send + Sync>;

pub(crate) struct AdminRequest {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) if_match: Option<String>,
    pub(crate) content_type: Option<&'static str>,
    pub(crate) bearer: Option<Zeroizing<String>>,
    pub(crate) body: Vec<u8>,
}

impl fmt::Debug for AdminRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("if_match", &self.if_match)
            .field("content_type", &self.content_type)
            .field("bearer", &self.bearer.as_ref().map(|_| "[REDACTED]"))
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct AdminResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: Bytes,
}

pub(crate) async fn request(
    socket: &Path,
    request: AdminRequest,
) -> Result<AdminResponse, BoxError> {
    let stream = UnixStream::connect(socket).await?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "administrative client connection ended");
        }
    });
    let mut builder = Request::builder()
        .method(request.method)
        .uri(request.path)
        .header(HOST, "localhost");
    if let Some(revision) = request.if_match {
        builder = builder.header("if-match", format!("\"{revision}\""));
    }
    if let Some(content_type) = request.content_type {
        builder = builder.header("content-type", content_type);
    }
    if let Some(token) = request.bearer {
        let mut authorization = Zeroizing::new(String::with_capacity(7 + token.len()));
        authorization.push_str("Bearer ");
        authorization.push_str(&token);
        builder = builder.header("authorization", authorization.as_str());
        authorization.zeroize();
    }
    let response = sender
        .send_request(builder.body(Full::new(Bytes::from(request.body)))?)
        .await?;
    let status = response.status();
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await?
        .to_bytes();
    Ok(AdminResponse { status, body })
}
