#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! TLS identity loading, certificate selection, and server configuration.

mod acceptor;
mod client;
mod selector;
mod store;

pub use acceptor::{server_config, tls_acceptor};
pub use client::client_config;
pub use selector::CertificateResolver;
pub use store::{Identity, load_identity};
pub use tokio_rustls::{TlsAcceptor, server::TlsStream};

use thiserror::Error;

/// TLS preparation failure. Secret contents are never included.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Secret reference or source failure.
    #[error("could not load TLS secret: {0}")]
    Secret(#[from] aegisproxy_secrets::SecretError),
    /// PEM input was malformed or contained an unexpected item.
    #[error("invalid TLS PEM: {0}")]
    Pem(String),
    /// Certificate metadata, chain, name, or validity was rejected.
    #[error("invalid TLS certificate: {0}")]
    Certificate(String),
    /// Private key was missing, unsupported, or did not match.
    #[error("invalid TLS private key")]
    PrivateKey,
    /// More than one identity claimed the same SNI name.
    #[error("duplicate TLS identity for {0}")]
    DuplicateName(String),
    /// Rustls server policy construction failed.
    #[error("invalid TLS server policy: {0}")]
    Policy(String),
    /// An upstream trust store was empty or rejected a certificate.
    #[error("invalid upstream TLS trust store: {0}")]
    TrustStore(String),
}
