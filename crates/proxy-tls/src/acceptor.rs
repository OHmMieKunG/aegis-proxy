use std::sync::Arc;

use rustls::{ServerConfig, crypto::aws_lc_rs, version};
use tokio_rustls::TlsAcceptor;

use crate::{CertificateResolver, TlsError, acme::tls_alpn_protocol};

/// Build an explicit Rustls server policy with isolated ACME, HTTP/2, and HTTP/1.1 ALPN.
pub fn server_config(
    resolver: CertificateResolver,
    minimum_version: &str,
) -> Result<Arc<ServerConfig>, TlsError> {
    let versions = match minimum_version {
        "1.2" => vec![&version::TLS13, &version::TLS12],
        "1.3" => vec![&version::TLS13],
        _ => {
            return Err(TlsError::Policy(
                "minimum version must be 1.2 or 1.3".into(),
            ));
        }
    };
    let mut config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&versions)
        .map_err(|error| TlsError::Policy(error.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![
        tls_alpn_protocol().to_vec(),
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
    Ok(Arc::new(config))
}

/// Build a Tokio TLS acceptor from the validated identity resolver.
pub fn tls_acceptor(
    resolver: CertificateResolver,
    minimum_version: &str,
) -> Result<TlsAcceptor, TlsError> {
    server_config(resolver, minimum_version).map(TlsAcceptor::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsupported_minimum_version() {
        let resolver = CertificateResolver::new(&[]).expect("empty resolver");
        assert!(server_config(resolver, "1.1").is_err());
    }

    #[test]
    fn advertises_acme_alpn_before_application_protocols() {
        let resolver = CertificateResolver::new(&[]).expect("empty resolver");
        let config = server_config(resolver, "1.3").expect("server config");
        assert_eq!(
            config.alpn_protocols,
            [b"acme-tls/1".as_slice(), b"h2", b"http/1.1"]
        );
    }
}
