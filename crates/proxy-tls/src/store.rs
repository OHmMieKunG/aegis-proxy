use std::{io::Cursor, sync::Arc};

use aegisproxy_secrets::SecretRef;
use rustls::{
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    sign::CertifiedKey,
};
use rustls_pemfile::Item;
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

use crate::TlsError;

const MAX_CERTIFICATE_PEM_BYTES: usize = 1024 * 1024;
const MAX_PRIVATE_KEY_PEM_BYTES: usize = 256 * 1024;
const MAX_CHAIN_CERTIFICATES: usize = 16;

/// A validated certificate identity ready for SNI selection.
#[derive(Clone)]
pub struct Identity {
    id: String,
    hosts: Vec<String>,
    key: Arc<CertifiedKey>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("id", &self.id)
            .field("hosts", &self.hosts)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Identity {
    pub(crate) fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub(crate) fn key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.key)
    }
}

/// Resolve, parse, and validate one configured certificate identity.
pub fn load_identity(
    id: String,
    hosts: Vec<String>,
    certificate_chain: &SecretRef,
    private_key: &SecretRef,
) -> Result<Identity, TlsError> {
    let certificate_chain = certificate_chain.resolve(MAX_CERTIFICATE_PEM_BYTES)?;
    let private_key = private_key.resolve(MAX_PRIVATE_KEY_PEM_BYTES)?;
    identity_from_pem(id, hosts, certificate_chain.as_ref(), private_key.as_ref())
}

pub(crate) fn identity_from_pem(
    id: String,
    hosts: Vec<String>,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<Identity, TlsError> {
    let certificates = parse_certificates(certificate_pem)?;
    let private_key = parse_private_key(private_key_pem)?;
    let provider = aws_lc_rs::default_provider();
    validate_certificate(&certificates, &hosts, &provider)?;
    let key = CertifiedKey::from_der(certificates, private_key, &provider)
        .map_err(|_| TlsError::PrivateKey)?;
    Ok(Identity {
        id,
        hosts,
        key: Arc::new(key),
    })
}

fn parse_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut certificates = Vec::new();
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        match item.map_err(|error| TlsError::Pem(error.to_string()))? {
            Item::X509Certificate(certificate) => certificates.push(certificate),
            _ => {
                return Err(TlsError::Pem(
                    "certificate source contains a non-certificate item".into(),
                ));
            }
        }
        if certificates.len() > MAX_CHAIN_CERTIFICATES {
            return Err(TlsError::Certificate(format!(
                "chain exceeds {MAX_CHAIN_CERTIFICATES} certificates"
            )));
        }
    }
    if certificates.is_empty() {
        return Err(TlsError::Certificate("chain is empty".into()));
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut key = None;
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        let candidate = match item.map_err(|error| TlsError::Pem(error.to_string()))? {
            Item::Pkcs1Key(value) => PrivateKeyDer::from(value),
            Item::Pkcs8Key(value) => PrivateKeyDer::from(value),
            Item::Sec1Key(value) => PrivateKeyDer::from(value),
            _ => {
                return Err(TlsError::Pem(
                    "private-key source contains a non-key item".into(),
                ));
            }
        };
        if key.replace(candidate).is_some() {
            return Err(TlsError::PrivateKey);
        }
    }
    key.ok_or(TlsError::PrivateKey)
}

fn validate_certificate(
    certificates: &[CertificateDer<'static>],
    hosts: &[String],
    provider: &CryptoProvider,
) -> Result<(), TlsError> {
    let leaf = EndEntityCert::try_from(&certificates[0])
        .map_err(|error| TlsError::Certificate(error.to_string()))?;
    let anchor_certificate = certificates
        .last()
        .ok_or_else(|| TlsError::Certificate("chain is empty".into()))?;
    let anchor = anchor_from_trusted_cert(anchor_certificate)
        .map_err(|error| TlsError::Certificate(error.to_string()))?;
    let intermediates = if certificates.len() > 2 {
        &certificates[1..certificates.len() - 1]
    } else {
        &[]
    };
    leaf.verify_for_usage(
        provider.signature_verification_algorithms.all,
        &[anchor],
        intermediates,
        UnixTime::now(),
        KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|error| TlsError::Certificate(error.to_string()))?;

    for configured_host in hosts {
        let probe = configured_host
            .strip_prefix("*.")
            .map(|suffix| format!("a.{suffix}"))
            .unwrap_or_else(|| configured_host.clone());
        let name = ServerName::try_from(probe)
            .map_err(|error| TlsError::Certificate(error.to_string()))?;
        leaf.verify_is_valid_for_subject_name(&name)
            .map_err(|error| TlsError::Certificate(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, date_time_ymd, generate_simple_self_signed};

    fn test_identity(hosts: Vec<String>) -> Result<Identity, TlsError> {
        let generated = generate_simple_self_signed(vec!["example.test".into()])
            .expect("generate test identity");
        identity_from_pem(
            "site".into(),
            hosts,
            generated.cert.pem().as_bytes(),
            generated.signing_key.serialize_pem().as_bytes(),
        )
    }

    #[test]
    fn accepts_matching_certificate_and_key() {
        assert!(test_identity(vec!["example.test".into()]).is_ok());
    }

    #[test]
    fn rejects_wrong_hostname() {
        assert!(test_identity(vec!["other.test".into()]).is_err());
    }

    #[test]
    fn rejects_mismatched_private_key() {
        let certificate =
            generate_simple_self_signed(vec!["example.test".into()]).expect("generate certificate");
        let other = generate_simple_self_signed(vec!["example.test".into()]).expect("generate key");
        let result = identity_from_pem(
            "site".into(),
            vec!["example.test".into()],
            certificate.cert.pem().as_bytes(),
            other.signing_key.serialize_pem().as_bytes(),
        );
        assert!(matches!(result, Err(TlsError::PrivateKey)));
    }

    #[test]
    fn rejects_expired_certificate() {
        let mut params =
            CertificateParams::new(vec!["example.test".into()]).expect("certificate parameters");
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
        let key = KeyPair::generate().expect("generate key");
        let certificate = params.self_signed(&key).expect("sign certificate");
        let result = identity_from_pem(
            "site".into(),
            vec!["example.test".into()],
            certificate.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        );
        assert!(matches!(result, Err(TlsError::Certificate(_))));
    }

    #[test]
    fn identity_debug_is_redacted() {
        let identity = test_identity(vec!["example.test".into()]).expect("valid identity");
        let output = format!("{identity:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("PRIVATE KEY"));
    }
}
