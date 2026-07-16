use std::sync::Arc;

use aegisproxy_secrets::SecretRef;
use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs, version};

use crate::{TlsError, store::parse_certificates};

const MAX_CA_BUNDLE_BYTES: usize = 1024 * 1024;

/// Build an upstream client policy using public roots or one explicit CA bundle.
pub fn client_config(ca_bundle: Option<&str>) -> Result<ClientConfig, TlsError> {
    let roots = match ca_bundle {
        Some(reference) => {
            let pem = SecretRef::parse(reference)?.resolve(MAX_CA_BUNDLE_BYTES)?;
            let mut roots = RootCertStore::empty();
            for certificate in parse_certificates(pem.as_ref())? {
                roots
                    .add(certificate)
                    .map_err(|error| TlsError::TrustStore(error.to_string()))?;
            }
            roots
        }
        None => RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    };
    ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .map_err(|error| TlsError::Policy(error.to_string()))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn accepts_explicit_ca_and_rejects_non_certificate_pem() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["upstream.test".into()]).expect("generate CA");
        let base = std::env::temp_dir().join(format!(
            "aegisproxy-ca-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&base, generated.cert.pem()).expect("write CA");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o600)).expect("secure CA");
        }
        assert!(client_config(Some(&format!("file://{}", base.display()))).is_ok());
        fs::write(&base, generated.signing_key.serialize_pem()).expect("write key");
        assert!(client_config(Some(&format!("file://{}", base.display()))).is_err());
        fs::remove_file(base).expect("remove CA");
    }
}
