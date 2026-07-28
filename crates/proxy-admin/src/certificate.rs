//! Secret-free typed ownership metadata for existing certificate identities.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use aegisproxy_config::{Config, validate};
use thiserror::Error;

use crate::{ApiObject, CertificateSpec, ManagedHttpsPolicy, ObjectId};

/// Validated metadata allowed to influence managed-HTTPS selection.
#[derive(Clone, Eq, PartialEq)]
pub struct CertificateMetadata {
    owner_id: ObjectId,
    shared_with: BTreeSet<ObjectId>,
    enabled: bool,
    policy: ManagedHttpsPolicy,
    hosts: Vec<String>,
}

impl fmt::Debug for CertificateMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateMetadata")
            .field("enabled", &self.enabled)
            .field("shared_owner_count", &self.shared_with.len())
            .field("host_count", &self.hosts.len())
            .finish()
    }
}

/// Stable fail-closed certificate metadata error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CertificateCompileError {
    /// Typed ownership shape is invalid.
    #[error("certificate ownership contract is invalid")]
    InvalidContract,
    /// Canonical configuration is invalid.
    #[error("certificate configuration is invalid")]
    InvalidConfiguration,
    /// Referenced certificate does not exist.
    #[error("certificate identity is unavailable")]
    MissingCertificate,
    /// Certificate is not attached to exactly one HTTPS listener.
    #[error("certificate listener policy is unavailable")]
    InvalidListener,
    /// No enabled certificate covers the requested domain.
    #[error("managed HTTPS certificate is unavailable")]
    DomainNotCovered,
    /// Covering certificate exists but owner may not use it.
    #[error("managed HTTPS certificate is unauthorized")]
    Unauthorized,
    /// More than one authorized certificate could serve the domain.
    #[error("managed HTTPS certificate selection is ambiguous")]
    Ambiguous,
}

/// Compile one secret-free ownership object against canonical certificate configuration.
pub fn compile_certificate_metadata(
    object: &ApiObject<CertificateSpec>,
    config: &Config,
) -> Result<CertificateMetadata, CertificateCompileError> {
    validate(config).map_err(|_| CertificateCompileError::InvalidConfiguration)?;
    object
        .spec
        .validate_shape(&object.metadata.owner_id)
        .map_err(|_| CertificateCompileError::InvalidContract)?;
    let certificate_id = object.spec.certificate_ref.as_str();
    let hosts = config
        .certificates
        .iter()
        .find(|certificate| certificate.id == certificate_id)
        .map(|certificate| certificate.hosts.clone())
        .or_else(|| {
            config
                .acme
                .certificates
                .iter()
                .find(|certificate| certificate.id == certificate_id)
                .map(|certificate| certificate.hosts.clone())
        })
        .ok_or(CertificateCompileError::MissingCertificate)?;
    let mut listeners = config.listeners.iter().filter(|listener| {
        listener.protocol == "https" && listener.certificates.iter().any(|id| id == certificate_id)
    });
    let listener_id = listeners
        .next()
        .map(|listener| listener.id.clone())
        .ok_or(CertificateCompileError::InvalidListener)?;
    if listeners.next().is_some() {
        return Err(CertificateCompileError::InvalidListener);
    }
    let mut hosts = hosts;
    hosts.sort_unstable();
    Ok(CertificateMetadata {
        owner_id: object.metadata.owner_id.clone(),
        shared_with: object.spec.shared_with.iter().cloned().collect(),
        enabled: object.spec.enabled,
        policy: ManagedHttpsPolicy {
            listener_id,
            certificate_id: certificate_id.to_owned(),
        },
        hosts,
    })
}

/// Select one authorized managed-HTTPS policy without resolving certificate secrets.
pub fn select_managed_https_policy(
    certificates: &BTreeMap<ObjectId, CertificateMetadata>,
    owner_id: &ObjectId,
    domain: &str,
) -> Result<ManagedHttpsPolicy, CertificateCompileError> {
    let covering = certificates
        .values()
        .filter(|certificate| {
            certificate.enabled
                && certificate
                    .hosts
                    .iter()
                    .any(|host| host_matches(host, domain))
        })
        .collect::<Vec<_>>();
    if covering.is_empty() {
        return Err(CertificateCompileError::DomainNotCovered);
    }
    let permitted = covering
        .into_iter()
        .filter(|certificate| {
            &certificate.owner_id == owner_id || certificate.shared_with.contains(owner_id)
        })
        .collect::<Vec<_>>();
    match permitted.as_slice() {
        [] => Err(CertificateCompileError::Unauthorized),
        [certificate] => Ok(certificate.policy.clone()),
        _ => Err(CertificateCompileError::Ambiguous),
    }
}

fn host_matches(configured: &str, domain: &str) -> bool {
    configured == domain
        || configured
            .strip_prefix("*.")
            .and_then(|suffix| domain.strip_suffix(suffix))
            .is_some_and(|prefix| {
                prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::{CertificateConfig, ListenerConfig};

    fn config() -> Config {
        let mut config =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("base config");
        config.tls.identity = Some("env://TEST_AGE_IDENTITY".into());
        config.certificates.push(CertificateConfig {
            id: "managed-public".into(),
            hosts: vec!["example.test".into(), "*.apps.example.test".into()],
            certificate_chain: "file:///test/cert.pem".into(),
            private_key: "file:///test/key.age".into(),
        });
        config.listeners.push(ListenerConfig {
            id: "secure".into(),
            bind: "127.0.0.1:8443".parse().expect("bind"),
            protocol: "https".into(),
            certificates: vec!["managed-public".into()],
        });
        validate(&config).expect("valid config");
        config
    }

    fn object(owner: &str, shared_with: &[&str]) -> ApiObject<CertificateSpec> {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "public-cert", "owner_id": owner},
            "spec": {
                "enabled": true,
                "shared_with": shared_with,
                "certificate_ref": "managed-public"
            }
        }))
        .expect("certificate object")
    }

    #[test]
    fn compiles_secret_free_metadata_and_selects_exact_or_wildcard() {
        let config = config();
        let object = object("alice", &["bob"]);
        let metadata = compile_certificate_metadata(&object, &config).expect("metadata");
        let certificates = BTreeMap::from([(object.metadata.id.clone(), metadata.clone())]);
        for (owner, domain) in [("alice", "example.test"), ("bob", "one.apps.example.test")] {
            assert_eq!(
                select_managed_https_policy(&certificates, &owner.parse().expect("owner"), domain)
                    .expect("policy"),
                metadata.policy
            );
        }
        assert_eq!(
            select_managed_https_policy(
                &certificates,
                &"mallory".parse().expect("owner"),
                "example.test"
            ),
            Err(CertificateCompileError::Unauthorized)
        );
        assert!(!format!("{metadata:?}").contains("file:///"));
    }

    #[test]
    fn rejects_missing_ambiguous_and_cross_label_certificate_policy() {
        let config = config();
        let object = object("alice", &[]);
        let metadata = compile_certificate_metadata(&object, &config).expect("metadata");
        let mut certificates = BTreeMap::from([(object.metadata.id.clone(), metadata.clone())]);
        assert_eq!(
            select_managed_https_policy(
                &certificates,
                &"alice".parse().expect("owner"),
                "two.deep.apps.example.test"
            ),
            Err(CertificateCompileError::DomainNotCovered)
        );
        certificates.insert("other-cert".parse().expect("ID"), metadata);
        assert_eq!(
            select_managed_https_policy(
                &certificates,
                &"alice".parse().expect("owner"),
                "example.test"
            ),
            Err(CertificateCompileError::Ambiguous)
        );
        let mut missing = object;
        missing.spec.certificate_ref = "missing-cert".parse().expect("reference");
        assert_eq!(
            compile_certificate_metadata(&missing, &config),
            Err(CertificateCompileError::MissingCertificate)
        );
    }
}
