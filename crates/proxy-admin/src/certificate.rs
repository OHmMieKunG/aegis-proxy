//! Secret-free typed ownership metadata for existing certificate identities.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
};

use aegisproxy_config::{Config, validate};
use thiserror::Error;

use crate::{
    ApiObject, CertificateSpec, ManagedHttpsPolicy, ObjectId,
    typed_store::{StoredObject, TypedStore, TypedStoreError},
};

const MAX_CERTIFICATES: usize = 1_024;
const MAX_STORE_BYTES: u64 = 1024 * 1024;

/// One persisted Certificate-object generation.
pub type StoredCertificate = StoredObject<CertificateSpec>;

/// Durable Certificate-object storage failure.
pub type CertificateStoreError = TypedStoreError;

/// Exclusively owned durable Certificate-object store.
#[derive(Debug)]
pub struct CertificateStore(TypedStore<CertificateSpec>);

impl CertificateStore {
    /// Open and strictly validate a private Certificate-object file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CertificateStoreError> {
        TypedStore::open(
            path,
            ".certificate-objects-owner.lock",
            MAX_CERTIFICATES,
            MAX_STORE_BYTES,
            canonicalize_certificate,
        )
        .map(Self)
    }

    /// Create one globally unique owned Certificate object.
    pub fn create(
        &self,
        object: ApiObject<CertificateSpec>,
    ) -> Result<StoredCertificate, CertificateStoreError> {
        self.0.create(object)
    }

    /// Replace one owned Certificate object at its exact generation.
    pub fn update(
        &self,
        object: ApiObject<CertificateSpec>,
        expected_generation: u64,
    ) -> Result<StoredCertificate, CertificateStoreError> {
        self.0.update(object, expected_generation)
    }

    /// Delete one owned Certificate object at its exact generation.
    pub fn delete(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredCertificate, CertificateStoreError> {
        self.0.delete(owner_id, object_id, expected_generation)
    }

    /// Return one Certificate only within the requested owner namespace.
    #[must_use]
    pub fn get(&self, owner_id: &ObjectId, object_id: &ObjectId) -> Option<StoredCertificate> {
        self.0.get(owner_id, object_id)
    }

    /// Return stable Certificate-ID ordering within one owner namespace.
    #[must_use]
    pub fn list(&self, owner_id: &ObjectId) -> Vec<StoredCertificate> {
        self.0.list(owner_id)
    }

    /// Compile all stored Certificate objects into selection metadata.
    pub fn metadata(
        &self,
        config: &Config,
    ) -> Result<BTreeMap<ObjectId, CertificateMetadata>, CertificateStoreError> {
        self.0
            .all()?
            .into_iter()
            .map(|stored| {
                compile_certificate_metadata(&stored.object, config)
                    .map(|metadata| (stored.object.metadata.id, metadata))
                    .map_err(|_| CertificateStoreError::Invalid)
            })
            .collect()
    }
}

fn canonicalize_certificate(object: &mut ApiObject<CertificateSpec>) -> bool {
    if object
        .spec
        .validate_shape(&object.metadata.owner_id)
        .is_err()
    {
        return false;
    }
    object.spec.shared_with.sort_unstable();
    true
}

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
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NONCE: AtomicU64 = AtomicU64::new(0);

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

    #[test]
    fn store_is_private_canonical_owner_scoped_and_generation_checked() {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-certificate-store-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let path = root.join("admin/certificate-objects.json");
        let store = CertificateStore::open(&path).expect("store");
        let mut certificate = object("alice", &["carol", "bob"]);
        let stored = store.create(certificate.clone()).expect("create");
        assert_eq!(stored.generation, 1);
        assert_eq!(
            stored
                .object
                .spec
                .shared_with
                .iter()
                .map(ObjectId::as_str)
                .collect::<Vec<_>>(),
            ["bob", "carol"]
        );
        let alice = "alice".parse().expect("owner");
        let bob = "bob".parse().expect("owner");
        let id = "public-cert".parse().expect("ID");
        assert!(store.get(&bob, &id).is_none());
        certificate.spec.enabled = false;
        assert_eq!(store.update(certificate, 1).expect("update").generation, 2);
        assert!(matches!(
            store.delete(&alice, &id, 1),
            Err(CertificateStoreError::Conflict)
        ));
        drop(store);
        let reopened = CertificateStore::open(&path).expect("reopen");
        assert_eq!(reopened.list(&alice).len(), 1);
        reopened.delete(&alice, &id, 2).expect("delete");
        drop(reopened);
        assert!(
            CertificateStore::open(&path)
                .expect("reopen deleted")
                .list(&alice)
                .is_empty()
        );
        fs::remove_dir_all(root).expect("cleanup");
    }
}
