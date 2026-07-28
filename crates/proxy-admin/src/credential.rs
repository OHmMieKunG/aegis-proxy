//! Encrypted, write-only Stored Credential lifecycle.

use std::{
    fmt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use aegisproxy_secrets::encrypt_age;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    ApiObject, ApiVersion, ObjectId, ObjectMetadata,
    typed_store::{StoredObject, TypedStore, TypedStoreError},
};

const MAX_CREDENTIALS: usize = 1_024;
const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;
const MAX_STORE_BYTES: u64 = 96 * 1024 * 1024;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialRecord {
    label: String,
    enabled: bool,
    expires_unix_secs: Option<u64>,
    ciphertext_base64: Option<String>,
    fingerprint: String,
    created_unix_secs: u64,
    updated_unix_secs: u64,
    revoked: bool,
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRecord")
            .field("label", &self.label)
            .field("enabled", &self.enabled)
            .field("expires_unix_secs", &self.expires_unix_secs)
            .field("fingerprint", &self.fingerprint)
            .field("created_unix_secs", &self.created_unix_secs)
            .field("updated_unix_secs", &self.updated_unix_secs)
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// Secret-free Stored Credential response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StoredCredential {
    /// Globally unique credential ID.
    pub id: ObjectId,
    /// Owning identity.
    pub owner_id: ObjectId,
    /// Object-local generation.
    pub generation: u64,
    /// Human-readable label.
    pub label: String,
    /// Whether resolution is permitted.
    pub enabled: bool,
    /// Optional expiry.
    pub expires_unix_secs: Option<u64>,
    /// SHA-256 fingerprint of the plaintext.
    pub fingerprint: String,
    /// Creation timestamp.
    pub created_unix_secs: u64,
    /// Last mutation timestamp.
    pub updated_unix_secs: u64,
    /// Whether usable ciphertext has been removed.
    pub revoked: bool,
}

/// Stored Credential persistence or encryption failure.
#[derive(Debug, Error)]
pub enum CredentialStoreError {
    /// Shared durable store failure.
    #[error("Stored Credential persistence failed")]
    Store(#[from] TypedStoreError),
    /// Contract, recipient, clock, or encryption failure.
    #[error("Stored Credential request is invalid")]
    Invalid,
    /// Plaintext exceeds its fixed bound.
    #[error("Stored Credential plaintext exceeds its limit")]
    Limit,
}

/// Bounded encrypted Stored Credential store.
#[derive(Debug)]
pub struct CredentialStore {
    store: TypedStore<CredentialRecord>,
    recipients: Vec<String>,
}

/// Validated replacement fields, including an optional rotated secret.
pub struct CredentialReplacement {
    /// Label.
    pub label: String,
    /// Enabled state.
    pub enabled: bool,
    /// Optional expiry.
    pub expires_unix_secs: Option<u64>,
    /// New plaintext when rotating.
    pub plaintext: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for CredentialReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialReplacement")
            .field("label", &self.label)
            .field("enabled", &self.enabled)
            .field("expires_unix_secs", &self.expires_unix_secs)
            .field("rotates_plaintext", &self.plaintext.is_some())
            .finish()
    }
}

impl CredentialStore {
    /// Open the private encrypted store.
    pub fn open(
        path: impl AsRef<Path>,
        recipients: Vec<String>,
    ) -> Result<Self, CredentialStoreError> {
        Ok(Self {
            store: TypedStore::open(
                path,
                ".credentials-owner.lock",
                MAX_CREDENTIALS,
                MAX_STORE_BYTES,
                canonicalize,
            )?,
            recipients,
        })
    }

    /// Encrypt and create one credential.
    pub fn create(
        &self,
        metadata: ObjectMetadata,
        label: String,
        enabled: bool,
        expires_unix_secs: Option<u64>,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<StoredCredential, CredentialStoreError> {
        if self.recipients.is_empty() {
            return Err(CredentialStoreError::Invalid);
        }
        validate_plaintext(&plaintext)?;
        let now = now()?;
        let object = ApiObject {
            api_version: ApiVersion,
            metadata,
            spec: CredentialRecord {
                label,
                enabled,
                expires_unix_secs,
                ciphertext_base64: Some(
                    STANDARD.encode(
                        encrypt_age(&plaintext, &self.recipients)
                            .map_err(|_| CredentialStoreError::Invalid)?,
                    ),
                ),
                fingerprint: format!("{:x}", Sha256::digest(&plaintext)),
                created_unix_secs: now,
                updated_unix_secs: now,
                revoked: false,
            },
        };
        self.store.create(object).map(public).map_err(Into::into)
    }

    /// Replace metadata and optionally rotate the plaintext at an exact generation.
    pub fn replace(
        &self,
        owner: &ObjectId,
        id: &ObjectId,
        expected_generation: u64,
        replacement: CredentialReplacement,
    ) -> Result<StoredCredential, CredentialStoreError> {
        let previous = self.store.get(owner, id).ok_or(TypedStoreError::Conflict)?;
        if previous.object.spec.revoked {
            return Err(TypedStoreError::Conflict.into());
        }
        let (ciphertext_base64, fingerprint) = match replacement.plaintext {
            Some(plaintext) => {
                if self.recipients.is_empty() {
                    return Err(CredentialStoreError::Invalid);
                }
                validate_plaintext(&plaintext)?;
                (
                    Some(
                        STANDARD.encode(
                            encrypt_age(&plaintext, &self.recipients)
                                .map_err(|_| CredentialStoreError::Invalid)?,
                        ),
                    ),
                    format!("{:x}", Sha256::digest(&plaintext)),
                )
            }
            None => (
                previous.object.spec.ciphertext_base64.clone(),
                previous.object.spec.fingerprint.clone(),
            ),
        };
        let object = ApiObject {
            api_version: ApiVersion,
            metadata: previous.object.metadata,
            spec: CredentialRecord {
                label: replacement.label,
                enabled: replacement.enabled,
                expires_unix_secs: replacement.expires_unix_secs,
                ciphertext_base64,
                fingerprint,
                created_unix_secs: previous.object.spec.created_unix_secs,
                updated_unix_secs: now()?,
                revoked: false,
            },
        };
        self.store
            .update(object, expected_generation)
            .map(public)
            .map_err(Into::into)
    }

    /// Revoke a credential by removing usable ciphertext.
    pub fn revoke(
        &self,
        owner: &ObjectId,
        id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredCredential, CredentialStoreError> {
        let previous = self.store.get(owner, id).ok_or(TypedStoreError::Conflict)?;
        let mut record = previous.object.spec;
        record.enabled = false;
        record.revoked = true;
        record.ciphertext_base64 = None;
        record.updated_unix_secs = now()?;
        self.store
            .update(
                ApiObject {
                    api_version: ApiVersion,
                    metadata: previous.object.metadata,
                    spec: record,
                },
                expected_generation,
            )
            .map(public)
            .map_err(Into::into)
    }

    /// Return one owner-scoped redacted record.
    #[must_use]
    pub fn get(&self, owner: &ObjectId, id: &ObjectId) -> Option<StoredCredential> {
        self.store.get(owner, id).map(public)
    }

    /// Return stable owner-scoped redacted records.
    #[must_use]
    pub fn list(&self, owner: &ObjectId) -> Vec<StoredCredential> {
        self.store.list(owner).into_iter().map(public).collect()
    }
}

fn canonicalize(object: &mut ApiObject<CredentialRecord>) -> bool {
    let record = &object.spec;
    valid_label(&record.label)
        && record.fingerprint.len() == 64
        && record
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && record.created_unix_secs > 0
        && record.updated_unix_secs >= record.created_unix_secs
        && ((!record.revoked && record.ciphertext_base64.is_some())
            || (record.revoked && !record.enabled && record.ciphertext_base64.is_none()))
        && record
            .ciphertext_base64
            .as_ref()
            .is_none_or(|value| value.len() <= 96 * 1024 && STANDARD.decode(value).is_ok())
}

fn public(stored: StoredObject<CredentialRecord>) -> StoredCredential {
    StoredCredential {
        id: stored.object.metadata.id,
        owner_id: stored.object.metadata.owner_id,
        generation: stored.generation,
        label: stored.object.spec.label,
        enabled: stored.object.spec.enabled,
        expires_unix_secs: stored.object.spec.expires_unix_secs,
        fingerprint: stored.object.spec.fingerprint,
        created_unix_secs: stored.object.spec.created_unix_secs,
        updated_unix_secs: stored.object.spec.updated_unix_secs,
        revoked: stored.object.spec.revoked,
    }
}

fn validate_plaintext(plaintext: &[u8]) -> Result<(), CredentialStoreError> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(CredentialStoreError::Limit);
    }
    Ok(())
}

fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 128 && !label.chars().any(char::is_control)
}

fn now() -> Result<u64, CredentialStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CredentialStoreError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::{secrecy::ExposeSecret, x25519};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NONCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn encrypts_rotates_revokes_and_never_exposes_secret() {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-credentials-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let identity = x25519::Identity::generate();
        let store = CredentialStore::open(
            root.join("admin/credentials.json"),
            vec![identity.to_public().to_string()],
        )
        .expect("store");
        let metadata: ObjectMetadata = serde_json::from_value(serde_json::json!({
            "id": "dns-token",
            "owner_id": "alice"
        }))
        .expect("metadata");
        let canary = b"credential-secret-canary";
        let created = store
            .create(
                metadata,
                "DNS token".into(),
                true,
                None,
                Zeroizing::new(canary.to_vec()),
            )
            .expect("create");
        let bytes = fs::read(root.join("admin/credentials.json")).expect("bytes");
        assert!(!bytes.windows(canary.len()).any(|window| window == canary));
        assert!(
            !serde_json::to_vec(&created)
                .expect("response")
                .windows(canary.len())
                .any(|window| window == canary)
        );
        let id: ObjectId = "dns-token".parse().expect("id");
        let owner: ObjectId = "alice".parse().expect("owner");
        let rotated = store
            .replace(
                &owner,
                &id,
                1,
                CredentialReplacement {
                    label: "DNS token".into(),
                    enabled: true,
                    expires_unix_secs: None,
                    plaintext: Some(Zeroizing::new(b"rotated-canary".to_vec())),
                },
            )
            .expect("rotate");
        assert_ne!(created.fingerprint, rotated.fingerprint);
        let revoked = store.revoke(&owner, &id, 2).expect("revoke");
        assert!(revoked.revoked);
        let stored = fs::read_to_string(root.join("admin/credentials.json")).expect("stored");
        assert!(!stored.contains("AGE-SECRET-KEY"));
        assert!(!stored.contains(identity.to_string().expose_secret()));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
