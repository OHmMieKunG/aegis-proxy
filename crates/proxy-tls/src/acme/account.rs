use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use aegisproxy_secrets::{SecretBytes, decrypt_age, encrypt_age};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::client::validate_credentials;
use crate::{
    TlsError,
    generation::{
        create_private_dir, generation_id, read_bounded, sync_directory, validate_id,
        write_private_file,
    },
};

const MAX_ACCOUNT_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_ACCOUNT_ENVELOPE_BYTES: usize = 128 * 1024;
const MAX_DIRECTORY_URL_BYTES: usize = 4096;
const MAX_ACCOUNT_METADATA_BYTES: usize = 64 * 1024;

/// Sanitized encrypted ACME account failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AcmeAccountError {
    /// Credential plaintext did not match its configured issuer directory.
    #[error("invalid ACME account credentials")]
    Credentials,
    /// Envelope encryption or decryption failed without exposing key material.
    #[error("ACME account encryption failed")]
    Encryption,
}

/// Persisted operator-selected issuer classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredAcmeEnvironment {
    /// Production issuance material.
    Production,
    /// Staging/test issuance material.
    Staging,
}

/// Public metadata for one immutable encrypted ACME account generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAcmeAccount {
    /// Stable configured issuer ID.
    pub issuer_id: String,
    /// Immutable generation ID.
    pub generation: String,
    /// Exact configured directory URL.
    pub directory_url: String,
    /// Explicit operator-selected environment.
    pub environment: StoredAcmeEnvironment,
    /// Creation time as Unix seconds.
    pub created_unix_secs: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountPointer {
    schema_version: u32,
    current: String,
    previous: Option<String>,
    directory_url: String,
    environment: StoredAcmeEnvironment,
}

/// Validate and age-encrypt serialized ACME account credentials.
pub fn encrypt_account_credentials(
    credentials_json: &[u8],
    expected_directory_url: &str,
    recipients: &[String],
) -> Result<Vec<u8>, AcmeAccountError> {
    validate_directory_binding(credentials_json, expected_directory_url)?;
    if recipients.is_empty() || recipients.len() > 8 {
        return Err(AcmeAccountError::Encryption);
    }
    encrypt_age(credentials_json, recipients).map_err(|_| AcmeAccountError::Encryption)
}

/// Decrypt and validate an account envelope against its configured issuer directory.
pub fn decrypt_account_credentials(
    envelope: &[u8],
    identity: &[u8],
    expected_directory_url: &str,
) -> Result<SecretBytes, AcmeAccountError> {
    if envelope.is_empty() || envelope.len() > MAX_ACCOUNT_ENVELOPE_BYTES {
        return Err(AcmeAccountError::Encryption);
    }
    let plaintext = decrypt_age(envelope, identity, MAX_ACCOUNT_CREDENTIAL_BYTES)
        .map_err(|_| AcmeAccountError::Encryption)?;
    validate_directory_binding(plaintext.as_ref(), expected_directory_url)?;
    Ok(plaintext)
}

/// Persist a complete encrypted account generation before switching the active pointer.
pub fn persist_account_generation(
    state_dir: &Path,
    issuer_id: &str,
    directory_url: &str,
    environment: StoredAcmeEnvironment,
    credentials_json: &[u8],
    recipients: &[String],
) -> Result<StoredAcmeAccount, TlsError> {
    validate_id(issuer_id)?;
    let encrypted = encrypt_account_credentials(credentials_json, directory_url, recipients)
        .map_err(|_| TlsError::StoreFormat("invalid encrypted ACME account material".into()))?;
    let account_dir = state_dir.join("acme").join("accounts").join(issuer_id);
    let generations_dir = account_dir.join("generations");
    create_private_dir(&generations_dir)?;
    let pointer_path = account_dir.join("current.json");
    let previous = read_account_pointer(&pointer_path)?;
    if previous.as_ref().is_some_and(|pointer| {
        pointer.directory_url != directory_url || pointer.environment != environment
    }) {
        return Err(TlsError::StoreFormat(
            "ACME account directory or environment changed".into(),
        ));
    }

    let generation = generation_id()?;
    let metadata = StoredAcmeAccount {
        issuer_id: issuer_id.to_owned(),
        generation: generation.clone(),
        directory_url: directory_url.to_owned(),
        environment,
        created_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TlsError::StoreFormat("system clock predates Unix epoch".into()))?
            .as_secs(),
    };
    let staging = generations_dir.join(format!(
        ".account-{}-{}",
        std::process::id(),
        metadata.generation
    ));
    create_private_dir(&staging)?;
    let written = (|| {
        write_private_file(&staging.join("credentials.age"), &encrypted)?;
        let metadata_toml =
            toml::to_string(&metadata).map_err(|error| TlsError::StoreFormat(error.to_string()))?;
        write_private_file(&staging.join("metadata.toml"), metadata_toml.as_bytes())?;
        sync_directory(&staging)?;
        let final_dir = generations_dir.join(&metadata.generation);
        fs::rename(&staging, &final_dir)?;
        sync_directory(&generations_dir)?;
        Ok::<_, TlsError>(())
    })();
    if written.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    written?;

    let pointer = AccountPointer {
        schema_version: 1,
        current: metadata.generation.clone(),
        previous: previous.map(|pointer| pointer.current),
        directory_url: directory_url.to_owned(),
        environment,
    };
    write_account_pointer(&pointer_path, &pointer)?;
    Ok(metadata)
}

/// Load, decrypt, and cross-check the active account generation.
pub fn load_account_generation(
    state_dir: &Path,
    issuer_id: &str,
    directory_url: &str,
    environment: StoredAcmeEnvironment,
    identity: &[u8],
) -> Result<(StoredAcmeAccount, SecretBytes), TlsError> {
    validate_id(issuer_id)?;
    let account_dir = state_dir.join("acme").join("accounts").join(issuer_id);
    let pointer = read_account_pointer(&account_dir.join("current.json"))?
        .ok_or_else(|| TlsError::StoreFormat("ACME account pointer is missing".into()))?;
    if pointer.directory_url != directory_url || pointer.environment != environment {
        return Err(TlsError::StoreFormat(
            "ACME account directory or environment does not match configuration".into(),
        ));
    }
    validate_generation(&pointer.current)?;
    if let Some(previous) = pointer.previous.as_deref() {
        validate_generation(previous)?;
    }
    let generation_dir = account_dir.join("generations").join(&pointer.current);
    let metadata: StoredAcmeAccount = toml::from_str(
        std::str::from_utf8(&read_bounded(
            &generation_dir.join("metadata.toml"),
            MAX_ACCOUNT_METADATA_BYTES,
        )?)
        .map_err(|_| TlsError::StoreFormat("ACME account metadata is not UTF-8".into()))?,
    )
    .map_err(|error| TlsError::StoreFormat(error.to_string()))?;
    if metadata.issuer_id != issuer_id
        || metadata.generation != pointer.current
        || metadata.directory_url != directory_url
        || metadata.environment != environment
    {
        return Err(TlsError::StoreFormat(
            "ACME account metadata does not match its pointer".into(),
        ));
    }
    let envelope = read_bounded(
        &generation_dir.join("credentials.age"),
        MAX_ACCOUNT_ENVELOPE_BYTES,
    )?;
    let credentials = decrypt_account_credentials(&envelope, identity, directory_url)
        .map_err(|_| TlsError::StoreFormat("invalid encrypted ACME account material".into()))?;
    Ok((metadata, credentials))
}

fn read_account_pointer(path: &Path) -> Result<Option<AccountPointer>, TlsError> {
    if !path.exists() {
        return Ok(None);
    }
    let pointer: AccountPointer =
        serde_json::from_slice(&read_bounded(path, MAX_ACCOUNT_METADATA_BYTES)?)
            .map_err(|error| TlsError::StoreFormat(error.to_string()))?;
    if pointer.schema_version != 1 {
        return Err(TlsError::StoreFormat(
            "unsupported ACME account pointer version".into(),
        ));
    }
    Ok(Some(pointer))
}

fn write_account_pointer(path: &Path, pointer: &AccountPointer) -> Result<(), TlsError> {
    let bytes = serde_json::to_vec_pretty(pointer)
        .map_err(|error| TlsError::StoreFormat(error.to_string()))?;
    let temporary = path.with_file_name(format!(
        ".current-{}-{}.json",
        std::process::id(),
        generation_id()?
    ));
    write_private_file(&temporary, &bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_directory(
        path.parent()
            .ok_or_else(|| TlsError::StoreFormat("ACME account path has no parent".into()))?,
    )
}

fn validate_generation(generation: &str) -> Result<(), TlsError> {
    if generation.is_empty()
        || generation.len() > 32
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TlsError::StoreFormat(
            "invalid ACME account generation".into(),
        ));
    }
    Ok(())
}

fn validate_directory_binding(
    credentials_json: &[u8],
    expected_directory_url: &str,
) -> Result<(), AcmeAccountError> {
    if expected_directory_url.is_empty() || expected_directory_url.len() > MAX_DIRECTORY_URL_BYTES {
        return Err(AcmeAccountError::Credentials);
    }
    let _credentials =
        validate_credentials(credentials_json).map_err(|_| AcmeAccountError::Credentials)?;
    #[derive(Deserialize)]
    struct DirectoryBinding {
        directory: String,
    }
    let binding: DirectoryBinding =
        serde_json::from_slice(credentials_json).map_err(|_| AcmeAccountError::Credentials)?;
    if binding.directory != expected_directory_url {
        return Err(AcmeAccountError::Credentials);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use age::{secrecy::ExposeSecret, x25519};

    use super::*;

    const DIRECTORY: &str = "https://acme.test/directory";
    const CREDENTIALS: &[u8] = br#"{
        "id":"https://acme.test/account/private-canary",
        "key_pkcs8":"cHJpdmF0ZS1jYW5hcnk",
        "directory":"https://acme.test/directory"
    }"#;
    const CREDENTIALS_2: &[u8] = br#"{
        "id":"https://acme.test/account/rotated",
        "key_pkcs8":"cm90YXRlZC1rZXk",
        "directory":"https://acme.test/directory"
    }"#;

    #[test]
    fn account_envelope_round_trips_without_plaintext() {
        let identity = x25519::Identity::generate();
        let encrypted = encrypt_account_credentials(
            CREDENTIALS,
            DIRECTORY,
            &[identity.to_public().to_string()],
        )
        .expect("encrypt credentials");
        assert!(
            !encrypted
                .windows(14)
                .any(|window| window == b"private-canary")
        );
        let decrypted = decrypt_account_credentials(
            &encrypted,
            identity.to_string().expose_secret().as_bytes(),
            DIRECTORY,
        )
        .expect("decrypt credentials");
        assert_eq!(decrypted.as_ref(), CREDENTIALS);
    }

    #[test]
    fn wrong_identity_and_directory_fail_closed() {
        let identity = x25519::Identity::generate();
        let encrypted = encrypt_account_credentials(
            CREDENTIALS,
            DIRECTORY,
            &[identity.to_public().to_string()],
        )
        .expect("encrypt credentials");
        let wrong = x25519::Identity::generate();
        assert_eq!(
            decrypt_account_credentials(
                &encrypted,
                wrong.to_string().expose_secret().as_bytes(),
                DIRECTORY,
            )
            .expect_err("wrong identity must fail"),
            AcmeAccountError::Encryption
        );
        assert_eq!(
            decrypt_account_credentials(
                &encrypted,
                identity.to_string().expose_secret().as_bytes(),
                "https://other.test/directory",
            )
            .expect_err("wrong directory must fail"),
            AcmeAccountError::Credentials
        );
    }

    #[test]
    fn account_generations_switch_atomically_and_retain_previous() {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-acme-account-{}-{}",
            std::process::id(),
            generation_id().expect("generation")
        ));
        fs::create_dir(&root).expect("create test root");
        let identity = x25519::Identity::generate();
        let recipients = [identity.to_public().to_string()];
        let first = persist_account_generation(
            &root,
            "pebble",
            DIRECTORY,
            StoredAcmeEnvironment::Staging,
            CREDENTIALS,
            &recipients,
        )
        .expect("persist first account");
        let second = persist_account_generation(
            &root,
            "pebble",
            DIRECTORY,
            StoredAcmeEnvironment::Staging,
            CREDENTIALS_2,
            &recipients,
        )
        .expect("persist rotated account");
        assert_ne!(first.generation, second.generation);
        let (loaded, credentials) = load_account_generation(
            &root,
            "pebble",
            DIRECTORY,
            StoredAcmeEnvironment::Staging,
            identity.to_string().expose_secret().as_bytes(),
        )
        .expect("load active account");
        assert_eq!(loaded, second);
        assert_eq!(credentials.as_ref(), CREDENTIALS_2);
        let pointer = read_account_pointer(
            &root
                .join("acme")
                .join("accounts")
                .join("pebble")
                .join("current.json"),
        )
        .expect("read pointer")
        .expect("active pointer");
        assert_eq!(pointer.previous.as_deref(), Some(first.generation.as_str()));
        assert!(
            root.join("acme")
                .join("accounts")
                .join("pebble")
                .join("generations")
                .join(&first.generation)
                .is_dir()
        );
        assert!(
            persist_account_generation(
                &root,
                "pebble",
                DIRECTORY,
                StoredAcmeEnvironment::Production,
                CREDENTIALS_2,
                &recipients,
            )
            .is_err()
        );
        let (still_active, _) = load_account_generation(
            &root,
            "pebble",
            DIRECTORY,
            StoredAcmeEnvironment::Staging,
            identity.to_string().expose_secret().as_bytes(),
        )
        .expect("failed replacement preserves active account");
        assert_eq!(still_active, second);
        fs::remove_dir_all(root).expect("remove test root");
    }
}
