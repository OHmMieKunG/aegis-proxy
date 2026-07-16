use aegisproxy_secrets::{SecretBytes, decrypt_age, encrypt_age};
use serde::Deserialize;
use thiserror::Error;

use super::client::validate_credentials;

const MAX_ACCOUNT_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_ACCOUNT_ENVELOPE_BYTES: usize = 128 * 1024;
const MAX_DIRECTORY_URL_BYTES: usize = 4096;

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
}
