use std::{fmt, path::Path};

use instant_acme::{Account, AccountCredentials};
use thiserror::Error;

const MAX_ACCOUNT_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Sanitized ACME client initialization failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AcmeClientError {
    /// Encrypted account plaintext was malformed or oversized.
    #[error("invalid ACME account credentials")]
    Credentials,
    /// ACME transport/account initialization failed without exposing credential data.
    #[error("ACME account initialization failed")]
    Initialization,
}

/// Narrow account boundary that prevents `instant-acme` types leaking into proxy configuration.
#[derive(Clone)]
pub struct AcmeClient {
    account: Account,
}

impl fmt::Debug for AcmeClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeClient")
            .field("account", &"[REDACTED]")
            .finish()
    }
}

impl AcmeClient {
    /// Restore one account using system trust or one explicit test/private CA root.
    pub async fn restore(
        credentials_json: &[u8],
        ca_bundle: Option<&Path>,
    ) -> Result<Self, AcmeClientError> {
        let credentials = parse_credentials(credentials_json)?;
        let builder = match ca_bundle {
            Some(path) => Account::builder_with_root(path),
            None => Account::builder(),
        }
        .map_err(|_| AcmeClientError::Initialization)?;
        let account = builder
            .from_credentials(credentials)
            .await
            .map_err(|_| AcmeClientError::Initialization)?;
        Ok(Self { account })
    }

    /// Return the CA-assigned account URL without exposing account-key material.
    #[must_use]
    pub fn account_id(&self) -> &str {
        self.account.id()
    }
}

fn parse_credentials(bytes: &[u8]) -> Result<AccountCredentials, AcmeClientError> {
    if bytes.is_empty() || bytes.len() > MAX_ACCOUNT_CREDENTIAL_BYTES {
        return Err(AcmeClientError::Credentials);
    }
    serde_json::from_slice(bytes).map_err(|_| AcmeClientError::Credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_and_sanitizes_account_credentials() {
        let valid_shape = br#"{
            "id":"https://acme.test/account/1",
            "key_pkcs8":"AQID",
            "directory":"https://acme.test/directory"
        }"#;
        assert!(parse_credentials(valid_shape).is_ok());
        assert!(matches!(
            parse_credentials(&vec![b'x'; MAX_ACCOUNT_CREDENTIAL_BYTES + 1]),
            Err(AcmeClientError::Credentials)
        ));
        let error = parse_credentials(b"private-canary")
            .err()
            .expect("malformed credentials must fail");
        assert_eq!(error.to_string(), "invalid ACME account credentials");
    }
}
