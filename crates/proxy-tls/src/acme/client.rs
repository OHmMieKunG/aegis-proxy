use std::{fmt, net::IpAddr, path::Path};

use instant_acme::{Account, AccountCredentials, ExternalAccountKey, NewAccount};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MAX_ACCOUNT_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_URL_BYTES: usize = 2 * 1024;
const MAX_ACCOUNT_EMAIL_BYTES: usize = 254;
const MAX_EXTERNAL_ACCOUNT_KEY_ID_BYTES: usize = 256;
const MAX_EXTERNAL_ACCOUNT_KEY_BYTES: usize = 4 * 1024;

/// Optional RFC 8555 external-account binding material.
pub struct AcmeExternalAccountBinding<'a> {
    /// CA-provided non-secret key identifier.
    pub key_id: &'a str,
    /// Raw, decoded HMAC key bytes resolved from an approved secret provider.
    pub hmac_key: &'a [u8],
}

impl fmt::Debug for AcmeExternalAccountBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeExternalAccountBinding")
            .field("key_id", &"[REDACTED]")
            .field("hmac_key", &"[REDACTED]")
            .finish()
    }
}

/// Validated inputs used to create one ACME account.
pub struct AcmeAccountCreateRequest<'a> {
    /// Explicit ACME directory URL.
    pub directory_url: &'a Url,
    /// Optional account contact email without the `mailto:` prefix.
    pub account_email: Option<&'a str>,
    /// Explicit operator acceptance of the CA terms of service.
    pub terms_of_service_agreed: bool,
    /// Optional paired external-account key ID and HMAC key.
    pub external_account: Option<AcmeExternalAccountBinding<'a>>,
}

impl fmt::Debug for AcmeAccountCreateRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeAccountCreateRequest")
            .field("directory_url", &"[REDACTED]")
            .field("account_email", &self.account_email.map(|_| "[REDACTED]"))
            .field("terms_of_service_agreed", &self.terms_of_service_agreed)
            .field("external_account", &self.external_account)
            .finish()
    }
}

/// Sanitized ACME client initialization failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AcmeClientError {
    /// Account creation was not explicitly authorized by configuration.
    #[error("ACME account creation policy denied the request")]
    Policy,
    /// Account creation input was malformed or outside a resource bound.
    #[error("invalid ACME account creation input")]
    Input,
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
    /// Create an account and return bounded serialized credentials for immediate encryption.
    pub async fn create(
        request: AcmeAccountCreateRequest<'_>,
        ca_bundle: Option<&Path>,
    ) -> Result<(Self, Zeroizing<Vec<u8>>), AcmeClientError> {
        validate_create_request(&request)?;
        let contact = request.account_email.map(|email| format!("mailto:{email}"));
        let contact_refs = contact
            .as_deref()
            .map(|value| vec![value])
            .unwrap_or_default();
        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let external_account = request
            .external_account
            .map(|binding| ExternalAccountKey::new(binding.key_id.to_owned(), binding.hmac_key));
        let builder = match ca_bundle {
            Some(path) => Account::builder_with_root(path),
            None => Account::builder(),
        }
        .map_err(|_| AcmeClientError::Initialization)?;
        let (account, credentials) = builder
            .create(
                &new_account,
                request.directory_url.as_str().to_owned(),
                external_account.as_ref(),
            )
            .await
            .map_err(|_| AcmeClientError::Initialization)?;
        let credentials =
            serde_json::to_vec(&credentials).map_err(|_| AcmeClientError::Credentials)?;
        if credentials.is_empty() || credentials.len() > MAX_ACCOUNT_CREDENTIAL_BYTES {
            return Err(AcmeClientError::Credentials);
        }
        Ok((Self { account }, Zeroizing::new(credentials)))
    }

    /// Restore one account using system trust or one explicit test/private CA root.
    pub async fn restore(
        credentials_json: &[u8],
        ca_bundle: Option<&Path>,
    ) -> Result<Self, AcmeClientError> {
        let credentials = validate_credentials(credentials_json)?;
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

fn validate_create_request(request: &AcmeAccountCreateRequest<'_>) -> Result<(), AcmeClientError> {
    if !request.terms_of_service_agreed {
        return Err(AcmeClientError::Policy);
    }
    let directory = request.directory_url;
    if directory.as_str().len() > MAX_DIRECTORY_URL_BYTES
        || directory.username() != ""
        || directory.password().is_some()
        || directory.query().is_some()
        || directory.fragment().is_some()
        || directory.host_str().is_none()
        || !valid_directory_transport(directory)
    {
        return Err(AcmeClientError::Input);
    }
    if let Some(email) = request.account_email
        && (email.is_empty()
            || email.len() > MAX_ACCOUNT_EMAIL_BYTES
            || !email.is_ascii()
            || email.bytes().any(|byte| byte.is_ascii_control())
            || email.matches('@').count() != 1)
    {
        return Err(AcmeClientError::Input);
    }
    if let Some(binding) = &request.external_account
        && (binding.key_id.is_empty()
            || binding.key_id.len() > MAX_EXTERNAL_ACCOUNT_KEY_ID_BYTES
            || binding.key_id.bytes().any(|byte| byte.is_ascii_control())
            || binding.hmac_key.is_empty()
            || binding.hmac_key.len() > MAX_EXTERNAL_ACCOUNT_KEY_BYTES)
    {
        return Err(AcmeClientError::Input);
    }
    Ok(())
}

fn valid_directory_transport(directory: &Url) -> bool {
    if directory.scheme() == "https" {
        return true;
    }
    directory.scheme() == "http"
        && directory.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        })
}

pub(super) fn validate_credentials(bytes: &[u8]) -> Result<AccountCredentials, AcmeClientError> {
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
        assert!(validate_credentials(valid_shape).is_ok());
        assert!(matches!(
            validate_credentials(&vec![b'x'; MAX_ACCOUNT_CREDENTIAL_BYTES + 1]),
            Err(AcmeClientError::Credentials)
        ));
        let error = validate_credentials(b"private-canary")
            .err()
            .expect("malformed credentials must fail");
        assert_eq!(error.to_string(), "invalid ACME account credentials");
    }

    #[test]
    fn requires_explicit_terms_before_account_creation() {
        let directory = Url::parse("https://acme.test/directory").expect("URL");
        let request = AcmeAccountCreateRequest {
            directory_url: &directory,
            account_email: Some("ops@example.test"),
            terms_of_service_agreed: false,
            external_account: None,
        };
        assert_eq!(
            validate_create_request(&request),
            Err(AcmeClientError::Policy)
        );
    }

    #[test]
    fn bounds_and_redacts_account_creation_input() {
        let directory = Url::parse("http://127.0.0.1:14000/dir").expect("URL");
        let secret = b"eab-secret-canary";
        let request = AcmeAccountCreateRequest {
            directory_url: &directory,
            account_email: Some("ops@example.test"),
            terms_of_service_agreed: true,
            external_account: Some(AcmeExternalAccountBinding {
                key_id: "kid-1",
                hmac_key: secret,
            }),
        };
        assert_eq!(validate_create_request(&request), Ok(()));
        let debug = format!("{request:?}");
        assert!(!debug.contains("ops@example.test"));
        assert!(!debug.contains("127.0.0.1"));
        assert!(!debug.contains("kid-1"));
        assert!(!debug.contains("eab-secret-canary"));

        let remote_http = Url::parse("http://acme.test/directory").expect("URL");
        let invalid = AcmeAccountCreateRequest {
            directory_url: &remote_http,
            account_email: None,
            terms_of_service_agreed: true,
            external_account: None,
        };
        assert_eq!(
            validate_create_request(&invalid),
            Err(AcmeClientError::Input)
        );
    }
}
