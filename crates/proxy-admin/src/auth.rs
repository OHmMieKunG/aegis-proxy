//! Hash-only administrative API-token records.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::Role;

const TOKEN_ID_BYTES: usize = 12;
const TOKEN_SECRET_BYTES: usize = 32;
const TOKEN_SALT_BYTES: usize = 16;
const MAX_PRESENTED_TOKEN_BYTES: usize = 128;

/// API-token creation or verification failure.
#[derive(Debug, Error)]
pub enum TokenError {
    /// Operating-system entropy was unavailable.
    #[error("operating-system randomness is unavailable")]
    RandomUnavailable,
    /// Argon2id could not create or parse a hash under the fixed policy.
    #[error("API token hashing failed")]
    Hash,
}

/// Newly issued plaintext token. Formatting always redacts its value.
pub struct IssuedToken(Zeroizing<String>);

impl IssuedToken {
    /// Consume the one-time result and expose its plaintext to the CLI caller.
    #[must_use]
    pub fn into_plaintext(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedToken([REDACTED])")
    }
}

/// Persisted hash-only token metadata.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    /// Public indexed token identifier.
    pub id: String,
    /// Authorized built-in role.
    pub role: Role,
    /// Absolute Unix expiry time.
    pub expires_unix_secs: u64,
    /// Explicit revocation marker.
    pub revoked: bool,
    password_hash: String,
}

impl fmt::Debug for TokenRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenRecord")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("expires_unix_secs", &self.expires_unix_secs)
            .field("revoked", &self.revoked)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}

impl TokenRecord {
    /// Issue a 256-bit token and return its hash-only record.
    pub fn issue(role: Role, expires_unix_secs: u64) -> Result<(Self, IssuedToken), TokenError> {
        let mut id = [0_u8; TOKEN_ID_BYTES];
        let mut secret = Zeroizing::new([0_u8; TOKEN_SECRET_BYTES]);
        let mut salt = [0_u8; TOKEN_SALT_BYTES];
        getrandom::fill(&mut id).map_err(|_| TokenError::RandomUnavailable)?;
        getrandom::fill(&mut *secret).map_err(|_| TokenError::RandomUnavailable)?;
        getrandom::fill(&mut salt).map_err(|_| TokenError::RandomUnavailable)?;
        let id = URL_SAFE_NO_PAD.encode(id);
        let encoded_secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_ref()));
        let hash = hash_secret(encoded_secret.as_bytes(), &salt)?;
        let plaintext = IssuedToken(Zeroizing::new(format!("{id}.{}", encoded_secret.as_str())));
        Ok((
            Self {
                id,
                role,
                expires_unix_secs,
                revoked: false,
                password_hash: hash,
            },
            plaintext,
        ))
    }

    /// Verify one full token under expiry and revocation policy.
    #[must_use]
    pub fn verify(&self, presented: &str, now_unix_secs: u64) -> bool {
        if self.revoked
            || now_unix_secs >= self.expires_unix_secs
            || presented.len() > MAX_PRESENTED_TOKEN_BYTES
        {
            return false;
        }
        let Some((id, secret)) = presented.split_once('.') else {
            return false;
        };
        if id != self.id || secret.is_empty() {
            return false;
        }
        let Ok(hash) = PasswordHash::new(&self.password_hash) else {
            return false;
        };
        argon2().is_some_and(|argon2| argon2.verify_password(secret.as_bytes(), &hash).is_ok())
    }

    /// Revoke this record without deleting audit-relevant metadata.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

fn hash_secret(secret: &[u8], salt: &[u8]) -> Result<String, TokenError> {
    let salt = argon2::password_hash::SaltString::encode_b64(salt).map_err(|_| TokenError::Hash)?;
    argon2()
        .ok_or(TokenError::Hash)?
        .hash_password(secret, &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| TokenError::Hash)
}

fn argon2() -> Option<Argon2<'static>> {
    Params::new(19_456, 2, 1, Some(32))
        .ok()
        .map(|parameters| Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters))
}

#[cfg(test)]
mod tests {
    use super::TokenRecord;
    use crate::Role;

    #[test]
    fn token_is_hash_only_redacted_expiring_and_revocable() {
        let (mut record, issued) = TokenRecord::issue(Role::Operator, 200).expect("issue");
        let plaintext = issued.into_plaintext();
        assert_eq!(plaintext.split_once('.').expect("token").1.len(), 43);
        assert!(record.verify(&plaintext, 199));
        assert!(!record.verify(&plaintext, 200));
        assert!(!record.verify("wrong.secret", 100));
        assert!(!format!("{record:?}").contains(plaintext.as_str()));
        assert!(
            !serde_json::to_string(&record)
                .expect("serialize")
                .contains(plaintext.as_str())
        );
        record.revoke();
        assert!(!record.verify(&plaintext, 100));
    }
}
