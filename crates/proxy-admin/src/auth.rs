//! Hash-only administrative API-token records.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

use argon2::{
    ARGON2ID_IDENT, Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier,
    Version,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{Action, ObjectId, Role, TokenScopeError, TokenScopes};

const TOKEN_ID_BYTES: usize = 12;
const TOKEN_SECRET_BYTES: usize = 32;
const TOKEN_SALT_BYTES: usize = 16;
const MAX_PRESENTED_TOKEN_BYTES: usize = 128;
const MAX_TOKEN_RECORDS: usize = 1_024;
const MAX_TOKEN_FILE_BYTES: u64 = 1024 * 1024;
const TOKEN_FILE_SCHEMA_VERSION: u32 = 1;
const ARGON2_MEMORY_KIB: u32 = 19_456;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_LANES: u32 = 1;

/// API-token creation or verification failure.
#[derive(Debug, Error)]
pub enum TokenError {
    /// Operating-system entropy was unavailable.
    #[error("operating-system randomness is unavailable")]
    RandomUnavailable,
    /// Argon2id could not create or parse a hash under the fixed policy.
    #[error("API token hashing failed")]
    Hash,
    /// Requested scopes were empty, duplicated, or exceeded the role.
    #[error("invalid API token scopes")]
    InvalidScopes(#[from] TokenScopeError),
}

/// Durable token-store failure.
#[derive(Debug, Error)]
pub enum TokenStoreError {
    /// Token creation failed.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// Token filesystem operation failed.
    #[error("token storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Stored token file failed strict validation.
    #[error("stored token metadata is invalid")]
    Invalid,
    /// Token count reached its hard bound.
    #[error("token count reached its hard limit")]
    Limit,
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
    /// Stable owner for typed objects. Missing legacy ownership cannot use typed endpoints.
    #[serde(default)]
    pub owner_id: Option<ObjectId>,
    /// Enabled user identity for newly issued tokens. Missing records remain legacy automation.
    #[serde(default)]
    pub user_ref: Option<ObjectId>,
    /// Explicit action scopes. Missing legacy scopes deserialize to deny-all.
    #[serde(default)]
    pub scopes: TokenScopes,
    /// Absolute Unix expiry time.
    pub expires_unix_secs: u64,
    /// Explicit revocation marker.
    pub revoked: bool,
    password_hash: String,
}

/// Redacted token metadata safe for administrative responses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TokenMetadata {
    /// Public indexed token identifier.
    pub id: String,
    /// Authorized built-in role.
    pub role: Role,
    /// Stable typed-object owner; absent only for legacy records.
    pub owner_id: Option<ObjectId>,
    /// Bound user identity; absent only for legacy automation tokens.
    pub user_ref: Option<ObjectId>,
    /// Explicit action scopes.
    pub scopes: TokenScopes,
    /// Absolute Unix expiry time.
    pub expires_unix_secs: u64,
    /// Explicit revocation marker.
    pub revoked: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenFile {
    schema_version: u32,
    records: Vec<TokenRecord>,
}

/// Private file-backed API-token store.
pub struct TokenStore {
    path: PathBuf,
    records: Mutex<Vec<TokenRecord>>,
    fallback: TokenRecord,
}

impl fmt::Debug for TokenStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenStore")
            .field("path", &self.path)
            .field("records", &"[REDACTED]")
            .field("fallback", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for TokenRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenRecord")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("owner_id", &self.owner_id)
            .field("user_ref", &self.user_ref)
            .field("scopes", &self.scopes)
            .field("expires_unix_secs", &self.expires_unix_secs)
            .field("revoked", &self.revoked)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}

impl TokenRecord {
    /// Issue a 256-bit token and return its hash-only record.
    pub fn issue(
        role: Role,
        user_ref: ObjectId,
        scopes: TokenScopes,
        expires_unix_secs: u64,
    ) -> Result<(Self, IssuedToken), TokenError> {
        scopes.validate_for_issue(role)?;
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
                owner_id: Some(user_ref.clone()),
                user_ref: Some(user_ref),
                scopes,
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
        if presented.len() > MAX_PRESENTED_TOKEN_BYTES {
            return false;
        }
        let Some((id, secret)) = presented.split_once('.') else {
            return false;
        };
        if id != self.id || secret.is_empty() {
            return false;
        }
        self.verify_secret(secret, now_unix_secs)
    }

    fn verify_secret(&self, secret: &str, now_unix_secs: u64) -> bool {
        if self.revoked || now_unix_secs >= self.expires_unix_secs || secret.is_empty() {
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

    fn metadata(&self) -> TokenMetadata {
        TokenMetadata {
            id: self.id.clone(),
            role: self.role,
            owner_id: self.owner_id.clone(),
            user_ref: self.user_ref.clone(),
            scopes: self.scopes.clone(),
            expires_unix_secs: self.expires_unix_secs,
            revoked: self.revoked,
        }
    }
}

impl TokenStore {
    /// Open and strictly validate a private token file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TokenStoreError> {
        let path = path.as_ref().to_path_buf();
        let records = load_token_file(&path)?;
        validate_records(&records)?;
        let fallback_scopes =
            TokenScopes::new(Role::Viewer, vec![Action::ReadStatus]).map_err(TokenError::from)?;
        let fallback_owner = "system".parse().map_err(|_| TokenStoreError::Invalid)?;
        let (fallback, fallback_plaintext) =
            TokenRecord::issue(Role::Viewer, fallback_owner, fallback_scopes, u64::MAX)?;
        drop(fallback_plaintext);
        Ok(Self {
            path,
            records: Mutex::new(records),
            fallback,
        })
    }

    /// Issue and durably persist a token. Plaintext is returned only here.
    pub fn issue(
        &self,
        role: Role,
        owner_id: ObjectId,
        scopes: TokenScopes,
        expires_unix_secs: u64,
    ) -> Result<(TokenMetadata, IssuedToken), TokenStoreError> {
        let (record, issued) = TokenRecord::issue(role, owner_id, scopes, expires_unix_secs)?;
        let metadata = record.metadata();
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if records.len() >= MAX_TOKEN_RECORDS {
            return Err(TokenStoreError::Limit);
        }
        if records.iter().any(|stored| stored.id == record.id) {
            return Err(TokenStoreError::Invalid);
        }
        records.push(record);
        if let Err(error) = persist_token_file(&self.path, &records) {
            records.pop();
            return Err(error);
        }
        Ok((metadata, issued))
    }

    /// Authenticate one bearer token. Unknown IDs still pay Argon2id cost.
    #[must_use]
    pub fn authenticate(&self, presented: &str, now_unix_secs: u64) -> Option<TokenMetadata> {
        if presented.len() > MAX_PRESENTED_TOKEN_BYTES {
            return None;
        }
        let (id, secret) = presented.split_once('.')?;
        if id.is_empty() || secret.is_empty() {
            return None;
        }
        let known = {
            let records = self
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            records.iter().find(|record| record.id == id).cloned()
        };
        let candidate = known.as_ref().unwrap_or(&self.fallback);
        let verified = candidate.verify_secret(secret, now_unix_secs);
        known.filter(|_| verified).map(|record| record.metadata())
    }

    /// Revoke a token and durably retain its metadata.
    pub fn revoke(&self, id: &str) -> Result<bool, TokenStoreError> {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(position) = records.iter().position(|record| record.id == id) else {
            return Ok(false);
        };
        if records[position].revoked {
            return Ok(true);
        }
        records[position].revoke();
        if let Err(error) = persist_token_file(&self.path, &records) {
            records[position].revoked = false;
            return Err(error);
        }
        Ok(true)
    }

    /// Return redacted token metadata.
    #[must_use]
    pub fn list(&self) -> Vec<TokenMetadata> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(TokenRecord::metadata)
            .collect()
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
    Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, Some(32))
        .ok()
        .map(|parameters| Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters))
}

fn load_token_file(path: &Path) -> Result<Vec<TokenRecord>, TokenStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > MAX_TOKEN_FILE_BYTES
            {
                return Err(TokenStoreError::Invalid);
            }
            reject_insecure_file_permissions(&metadata)?;
            let bytes = fs::read(path)?;
            let file: TokenFile =
                serde_json::from_slice(&bytes).map_err(|_| TokenStoreError::Invalid)?;
            if file.schema_version != TOKEN_FILE_SCHEMA_VERSION {
                return Err(TokenStoreError::Invalid);
            }
            Ok(file.records)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn validate_records(records: &[TokenRecord]) -> Result<(), TokenStoreError> {
    if records.len() > MAX_TOKEN_RECORDS {
        return Err(TokenStoreError::Limit);
    }
    let mut ids = HashSet::with_capacity(records.len());
    for record in records {
        if !valid_token_id(&record.id)
            || !ids.insert(record.id.as_str())
            || !valid_password_hash(&record.password_hash)
            || record.scopes.validate_stored(record.role).is_err()
        {
            return Err(TokenStoreError::Invalid);
        }
    }
    Ok(())
}

fn valid_password_hash(value: &str) -> bool {
    let Ok(hash) = PasswordHash::new(value) else {
        return false;
    };
    let Ok(parameters) = Params::try_from(&hash) else {
        return false;
    };
    hash.algorithm == ARGON2ID_IDENT
        && hash.version == Some(0x13)
        && parameters.m_cost() == ARGON2_MEMORY_KIB
        && parameters.t_cost() == ARGON2_ITERATIONS
        && parameters.p_cost() == ARGON2_LANES
        && hash.salt.is_some()
        && hash.hash.is_some()
}

fn valid_token_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn persist_token_file(path: &Path, records: &[TokenRecord]) -> Result<(), TokenStoreError> {
    let parent = path.parent().ok_or(TokenStoreError::Invalid)?;
    create_private_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(&TokenFile {
        schema_version: TOKEN_FILE_SCHEMA_VERSION,
        records: records.to_vec(),
    })
    .map_err(|_| TokenStoreError::Invalid)?;
    if bytes.len() as u64 > MAX_TOKEN_FILE_BYTES {
        return Err(TokenStoreError::Limit);
    }
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| TokenError::RandomUnavailable)?;
    let temporary = parent.join(format!(".tokens-{}.tmp", URL_SAFE_NO_PAD.encode(suffix)));
    let result = write_private_file(&temporary, &bytes).and_then(|()| {
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(TokenStoreError::Io)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn create_private_directory(path: &Path) -> Result<(), std::io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            reject_insecure_directory_permissions(&metadata)
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "token parent is not a private directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            set_private_directory_permissions(path)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn reject_insecure_directory_permissions(metadata: &fs::Metadata) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "token parent permissions are too broad",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_directory_permissions(_metadata: &fs::Metadata) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn reject_insecure_file_permissions(metadata: &fs::Metadata) -> Result<(), TokenStoreError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(TokenStoreError::Invalid);
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_file_permissions(_metadata: &fs::Metadata) -> Result<(), TokenStoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{TokenRecord, TokenStore};
    use crate::{Action, ObjectId, Role, TokenScopes};

    fn operator_scopes() -> TokenScopes {
        TokenScopes::new(Role::Operator, vec![Action::ReadStatus, Action::ReadRoutes])
            .expect("operator scopes")
    }

    fn owner() -> ObjectId {
        "alice".parse().expect("owner")
    }

    #[test]
    fn token_is_hash_only_redacted_expiring_and_revocable() {
        let (mut record, issued) =
            TokenRecord::issue(Role::Operator, owner(), operator_scopes(), 200).expect("issue");
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

    #[test]
    fn store_persists_only_hashes_and_rejects_unknown_tokens() {
        let directory =
            std::env::temp_dir().join(format!("aegisproxy-token-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("tokens.json");
        let store = TokenStore::open(&path).expect("open");
        let (metadata, issued) = store
            .issue(Role::Operator, owner(), operator_scopes(), 200)
            .expect("issue");
        let plaintext = issued.into_plaintext();
        assert_eq!(
            store.authenticate(&plaintext, 100).map(|token| token.role),
            Some(Role::Operator)
        );
        assert!(store.authenticate("unknown.invalid", 100).is_none());
        assert!(
            !fs::read_to_string(&path)
                .expect("read")
                .contains(plaintext.as_str())
        );
        assert!(store.revoke(&metadata.id).expect("revoke"));
        assert!(store.authenticate(&plaintext, 100).is_none());
        drop(store);
        let reopened = TokenStore::open(&path).expect("reopen");
        assert_eq!(reopened.list().len(), 1);
        assert!(reopened.list()[0].revoked);
        fs::remove_dir_all(directory).expect("remove");
    }

    #[test]
    fn legacy_missing_scopes_load_as_deny_all() {
        let directory = std::env::temp_dir().join(format!(
            "aegisproxy-legacy-token-store-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("tokens.json");
        let store = TokenStore::open(&path).expect("open");
        let (_metadata, issued) = store
            .issue(Role::Operator, owner(), operator_scopes(), 200)
            .expect("issue");
        let plaintext = issued.into_plaintext();
        drop(store);

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read token file")).expect("token JSON");
        value["records"][0]
            .as_object_mut()
            .expect("token record")
            .remove("scopes");
        value["records"][0]
            .as_object_mut()
            .expect("token record")
            .remove("owner_id");
        value["records"][0]
            .as_object_mut()
            .expect("token record")
            .remove("user_ref");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&value).expect("legacy JSON"),
        )
        .expect("write legacy file");

        let reopened = TokenStore::open(&path).expect("open legacy");
        let authenticated = reopened
            .authenticate(&plaintext, 100)
            .expect("authenticate");
        assert!(authenticated.scopes.as_slice().is_empty());
        assert!(authenticated.owner_id.is_none());
        assert!(authenticated.user_ref.is_none());
        assert!(!authenticated.scopes.allows(Action::ReadStatus));
        fs::remove_dir_all(directory).expect("remove");
    }
}
