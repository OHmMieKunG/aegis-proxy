#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Secret references. Values are resolved only at explicit activation time.

mod envelope;

pub use envelope::{decrypt_age, encrypt_age};

use std::{
    fmt,
    fs::{File, Metadata},
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

use thiserror::Error;
use zeroize::Zeroizing;

/// A non-secret reference to an allowed local secret source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretRef {
    /// An environment variable name.
    Env(String),
    /// An absolute file path.
    File(PathBuf),
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(name) => write!(f, "env://{name}"),
            Self::File(path) => write!(f, "file://{}", path.display()),
        }
    }
}

/// Secret loading failure.
#[derive(Debug, Error)]
pub enum SecretError {
    /// Reference syntax is invalid.
    #[error("invalid secret reference: {0}")]
    InvalidReference(String),
    /// The source could not be read.
    #[error("could not read secret source: {0}")]
    Io(#[from] std::io::Error),
    /// The source exceeds the configured bound.
    #[error("secret exceeds maximum size of {0} bytes")]
    TooLarge(usize),
    /// File permissions allow access outside the owner.
    #[error("secret file permissions are too broad")]
    InsecurePermissions,
    /// Authenticated envelope encryption or decryption failed.
    #[error("secret envelope operation failed")]
    Envelope,
}

/// Secret bytes that zero memory on drop and never reveal their value in formatting.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl SecretRef {
    /// Parse an `env://NAME` or absolute `file:///path` reference.
    pub fn parse(value: &str) -> Result<Self, SecretError> {
        if let Some(name) = value.strip_prefix("env://") {
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(SecretError::InvalidReference(value.to_owned()));
            }
            return Ok(Self::Env(name.to_owned()));
        }
        let Some(raw) = value.strip_prefix("file://") else {
            return Err(SecretError::InvalidReference(value.to_owned()));
        };
        if !portable_absolute_file_path(raw) {
            return Err(SecretError::InvalidReference(value.to_owned()));
        }
        #[cfg(windows)]
        let raw = raw
            .strip_prefix('/')
            .filter(|candidate| windows_drive_absolute(candidate))
            .unwrap_or(raw);
        let path = Path::new(raw);
        if path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(SecretError::InvalidReference(value.to_owned()));
        }
        Ok(Self::File(path.to_path_buf()))
    }

    /// Resolve the reference with a strict maximum size.
    pub fn resolve(&self, max_bytes: usize) -> Result<SecretBytes, SecretError> {
        let bytes = match self {
            Self::Env(name) => std::env::var_os(name)
                .map(|v| v.to_string_lossy().into_owned().into_bytes())
                .ok_or_else(|| {
                    SecretError::InvalidReference(format!("missing environment variable {name}"))
                })?,
            Self::File(path) if path.is_absolute() => read_file(path, max_bytes)?,
            Self::File(_) => {
                return Err(SecretError::InvalidReference(
                    "file reference is absolute for a different platform".into(),
                ));
            }
        };
        if bytes.len() > max_bytes {
            return Err(SecretError::TooLarge(max_bytes));
        }
        Ok(SecretBytes::new(bytes))
    }
}

/// Validate one public age X25519 recipient without accepting plugin recipients.
pub fn validate_age_recipient(value: &str) -> Result<(), SecretError> {
    age::x25519::Recipient::from_str(value)
        .map(|_| ())
        .map_err(|_| SecretError::Envelope)
}

fn portable_absolute_file_path(raw: &str) -> bool {
    (raw.starts_with('/') && !raw.starts_with("//"))
        || windows_drive_absolute(raw)
        || raw.strip_prefix('/').is_some_and(windows_drive_absolute)
}

fn windows_drive_absolute(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn read_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, SecretError> {
    let file = File::open(path)?;
    reject_insecure_permissions(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(unix)]
fn reject_insecure_permissions(metadata: &Metadata) -> Result<(), SecretError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SecretError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_permissions(_metadata: &Metadata) -> Result<(), SecretError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_unapproved_secret_providers() {
        assert!(SecretRef::parse("exec://printenv").is_err());
        assert!(SecretRef::parse("file://relative/key.pem").is_err());
        assert!(SecretRef::parse("file:////server/share/key.pem").is_err());
        assert!(SecretRef::parse("file:///etc/aegisproxy/key.pem").is_ok());
        assert!(SecretRef::parse("file:///C:/aegisproxy/key.pem").is_ok());
        assert!(SecretRef::parse("env://TLS_KEY").is_ok());
    }

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretBytes(Zeroizing::new(b"private-canary".to_vec()));
        let output = format!("{secret:?}");
        assert!(!output.contains("private-canary"));
        assert!(output.contains("REDACTED"));
    }

    #[test]
    fn validates_only_x25519_recipients() {
        use age::secrecy::ExposeSecret;

        let identity = age::x25519::Identity::generate();
        assert!(validate_age_recipient(&identity.to_public().to_string()).is_ok());
        assert!(validate_age_recipient(identity.to_string().expose_secret()).is_err());
        assert!(validate_age_recipient("ssh-ed25519 AAAA").is_err());
    }

    #[test]
    fn bounds_file_secret_reads() {
        let path = std::env::temp_dir().join(format!(
            "aegisproxy-secret-bound-{}.test",
            std::process::id()
        ));
        fs::write(&path, b"too-large").expect("write test secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secure test secret");
        }
        let result = SecretRef::File(path.clone()).resolve(4);
        fs::remove_file(path).expect("remove test secret");
        assert!(matches!(result, Err(SecretError::TooLarge(4))));
    }
}
