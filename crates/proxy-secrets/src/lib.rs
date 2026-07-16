#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Secret references. Values are resolved only at explicit activation time.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use thiserror::Error;

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
        let path = Path::new(raw);
        if !path.is_absolute() || raw.contains("..") {
            return Err(SecretError::InvalidReference(value.to_owned()));
        }
        Ok(Self::File(path.to_path_buf()))
    }

    /// Resolve the reference with a strict maximum size.
    pub fn resolve(&self, max_bytes: usize) -> Result<Vec<u8>, SecretError> {
        let bytes = match self {
            Self::Env(name) => std::env::var_os(name)
                .map(|v| v.to_string_lossy().into_owned().into_bytes())
                .ok_or_else(|| {
                    SecretError::InvalidReference(format!("missing environment variable {name}"))
                })?,
            Self::File(path) => fs::read(path)?,
        };
        if bytes.len() > max_bytes {
            return Err(SecretError::TooLarge(max_bytes));
        }
        Ok(bytes)
    }
}
