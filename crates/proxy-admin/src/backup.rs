//! Bounded encrypted state backups and non-mutating restore validation.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use aegisproxy_secrets::{decrypt_age, encrypt_age};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const BACKUP_SCHEMA_VERSION: u32 = 1;
const MAX_BACKUP_FILES: usize = 20_000;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 96 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DEPTH: usize = 16;
const INCLUDED_ROOTS: [&str; 5] = ["config", "certificates", "acme", "admin", "audit"];

/// Backup creation or validation failure.
#[derive(Debug, Error)]
pub enum BackupError {
    /// Backup filesystem operation failed.
    #[error("backup I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Encryption, authentication, or identity handling failed.
    #[error("backup encryption or authentication failed")]
    Encryption,
    /// Manifest, entry, checksum, or path is invalid.
    #[error("backup manifest is invalid")]
    Invalid,
    /// Backup exceeded a hard resource bound.
    #[error("backup exceeds a configured resource limit")]
    Limit,
    /// Source changed while snapshot bytes were collected.
    #[error("state changed during backup; retry")]
    Changed,
}

/// Redacted backup metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BackupSummary {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Backup creation time as Unix seconds.
    pub created_unix_secs: u64,
    /// Included regular-file count.
    pub file_count: usize,
    /// Total plaintext state bytes.
    pub total_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    schema_version: u32,
    created_unix_secs: u64,
    entries: Vec<BackupEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupEntry {
    path: String,
    mode: u32,
    size: u64,
    sha256: String,
    content_base64: String,
}

impl Drop for BackupEntry {
    fn drop(&mut self) {
        self.content_base64.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    path: PathBuf,
    size: u64,
    modified: Option<SystemTime>,
}

/// Create, encrypt, fsync, verify-size, and atomically publish one backup.
pub fn create_backup(
    state_dir: impl AsRef<Path>,
    output: impl AsRef<Path>,
    recipients: &[String],
) -> Result<BackupSummary, BackupError> {
    let state_dir = state_dir.as_ref();
    let output = output.as_ref();
    validate_state_root(state_dir)?;
    if output.starts_with(state_dir) {
        return Err(BackupError::Invalid);
    }
    let before = collect_stamps(state_dir)?;
    let mut total_bytes = 0_u64;
    let mut entries = Vec::with_capacity(before.len());
    for stamp in &before {
        let bytes = Zeroizing::new(fs::read(&stamp.path)?);
        let metadata = fs::symlink_metadata(&stamp.path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || bytes.len() as u64 != stamp.size
            || metadata.modified().ok() != stamp.modified
        {
            return Err(BackupError::Changed);
        }
        total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(BackupError::Limit)?;
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(BackupError::Limit);
        }
        let relative = stamp
            .path
            .strip_prefix(state_dir)
            .map_err(|_| BackupError::Invalid)?;
        let path = portable_path(relative)?;
        entries.push(BackupEntry {
            path,
            mode: file_mode(&metadata),
            size: bytes.len() as u64,
            sha256: hex(&Sha256::digest(&bytes)),
            content_base64: STANDARD.encode(bytes.as_slice()),
        });
    }
    if before != collect_stamps(state_dir)? {
        return Err(BackupError::Changed);
    }
    let created_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackupError::Invalid)?
        .as_secs();
    let manifest = BackupManifest {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_unix_secs,
        entries,
    };
    validate_manifest(&manifest)?;
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&manifest).map_err(|_| BackupError::Invalid)?);
    if plaintext.len() > MAX_MANIFEST_BYTES {
        return Err(BackupError::Limit);
    }
    let ciphertext = encrypt_age(&plaintext, recipients).map_err(|_| BackupError::Encryption)?;
    if ciphertext.len() as u64 > MAX_CIPHERTEXT_BYTES {
        return Err(BackupError::Limit);
    }
    write_atomic_private(output, &ciphertext)?;
    Ok(BackupSummary {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_unix_secs,
        file_count: manifest.entries.len(),
        total_bytes,
    })
}

/// Decrypt and validate a backup without writing restored state.
pub fn validate_backup(
    input: impl AsRef<Path>,
    identity_source: &[u8],
) -> Result<BackupSummary, BackupError> {
    let metadata = fs::symlink_metadata(input.as_ref())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(BackupError::Invalid);
    }
    let ciphertext = fs::read(input)?;
    let plaintext = decrypt_age(&ciphertext, identity_source, MAX_MANIFEST_BYTES)
        .map_err(|_| BackupError::Encryption)?;
    let manifest: BackupManifest =
        serde_json::from_slice(plaintext.as_ref()).map_err(|_| BackupError::Invalid)?;
    let total_bytes = validate_manifest(&manifest)?;
    Ok(BackupSummary {
        schema_version: manifest.schema_version,
        created_unix_secs: manifest.created_unix_secs,
        file_count: manifest.entries.len(),
        total_bytes,
    })
}

fn validate_manifest(manifest: &BackupManifest) -> Result<u64, BackupError> {
    if manifest.schema_version != BACKUP_SCHEMA_VERSION || manifest.entries.len() > MAX_BACKUP_FILES
    {
        return Err(BackupError::Invalid);
    }
    let mut paths = HashSet::with_capacity(manifest.entries.len());
    let mut total = 0_u64;
    for entry in &manifest.entries {
        if !safe_manifest_path(&entry.path)
            || !paths.insert(entry.path.as_str())
            || entry.size > MAX_FILE_BYTES
            || !matches!(entry.mode, 0o600 | 0o640 | 0o644)
        {
            return Err(BackupError::Invalid);
        }
        let content = Zeroizing::new(
            STANDARD
                .decode(&entry.content_base64)
                .map_err(|_| BackupError::Invalid)?,
        );
        if content.len() as u64 != entry.size || hex(&Sha256::digest(&content)) != entry.sha256 {
            return Err(BackupError::Invalid);
        }
        total = total.checked_add(entry.size).ok_or(BackupError::Limit)?;
        if total > MAX_TOTAL_BYTES {
            return Err(BackupError::Limit);
        }
    }
    Ok(total)
}

fn collect_stamps(state_dir: &Path) -> Result<Vec<FileStamp>, BackupError> {
    let mut output = Vec::new();
    for root in INCLUDED_ROOTS {
        let path = state_dir.join(root);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                collect_directory(&path, 0, &mut output)?;
            }
            Ok(_) => return Err(BackupError::Invalid),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    output.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    if output.len() > MAX_BACKUP_FILES {
        return Err(BackupError::Limit);
    }
    Ok(output)
}

fn collect_directory(
    directory: &Path,
    depth: usize,
    output: &mut Vec<FileStamp>,
) -> Result<(), BackupError> {
    if depth > MAX_DEPTH {
        return Err(BackupError::Limit);
    }
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_unstable_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(BackupError::Invalid);
        }
        if metadata.is_dir() {
            collect_directory(&path, depth + 1, output)?;
        } else if metadata.is_file() && !excluded_file(&path) {
            if metadata.len() > MAX_FILE_BYTES || output.len() >= MAX_BACKUP_FILES {
                return Err(BackupError::Limit);
            }
            output.push(FileStamp {
                path,
                size: metadata.len(),
                modified: metadata.modified().ok(),
            });
        } else if !metadata.is_file() {
            return Err(BackupError::Invalid);
        }
    }
    Ok(())
}

fn excluded_file(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "owner.lock")
        || path
            .extension()
            .is_some_and(|extension| extension == "lock")
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with('.') && name.ends_with(".tmp"))
}

fn validate_state_root(path: &Path) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(BackupError::Invalid);
    }
    reject_insecure_state_permissions(&metadata)?;
    Ok(())
}

fn portable_path(path: &Path) -> Result<String, BackupError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(BackupError::Invalid);
        };
        let part = part.to_str().ok_or(BackupError::Invalid)?;
        if part.is_empty() || part.len() > 255 || part.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(BackupError::Invalid);
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(BackupError::Invalid);
    }
    Ok(parts.join("/"))
}

fn safe_manifest_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 4_096 || path.contains('\\') || path.starts_with('/') {
        return false;
    }
    let components = path.split('/').collect::<Vec<_>>();
    let Some(root) = components.first() else {
        return false;
    };
    INCLUDED_ROOTS.contains(root)
        && components.len() >= 2
        && components[1..].iter().all(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && part.len() <= 255
                && !part.bytes().any(|byte| byte.is_ascii_control())
        })
}

fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    let parent = path.parent().ok_or(BackupError::Invalid)?;
    if !parent.is_dir() {
        return Err(BackupError::Invalid);
    }
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| BackupError::Encryption)?;
    let temporary = parent.join(format!(".backup-{}.tmp", URL_SAFE_NO_PAD.encode(suffix)));
    let result = write_private(&temporary, bytes).and_then(|()| {
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(BackupError::Io)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
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
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0o600
}

#[cfg(unix)]
fn reject_insecure_state_permissions(metadata: &fs::Metadata) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(BackupError::Invalid);
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_state_permissions(_metadata: &fs::Metadata) -> Result<(), BackupError> {
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[(byte >> 4) as usize]));
        output.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;

    use age::{secrecy::ExposeSecret, x25519};

    use super::{BackupError, create_backup, validate_backup};

    #[test]
    fn encrypted_backup_validates_and_tampering_fails() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("aegisproxy-backup-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let state = root.join("state");
        let output = root.join("backup.age");
        fs::create_dir_all(state.join("config/revisions")).expect("directories");
        #[cfg(unix)]
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("permissions");
        fs::write(
            state.join("config/revisions/one.toml"),
            b"backup-private-canary",
        )
        .expect("state");
        let identity = x25519::Identity::generate();
        let summary =
            create_backup(&state, &output, &[identity.to_public().to_string()]).expect("backup");
        assert_eq!(summary.file_count, 1);
        let ciphertext = fs::read(&output).expect("read");
        assert!(
            !ciphertext
                .windows(b"backup-private-canary".len())
                .any(|window| window == b"backup-private-canary")
        );
        let identity = identity.to_string();
        assert_eq!(
            validate_backup(&output, identity.expose_secret().as_bytes())
                .expect("validate")
                .total_bytes,
            21
        );
        let last = ciphertext.len() - 1;
        let mut tampered = ciphertext;
        tampered[last] ^= 1;
        fs::write(&output, tampered).expect("tamper");
        assert!(matches!(
            validate_backup(&output, identity.expose_secret().as_bytes()),
            Err(BackupError::Encryption)
        ));
        fs::remove_dir_all(root).expect("remove");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_state_entries() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = std::env::temp_dir().join(format!(
            "aegisproxy-backup-link-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let state = root.join("state");
        fs::create_dir_all(state.join("config")).expect("directories");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("permissions");
        symlink("/etc/passwd", state.join("config/escape")).expect("symlink");
        let identity = x25519::Identity::generate();
        assert!(matches!(
            create_backup(
                &state,
                root.join("backup.age"),
                &[identity.to_public().to_string()]
            ),
            Err(BackupError::Invalid)
        ));
        fs::remove_dir_all(root).expect("remove");
    }
}
