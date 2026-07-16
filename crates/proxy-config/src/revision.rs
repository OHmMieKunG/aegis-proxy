//! Locked, immutable configuration candidate persistence.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{Config, MAX_CONFIG_BYTES, validate};

const MAX_REVISIONS: usize = 1_000;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_SOURCE_BYTES: usize = 128;

static OWNED_STATE_DIRS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[derive(Debug)]
struct StateRegistration(PathBuf);

impl Drop for StateRegistration {
    fn drop(&mut self) {
        let owned = OWNED_STATE_DIRS.get_or_init(Default::default);
        owned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.0);
    }
}

/// Durable immutable revision metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionMetadata {
    /// Stable sequence-and-hash revision identifier.
    pub id: String,
    /// Monotonic sequence within one state directory.
    pub sequence: u64,
    /// Lowercase SHA-256 of canonical TOML bytes.
    pub hash: String,
    /// Candidate creation time as Unix seconds.
    pub created_unix_secs: u64,
    /// Bounded operator or provider source label.
    pub source: String,
}

/// Revision persistence failure.
#[derive(Debug, Error)]
pub enum RevisionError {
    /// Filesystem operation failed.
    #[error("revision storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Another process owns this state directory.
    #[error("revision state directory is already locked")]
    Locked,
    /// Candidate configuration is invalid.
    #[error("candidate configuration is invalid: {0}")]
    InvalidConfig(String),
    /// Revision or metadata serialization failed.
    #[error("revision serialization failed: {0}")]
    Serialization(String),
    /// Stored revision failed integrity or schema checks.
    #[error("stored revision is invalid: {0}")]
    InvalidStored(String),
    /// Revision retention bound was reached.
    #[error("revision count reached the hard limit of {MAX_REVISIONS}")]
    Limit,
}

/// Exclusive owner of one file-backed revision state directory.
#[derive(Debug)]
pub struct RevisionStore {
    config_dir: PathBuf,
    _registration: StateRegistration,
    _lock: File,
    next_sequence: Mutex<u64>,
}

impl RevisionStore {
    /// Open and exclusively lock a state directory.
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self, RevisionError> {
        let config_dir = state_dir.as_ref().join("config");
        let revisions = config_dir.join("revisions");
        let metadata = config_dir.join("metadata");
        create_private_dir(&config_dir)?;
        create_private_dir(&revisions)?;
        create_private_dir(&metadata)?;
        let registration = register_state_dir(&config_dir)?;
        let lock_path = config_dir.join("owner.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        secure_file_permissions(&lock)?;
        lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                RevisionError::Locked
            } else {
                RevisionError::Io(error)
            }
        })?;
        let next_sequence = scan_next_sequence(&revisions)?;
        Ok(Self {
            config_dir,
            _registration: registration,
            _lock: lock,
            next_sequence: Mutex::new(next_sequence),
        })
    }

    /// Persist a validated immutable candidate, deduplicated by canonical content hash.
    pub fn create_candidate(
        &self,
        config: &Config,
        source: &str,
    ) -> Result<RevisionMetadata, RevisionError> {
        validate(config).map_err(|error| RevisionError::InvalidConfig(error.to_string()))?;
        validate_source(source)?;
        let canonical = toml::to_string_pretty(config)
            .map_err(|error| RevisionError::Serialization(error.to_string()))?
            .into_bytes();
        if canonical.len() > MAX_CONFIG_BYTES {
            return Err(RevisionError::InvalidConfig(
                "canonical candidate exceeds configuration size limit".into(),
            ));
        }
        let hash = hex_sha256(&canonical);
        if let Some(existing) = self
            .list()?
            .into_iter()
            .find(|revision| revision.hash == hash)
        {
            return Ok(existing);
        }
        if revision_count(&self.config_dir.join("revisions"))? >= MAX_REVISIONS {
            return Err(RevisionError::Limit);
        }
        let mut sequence = self
            .next_sequence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = *sequence;
        *sequence = sequence
            .checked_add(1)
            .ok_or_else(|| RevisionError::InvalidStored("revision sequence overflow".into()))?;
        drop(sequence);
        let id = format!("{current:020}-{hash}");
        let metadata = RevisionMetadata {
            id: id.clone(),
            sequence: current,
            hash,
            created_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| {
                    RevisionError::InvalidStored("system clock predates Unix epoch".into())
                })?
                .as_secs(),
            source: source.to_owned(),
        };
        write_new_synced(
            &self.config_dir.join("revisions").join(format!("{id}.toml")),
            &canonical,
        )?;
        let metadata_bytes = serde_json::to_vec_pretty(&metadata)
            .map_err(|error| RevisionError::Serialization(error.to_string()))?;
        write_new_synced(
            &self.config_dir.join("metadata").join(format!("{id}.json")),
            &metadata_bytes,
        )?;
        sync_directory(&self.config_dir.join("revisions"))?;
        sync_directory(&self.config_dir.join("metadata"))?;
        Ok(metadata)
    }

    /// Load and integrity-check one immutable revision.
    pub fn load(&self, id: &str) -> Result<Config, RevisionError> {
        validate_revision_id(id)?;
        let metadata = self.load_metadata(id)?;
        let bytes = read_bounded(
            &self.config_dir.join("revisions").join(format!("{id}.toml")),
            MAX_CONFIG_BYTES,
        )?;
        if hex_sha256(&bytes) != metadata.hash {
            return Err(RevisionError::InvalidStored(
                "revision content hash does not match metadata".into(),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| RevisionError::InvalidStored("revision is not UTF-8".into()))?;
        let config: Config = toml::from_str(text)
            .map_err(|error| RevisionError::InvalidStored(error.to_string()))?;
        validate(&config).map_err(|error| RevisionError::InvalidStored(error.to_string()))?;
        Ok(config)
    }

    /// List complete candidate metadata in sequence order.
    pub fn list(&self) -> Result<Vec<RevisionMetadata>, RevisionError> {
        let mut revisions = Vec::new();
        for entry in fs::read_dir(self.config_dir.join("metadata"))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(id) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            if validate_revision_id(id).is_err() {
                continue;
            }
            revisions.push(self.load_metadata(id)?);
            if revisions.len() > MAX_REVISIONS {
                return Err(RevisionError::Limit);
            }
        }
        revisions.sort_unstable_by_key(|revision| revision.sequence);
        Ok(revisions)
    }

    fn load_metadata(&self, id: &str) -> Result<RevisionMetadata, RevisionError> {
        let bytes = read_bounded(
            &self.config_dir.join("metadata").join(format!("{id}.json")),
            MAX_METADATA_BYTES,
        )?;
        let metadata: RevisionMetadata = serde_json::from_slice(&bytes)
            .map_err(|error| RevisionError::InvalidStored(error.to_string()))?;
        if metadata.id != id
            || metadata.hash.len() != 64
            || !metadata
                .hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || id != format!("{:020}-{}", metadata.sequence, metadata.hash)
        {
            return Err(RevisionError::InvalidStored(
                "revision metadata identity is inconsistent".into(),
            ));
        }
        validate_source(&metadata.source)?;
        Ok(metadata)
    }
}

fn register_state_dir(config_dir: &Path) -> Result<StateRegistration, RevisionError> {
    let path = config_dir.canonicalize()?;
    let owned = OWNED_STATE_DIRS.get_or_init(Default::default);
    let mut owned = owned
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !owned.insert(path.clone()) {
        return Err(RevisionError::Locked);
    }
    Ok(StateRegistration(path))
}

fn validate_source(source: &str) -> Result<(), RevisionError> {
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES || source.chars().any(char::is_control)
    {
        return Err(RevisionError::InvalidStored(
            "revision source is empty, oversized, or contains control characters".into(),
        ));
    }
    Ok(())
}

fn validate_revision_id(id: &str) -> Result<(), RevisionError> {
    if id.len() != 85
        || id.as_bytes().get(20) != Some(&b'-')
        || !id[..20].bytes().all(|byte| byte.is_ascii_digit())
        || !id[21..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RevisionError::InvalidStored("invalid revision ID".into()));
    }
    Ok(())
}

fn scan_next_sequence(revisions: &Path) -> Result<u64, RevisionError> {
    let mut next = 1_u64;
    for entry in fs::read_dir(revisions)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(sequence) = name.get(..20).and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        next = next.max(sequence.saturating_add(1));
    }
    Ok(next)
}

fn revision_count(revisions: &Path) -> Result<usize, RevisionError> {
    Ok(fs::read_dir(revisions)?
        .filter_map(Result::ok)
        .take(MAX_REVISIONS + 1)
        .count())
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), RevisionError> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    secure_file_permissions(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, RevisionError> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(RevisionError::InvalidStored(
            "stored file exceeds its size bound".into(),
        ));
    }
    Ok(bytes)
}

fn create_private_dir(path: &Path) -> Result<(), RevisionError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn secure_file_permissions(file: &File) -> Result<(), RevisionError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), RevisionError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), RevisionError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        AdminConfig, LimitsConfig, ListenerConfig, RuntimeConfig, TlsConfig, TrustedProxyConfig,
    };

    fn config() -> Config {
        Config {
            schema_version: 1,
            runtime: RuntimeConfig::default(),
            limits: LimitsConfig::default(),
            listeners: vec![ListenerConfig {
                id: "http".into(),
                bind: "127.0.0.1:8080".parse().expect("listener address"),
                protocol: "http".into(),
                certificates: vec![],
            }],
            tls: TlsConfig::default(),
            certificates: vec![],
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![],
            middlewares: BTreeMap::new(),
            routes: vec![],
            admin: AdminConfig::default(),
        }
    }

    fn temporary_state() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegisproxy-revisions-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ))
    }

    #[test]
    fn candidate_round_trip_deduplicates_and_detects_tampering() {
        let state = temporary_state();
        let store = RevisionStore::open(&state).expect("store");
        let metadata = store
            .create_candidate(&config(), "test")
            .expect("candidate");
        assert_eq!(store.load(&metadata.id).expect("load").schema_version, 1);
        assert_eq!(
            store.create_candidate(&config(), "second").expect("dedupe"),
            metadata
        );
        assert_eq!(store.list().expect("list"), vec![metadata.clone()]);
        fs::write(
            state
                .join("config/revisions")
                .join(format!("{}.toml", metadata.id)),
            b"schema_version = 2\n",
        )
        .expect("tamper");
        assert!(matches!(
            store.load(&metadata.id),
            Err(RevisionError::InvalidStored(_))
        ));
        drop(store);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn state_directory_has_one_owner_and_ids_cannot_traverse() {
        let state = temporary_state();
        let store = RevisionStore::open(&state).expect("store");
        assert!(matches!(
            RevisionStore::open(&state),
            Err(RevisionError::Locked)
        ));
        assert!(matches!(
            store.load("../active"),
            Err(RevisionError::InvalidStored(_))
        ));
        assert!(store.create_candidate(&config(), "bad\nsource").is_err());
        drop(store);
        fs::remove_dir_all(state).expect("cleanup");
    }
}
