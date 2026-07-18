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
const RETAIN_RECENT_REVISIONS: usize = 70;
const MIN_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 64 * 1024;
const MAX_SOURCE_BYTES: usize = 128;
const STATE_SCHEMA_VERSION: u32 = 1;

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

/// Integrity-bound reference to an immutable revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionTarget {
    /// Immutable revision identifier.
    pub id: String,
    /// Revision sequence copied from metadata.
    pub sequence: u64,
    /// Revision content hash copied from metadata.
    pub hash: String,
}

/// Durable current and immediately previous revision pointer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePointer {
    /// Pointer format version.
    pub schema_version: u32,
    /// Revision selected for startup and request handling.
    pub active: RevisionTarget,
    /// Last committed revision retained for rollback.
    pub previous: Option<RevisionTarget>,
}

/// Durable activation state used for crash recovery.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationPhase {
    /// Intent is durable; pointer may or may not have switched.
    Intent,
    /// Runtime was published and is undergoing structural probation.
    Probation,
    /// Candidate completed probation.
    Committed,
    /// Previous revision was durably restored.
    RolledBack,
}

/// Single-writer activation journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationJournal {
    /// Journal format version.
    pub schema_version: u32,
    /// Candidate under activation.
    pub candidate: RevisionTarget,
    /// Revision to restore after an incomplete activation.
    pub previous: Option<RevisionTarget>,
    /// Current durable phase.
    pub phase: ActivationPhase,
    /// Journal creation time as Unix seconds.
    pub created_unix_secs: u64,
    /// Last durable transition time as Unix seconds.
    pub updated_unix_secs: u64,
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
    /// Compare-and-swap or journal state did not match.
    #[error("revision activation conflict")]
    Conflict,
}

/// Exclusive owner of one file-backed revision state directory.
#[derive(Debug)]
pub struct RevisionStore {
    config_dir: PathBuf,
    _registration: StateRegistration,
    _lock: File,
    next_sequence: Mutex<u64>,
    mutation: Mutex<()>,
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
            mutation: Mutex::new(()),
        })
    }

    /// Persist a validated immutable candidate, deduplicated by canonical content hash.
    pub fn create_candidate(
        &self,
        config: &Config,
        source: &str,
    ) -> Result<RevisionMetadata, RevisionError> {
        self.persist_candidate(config, source, true)
    }

    /// Persist a new forward revision even when content matches a retained revision.
    pub fn create_forward_revision(
        &self,
        config: &Config,
        source: &str,
    ) -> Result<RevisionMetadata, RevisionError> {
        self.persist_candidate(config, source, false)
    }

    fn persist_candidate(
        &self,
        config: &Config,
        source: &str,
        deduplicate: bool,
    ) -> Result<RevisionMetadata, RevisionError> {
        let _guard = self
            .mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let revisions = self.list()?;
        if let (true, Some(existing)) = (
            deduplicate,
            revisions.iter().find(|revision| revision.hash == hash),
        ) {
            return Ok(existing.clone());
        }
        self.prune_revisions(&revisions)?;
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

    /// Load and verify the active pointer and every referenced revision.
    pub fn active(&self) -> Result<Option<ActivePointer>, RevisionError> {
        let path = self.config_dir.join("active.json");
        let Some(pointer) = read_optional_json::<ActivePointer>(&path)? else {
            return Ok(None);
        };
        self.validate_pointer(&pointer)?;
        Ok(Some(pointer))
    }

    /// Durably record activation intent and switch the active pointer.
    ///
    /// `expected_active` is an exact compare-and-swap precondition. `None` means
    /// that no active revision may exist.
    pub fn begin_activation(
        &self,
        candidate_id: &str,
        expected_active: Option<&str>,
    ) -> Result<ActivationJournal, RevisionError> {
        let _guard = self
            .mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let candidate = self.revision_target(candidate_id)?;
        let current = self.active()?;
        if current.as_ref().map(|pointer| pointer.active.id.as_str()) != expected_active {
            return Err(RevisionError::Conflict);
        }
        let now = unix_time()?;
        let journal = ActivationJournal {
            schema_version: STATE_SCHEMA_VERSION,
            candidate: candidate.clone(),
            previous: current.as_ref().map(|pointer| pointer.active.clone()),
            phase: ActivationPhase::Intent,
            created_unix_secs: now,
            updated_unix_secs: now,
        };
        self.write_journal(&journal)?;
        self.write_pointer(&ActivePointer {
            schema_version: STATE_SCHEMA_VERSION,
            active: candidate,
            previous: journal.previous.clone(),
        })?;
        Ok(journal)
    }

    /// Mark a published candidate as undergoing structural probation.
    pub fn mark_probation(&self, candidate_id: &str) -> Result<(), RevisionError> {
        let _guard = self
            .mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.transition_journal(
            candidate_id,
            ActivationPhase::Intent,
            ActivationPhase::Probation,
        )
    }

    /// Mark a candidate as committed after structural probation succeeds.
    pub fn commit_activation(&self, candidate_id: &str) -> Result<(), RevisionError> {
        let _guard = self
            .mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.transition_journal(
            candidate_id,
            ActivationPhase::Probation,
            ActivationPhase::Committed,
        )
    }

    /// Restore the previous revision and mark the activation rolled back.
    pub fn rollback_activation(
        &self,
        candidate_id: &str,
    ) -> Result<Option<ActivePointer>, RevisionError> {
        let _guard = self
            .mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let journal = self.load_journal()?.ok_or(RevisionError::Conflict)?;
        if journal.candidate.id != candidate_id
            || !matches!(
                journal.phase,
                ActivationPhase::Intent | ActivationPhase::Probation
            )
        {
            return Err(RevisionError::Conflict);
        }
        self.restore_previous(&journal)?;
        let mut rolled_back = journal;
        rolled_back.phase = ActivationPhase::RolledBack;
        rolled_back.updated_unix_secs = unix_time()?;
        self.write_journal(&rolled_back)?;
        self.active()
    }

    /// Recover an incomplete activation before serving startup traffic.
    pub fn recover_incomplete(&self) -> Result<Option<ActivePointer>, RevisionError> {
        let Some(journal) = self.load_journal()? else {
            return self.active();
        };
        if matches!(
            journal.phase,
            ActivationPhase::Intent | ActivationPhase::Probation
        ) {
            return self.rollback_activation(&journal.candidate.id);
        }
        self.active()
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

    fn revision_target(&self, id: &str) -> Result<RevisionTarget, RevisionError> {
        validate_revision_id(id)?;
        let metadata = self.load_metadata(id)?;
        self.load(id)?;
        Ok(RevisionTarget {
            id: metadata.id,
            sequence: metadata.sequence,
            hash: metadata.hash,
        })
    }

    fn validate_pointer(&self, pointer: &ActivePointer) -> Result<(), RevisionError> {
        if pointer.schema_version != STATE_SCHEMA_VERSION
            || pointer.previous.as_ref() == Some(&pointer.active)
        {
            return Err(RevisionError::InvalidStored(
                "active pointer schema or references are invalid".into(),
            ));
        }
        self.validate_target(&pointer.active)?;
        if let Some(previous) = &pointer.previous {
            self.validate_target(previous)?;
        }
        Ok(())
    }

    fn validate_target(&self, target: &RevisionTarget) -> Result<(), RevisionError> {
        let expected = self.revision_target(&target.id)?;
        if expected != *target {
            return Err(RevisionError::InvalidStored(
                "revision target does not match immutable metadata".into(),
            ));
        }
        Ok(())
    }

    fn load_journal(&self) -> Result<Option<ActivationJournal>, RevisionError> {
        let journal =
            read_optional_json::<ActivationJournal>(&self.config_dir.join("activation.json"))?;
        if let Some(journal) = &journal {
            if journal.schema_version != STATE_SCHEMA_VERSION
                || journal.updated_unix_secs < journal.created_unix_secs
                || journal.previous.as_ref() == Some(&journal.candidate)
            {
                return Err(RevisionError::InvalidStored(
                    "activation journal schema or references are invalid".into(),
                ));
            }
            self.validate_target(&journal.candidate)?;
            if let Some(previous) = &journal.previous {
                self.validate_target(previous)?;
            }
        }
        Ok(journal)
    }

    fn transition_journal(
        &self,
        candidate_id: &str,
        from: ActivationPhase,
        to: ActivationPhase,
    ) -> Result<(), RevisionError> {
        let mut journal = self.load_journal()?.ok_or(RevisionError::Conflict)?;
        if journal.candidate.id != candidate_id || journal.phase != from {
            return Err(RevisionError::Conflict);
        }
        let pointer = self.active()?.ok_or(RevisionError::Conflict)?;
        if pointer.active != journal.candidate {
            return Err(RevisionError::Conflict);
        }
        journal.phase = to;
        journal.updated_unix_secs = unix_time()?;
        self.write_journal(&journal)
    }

    fn restore_previous(&self, journal: &ActivationJournal) -> Result<(), RevisionError> {
        match &journal.previous {
            Some(previous) => self.write_pointer(&ActivePointer {
                schema_version: STATE_SCHEMA_VERSION,
                active: previous.clone(),
                previous: None,
            }),
            None => remove_synced(&self.config_dir.join("active.json")),
        }
    }

    fn write_pointer(&self, pointer: &ActivePointer) -> Result<(), RevisionError> {
        self.validate_pointer(pointer)?;
        write_json_atomic(&self.config_dir.join("active.json"), pointer)
    }

    fn write_journal(&self, journal: &ActivationJournal) -> Result<(), RevisionError> {
        write_json_atomic(&self.config_dir.join("activation.json"), journal)
    }

    fn prune_revisions(&self, revisions: &[RevisionMetadata]) -> Result<(), RevisionError> {
        if revisions.len() <= RETAIN_RECENT_REVISIONS {
            return Ok(());
        }
        let mut protected = HashSet::new();
        if let Some(pointer) = self.active()? {
            protected.insert(pointer.active.id);
            if let Some(previous) = pointer.previous {
                protected.insert(previous.id);
            }
        }
        if let Some(journal) = self.load_journal()? {
            protected.insert(journal.candidate.id);
            if let Some(previous) = journal.previous {
                protected.insert(previous.id);
            }
        }
        let cutoff = unix_time()?.saturating_sub(MIN_RETENTION_SECS);
        let prune_before = revisions.len() - RETAIN_RECENT_REVISIONS;
        for revision in &revisions[..prune_before] {
            if revision.created_unix_secs > cutoff || protected.contains(&revision.id) {
                continue;
            }
            remove_synced(
                &self
                    .config_dir
                    .join("metadata")
                    .join(format!("{}.json", revision.id)),
            )?;
            remove_synced(
                &self
                    .config_dir
                    .join("revisions")
                    .join(format!("{}.toml", revision.id)),
            )?;
        }
        Ok(())
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

fn read_optional_json<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<Option<T>, RevisionError> {
    let bytes = match read_bounded(path, MAX_STATE_BYTES) {
        Ok(bytes) => bytes,
        Err(RevisionError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| RevisionError::InvalidStored(error.to_string()))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), RevisionError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| RevisionError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(RevisionError::Serialization(
            "durable state exceeds its size bound".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| RevisionError::InvalidStored("state path has no parent".into()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RevisionError::InvalidStored("state path is not UTF-8".into()))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RevisionError::InvalidStored("system clock predates Unix epoch".into()))?
            .as_nanos()
    ));
    write_new_synced(&temporary, &bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(RevisionError::Io(error));
    }
    sync_directory(parent)
}

fn remove_synced(path: &Path) -> Result<(), RevisionError> {
    match fs::remove_file(path) {
        Ok(()) => sync_directory(
            path.parent()
                .ok_or_else(|| RevisionError::InvalidStored("state path has no parent".into()))?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RevisionError::Io(error)),
    }
}

fn unix_time() -> Result<u64, RevisionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RevisionError::InvalidStored("system clock predates Unix epoch".into()))
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
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{
        AdminConfig, LimitsConfig, ListenerConfig, ObservabilityConfig, RuntimeConfig, TlsConfig,
        TrustedProxyConfig,
    };

    fn config() -> Config {
        config_on(8080)
    }

    fn config_on(port: u16) -> Config {
        Config {
            schema_version: 1,
            runtime: RuntimeConfig::default(),
            limits: LimitsConfig::default(),
            listeners: vec![ListenerConfig {
                id: "http".into(),
                bind: format!("127.0.0.1:{port}")
                    .parse()
                    .expect("listener address"),
                protocol: "http".into(),
                certificates: vec![],
            }],
            tls: TlsConfig::default(),
            certificates: vec![],
            acme: crate::AcmeConfig::default(),
            trusted_proxies: TrustedProxyConfig::default(),
            upstream_groups: vec![],
            middlewares: BTreeMap::new(),
            routes: vec![],
            admin: AdminConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }

    fn temporary_state() -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "aegisproxy-revisions-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
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

    #[test]
    fn activation_is_compare_and_swap_and_rollback_restores_previous() {
        let state = temporary_state();
        let store = RevisionStore::open(&state).expect("store");
        let first = store
            .create_candidate(&config_on(8080), "first")
            .expect("first");
        store
            .begin_activation(&first.id, None)
            .expect("first intent");
        store.mark_probation(&first.id).expect("first probation");
        store.commit_activation(&first.id).expect("first commit");

        let second = store
            .create_candidate(&config_on(8081), "second")
            .expect("second");
        store
            .begin_activation(&second.id, Some(&first.id))
            .expect("second intent");
        assert!(matches!(
            store.begin_activation(&first.id, Some(&first.id)),
            Err(RevisionError::Conflict)
        ));
        store.mark_probation(&second.id).expect("second probation");
        let restored = store
            .rollback_activation(&second.id)
            .expect("rollback")
            .expect("active pointer");
        assert_eq!(restored.active.id, first.id);
        assert_eq!(
            store
                .load_journal()
                .expect("journal")
                .expect("journal")
                .phase,
            ActivationPhase::RolledBack
        );
        drop(store);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn restart_recovers_incomplete_probation() {
        let state = temporary_state();
        let store = RevisionStore::open(&state).expect("store");
        let first = store
            .create_candidate(&config_on(8080), "first")
            .expect("first");
        store
            .begin_activation(&first.id, None)
            .expect("first intent");
        store.mark_probation(&first.id).expect("first probation");
        store.commit_activation(&first.id).expect("first commit");
        let second = store
            .create_candidate(&config_on(8081), "second")
            .expect("second");
        store
            .begin_activation(&second.id, Some(&first.id))
            .expect("second intent");
        store.mark_probation(&second.id).expect("second probation");
        drop(store);

        let reopened = RevisionStore::open(&state).expect("reopen");
        let recovered = reopened
            .recover_incomplete()
            .expect("recovery")
            .expect("active pointer");
        assert_eq!(recovered.active.id, first.id);
        assert_eq!(
            reopened
                .load_journal()
                .expect("journal")
                .expect("journal")
                .phase,
            ActivationPhase::RolledBack
        );
        drop(reopened);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn restart_recovers_intent_written_before_pointer_switch() {
        let state = temporary_state();
        let store = RevisionStore::open(&state).expect("store");
        let first = store
            .create_candidate(&config_on(8080), "first")
            .expect("first");
        store
            .begin_activation(&first.id, None)
            .expect("first intent");
        store.mark_probation(&first.id).expect("first probation");
        store.commit_activation(&first.id).expect("first commit");
        let second = store
            .create_candidate(&config_on(8081), "second")
            .expect("second");
        let now = unix_time().expect("time");
        store
            .write_journal(&ActivationJournal {
                schema_version: STATE_SCHEMA_VERSION,
                candidate: store.revision_target(&second.id).expect("second target"),
                previous: Some(store.revision_target(&first.id).expect("first target")),
                phase: ActivationPhase::Intent,
                created_unix_secs: now,
                updated_unix_secs: now,
            })
            .expect("intent journal");
        drop(store);

        let reopened = RevisionStore::open(&state).expect("reopen");
        let recovered = reopened
            .recover_incomplete()
            .expect("recovery")
            .expect("active");
        assert_eq!(recovered.active.id, first.id);
        drop(reopened);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn restart_keeps_fully_committed_pointer() {
        let state = temporary_state();
        let store = RevisionStore::open(&state).expect("store");
        let first = store
            .create_candidate(&config_on(8080), "first")
            .expect("first");
        store
            .begin_activation(&first.id, None)
            .expect("first intent");
        store.mark_probation(&first.id).expect("first probation");
        store.commit_activation(&first.id).expect("first commit");
        drop(store);

        let reopened = RevisionStore::open(&state).expect("reopen");
        let recovered = reopened
            .recover_incomplete()
            .expect("recovery")
            .expect("active");
        assert_eq!(recovered.active.id, first.id);
        drop(reopened);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn concurrent_identical_candidates_deduplicate() {
        let state = temporary_state();
        let store = Arc::new(RevisionStore::open(&state).expect("store"));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    store
                        .create_candidate(&config(), "concurrent")
                        .expect("candidate")
                        .id
                })
            })
            .collect();
        let ids: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().expect("thread"))
            .collect();
        assert!(ids.iter().all(|id| id == &ids[0]));
        assert_eq!(store.list().expect("list").len(), 1);
        drop(store);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn rollback_content_creates_a_new_forward_revision() {
        let state = temporary_state();
        let store = RevisionStore::open(&state).expect("store");
        let original = store
            .create_candidate(&config(), "original")
            .expect("original");
        let forward = store
            .create_forward_revision(&config(), "rollback")
            .expect("forward revision");
        assert_ne!(forward.id, original.id);
        assert!(forward.sequence > original.sequence);
        assert_eq!(forward.hash, original.hash);
        assert_eq!(
            toml::to_string(&store.load(&forward.id).expect("forward config"))
                .expect("stored TOML"),
            toml::to_string(&config()).expect("expected TOML")
        );
        drop(store);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn retention_prunes_old_candidates_but_protects_rollback_targets() {
        let state = temporary_state();
        let store = RevisionStore::open(&state).expect("store");
        let mut revisions = Vec::new();
        for poll_secs in 1..=73 {
            let mut candidate = config();
            candidate.runtime.config_poll_secs = poll_secs;
            revisions.push(
                store
                    .create_candidate(&candidate, "retention")
                    .expect("candidate"),
            );
        }
        store
            .begin_activation(&revisions[0].id, None)
            .expect("first intent");
        store
            .mark_probation(&revisions[0].id)
            .expect("first probation");
        store
            .commit_activation(&revisions[0].id)
            .expect("first commit");
        store
            .begin_activation(&revisions[1].id, Some(&revisions[0].id))
            .expect("second intent");
        store
            .mark_probation(&revisions[1].id)
            .expect("second probation");
        store
            .commit_activation(&revisions[1].id)
            .expect("second commit");
        for revision in &revisions {
            let mut aged = revision.clone();
            aged.created_unix_secs = 0;
            write_json_atomic(
                &state
                    .join("config/metadata")
                    .join(format!("{}.json", revision.id)),
                &aged,
            )
            .expect("age metadata");
        }

        let mut newest = config();
        newest.runtime.config_poll_secs = 74;
        store
            .create_candidate(&newest, "retention")
            .expect("trigger retention");
        assert!(store.load(&revisions[0].id).is_ok());
        assert!(store.load(&revisions[1].id).is_ok());
        assert!(matches!(
            store.load(&revisions[2].id),
            Err(RevisionError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert_eq!(store.list().expect("retained revisions").len(), 73);
        drop(store);
        fs::remove_dir_all(state).expect("cleanup");
    }
}
