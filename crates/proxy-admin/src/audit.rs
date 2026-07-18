//! Durable HMAC-chained administrative audit records.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const MIN_KEY_BYTES: usize = 32;
const MAX_KEY_BYTES: usize = 64;
const MAX_AUDIT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AUDIT_RECORDS: u64 = 100_000;
const MAX_LINE_BYTES: usize = 8 * 1024;
const MAX_FIELD_BYTES: usize = 256;
const AUDIT_SCHEMA_VERSION: u32 = 1;

type HmacSha256 = Hmac<Sha256>;

/// Durable audit failure. Mutations must fail closed on this error.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Audit filesystem operation failed.
    #[error("audit storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Audit key is outside the approved bound.
    #[error("audit key must contain 32 to 64 bytes")]
    InvalidKey,
    /// Record contains invalid, unbounded, or unsafe text.
    #[error("audit record contains an invalid field")]
    InvalidRecord,
    /// Stored chain failed schema, sequence, or HMAC verification.
    #[error("stored audit chain is invalid")]
    InvalidChain,
    /// Audit file or record count reached its hard bound.
    #[error("audit storage reached its configured hard limit")]
    Limit,
    /// Prior durable append failed; this writer cannot safely continue.
    #[error("audit storage is unavailable after a durability failure")]
    Unavailable,
}

/// Mutation or authorization outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Durable intent written before mutation.
    Intent,
    /// Operation completed.
    Success,
    /// Authentication or authorization denied operation.
    Denied,
    /// Authorized operation failed safely.
    Failed,
}

/// Validated fields supplied by one administrative operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Stable actor type, such as `unix_peer` or `api_token`.
    pub actor_type: String,
    /// Stable non-secret actor identifier.
    pub actor_id: String,
    /// Stable operation name.
    pub action: String,
    /// Stable affected object identifier.
    pub resource_id: String,
    /// Bounded request identifier.
    pub request_id: String,
    /// Previous revision hash or ID.
    pub old_revision: Option<String>,
    /// Candidate/result revision hash or ID.
    pub new_revision: Option<String>,
    /// Server-side authorization result.
    pub authorized: bool,
    /// Operation outcome.
    pub outcome: AuditOutcome,
    /// Stable redacted error code.
    pub error_code: Option<String>,
}

/// One persisted, authenticated audit record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Storage schema version.
    pub schema_version: u32,
    /// Strictly increasing segment sequence.
    pub sequence: u64,
    /// UTC time represented as Unix seconds.
    pub timestamp_unix_secs: u64,
    /// Stable actor type.
    pub actor_type: String,
    /// Stable non-secret actor identifier.
    pub actor_id: String,
    /// Stable operation name.
    pub action: String,
    /// Stable affected object identifier.
    pub resource_id: String,
    /// Bounded request identifier.
    pub request_id: String,
    /// Previous revision hash or ID.
    pub old_revision: Option<String>,
    /// Candidate/result revision hash or ID.
    pub new_revision: Option<String>,
    /// Server-side authorization result.
    pub authorized: bool,
    /// Operation outcome.
    pub outcome: AuditOutcome,
    /// Stable redacted error code.
    pub error_code: Option<String>,
    /// HMAC of previous record, or zeros for first record.
    pub previous_mac: String,
    /// HMAC-SHA256 over all preceding fields.
    pub mac: String,
}

#[derive(Serialize)]
struct UnsignedRecord<'a> {
    schema_version: u32,
    sequence: u64,
    timestamp_unix_secs: u64,
    actor_type: &'a str,
    actor_id: &'a str,
    action: &'a str,
    resource_id: &'a str,
    request_id: &'a str,
    old_revision: &'a Option<String>,
    new_revision: &'a Option<String>,
    authorized: bool,
    outcome: AuditOutcome,
    error_code: &'a Option<String>,
    previous_mac: &'a str,
}

#[derive(Debug)]
struct AuditState {
    file: File,
    sequence: u64,
    previous_mac: String,
    bytes: u64,
    failed: bool,
}

/// Single-segment durable audit writer and verifier.
pub struct AuditLog {
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
    state: Mutex<AuditState>,
}

impl fmt::Debug for AuditLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditLog")
            .field("path", &self.path)
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Open or create a private audit segment and verify its complete chain.
    pub fn open(path: impl AsRef<Path>, key: Vec<u8>) -> Result<Self, AuditError> {
        if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len()) {
            return Err(AuditError::InvalidKey);
        }
        let path = path.as_ref().to_path_buf();
        let parent = path.parent().ok_or(AuditError::InvalidRecord)?;
        create_private_directory(parent)?;
        reject_symlink(&path)?;
        let mut file = open_private_append(&path)?;
        reject_insecure_permissions(&file.metadata()?)?;
        let bytes = file.metadata()?.len();
        if bytes > MAX_AUDIT_BYTES {
            return Err(AuditError::Limit);
        }
        let key = Zeroizing::new(key);
        let records = read_records(&mut file, bytes, &key)?;
        let sequence = records.last().map_or(0, |record| record.sequence);
        let previous_mac = records
            .last()
            .map_or_else(zero_mac, |record| record.mac.clone());
        Ok(Self {
            path,
            key,
            state: Mutex::new(AuditState {
                file,
                sequence,
                previous_mac,
                bytes,
                failed: false,
            }),
        })
    }

    /// Append, flush, and sync one record before returning success.
    pub fn append(&self, event: AuditEvent) -> Result<AuditRecord, AuditError> {
        validate_event(&event)?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.failed {
            return Err(AuditError::Unavailable);
        }
        if state.sequence >= MAX_AUDIT_RECORDS || state.bytes >= MAX_AUDIT_BYTES {
            return Err(AuditError::Limit);
        }
        let sequence = state.sequence.checked_add(1).ok_or(AuditError::Limit)?;
        let timestamp_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuditError::InvalidRecord)?
            .as_secs();
        let previous_mac = state.previous_mac.clone();
        let unsigned = unsigned(sequence, timestamp_unix_secs, &event, &previous_mac);
        let mac = sign(&self.key, &unsigned)?;
        let record = AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            sequence,
            timestamp_unix_secs,
            actor_type: event.actor_type,
            actor_id: event.actor_id,
            action: event.action,
            resource_id: event.resource_id,
            request_id: event.request_id,
            old_revision: event.old_revision,
            new_revision: event.new_revision,
            authorized: event.authorized,
            outcome: event.outcome,
            error_code: event.error_code,
            previous_mac,
            mac,
        };
        let mut line = serde_json::to_vec(&record).map_err(|_| AuditError::InvalidRecord)?;
        line.push(b'\n');
        if line.len() > MAX_LINE_BYTES
            || state.bytes.saturating_add(line.len() as u64) > MAX_AUDIT_BYTES
        {
            return Err(AuditError::Limit);
        }
        if let Err(error) = state
            .file
            .write_all(&line)
            .and_then(|()| state.file.flush())
            .and_then(|()| state.file.sync_data())
        {
            state.failed = true;
            return Err(AuditError::Io(error));
        }
        state.bytes += line.len() as u64;
        state.sequence = sequence;
        state.previous_mac.clone_from(&record.mac);
        Ok(record)
    }

    /// Read and verify every record in this bounded segment.
    pub fn records(&self) -> Result<Vec<AuditRecord>, AuditError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut file = File::open(&self.path)?;
        read_records(&mut file, state.bytes, &self.key)
    }
}

fn unsigned<'a>(
    sequence: u64,
    timestamp_unix_secs: u64,
    event: &'a AuditEvent,
    previous_mac: &'a str,
) -> UnsignedRecord<'a> {
    UnsignedRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        sequence,
        timestamp_unix_secs,
        actor_type: &event.actor_type,
        actor_id: &event.actor_id,
        action: &event.action,
        resource_id: &event.resource_id,
        request_id: &event.request_id,
        old_revision: &event.old_revision,
        new_revision: &event.new_revision,
        authorized: event.authorized,
        outcome: event.outcome,
        error_code: &event.error_code,
        previous_mac,
    }
}

fn sign(key: &[u8], unsigned: &UnsignedRecord<'_>) -> Result<String, AuditError> {
    let bytes = serde_json::to_vec(unsigned).map_err(|_| AuditError::InvalidRecord)?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| AuditError::InvalidKey)?;
    mac.update(&bytes);
    Ok(hex(&mac.finalize().into_bytes()))
}

fn verify(key: &[u8], unsigned: &UnsignedRecord<'_>, expected: &str) -> bool {
    let Ok(bytes) = serde_json::to_vec(unsigned) else {
        return false;
    };
    let Ok(expected) = decode_hex(expected) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(&bytes);
    mac.verify_slice(&expected).is_ok()
}

fn read_records(file: &mut File, bytes: u64, key: &[u8]) -> Result<Vec<AuditRecord>, AuditError> {
    let mut content = String::new();
    file.take(bytes.saturating_add(1))
        .read_to_string(&mut content)?;
    if content.len() as u64 != bytes || (!content.is_empty() && !content.ends_with('\n')) {
        return Err(AuditError::InvalidChain);
    }
    let mut records = Vec::new();
    let mut previous_mac = zero_mac();
    for line in content.lines() {
        if line.len() > MAX_LINE_BYTES || records.len() as u64 >= MAX_AUDIT_RECORDS {
            return Err(AuditError::Limit);
        }
        let record: AuditRecord =
            serde_json::from_str(line).map_err(|_| AuditError::InvalidChain)?;
        let expected_sequence = records.len() as u64 + 1;
        let event = event_from(&record);
        let unsigned = unsigned(
            record.sequence,
            record.timestamp_unix_secs,
            &event,
            &record.previous_mac,
        );
        if record.schema_version != AUDIT_SCHEMA_VERSION
            || record.sequence != expected_sequence
            || record.previous_mac != previous_mac
            || !verify(key, &unsigned, &record.mac)
        {
            return Err(AuditError::InvalidChain);
        }
        validate_event(&event).map_err(|_| AuditError::InvalidChain)?;
        previous_mac.clone_from(&record.mac);
        records.push(record);
    }
    Ok(records)
}

fn event_from(record: &AuditRecord) -> AuditEvent {
    AuditEvent {
        actor_type: record.actor_type.clone(),
        actor_id: record.actor_id.clone(),
        action: record.action.clone(),
        resource_id: record.resource_id.clone(),
        request_id: record.request_id.clone(),
        old_revision: record.old_revision.clone(),
        new_revision: record.new_revision.clone(),
        authorized: record.authorized,
        outcome: record.outcome,
        error_code: record.error_code.clone(),
    }
}

fn validate_event(event: &AuditEvent) -> Result<(), AuditError> {
    for value in [
        Some(event.actor_type.as_str()),
        Some(event.actor_id.as_str()),
        Some(event.action.as_str()),
        Some(event.resource_id.as_str()),
        Some(event.request_id.as_str()),
        event.old_revision.as_deref(),
        event.new_revision.as_deref(),
        event.error_code.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.is_empty()
            || value.len() > MAX_FIELD_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
            })
        {
            return Err(AuditError::InvalidRecord);
        }
    }
    Ok(())
}

fn zero_mac() -> String {
    "0".repeat(64)
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

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() != 64 {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = digit(pair[0])?;
            let low = digit(pair[1])?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn digit(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

fn reject_symlink(path: &Path) -> Result<(), AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AuditError::InvalidRecord),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn open_private_append(path: &Path) -> Result<File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private_append(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
}

fn create_private_directory(path: &Path) -> Result<(), std::io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "audit parent is not a private directory",
            ));
        }
        Ok(metadata) => {
            reject_insecure_directory_permissions(&metadata)?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn reject_insecure_directory_permissions(metadata: &fs::Metadata) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "audit parent permissions are too broad",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_directory_permissions(_metadata: &fs::Metadata) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn reject_insecure_permissions(metadata: &fs::Metadata) -> Result<(), AuditError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(AuditError::InvalidRecord);
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_permissions(_metadata: &fs::Metadata) -> Result<(), AuditError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{AuditError, AuditEvent, AuditLog, AuditOutcome};

    fn event(outcome: AuditOutcome) -> AuditEvent {
        AuditEvent {
            actor_type: "api_token".into(),
            actor_id: "token-1".into(),
            action: "config.activate".into(),
            resource_id: "candidate-1".into(),
            request_id: "request-1".into(),
            old_revision: Some("revision-1".into()),
            new_revision: Some("revision-2".into()),
            authorized: true,
            outcome,
            error_code: None,
        }
    }

    fn directory(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("aegisproxy-audit-{}-{name}", std::process::id()))
    }

    #[test]
    fn append_reopen_and_tamper_detection() {
        let directory = directory("chain");
        let path = directory.join("audit.jsonl");
        let _ = fs::remove_dir_all(&directory);
        let key = b"audit-test-key-is-at-least-32-bytes".to_vec();
        let log = AuditLog::open(&path, key.clone()).expect("open");
        log.append(event(AuditOutcome::Intent)).expect("intent");
        log.append(event(AuditOutcome::Success)).expect("success");
        assert_eq!(log.records().expect("records").len(), 2);
        drop(log);
        assert_eq!(
            AuditLog::open(&path, key.clone())
                .expect("reopen")
                .records()
                .expect("records")
                .len(),
            2
        );
        let content = fs::read_to_string(&path).expect("read");
        fs::write(&path, content.replacen("revision-2", "revision-3", 1)).expect("tamper");
        assert!(matches!(
            AuditLog::open(&path, key),
            Err(AuditError::InvalidChain)
        ));
        fs::remove_dir_all(directory).expect("remove");
    }

    #[test]
    fn rejects_log_injection_and_redacts_key() {
        let directory = directory("redact");
        let path = directory.join("audit.jsonl");
        let _ = fs::remove_dir_all(&directory);
        let key = b"private-audit-canary-key-32-bytes!".to_vec();
        let log = AuditLog::open(&path, key).expect("open");
        let mut event = event(AuditOutcome::Denied);
        event.actor_id = "attacker\nforged".into();
        assert!(matches!(log.append(event), Err(AuditError::InvalidRecord)));
        assert!(!format!("{log:?}").contains("private-audit-canary"));
        assert!(
            !fs::read_to_string(&path)
                .expect("read")
                .contains("private-audit-canary")
        );
        fs::remove_dir_all(directory).expect("remove");
    }
}
