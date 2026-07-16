use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Duration,
};

use fs2::FileExt;
use thiserror::Error;

use crate::generation::{create_private_dir, sync_directory, validate_id};

const DAY_SECS: u64 = 24 * 60 * 60;
const RETRY_BASE_SECS: u64 = 60;
const RETRY_MAX_SECS: u64 = 6 * 60 * 60;
const MAX_RETRY_ATTEMPT: u32 = 16;

/// One validated fallback renewal decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewalSchedule {
    /// Unix timestamp at which renewal work becomes due.
    pub renew_at_unix_secs: u64,
    /// Effective lead time after clamping to one third of certificate lifetime.
    pub lead_time: Duration,
}

/// Invalid certificate timing or renewal policy.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RenewalScheduleError {
    /// Certificate validity timestamps or renewal window were invalid.
    #[error("invalid certificate renewal timing")]
    Invalid,
}

/// Failure to acquire the durable single-flight lock for one managed certificate.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CertificateOrderLockError {
    /// State path or certificate ID was invalid.
    #[error("invalid certificate order lock input")]
    Input,
    /// Another issuance or renewal owns the certificate lock.
    #[error("certificate order is already in progress")]
    Busy,
    /// Lock storage or the blocking worker was unavailable.
    #[error("certificate order lock is unavailable")]
    Unavailable,
}

/// Durable operator renewal-request failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RenewalRequestError {
    /// State path or certificate ID is invalid.
    #[error("invalid certificate renewal request")]
    Input,
    /// Durable request state could not be read or changed.
    #[error("certificate renewal request storage failed")]
    Storage,
}

/// Durably request renewal; repeated requests for the same certificate are idempotent.
pub fn request_certificate_renewal(
    state_dir: &Path,
    certificate_id: &str,
) -> Result<(), RenewalRequestError> {
    let path = renewal_request_path(state_dir, certificate_id)?;
    let directory = path.parent().ok_or(RenewalRequestError::Input)?;
    create_private_dir(directory).map_err(|_| RenewalRequestError::Storage)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(b"renew\n")
                .and_then(|()| file.sync_all())
                .map_err(|_| RenewalRequestError::Storage)?;
            sync_directory(directory).map_err(|_| RenewalRequestError::Storage)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            certificate_renewal_requested(state_dir, certificate_id).and_then(|requested| {
                if requested {
                    Ok(())
                } else {
                    Err(RenewalRequestError::Storage)
                }
            })
        }
        Err(_) => Err(RenewalRequestError::Storage),
    }
}

/// Check whether a durable operator renewal request exists.
pub fn certificate_renewal_requested(
    state_dir: &Path,
    certificate_id: &str,
) -> Result<bool, RenewalRequestError> {
    let path = renewal_request_path(state_dir, certificate_id)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 6 => Ok(true),
        Ok(_) => Err(RenewalRequestError::Storage),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(RenewalRequestError::Storage),
    }
}

/// Clear one fulfilled durable operator renewal request.
pub fn clear_certificate_renewal_request(
    state_dir: &Path,
    certificate_id: &str,
) -> Result<(), RenewalRequestError> {
    let path = renewal_request_path(state_dir, certificate_id)?;
    let directory = path.parent().ok_or(RenewalRequestError::Input)?;
    match fs::remove_file(&path) {
        Ok(()) => sync_directory(directory).map_err(|_| RenewalRequestError::Storage),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RenewalRequestError::Storage),
    }
}

fn renewal_request_path(
    state_dir: &Path,
    certificate_id: &str,
) -> Result<PathBuf, RenewalRequestError> {
    if !state_dir.is_absolute() || validate_id(certificate_id).is_err() {
        return Err(RenewalRequestError::Input);
    }
    Ok(state_dir
        .join("acme")
        .join("renewal-requests")
        .join(format!("{certificate_id}.request")))
}

/// Owned OS file lock that releases when dropped and leaves a stable lock inode behind.
pub struct CertificateOrderLock {
    certificate_id: String,
    lock_path: PathBuf,
    _file: File,
}

impl fmt::Debug for CertificateOrderLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateOrderLock")
            .field("certificate_id", &self.certificate_id)
            .finish_non_exhaustive()
    }
}

impl Drop for CertificateOrderLock {
    fn drop(&mut self) {
        if FileExt::unlock(&self._file).is_ok()
            && let Ok(mut held) = process_locks().lock()
        {
            held.remove(&self.lock_path);
        }
    }
}

impl CertificateOrderLock {
    /// Try to acquire one cross-task/process certificate lock off Tokio workers.
    pub async fn acquire(
        state_dir: &Path,
        certificate_id: &str,
    ) -> Result<Self, CertificateOrderLockError> {
        if !state_dir.is_absolute() || validate_id(certificate_id).is_err() {
            return Err(CertificateOrderLockError::Input);
        }
        let state_dir = state_dir.to_owned();
        let certificate_id = certificate_id.to_owned();
        tokio::task::spawn_blocking(move || acquire_lock(state_dir, certificate_id))
            .await
            .map_err(|_| CertificateOrderLockError::Unavailable)?
    }
}

fn acquire_lock(
    state_dir: PathBuf,
    certificate_id: String,
) -> Result<CertificateOrderLock, CertificateOrderLockError> {
    let lock_dir = state_dir.join("acme").join("locks");
    create_private_dir(&lock_dir).map_err(|_| CertificateOrderLockError::Unavailable)?;
    let path = lock_dir.join(format!("{certificate_id}.lock"));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|_| CertificateOrderLockError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| CertificateOrderLockError::Unavailable)?;
    }
    let lock_path = fs::canonicalize(&path).map_err(|_| CertificateOrderLockError::Unavailable)?;
    {
        let mut held = process_locks()
            .lock()
            .map_err(|_| CertificateOrderLockError::Unavailable)?;
        if !held.insert(lock_path.clone()) {
            return Err(CertificateOrderLockError::Busy);
        }
    }
    match file.try_lock_exclusive() {
        Ok(()) => Ok(CertificateOrderLock {
            certificate_id,
            lock_path,
            _file: file,
        }),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            release_process_lock(&lock_path);
            Err(CertificateOrderLockError::Busy)
        }
        Err(_) => {
            release_process_lock(&lock_path);
            Err(CertificateOrderLockError::Unavailable)
        }
    }
}

fn process_locks() -> &'static Mutex<HashSet<PathBuf>> {
    static LOCKS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn release_process_lock(path: &Path) {
    if let Ok(mut held) = process_locks().lock() {
        held.remove(path);
    }
}

/// Schedule fallback renewal with stable jitter when ACME ARI is unavailable.
pub fn fallback_renewal_schedule(
    certificate_id: &str,
    not_before_unix_secs: i64,
    not_after_unix_secs: i64,
    now_unix_secs: u64,
    renew_before_days: u16,
) -> Result<RenewalSchedule, RenewalScheduleError> {
    if certificate_id.is_empty()
        || certificate_id.len() > 63
        || not_before_unix_secs < 0
        || not_after_unix_secs <= not_before_unix_secs
        || renew_before_days == 0
        || renew_before_days > 90
    {
        return Err(RenewalScheduleError::Invalid);
    }
    let not_before = not_before_unix_secs as u64;
    let not_after = not_after_unix_secs as u64;
    let lifetime = not_after
        .checked_sub(not_before)
        .ok_or(RenewalScheduleError::Invalid)?;
    let configured_lead = u64::from(renew_before_days)
        .checked_mul(DAY_SECS)
        .ok_or(RenewalScheduleError::Invalid)?;
    let lead = configured_lead.min(lifetime / 3);
    if lead == 0 {
        return Err(RenewalScheduleError::Invalid);
    }
    let window_start = not_after
        .checked_sub(lead)
        .ok_or(RenewalScheduleError::Invalid)?;
    let jitter_span = (lead / 10).max(1);
    let jitter = stable_hash(certificate_id) % jitter_span;
    let scheduled = window_start
        .checked_add(jitter)
        .ok_or(RenewalScheduleError::Invalid)?;
    Ok(RenewalSchedule {
        renew_at_unix_secs: scheduled.max(now_unix_secs),
        lead_time: Duration::from_secs(lead),
    })
}

/// Capped exponential retry delay with stable 0–20% per-certificate jitter.
#[must_use]
pub fn retry_delay(certificate_id: &str, attempt: u32) -> Duration {
    let exponent = attempt.min(MAX_RETRY_ATTEMPT);
    let base = RETRY_BASE_SECS
        .saturating_mul(1_u64.checked_shl(exponent).unwrap_or(u64::MAX))
        .min(RETRY_MAX_SECS);
    let jitter_span = (base / 5).max(1);
    Duration::from_secs(base.saturating_add(stable_hash(certificate_id) % jitter_span))
}

/// Return the active expiry-alert threshold: 30, 14, 7, 3, 1, or 0 days.
#[must_use]
pub fn expiry_alert_days(not_after_unix_secs: i64, now_unix_secs: u64) -> Option<u16> {
    if not_after_unix_secs < 0 || not_after_unix_secs as u64 <= now_unix_secs {
        return Some(0);
    }
    let remaining = (not_after_unix_secs as u64 - now_unix_secs).div_ceil(DAY_SECS);
    [1_u16, 3, 7, 14, 30]
        .into_iter()
        .find(|threshold| remaining <= u64::from(*threshold))
}

fn stable_hash(value: &str) -> u64 {
    value
        .bytes()
        .fold(14_695_981_039_346_656_037, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(1_099_511_628_211)
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn fallback_is_deterministic_bounded_and_immediate_when_late() {
        let not_before = 1_700_000_000_i64;
        let not_after = not_before + 90 * DAY_SECS as i64;
        let schedule = fallback_renewal_schedule("site", not_before, not_after, 0, 30)
            .expect("valid schedule");
        let window_start = not_after as u64 - 30 * DAY_SECS;
        assert!(schedule.renew_at_unix_secs >= window_start);
        assert!(schedule.renew_at_unix_secs < window_start + 3 * DAY_SECS);
        assert_eq!(
            schedule,
            fallback_renewal_schedule("site", not_before, not_after, 0, 30).expect("same schedule")
        );
        let overdue = fallback_renewal_schedule(
            "site",
            not_before,
            not_after,
            not_after as u64 - DAY_SECS,
            30,
        )
        .expect("overdue schedule");
        assert_eq!(overdue.renew_at_unix_secs, not_after as u64 - DAY_SECS);
    }

    #[test]
    fn short_lifetime_clamps_lead_and_invalid_timing_fails() {
        let schedule =
            fallback_renewal_schedule("short", 1_000, 4_000, 0, 30).expect("short schedule");
        assert_eq!(schedule.lead_time, Duration::from_secs(1_000));
        assert!(fallback_renewal_schedule("site", 4_000, 1_000, 0, 30).is_err());
        assert!(fallback_renewal_schedule("", 1_000, 4_000, 0, 30).is_err());
    }

    #[test]
    fn retries_cap_and_alerts_escalate() {
        assert!(retry_delay("site", 0) >= Duration::from_secs(RETRY_BASE_SECS));
        assert!(retry_delay("site", 100) < Duration::from_secs(RETRY_MAX_SECS * 6 / 5));
        let now = 1_700_000_000_u64;
        assert_eq!(expiry_alert_days((now + 31 * DAY_SECS) as i64, now), None);
        assert_eq!(expiry_alert_days((now + 5 * DAY_SECS) as i64, now), Some(7));
        assert_eq!(expiry_alert_days((now + DAY_SECS) as i64, now), Some(1));
        assert_eq!(expiry_alert_days(now as i64, now), Some(0));
    }

    #[test]
    fn certificate_order_lock_is_cross_handle_single_flight() {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-acme-lock-{}-{}",
            std::process::id(),
            stable_hash("certificate-order-lock")
        ));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale test root");
        }
        fs::create_dir(&root).expect("create test root");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        let first = runtime
            .block_on(CertificateOrderLock::acquire(&root, "site"))
            .expect("first lock");
        assert!(matches!(
            runtime.block_on(CertificateOrderLock::acquire(&root, "site")),
            Err(CertificateOrderLockError::Busy)
        ));
        drop(first);
        runtime
            .block_on(CertificateOrderLock::acquire(&root, "site"))
            .expect("lock after release");
        assert!(root.join("acme/locks/site.lock").is_file());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn renewal_request_is_durable_idempotent_and_exact() {
        let state = std::env::temp_dir().join(format!(
            "aegisproxy-renewal-request-{}-{}",
            std::process::id(),
            stable_hash("renewal-request-test")
        ));
        request_certificate_renewal(&state, "site").expect("request renewal");
        request_certificate_renewal(&state, "site").expect("repeat renewal");
        assert_eq!(certificate_renewal_requested(&state, "site"), Ok(true));
        assert_eq!(certificate_renewal_requested(&state, "other"), Ok(false));
        clear_certificate_renewal_request(&state, "site").expect("clear renewal");
        assert_eq!(certificate_renewal_requested(&state, "site"), Ok(false));
        clear_certificate_renewal_request(&state, "site").expect("repeat clear");
        fs::remove_dir_all(state).expect("cleanup");
    }
}
