use std::time::Duration;

use thiserror::Error;

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
}
