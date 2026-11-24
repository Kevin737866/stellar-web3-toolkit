//! Per-channel monitoring failure reports (issue #374).
//!
//! A failure on one channel is recorded, alerted and made queryable without
//! interrupting the scan of any other channel. Reports are idempotent under
//! repeated scans: consecutive failures increment once per failed scan, and a
//! success clears the active state without erasing the history of the incident.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::WatchtowerError;

/// Maximum accepted length of a failure reason, in bytes.
pub const MAX_FAILURE_REASON_LEN: usize = 2_048;

/// Observable state of a channel's most recent monitoring incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelFailureReport {
    /// Channel that failed.
    pub channel_id: String,
    /// Human-readable cause of the failure.
    pub error: String,
    /// Number of consecutive failed scans for this channel.
    pub consecutive_failures: u32,
    /// First failure of the current incident.
    pub first_failed_at: u64,
    /// Most recent failure of the current incident.
    pub last_failed_at: u64,
    /// Whether a subsequent scan has succeeded (operator recovery).
    pub recovered: bool,
    /// When the channel last recovered, if it did.
    pub last_recovered_at: Option<u64>,
}

impl ChannelFailureReport {
    /// Whether this channel is still failing.
    pub fn is_active(&self) -> bool {
        !self.recovered
    }

    /// Actionable message suitable for an operator alert.
    pub fn message(&self) -> String {
        format!(
            "Channel {} monitoring failed {} consecutive time(s): {}. Retry with Watchtower::retry_channel or clear with Watchtower::clear_channel_failure.",
            self.channel_id, self.consecutive_failures, self.error
        )
    }
}

/// Registry of the latest failure report for each channel.
#[derive(Debug, Clone, Default)]
pub struct ChannelFailureRegistry {
    reports: HashMap<String, ChannelFailureReport>,
}

impl ChannelFailureRegistry {
    /// Validate a channel identifier before it enters the registry.
    pub fn validate_channel_id(channel_id: &str) -> Result<(), WatchtowerError> {
        if channel_id.trim().is_empty() {
            return Err(WatchtowerError::InvalidChannel(
                "channel id must not be blank".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate a failure reason, rejecting blank and oversized input rather
    /// than silently substituting a default or truncating it.
    pub fn validate_reason(reason: &str) -> Result<(), WatchtowerError> {
        if reason.trim().is_empty() {
            return Err(WatchtowerError::InvalidFailureReason(
                "failure reason must not be blank".to_string(),
            ));
        }
        if reason.len() > MAX_FAILURE_REASON_LEN {
            return Err(WatchtowerError::InvalidFailureReason(format!(
                "failure reason exceeds {MAX_FAILURE_REASON_LEN} bytes"
            )));
        }
        Ok(())
    }

    /// Compute the report a failure would produce without mutating state.
    ///
    /// Lets callers persist the corresponding alert before committing the
    /// in-memory update, so a storage failure cannot leave partial state.
    pub fn preview_failure(
        &self,
        channel_id: &str,
        reason: &str,
        now: u64,
    ) -> Result<ChannelFailureReport, WatchtowerError> {
        Self::validate_channel_id(channel_id)?;
        Self::validate_reason(reason)?;

        let previous = self.reports.get(channel_id);
        let continuing = previous.map_or(false, |report| report.is_active());
        Ok(ChannelFailureReport {
            channel_id: channel_id.to_string(),
            error: reason.to_string(),
            consecutive_failures: if continuing {
                previous
                    .expect("checked above")
                    .consecutive_failures
                    .saturating_add(1)
            } else {
                1
            },
            first_failed_at: if continuing {
                previous.expect("checked above").first_failed_at
            } else {
                now
            },
            last_failed_at: now,
            recovered: false,
            last_recovered_at: None,
        })
    }

    /// Record a failed scan and return the updated report.
    pub fn record_failure(
        &mut self,
        channel_id: &str,
        reason: &str,
        now: u64,
    ) -> Result<ChannelFailureReport, WatchtowerError> {
        let report = self.preview_failure(channel_id, reason, now)?;
        self.reports.insert(channel_id.to_string(), report.clone());
        Ok(report)
    }

    /// Mark a previously failing channel as recovered.
    ///
    /// Returns the recovered report only when there was an active failure, so
    /// repeated successful scans are safe and do not emit duplicate alerts.
    pub fn record_success(&mut self, channel_id: &str, now: u64) -> Option<ChannelFailureReport> {
        let report = self.reports.get_mut(channel_id)?;
        if !report.is_active() {
            return None;
        }
        report.recovered = true;
        report.last_recovered_at = Some(now);
        Some(report.clone())
    }

    /// Latest report for a channel, including recovered ones.
    pub fn get(&self, channel_id: &str) -> Option<ChannelFailureReport> {
        self.reports.get(channel_id).cloned()
    }

    /// All reports, sorted by channel id for deterministic output.
    pub fn all(&self) -> Vec<ChannelFailureReport> {
        let mut reports: Vec<_> = self.reports.values().cloned().collect();
        reports.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));
        reports
    }

    /// Reports for channels that are still failing.
    pub fn active(&self) -> Vec<ChannelFailureReport> {
        let mut reports: Vec<_> = self
            .reports
            .values()
            .filter(|report| report.is_active())
            .cloned()
            .collect();
        reports.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));
        reports
    }

    /// Total consecutive failures counted across all current incidents.
    pub fn total_failures(&self) -> u64 {
        self.reports
            .values()
            .map(|report| u64::from(report.consecutive_failures))
            .sum()
    }

    /// Forget a channel's report (operator recovery). Returns whether one existed.
    pub fn clear(&mut self, channel_id: &str) -> bool {
        self.reports.remove(channel_id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consecutive_failures_are_counted_per_channel() {
        let mut registry = ChannelFailureRegistry::default();
        let first = registry
            .record_failure("alpha", "rpc timeout", 100)
            .unwrap();
        let second = registry
            .record_failure("alpha", "rpc timeout", 110)
            .unwrap();
        let other = registry
            .record_failure("beta", "bad response", 120)
            .unwrap();

        assert_eq!(first.consecutive_failures, 1);
        assert_eq!(second.consecutive_failures, 2);
        assert_eq!(second.first_failed_at, 100);
        assert_eq!(second.last_failed_at, 110);
        assert_eq!(other.consecutive_failures, 1);
        assert_eq!(registry.get("alpha"), Some(second.clone()));
        assert_eq!(registry.get("missing"), None);
        assert_eq!(registry.total_failures(), 3);
        assert_eq!(registry.active().len(), 2);
    }

    #[test]
    fn success_recovers_once_and_is_safe_to_repeat() {
        let mut registry = ChannelFailureRegistry::default();
        registry
            .record_failure("alpha", "rpc timeout", 100)
            .unwrap();
        registry
            .record_failure("alpha", "rpc timeout", 110)
            .unwrap();

        let recovered = registry.record_success("alpha", 120).unwrap();
        assert!(recovered.recovered);
        assert_eq!(recovered.last_recovered_at, Some(120));
        assert_eq!(recovered.consecutive_failures, 2);
        assert_eq!(registry.record_success("alpha", 130), None);
        assert!(registry.active().is_empty());

        // A new incident after recovery starts a fresh sequence.
        let again = registry
            .record_failure("alpha", "disconnected", 140)
            .unwrap();
        assert_eq!(again.consecutive_failures, 1);
        assert_eq!(again.first_failed_at, 140);
    }

    #[test]
    fn blank_or_oversized_input_is_rejected_without_mutation() {
        let mut registry = ChannelFailureRegistry::default();
        assert!(matches!(
            registry.record_failure("   ", "boom", 1),
            Err(WatchtowerError::InvalidChannel(_))
        ));
        assert!(matches!(
            registry.record_failure("alpha", "", 1),
            Err(WatchtowerError::InvalidFailureReason(_))
        ));
        let oversized = "x".repeat(MAX_FAILURE_REASON_LEN + 1);
        assert!(matches!(
            registry.record_failure("alpha", &oversized, 1),
            Err(WatchtowerError::InvalidFailureReason(_))
        ));
        assert!(registry.all().is_empty());

        let exact = "y".repeat(MAX_FAILURE_REASON_LEN);
        assert!(registry.record_failure("alpha", &exact, 1).is_ok());
    }

    #[test]
    fn preview_does_not_mutate_and_clear_is_idempotent() {
        let mut registry = ChannelFailureRegistry::default();
        registry.record_failure("alpha", "boom", 10).unwrap();
        let preview = registry.preview_failure("alpha", "boom", 20).unwrap();
        assert_eq!(preview.consecutive_failures, 2);
        assert_eq!(registry.get("alpha").unwrap().consecutive_failures, 1);

        assert!(registry.clear("alpha"));
        assert!(!registry.clear("alpha"));
        assert!(!registry.clear("never-seen"));
    }

    #[test]
    fn report_message_is_actionable() {
        let mut registry = ChannelFailureRegistry::default();
        let report = registry.record_failure("alpha", "rpc timeout", 10).unwrap();
        let message = report.message();
        assert!(message.contains("alpha"));
        assert!(message.contains("rpc timeout"));
        assert!(message.contains("retry_channel"));
    }
}
