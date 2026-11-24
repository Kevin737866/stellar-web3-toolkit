//! # Storage Module
//!
//! Persistent storage backends for the watchtower.

use crate::monitor::{ChannelMonitorState, ChannelUpdate};
use crate::Alert;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Retention rules applied by [`StorageBackend::compact`].
///
/// A watchtower writes continuously -- a state and an update per channel per
/// scan, plus an alert per incident -- so without retention the store grows
/// with uptime rather than with the number of channels being watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionPolicy {
    /// Keep at most this many alerts, newest first.
    pub max_alerts: usize,
    /// Drop alerts older than this, in seconds.
    pub alert_retention_secs: u64,
    /// Drop the cached update of a channel not refreshed within this, in
    /// seconds. A channel that keeps being scanned keeps its update fresh, so
    /// only unsubscribed or abandoned channels age out.
    pub update_retention_secs: u64,
    /// Keep at most this many cached channel updates, newest first.
    pub max_channel_updates: usize,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        CompactionPolicy {
            max_alerts: 1_000,
            alert_retention_secs: 7 * 24 * 60 * 60, // one week
            update_retention_secs: 24 * 60 * 60,    // one day
            max_channel_updates: 10_000,
        }
    }
}

/// What a compaction pass removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionReport {
    /// Alerts before the pass.
    pub alerts_before: usize,
    /// Alerts after the pass.
    pub alerts_after: usize,
    /// Cached channel updates before the pass.
    pub channel_updates_before: usize,
    /// Cached channel updates after the pass.
    pub channel_updates_after: usize,
    /// Duplicate subscriptions collapsed during the pass.
    pub subscriptions_deduplicated: usize,
}

impl CompactionReport {
    /// Alerts removed by the pass.
    pub fn alerts_removed(&self) -> usize {
        self.alerts_before.saturating_sub(self.alerts_after)
    }

    /// Cached channel updates removed by the pass.
    pub fn channel_updates_removed(&self) -> usize {
        self.channel_updates_before
            .saturating_sub(self.channel_updates_after)
    }

    /// Everything the pass removed.
    pub fn total_removed(&self) -> usize {
        self.alerts_removed() + self.channel_updates_removed() + self.subscriptions_deduplicated
    }

    /// Whether the pass changed anything.
    pub fn is_noop(&self) -> bool {
        self.total_removed() == 0
    }
}

/// Errors returned by storage backends.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// A transient failure (I/O timeout, lock contention, temporarily
    /// unavailable backend). Safe to retry the same operation.
    #[error("transient storage failure: {0}")]
    Transient(String),
    /// A permanent failure (corruption, invalid input, unsupported operation).
    /// Retrying will not help; operator intervention is required.
    #[error("storage failure: {0}")]
    Permanent(String),
}

impl StorageError {
    /// Whether the failed operation may be retried safely.
    pub fn is_transient(&self) -> bool {
        matches!(self, StorageError::Transient(_))
    }
}

/// Policy controlling how transient storage failures are retried.
///
/// Retries are only attempted for [`StorageError::Transient`]. Permanent
/// errors are returned immediately. Callers must only pass idempotent
/// operations (or operations keyed by a stable ID) to [`retry_transient`],
/// so that a retry after an ambiguous failure cannot duplicate an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Total attempts including the first one. Must be at least 1.
    pub max_attempts: u32,
    /// Delay before the second attempt, in milliseconds.
    pub initial_backoff_ms: u64,
    /// Upper bound on any single backoff, in milliseconds.
    pub max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff_ms: 50,
            max_backoff_ms: 1_000,
        }
    }
}

impl RetryPolicy {
    /// Validate the policy, rejecting values that would make retries unsafe
    /// or meaningless rather than silently substituting defaults.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.max_attempts == 0 {
            return Err(StorageError::Permanent(
                "retry policy max_attempts must be at least 1".to_string(),
            ));
        }
        if self.initial_backoff_ms > self.max_backoff_ms {
            return Err(StorageError::Permanent(format!(
                "retry policy initial_backoff_ms ({}) exceeds max_backoff_ms ({})",
                self.initial_backoff_ms, self.max_backoff_ms
            )));
        }
        Ok(())
    }

    /// Backoff to sleep after the given failed attempt (1-based), capped.
    pub fn backoff_for_attempt(&self, attempt: u32) -> u64 {
        let shift = attempt.saturating_sub(1).min(63);
        let scaled = self
            .initial_backoff_ms
            .checked_shl(shift)
            .unwrap_or(u64::MAX);
        scaled.min(self.max_backoff_ms)
    }
}

/// Run `op` under `policy`, retrying only on transient errors.
///
/// `op` must be idempotent or keyed by a stable identifier: an ambiguous
/// transient failure may have partially succeeded, and the retry must not
/// create a second, distinct effect. Returns the last error when attempts are
/// exhausted, and the first permanent error immediately.
pub fn retry_transient<T, F>(policy: &RetryPolicy, mut op: F) -> Result<T, StorageError>
where
    F: FnMut() -> Result<T, StorageError>,
{
    policy.validate()?;

    let mut attempt: u32 = 1;
    loop {
        match op() {
            Ok(value) => {
                if attempt > 1 {
                    info!(attempt, "storage operation succeeded after transient failures");
                }
                return Ok(value);
            }
            Err(err) if !err.is_transient() => return Err(err),
            Err(err) => {
                if attempt >= policy.max_attempts {
                    warn!(attempt, error = %err, "storage retries exhausted");
                    return Err(err);
                }
                let backoff = policy.backoff_for_attempt(attempt);
                debug!(attempt, backoff_ms = backoff, error = %err, "retrying transient storage failure");
                if backoff > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(backoff));
                }
                attempt += 1;
            }
        }
    }
}

/// Storage backend trait
pub trait StorageBackend: Send + Sync {
    /// Store a channel state
    fn store_channel_state(
        &self,
        channel_id: &str,
        state: &ChannelMonitorState,
    ) -> Result<(), StorageError>;

    /// Get a channel state
    fn get_channel_state(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelMonitorState>, StorageError>;

    /// Store an alert
    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError>;

    /// Get alerts
    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError>;

    /// Store a cached channel update
    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError>;

    /// Get cached channel update
    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError>;

    /// Store a channel we're subscribed to
    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError>;

    /// Get all subscriptions
    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError>;

    /// Remove a subscription
    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError>;

    /// Apply `policy` to the stored data and report what was removed.
    ///
    /// Compaction must never drop data a monitor still depends on: a channel
    /// that is still subscribed keeps its state and cached update regardless
    /// of age.
    fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError>;

    /// Apply the default retention rules.
    fn compact_with_defaults(&self) -> Result<CompactionReport, StorageError> {
        self.compact(&CompactionPolicy::default())
    }

    // ── Justice action persistence (issue #368) ───────────────────────────────

    /// Persist a justice action record.
    ///
    /// Called **before** the justice transaction is submitted so that the
    /// breach evidence is never silently lost on a failed submission.
    fn store_justice_action(
        &self,
        action: &crate::justice::JusticeAction,
    ) -> Result<(), StorageError>;

    /// Retrieve a justice action by its ID.
    fn get_justice_action(
        &self,
        id: &str,
    ) -> Result<Option<crate::justice::JusticeAction>, StorageError>;

    /// Retrieve all justice actions whose status is `Pending`.
    ///
    /// Used by the operator recovery path: after a restart, any `Pending`
    /// action can be retried via [`crate::justice::JusticeService::retry_pending_actions`].
    fn get_pending_justice_actions(
        &self,
    ) -> Result<Vec<crate::justice::JusticeAction>, StorageError>;

    /// Update the status and optional transaction hash of a persisted action.
    ///
    /// A no-op when the `id` is not found (the in-process record is the
    /// authoritative source; storage is best-effort for durability).
    fn update_justice_action_status(
        &self,
        id: &str,
        status: crate::justice::ActionStatus,
        tx_hash: Option<&str>,
    ) -> Result<(), StorageError>;
}

/// In-memory storage backend
pub struct InMemoryStorage {
    channel_states: parking_lot::RwLock<HashMap<String, ChannelMonitorState>>,
    channel_updates: parking_lot::RwLock<HashMap<String, ChannelUpdate>>,
    alerts: parking_lot::RwLock<Vec<Alert>>,
    subscriptions: parking_lot::RwLock<Vec<String>>,
    /// Justice action records, keyed by action ID (issue #368).
    justice_actions:
        parking_lot::RwLock<HashMap<String, crate::justice::JusticeAction>>,
}

impl InMemoryStorage {
    /// Create a new in-memory storage
    pub fn new() -> Self {
        InMemoryStorage {
            channel_states: parking_lot::RwLock::new(HashMap::new()),
            channel_updates: parking_lot::RwLock::new(HashMap::new()),
            alerts: parking_lot::RwLock::new(Vec::new()),
            subscriptions: parking_lot::RwLock::new(Vec::new()),
            justice_actions: parking_lot::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryStorage {
    fn store_channel_state(
        &self,
        channel_id: &str,
        state: &ChannelMonitorState,
    ) -> Result<(), StorageError> {
        let mut states = self.channel_states.write();
        states.insert(channel_id.to_string(), state.clone());
        Ok(())
    }

    fn get_channel_state(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelMonitorState>, StorageError> {
        let states = self.channel_states.read();
        Ok(states.get(channel_id).cloned())
    }

    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError> {
        let mut alerts = self.alerts.write();
        alerts.push(alert.clone());

        // Keep only last 1000
        if alerts.len() > 1000 {
            alerts.drain(0..500);
        }

        Ok(())
    }

    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
        let alerts = self.alerts.read();
        Ok(alerts.iter().rev().take(limit).cloned().collect())
    }

    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError> {
        let mut updates = self.channel_updates.write();
        updates.insert(update.channel_id.clone(), update.clone());
        Ok(())
    }

    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError> {
        let updates = self.channel_updates.read();
        Ok(updates.get(channel_id).cloned())
    }

    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        let mut subs = self.subscriptions.write();
        if !subs.contains(&channel_id.to_string()) {
            subs.push(channel_id.to_string());
        }
        Ok(())
    }

    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
        let subs = self.subscriptions.read();
        Ok(subs.clone())
    }

    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        let mut subs = self.subscriptions.write();
        subs.retain(|s| s != channel_id);
        Ok(())
    }

    fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
        let now = current_timestamp();
        let mut report = CompactionReport::default();

        // Subscriptions first: the set of channels still being watched decides
        // what the other passes are allowed to drop.
        let mut subscriptions: Vec<String> = {
            let subs = self.subscriptions.read();
            subs.clone()
        };
        let before = subscriptions.len();
        let mut seen = std::collections::HashSet::with_capacity(before);
        subscriptions.retain(|id| seen.insert(id.clone()));
        report.subscriptions_deduplicated = before - subscriptions.len();
        if report.subscriptions_deduplicated > 0 {
            *self.subscriptions.write() = subscriptions;
        }

        let subscribed: std::collections::HashSet<String> = {
            let subs = self.subscriptions.read();
            subs.iter().cloned().collect()
        };

        // Alerts: drop the aged-out ones, then the overflow beyond max_alerts.
        {
            let mut alerts = self.alerts.write();
            report.alerts_before = alerts.len();

            let cutoff = now.saturating_sub(policy.alert_retention_secs);
            alerts.retain(|alert| alert.timestamp >= cutoff);

            if alerts.len() > policy.max_alerts {
                // Evict by timestamp rather than by position: a backend that
                // reloaded from disk is not guaranteed to hold alerts in the
                // order they arrived, and "the last 1000" must mean the newest.
                let mut by_age: Vec<(usize, u64)> = alerts
                    .iter()
                    .enumerate()
                    .map(|(index, alert)| (index, alert.timestamp))
                    .collect();
                by_age.sort_by_key(|(_, timestamp)| *timestamp);

                let mut evicted: Vec<usize> = by_age
                    .into_iter()
                    .take(alerts.len() - policy.max_alerts)
                    .map(|(index, _)| index)
                    .collect();
                // Remove from the back so the earlier indices stay valid.
                evicted.sort_unstable_by(|a, b| b.cmp(a));
                for index in evicted {
                    alerts.remove(index);
                }
            }

            report.alerts_after = alerts.len();
        }

        // Channel updates: keep the freshest `max_channel_updates` among those
        // that are neither stale nor still subscribed.
        {
            let mut updates = self.channel_updates.write();
            report.channel_updates_before = updates.len();

            let cutoff = now.saturating_sub(policy.update_retention_secs);
            updates.retain(|channel_id, update| {
                subscribed.contains(channel_id) || update.timestamp >= cutoff
            });

            if updates.len() > policy.max_channel_updates {
                let mut by_age: Vec<(String, u64)> = updates
                    .iter()
                    .map(|(id, update)| (id.clone(), update.timestamp))
                    .collect();
                by_age.sort_by_key(|(_, timestamp)| *timestamp);
                let excess = updates.len() - policy.max_channel_updates;
                for (id, _) in by_age.into_iter().take(excess) {
                    if !subscribed.contains(&id) {
                        updates.remove(&id);
                    }
                }
            }

            report.channel_updates_after = updates.len();
        }

        Ok(report)
    }

    fn store_justice_action(
        &self,
        action: &crate::justice::JusticeAction,
    ) -> Result<(), StorageError> {
        let mut actions = self.justice_actions.write();
        actions.insert(action.id.clone(), action.clone());
        Ok(())
    }

    fn get_justice_action(
        &self,
        id: &str,
    ) -> Result<Option<crate::justice::JusticeAction>, StorageError> {
        let actions = self.justice_actions.read();
        Ok(actions.get(id).cloned())
    }

    fn get_pending_justice_actions(
        &self,
    ) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        let actions = self.justice_actions.read();
        Ok(actions
            .values()
            .filter(|a| a.status == crate::justice::ActionStatus::Pending)
            .cloned()
            .collect())
    }

    fn update_justice_action_status(
        &self,
        id: &str,
        status: crate::justice::ActionStatus,
        tx_hash: Option<&str>,
    ) -> Result<(), StorageError> {
        let mut actions = self.justice_actions.write();
        if let Some(action) = actions.get_mut(id) {
            action.status = status;
            if let Some(hash) = tx_hash {
                action.tx_hash = Some(hash.to_string());
            }
        }
        Ok(())
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn policy(max_attempts: u32, initial: u64, max: u64) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            initial_backoff_ms: initial,
            max_backoff_ms: max,
        }
    }

    #[test]
    fn retry_succeeds_first_attempt_without_retrying() {
        let calls = Cell::new(0u32);
        let result = retry_transient(&policy(3, 0, 0), || {
            calls.set(calls.get() + 1);
            Ok::<_, StorageError>(42)
        });
        assert_eq!(result, Ok(42));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn retry_recovers_after_transient_failures() {
        let calls = Cell::new(0u32);
        let result = retry_transient(&policy(3, 0, 0), || {
            calls.set(calls.get() + 1);
            if calls.get() < 3 {
                Err(StorageError::Transient("busy".into()))
            } else {
                Ok(7)
            }
        });
        assert_eq!(result, Ok(7));
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn retry_does_not_retry_permanent_errors() {
        let calls = Cell::new(0u32);
        let result: Result<(), _> = retry_transient(&policy(5, 0, 0), || {
            calls.set(calls.get() + 1);
            Err(StorageError::Permanent("corrupt".into()))
        });
        assert_eq!(result, Err(StorageError::Permanent("corrupt".into())));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn retry_returns_last_error_when_exhausted() {
        let calls = Cell::new(0u32);
        let result: Result<(), _> = retry_transient(&policy(3, 0, 0), || {
            calls.set(calls.get() + 1);
            Err(StorageError::Transient(format!("attempt {}", calls.get())))
        });
        assert_eq!(result, Err(StorageError::Transient("attempt 3".into())));
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn single_attempt_policy_never_retries() {
        let calls = Cell::new(0u32);
        let result: Result<(), _> = retry_transient(&policy(1, 0, 0), || {
            calls.set(calls.get() + 1);
            Err(StorageError::Transient("busy".into()))
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn zero_max_attempts_is_rejected_without_calling_op() {
        let calls = Cell::new(0u32);
        let result: Result<(), _> = retry_transient(&policy(0, 0, 0), || {
            calls.set(calls.get() + 1);
            Ok(())
        });
        assert!(matches!(result, Err(StorageError::Permanent(_))));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn inverted_backoff_bounds_are_rejected() {
        let p = policy(3, 500, 100);
        assert!(matches!(p.validate(), Err(StorageError::Permanent(_))));
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let p = policy(10, 10, 50);
        assert_eq!(p.backoff_for_attempt(1), 10);
        assert_eq!(p.backoff_for_attempt(2), 20);
        assert_eq!(p.backoff_for_attempt(3), 40);
        assert_eq!(p.backoff_for_attempt(4), 50);
        assert_eq!(p.backoff_for_attempt(200), 50);
    }

    #[test]
    fn keyed_status_update_is_idempotent_under_retry() {
        // Retrying a keyed update must not create a second record.
        let storage = InMemoryStorage::new();
        let calls = Cell::new(0u32);
        let result = retry_transient(&policy(3, 0, 0), || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                // Simulate an ambiguous failure after the write landed.
                storage.update_justice_action_status("missing", crate::justice::ActionStatus::Pending, None)?;
                Err(StorageError::Transient("ack lost".into()))
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Ok(()));
        assert!(storage.get_justice_action("missing").unwrap().is_none());
    }

    #[test]
    fn storage_error_classification() {
        assert!(StorageError::Transient("x".into()).is_transient());
        assert!(!StorageError::Permanent("x".into()).is_transient());
    }
}
