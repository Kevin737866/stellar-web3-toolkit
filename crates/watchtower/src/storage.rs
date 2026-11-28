//! # Storage Module
//!
//! Persistent storage backends for the watchtower.

use crate::monitor::{ChannelMonitorState, ChannelUpdate};
use crate::Alert;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Retention rules applied by [`StorageBackend::compact`].
///
/// A watchtower writes continuously -- a state and an update per channel per
/// scan, plus an alert per incident -- so without retention the store grows
/// with uptime rather than with the number of channels being watched.
///
/// Justice action records are the most sensitive part of the store: they
/// contain breach evidence and are written before every justice transaction
/// submission. Without a retention policy the action log grows without bound
/// as the watchtower monitors channels over time, and old `Submitted` or
/// `Confirmed` records that are no longer needed for recovery consume storage
/// indefinitely. The fields `max_justice_actions` and
/// `justice_action_retention_secs` bound that growth.
///
/// Only actions whose status is `Submitted`, `Confirmed`, or `Failed` are
/// eligible for expiry. `Pending` actions are always kept regardless of age,
/// because they still need to be retried.
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
    /// Keep at most this many finalised justice action records (those with
    /// status `Submitted`, `Confirmed`, or `Failed`). `Pending` actions are
    /// never counted against this limit.
    ///
    /// A value of 0 disables the count-based limit for justice actions.
    pub max_justice_actions: usize,
    /// Drop finalised justice action records older than this many seconds.
    ///
    /// A value of 0 disables the age-based limit for justice actions.
    /// `Pending` actions are never dropped regardless of age.
    pub justice_action_retention_secs: u64,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        CompactionPolicy {
            max_alerts: 1_000,
            alert_retention_secs: 7 * 24 * 60 * 60, // one week
            update_retention_secs: 24 * 60 * 60,    // one day
            max_channel_updates: 10_000,
            // Keep finalised justice action records for 90 days and no more
            // than 100 000 of them. Pending actions are always kept.
            max_justice_actions: 100_000,
            justice_action_retention_secs: 90 * 24 * 60 * 60, // 90 days
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
    /// Justice action records before the pass.
    pub justice_actions_before: usize,
    /// Justice action records after the pass.
    pub justice_actions_after: usize,
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

    /// Justice action records removed by the pass.
    pub fn justice_actions_removed(&self) -> usize {
        self.justice_actions_before
            .saturating_sub(self.justice_actions_after)
    }

    /// Everything the pass removed.
    pub fn total_removed(&self) -> usize {
        self.alerts_removed()
            + self.channel_updates_removed()
            + self.subscriptions_deduplicated
            + self.justice_actions_removed()
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

/// Overall state reported by a storage health probe.
///
/// `Degraded` means the backend answered but could not meet the requested
/// guarantees (for example, a slow response or a backend that cannot verify
/// persistence). `Unhealthy` means a probe actually failed, so the backend
/// cannot currently be trusted to hold breach evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageHealthState {
    /// Every enabled probe succeeded within the configured latency budget.
    Healthy,
    /// Probes succeeded, but a guarantee requested by the caller was not met.
    Degraded,
    /// At least one required probe failed.
    Unhealthy,
}

impl StorageHealthState {
    /// Whether this state represents a backend that can be relied upon.
    pub fn is_healthy(self) -> bool {
        matches!(self, StorageHealthState::Healthy)
    }

    /// Stable label suitable for logs and alerts.
    pub fn as_str(self) -> &'static str {
        match self {
            StorageHealthState::Healthy => "healthy",
            StorageHealthState::Degraded => "degraded",
            StorageHealthState::Unhealthy => "unhealthy",
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

/// Options for a storage health probe.
///
/// Invalid options are rejected with [`StorageError::HealthCheckError`] instead
/// of being silently replaced with defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageHealthCheckOptions {
    /// Maximum acceptable duration of the whole probe, in milliseconds.
    /// Must be at least 1; a zero budget would make every backend fail.
    pub max_latency_ms: u64,
    /// Also perform a write/read/delete round-trip using a sentinel
    /// subscription. The sentinel is removed on every path, including failures.
    pub probe_writes: bool,
}

impl Default for StorageHealthCheckOptions {
    fn default() -> Self {
        StorageHealthCheckOptions {
            max_latency_ms: 1_000,
            probe_writes: false,
        }
    }
}

impl StorageHealthCheckOptions {
    /// Reject options that cannot describe a meaningful probe.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.max_latency_ms == 0 {
            return Err(StorageError::HealthCheckError(
                "max_latency_ms must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Result of a storage health probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageHealthReport {
    /// Name of the backend that was probed (`in-memory`, `sqlite`, or a custom
    /// backend's [`StorageBackend::backend_name`]).
    pub backend: String,
    /// Overall outcome of the probe.
    pub state: StorageHealthState,
    /// Unix timestamp at which the probe finished.
    pub checked_at: u64,
    /// Wall-clock duration of the probe in milliseconds.
    pub elapsed_ms: u64,
    /// Whether the read probe succeeded.
    pub read_ok: bool,
    /// Outcome of the write/read/delete probe, or `None` when it was not
    /// requested (or was skipped because the read probe had already failed).
    pub write_probe_ok: Option<bool>,
    /// Actionable messages explaining a degraded or unhealthy result.
    pub details: Vec<String>,
}

impl StorageHealthReport {
    /// Whether the probed backend can be relied upon.
    pub fn is_healthy(&self) -> bool {
        self.state.is_healthy()
    }

    /// One-line summary suitable for an alert or log entry.
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "{} storage backend is {}: read_ok={}",
            self.backend,
            self.state.as_str(),
            self.read_ok
        );
        if let Some(write_ok) = self.write_probe_ok {
            write!(summary, ", write_probe_ok={write_ok}")
                .expect("writing to a String cannot fail");
        }
        for detail in &self.details {
            write!(summary, "; {detail}").expect("writing to a String cannot fail");
        }
        summary
    }
}

/// Storage backend trait
pub trait StorageBackend: Send + Sync {
    /// Stable name used in health reports and alerts.
    ///
    /// Existing implementations keep compiling with the default value.
    fn backend_name(&self) -> &'static str {
        "custom"
    }

    /// Probe the backend with the default options.
    fn check_health(&self) -> Result<StorageHealthReport, StorageError> {
        self.check_health_with(&StorageHealthCheckOptions::default())
    }

    /// Probe the backend with caller-supplied options.
    ///
    /// Returns `Err` only for invalid options or an internal probe failure. A
    /// failing backend is reported as an [`StorageHealthState::Unhealthy`]
    /// report carrying the backend's error in [`StorageHealthReport::details`].
    /// The default implementation works for any backend; implementations may
    /// override it to add backend-specific checks.
    fn check_health_with(
        &self,
        options: &StorageHealthCheckOptions,
    ) -> Result<StorageHealthReport, StorageError> {
        options.validate()?;
        Ok(probe_health(self, self.backend_name(), options))
    }

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

    /// Retrieve every persisted justice action, regardless of status.
    ///
    /// Recovery export needs submitted and failed records as well as pending
    /// ones. Backends that do not override this fail explicitly instead of
    /// silently producing a partial snapshot.
    fn get_all_justice_actions(&self) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        Err(StorageError::QueryError(
            "backend does not support full justice action export".to_string(),
        ))
    }

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

    // ── Retryable alert delivery persistence (issue #373) ────────────────────

    /// Persist a new alert delivery record before attempting delivery.
    fn store_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError>;

    /// Retrieve an alert delivery record by its [`crate::alert::DeliveryId`].
    fn get_alert_delivery(
        &self,
        delivery_id: &str,
    ) -> Result<Option<crate::alert::AlertDelivery>, StorageError>;

    /// Retrieve all alert deliveries in [`crate::alert::DeliveryStatus::Pending`].
    fn get_pending_alert_deliveries(
        &self,
    ) -> Result<Vec<crate::alert::AlertDelivery>, StorageError>;

    /// Persist an updated alert delivery record (attempts, status, backoff).
    fn update_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError>;
}

/// In-memory storage backend
pub struct InMemoryStorage {
    channel_states: parking_lot::RwLock<HashMap<String, ChannelMonitorState>>,
    channel_updates: parking_lot::RwLock<HashMap<String, ChannelUpdate>>,
    alerts: parking_lot::RwLock<Vec<Alert>>,
    subscriptions: parking_lot::RwLock<Vec<String>>,
    /// Justice action records, keyed by action ID (issue #368).
    justice_actions: parking_lot::RwLock<HashMap<String, crate::justice::JusticeAction>>,
    /// Alert delivery records, keyed by delivery ID.
    alert_deliveries: parking_lot::RwLock<HashMap<String, crate::alert::AlertDelivery>>,
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
            alert_deliveries: parking_lot::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryStorage {
    fn backend_name(&self) -> &'static str {
        "in-memory"
    }

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

    fn get_all_justice_actions(&self) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        let actions = self.justice_actions.read();
        Ok(actions.values().cloned().collect())
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

    fn store_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError> {
        let mut deliveries = self.alert_deliveries.write();
        let key = delivery.delivery_id.as_str();
        if deliveries.contains_key(key) {
            return Err(StorageError::QueryError(format!(
                "alert delivery {key} already exists"
            )));
        }
        deliveries.insert(key.to_string(), delivery.clone());
        Ok(())
    }

    fn get_alert_delivery(
        &self,
        delivery_id: &str,
    ) -> Result<Option<crate::alert::AlertDelivery>, StorageError> {
        let deliveries = self.alert_deliveries.read();
        Ok(deliveries.get(delivery_id).cloned())
    }

    fn get_pending_alert_deliveries(
        &self,
    ) -> Result<Vec<crate::alert::AlertDelivery>, StorageError> {
        let deliveries = self.alert_deliveries.read();
        let mut pending: Vec<_> = deliveries
            .values()
            .filter(|d| d.status == crate::alert::DeliveryStatus::Pending)
            .cloned()
            .collect();
        pending.sort_by_key(|d| (d.next_retry_at, d.created_at));
        Ok(pending)
    }

    fn update_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError> {
        let mut deliveries = self.alert_deliveries.write();
        let key = delivery.delivery_id.as_str();
        let slot = deliveries
            .get_mut(key)
            .ok_or_else(|| StorageError::QueryError(format!("alert delivery {key} not found")))?;
        *slot = delivery.clone();
        Ok(())
    }
}

/// SQLite storage backend (placeholder implementation)
pub struct SqliteStorage {
    // Retained for the RPC/storage wiring still to come.
    #[allow(dead_code)]
    path: String,
}

impl SqliteStorage {
    /// Create a new SQLite storage backend
    pub fn new(path: &str) -> Result<Self, StorageError> {
        // In production, this would initialize SQLite connection
        Ok(SqliteStorage {
            path: path.to_string(),
        })
    }
}

impl StorageBackend for SqliteStorage {
    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    fn check_health_with(
        &self,
        options: &StorageHealthCheckOptions,
    ) -> Result<StorageHealthReport, StorageError> {
        options.validate()?;

        // This backend is a placeholder: operations report success but no rows
        // are persisted, so a write/read-back probe would always fail. Report
        // that limitation explicitly rather than claiming full health or
        // inventing a failing probe.
        let read_only = StorageHealthCheckOptions {
            probe_writes: false,
            ..*options
        };
        let mut report = probe_health(self, self.backend_name(), &read_only);
        if report.state == StorageHealthState::Healthy {
            report.state = StorageHealthState::Degraded;
        }
        report.details.push(
            "SQLite backend is a placeholder: persistence is not implemented, so durability cannot be verified".to_string(),
        );
        Ok(report)
    }

    fn store_channel_state(
        &self,
        channel_id: &str,
        _state: &ChannelMonitorState,
    ) -> Result<(), StorageError> {
        // In production: INSERT INTO channel_states VALUES (?, ?)
        info!("SQLite: storing channel state for {}", channel_id);
        Ok(())
    }

    fn get_channel_state(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelMonitorState>, StorageError> {
        // In production: SELECT * FROM channel_states WHERE channel_id = ?
        info!("SQLite: getting channel state for {}", channel_id);
        Ok(None)
    }

    fn store_alert(&self, alert: &Alert) -> Result<(), StorageError> {
        // In production: INSERT INTO alerts VALUES (?, ?)
        info!("SQLite: storing alert {}", alert.id);
        Ok(())
    }

    fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
        // In production: SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
        info!("SQLite: getting {} alerts", limit);
        Ok(Vec::new())
    }

    fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError> {
        // In production: INSERT OR REPLACE INTO channel_updates VALUES (?, ?)
        info!("SQLite: storing channel update for {}", update.channel_id);
        Ok(())
    }

    fn get_channel_update(&self, channel_id: &str) -> Result<Option<ChannelUpdate>, StorageError> {
        // In production: SELECT * FROM channel_updates WHERE channel_id = ?
        info!("SQLite: getting channel update for {}", channel_id);
        Ok(None)
    }

    fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        // In production: INSERT OR IGNORE INTO subscriptions VALUES (?)
        info!("SQLite: storing subscription for {}", channel_id);
        Ok(())
    }

    fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
        // In production: SELECT channel_id FROM subscriptions
        info!("SQLite: getting all subscriptions");
        Ok(Vec::new())
    }

    fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
        // In production: DELETE FROM subscriptions WHERE channel_id = ?
        info!("SQLite: removing subscription for {}", channel_id);
        Ok(())
    }

    fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
        // No rows are persisted yet, so there is nothing to reclaim. The
        // signature still has to exist: callers schedule compaction
        // unconditionally, and a silent no-op here is preferable to making
        // every caller check which backend is in use.
        info!(
            "SQLite: compact requested (max_alerts={}, alert_retention={}s, update_retention={}s, \
             max_justice_actions={}, justice_action_retention={}s)",
            policy.max_alerts,
            policy.alert_retention_secs,
            policy.update_retention_secs,
            policy.max_justice_actions,
            policy.justice_action_retention_secs,
        );
        Ok(CompactionReport::default())
    }

    fn store_justice_action(
        &self,
        action: &crate::justice::JusticeAction,
    ) -> Result<(), StorageError> {
        // In production: INSERT OR REPLACE INTO justice_actions VALUES (?, ?, ?)
        info!("SQLite: storing justice action {}", action.id);
        Ok(())
    }

    fn get_justice_action(
        &self,
        id: &str,
    ) -> Result<Option<crate::justice::JusticeAction>, StorageError> {
        // In production: SELECT * FROM justice_actions WHERE id = ?
        info!("SQLite: getting justice action {}", id);
        Ok(None)
    }

    fn get_all_justice_actions(&self) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        // The placeholder backend persists no rows, so an empty snapshot here
        // is accurate rather than a partial result.
        info!("SQLite: getting all justice actions");
        Ok(Vec::new())
    }

    fn get_pending_justice_actions(
        &self,
    ) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
        // In production: SELECT * FROM justice_actions WHERE status = 'pending'
        info!("SQLite: getting pending justice actions");
        Ok(Vec::new())
    }

    fn update_justice_action_status(
        &self,
        id: &str,
        status: crate::justice::ActionStatus,
        tx_hash: Option<&str>,
    ) -> Result<(), StorageError> {
        // In production: UPDATE justice_actions SET status = ?, tx_hash = ? WHERE id = ?
        info!(
            "SQLite: updating justice action {} to {:?} (tx: {:?})",
            id, status, tx_hash
        );
        Ok(())
    }

    fn store_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError> {
        info!("SQLite: storing alert delivery {}", delivery.delivery_id);
        Ok(())
    }

    fn get_alert_delivery(
        &self,
        delivery_id: &str,
    ) -> Result<Option<crate::alert::AlertDelivery>, StorageError> {
        info!("SQLite: getting alert delivery {}", delivery_id);
        Ok(None)
    }

    fn get_pending_alert_deliveries(
        &self,
    ) -> Result<Vec<crate::alert::AlertDelivery>, StorageError> {
        info!("SQLite: getting pending alert deliveries");
        Ok(Vec::new())
    }

    fn update_alert_delivery(
        &self,
        delivery: &crate::alert::AlertDelivery,
    ) -> Result<(), StorageError> {
        info!(
            "SQLite: updating alert delivery {} to {:?} (attempts={})",
            delivery.delivery_id, delivery.status, delivery.attempts
        );
        Ok(())
    }
}

/// Run the generic health probe against any backend.
///
/// A write probe uses a sentinel subscription so it never touches a real
/// channel subscription or a pending justice action. Cleanup is attempted on
/// every path, including a failed write or a failed verification, so a probe
/// cannot leave durable state behind.
fn probe_health<B: StorageBackend + ?Sized>(
    backend: &B,
    backend_name: &str,
    options: &StorageHealthCheckOptions,
) -> StorageHealthReport {
    let started = std::time::Instant::now();
    let mut state = StorageHealthState::Healthy;
    let mut details = Vec::new();

    // Read probe: any storage error is a health result, not an API error.
    let read_ok = match backend.get_subscriptions() {
        Ok(_) => true,
        Err(e) => {
            state = StorageHealthState::Unhealthy;
            details.push(format!("read probe failed: {e}"));
            false
        }
    };

    let mut write_probe_ok = None;
    if options.probe_writes {
        if read_ok {
            let sentinel = format!("__watchtower_health_probe__{:x}", rand::random::<u128>());

            match backend.store_subscription(&sentinel) {
                Ok(()) => {
                    let visible = match backend.get_subscriptions() {
                        Ok(subscriptions) => subscriptions.iter().any(|id| id == &sentinel),
                        Err(e) => {
                            details.push(format!("write probe verification failed: {e}"));
                            false
                        }
                    };

                    // Always try to remove the sentinel, even if verification
                    // failed: a probe must not leave partial state behind.
                    if let Err(e) = backend.remove_subscription(&sentinel) {
                        state = StorageHealthState::Unhealthy;
                        details.push(format!("write probe cleanup failed for {sentinel}: {e}"));
                    }

                    if visible {
                        write_probe_ok = Some(true);
                    } else {
                        state = StorageHealthState::Unhealthy;
                        details.push(
                            "write probe: sentinel subscription was not readable back".to_string(),
                        );
                        write_probe_ok = Some(false);
                    }
                }
                Err(e) => {
                    // The write may have partially succeeded, so still attempt
                    // cleanup before reporting.
                    if let Err(cleanup) = backend.remove_subscription(&sentinel) {
                        details.push(format!(
                            "write probe cleanup failed for {sentinel}: {cleanup}"
                        ));
                    }
                    state = StorageHealthState::Unhealthy;
                    details.push(format!("write probe failed: {e}"));
                    write_probe_ok = Some(false);
                }
            }
        } else {
            details.push("write probe skipped because the read probe failed".to_string());
        }
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    if elapsed_ms > options.max_latency_ms {
        if state == StorageHealthState::Healthy {
            state = StorageHealthState::Degraded;
        }
        details.push(format!(
            "probe took {elapsed_ms}ms, exceeding the {}ms budget",
            options.max_latency_ms
        ));
    }

    debug!(
        backend = backend_name,
        state = state.as_str(),
        elapsed_ms,
        "storage health probe completed"
    );

    StorageHealthReport {
        backend: backend_name.to_string(),
        state,
        checked_at: current_timestamp(),
        elapsed_ms,
        read_ok,
        write_probe_ok,
        details,
    }
}

/// Seconds since the Unix epoch.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Query error: {0}")]
    QueryError(String),

    /// Invalid health-check options or a failure to run the probe itself.
    /// A backend that answers but is unhealthy is reported as a
    /// [`StorageHealthReport`] instead.
    #[error("Health check error: {0}")]
    HealthCheckError(String),
}

#[cfg(test)]
impl InMemoryStorage {
    /// Insert a duplicate subscription without deduplicating.
    ///
    /// Stands in for a backend that does not deduplicate on insert, so the
    /// compaction pass can be exercised on data it actually has to fix.
    fn push_raw_subscription(&self, channel_id: &str) {
        self.subscriptions.write().push(channel_id.to_string());
    }
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

    // ── Storage backend health checks ─────────────────────────────────────────

    /// A backend that can be made to fail individual probe steps. Everything
    /// else is delegated to a real in-memory store so failures are isolated.
    struct FlakyStorage {
        inner: InMemoryStorage,
        fail_read: std::sync::atomic::AtomicBool,
        fail_write: std::sync::atomic::AtomicBool,
        fail_cleanup: std::sync::atomic::AtomicBool,
        slow_read: std::sync::atomic::AtomicBool,
    }

    impl FlakyStorage {
        fn new() -> Self {
            FlakyStorage {
                inner: InMemoryStorage::new(),
                fail_read: std::sync::atomic::AtomicBool::new(false),
                fail_write: std::sync::atomic::AtomicBool::new(false),
                fail_cleanup: std::sync::atomic::AtomicBool::new(false),
                slow_read: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn set_fail_read(&self, value: bool) {
            self.fail_read
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn set_fail_write(&self, value: bool) {
            self.fail_write
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn set_fail_cleanup(&self, value: bool) {
            self.fail_cleanup
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn set_slow_read(&self, value: bool) {
            self.slow_read
                .store(value, std::sync::atomic::Ordering::SeqCst);
        }

        fn probe_error(step: &str) -> StorageError {
            StorageError::DatabaseError(format!("injected {step} failure"))
        }
    }

    impl StorageBackend for FlakyStorage {
        fn backend_name(&self) -> &'static str {
            "flaky"
        }

        fn store_channel_state(
            &self,
            channel_id: &str,
            state: &ChannelMonitorState,
        ) -> Result<(), StorageError> {
            self.inner.store_channel_state(channel_id, state)
        }

        fn get_channel_state(
            &self,
            channel_id: &str,
        ) -> Result<Option<ChannelMonitorState>, StorageError> {
            self.inner.get_channel_state(channel_id)
        }

        fn store_alert(&self, alert: &Alert) -> Result<(), StorageError> {
            self.inner.store_alert(alert)
        }

        fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
            self.inner.get_alerts(limit)
        }

        fn store_channel_update(&self, update: &ChannelUpdate) -> Result<(), StorageError> {
            self.inner.store_channel_update(update)
        }

        fn get_channel_update(
            &self,
            channel_id: &str,
        ) -> Result<Option<ChannelUpdate>, StorageError> {
            self.inner.get_channel_update(channel_id)
        }

        fn store_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
            if self.fail_write.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Self::probe_error("write"));
            }
            self.inner.store_subscription(channel_id)
        }

        fn get_subscriptions(&self) -> Result<Vec<String>, StorageError> {
            if self.slow_read.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if self.fail_read.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Self::probe_error("read"));
            }
            self.inner.get_subscriptions()
        }

        fn remove_subscription(&self, channel_id: &str) -> Result<(), StorageError> {
            if self.fail_cleanup.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Self::probe_error("cleanup"));
            }
            self.inner.remove_subscription(channel_id)
        }

        fn store_alert_delivery(
            &self,
            delivery: &crate::alert::AlertDelivery,
        ) -> Result<(), StorageError> {
            self.inner.store_alert_delivery(delivery)
        }

        fn get_alert_delivery(
            &self,
            delivery_id: &str,
        ) -> Result<Option<crate::alert::AlertDelivery>, StorageError> {
            self.inner.get_alert_delivery(delivery_id)
        }

        fn get_pending_alert_deliveries(
            &self,
        ) -> Result<Vec<crate::alert::AlertDelivery>, StorageError> {
            self.inner.get_pending_alert_deliveries()
        }

        fn update_alert_delivery(
            &self,
            delivery: &crate::alert::AlertDelivery,
        ) -> Result<(), StorageError> {
            self.inner.update_alert_delivery(delivery)
        }

        fn compact(&self, policy: &CompactionPolicy) -> Result<CompactionReport, StorageError> {
            self.inner.compact(policy)
        }

        fn store_justice_action(
            &self,
            action: &crate::justice::JusticeAction,
        ) -> Result<(), StorageError> {
            self.inner.store_justice_action(action)
        }

        fn get_justice_action(
            &self,
            id: &str,
        ) -> Result<Option<crate::justice::JusticeAction>, StorageError> {
            self.inner.get_justice_action(id)
        }

        fn get_pending_justice_actions(
            &self,
        ) -> Result<Vec<crate::justice::JusticeAction>, StorageError> {
            self.inner.get_pending_justice_actions()
        }

        fn update_justice_action_status(
            &self,
            id: &str,
            status: crate::justice::ActionStatus,
            tx_hash: Option<&str>,
        ) -> Result<(), StorageError> {
            self.inner.update_justice_action_status(id, status, tx_hash)
        }
    }

    #[test]
    fn in_memory_probe_is_healthy_and_read_only_by_default() {
        let report = InMemoryStorage::new().check_health().unwrap();
        assert_eq!(report.backend, "in-memory");
        assert_eq!(report.state, StorageHealthState::Healthy);
        assert!(report.is_healthy());
        assert!(report.read_ok);
        assert_eq!(report.write_probe_ok, None);
        assert!(report.details.is_empty());
    }

    #[test]
    fn write_probe_verifies_and_removes_the_sentinel() {
        let storage = InMemoryStorage::new();
        storage.store_subscription("channel1").unwrap();

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Healthy);
        assert_eq!(report.write_probe_ok, Some(true));
        // The probe must not disturb real subscriptions or leave its sentinel.
        assert_eq!(storage.get_subscriptions().unwrap(), vec!["channel1"]);
    }

    #[test]
    fn invalid_health_check_options_are_rejected() {
        let options = StorageHealthCheckOptions {
            max_latency_ms: 0,
            probe_writes: true,
        };
        let error = InMemoryStorage::new()
            .check_health_with(&options)
            .unwrap_err();
        assert!(error.to_string().contains("max_latency_ms"));

        // Validation is available on its own so callers can reject bad config
        // before constructing a watchtower.
        assert!(options.validate().is_err());
    }

    #[test]
    fn a_failing_read_is_reported_as_unhealthy_without_a_write_probe() {
        let storage = FlakyStorage::new();
        storage.set_fail_read(true);

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Unhealthy);
        assert!(!report.read_ok);
        assert_eq!(report.write_probe_ok, None);
        assert!(report
            .details
            .iter()
            .any(|d| d.contains("read probe failed") && d.contains("injected read failure")));
        assert!(storage.get_subscriptions().is_err());
    }

    #[test]
    fn a_failed_write_probe_leaves_no_subscription_behind() {
        let storage = FlakyStorage::new();
        storage.set_fail_write(true);

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Unhealthy);
        assert_eq!(report.write_probe_ok, Some(false));
        assert!(report
            .details
            .iter()
            .any(|d| d.contains("write probe failed")));
        assert!(
            storage.inner.get_subscriptions().unwrap().is_empty(),
            "a failed probe must not leave partial state"
        );
    }

    #[test]
    fn a_failed_cleanup_is_actionable() {
        let storage = FlakyStorage::new();
        storage.set_fail_cleanup(true);

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Unhealthy);
        assert_eq!(report.write_probe_ok, Some(true));
        assert!(report.details.iter().any(|d| d.contains("cleanup failed")));
        // The sentinel is still visible; the error tells the operator which
        // key to remove rather than failing silently.
        assert!(report.summary().contains("cleanup failed"));
    }

    #[test]
    fn exceeding_the_latency_budget_degrades_the_report() {
        let storage = FlakyStorage::new();
        storage.set_slow_read(true);

        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                max_latency_ms: 1,
                probe_writes: false,
            })
            .unwrap();

        assert_eq!(report.state, StorageHealthState::Degraded);
        assert!(report.read_ok, "the read itself succeeded");
        assert!(report.details.iter().any(|d| d.contains("1ms budget")));
    }

    #[test]
    fn sqlite_probe_reports_that_durability_cannot_be_verified() {
        let storage = SqliteStorage::new(":memory:").unwrap();
        let report = storage
            .check_health_with(&StorageHealthCheckOptions {
                probe_writes: true,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(report.backend, "sqlite");
        assert_eq!(report.state, StorageHealthState::Degraded);
        assert_eq!(report.write_probe_ok, None);
        assert!(report.details.iter().any(|d| d.contains("placeholder")));
    }
}
